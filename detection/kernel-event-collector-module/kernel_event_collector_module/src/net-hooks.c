// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "module_state.h"
#include "net-helper.h"
#include "net-tracking.h"
#include "process-tracking.h"
#include "event-factory.h"
#include "cb-spinlock.h"
#include "cb-isolation.h"
#include "cb-banning.h"
#include <linux/inet.h>
#include <net/ip.h>
#include <net/sock.h>
#include <net/udp.h>

//#include <linux/skbuff.h>
//#include <linux/uio.h>
//#include <linux/audit.h>
//#include <linux/sctp.h>
//#include <linux/workqueue.h>
//#include <linux/jiffies.h>
#include <linux/file.h>

// Would be 'static' except symbol stripping by 'ld' makes it hard for 'perf'
// and analyzing crash dumps.  So use 'LOCAL' as a hint to ease maintenance.
#define LOCAL /*static*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)  //{ RHEL8
#define my_user_msghdr    user_msghdr
#define my_kernel_msghdr  msghdr
#else  //}{ RHEL 6,7
#define my_user_msghdr    msghdr
#define my_kernel_msghdr  msghdr
#endif  //}

#define UDP_PACKET_TIMEOUT   (30 * HZ)

uint64_t recvmsg_cnt;
uint64_t rcv_skb_cnt;
uint64_t relnode_cnt;
#define NETHOOK_RECVMSG_STAT_THROTTLE 100

// The MSG_UDP_HOOK flag is used skip the receive LSM hook so we can call our logic manually.
// This may clash with kernel added flags later!  FIXME: check every new kernel
#define MSG_UDP_HOOK 0x01000000

// Size of IOV buffer that we use to peek at the incoming UDP message
#define IOV_FOR_MSG_PEEK_SIZE 32

static int imax(int a, int b)
{
    return (a >= b) ? a : b;
}

struct Bugbuf {
    short avail;  // decremented by return value of snprintf()
    unsigned short used;  // next position for output
    char *buffer;
};

static int my_timed_recv(
    long (*call_recv_func)(void *p_recv_arg_block),
    void *p_recv_arg_block,
    struct socket *sock,
    long dlta,
    bool our_timeout
)
{
    int return_code = 0;
    struct Bugbuf *const bugbuf = *(struct Bugbuf **)p_recv_arg_block;

    if (bugbuf && bugbuf->buffer) {
        int len = snprintf(&bugbuf->buffer[bugbuf->used], imax(0, bugbuf->avail), "%s\n", __func__);

        bugbuf->used  += len;
        bugbuf->avail -= len;
    }
    if (sock && sock->sk)
    {
        do {
            /* Figure out when we expect our timer to exit so we can check for that later */
            unsigned long expire = sock->sk->sk_rcvtimeo + jiffies;
            mm_segment_t oldfs = get_fs();

            set_fs(get_ds());
            /* Call the system call to get the packet data */
            return_code = call_recv_func(p_recv_arg_block);
            set_fs(oldfs);
            /* If there was time left on the timer, it means that we either received some data or
             * something is wrong with the socket (some applications cause it to close early).
             * In either case we want to exit the loop now.
             */
            if (time_before(jiffies, expire))
            {
                break;
            }
            /* If the module is exiting we need to return from the function. */
            if (g_exiting)
            {
                /* If this is a timeout value that we asked for than simulate receiving a zero
                 * byte packet.  Otherwise we will return with a possibly collected packet.
                 */
                if (our_timeout && return_code == -EAGAIN)
                {
                    // Let caller consider the effect of blocking/non-blocking mode
                    return_code = -EINTR;
                }
                break;
            }
            /* The caller has set a timeout value larger than what we use, we want to subtract
             * from it after each of our timeouts.  When the last timeout will cause their timeout
             * to expire we configure the system to return the EAGAIN.
             */
            if (dlta)
            {
                dlta -= UDP_PACKET_TIMEOUT;
                /* We don't want to set sock->sk->sk_rcvtimeo to 0, it would mean infinite timeout */
                if (dlta <= 0)
                {
                    /* If we're here it means we didn't receive data and xcode has error code now */
                    break;
                } else if (dlta < UDP_PACKET_TIMEOUT)
                {
                    sock->sk->sk_rcvtimeo = dlta;
                }
            }
        } while (our_timeout && return_code == -EAGAIN);
    }
    if (bugbuf && bugbuf->buffer) {
        int len = snprintf(&bugbuf->buffer[bugbuf->used], imax(0, bugbuf->avail), "ptF %x\n", return_code);

        bugbuf->used  += len;
        bugbuf->avail -= len;
    }
    return return_code;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#  define IPV4_SOCKNAME(inet, a) ((inet)->inet_##a)
#  define IPV6_SOCKNAME(sk, a)   ((sk)->sk_v6_##a)
#else
#  define IPV4_SOCKNAME(inet, a) ((inet)->a)
#  define IPV6_SOCKNAME(sk, a)   (inet6_sk(sk)->a)
#endif

bool ec_getudppeername(struct sock *sk, CB_SOCK_ADDR *remoteAddr, struct my_user_msghdr *msg)
{
    int namelen;
    bool rval = false;

    mm_segment_t oldfs = get_fs();

    set_fs(get_ds());

    namelen = msg->msg_namelen;
    if (sk->sk_protocol == IPPROTO_UDP && msg->msg_name && namelen)
    {
        unsigned int nbytes = (sizeof(remoteAddr->ss_addr) >= namelen) ? namelen : sizeof(remoteAddr->ss_addr);

        memcpy(&remoteAddr->ss_addr, msg->msg_name, nbytes);
        rval = true;
    }

    set_fs(oldfs);
    return rval;
}

// I would prefer to use kernel_getpeername here, but it does not work if the socket state is closed.
//  (Which seems to happen under load.)
void ec_getpeername(struct sock *sk, CB_SOCK_ADDR *remoteAddr, struct my_user_msghdr *msg)
{
    CANCEL_VOID(sk);
    CANCEL_VOID(remoteAddr);
    CANCEL_VOID(msg);

    // Use msg->msg_name if we are doing UDP else ...
    if (!ec_getudppeername(sk, remoteAddr, msg))
    {
        struct inet_sock *inet;

        inet = inet_sk(sk);

        remoteAddr->sa_addr.sa_family = sk->sk_family;

        if (sk->sk_family == PF_INET)
        {
            remoteAddr->as_in4.sin_port        = IPV4_SOCKNAME(inet, dport);
            remoteAddr->as_in4.sin_addr.s_addr = IPV4_SOCKNAME(inet, daddr);
        } else {
            remoteAddr->as_in6.sin6_port = IPV4_SOCKNAME(inet, dport);
            memcpy(&remoteAddr->as_in6.sin6_addr, &IPV6_SOCKNAME(sk, daddr), sizeof(struct in6_addr));
        }
    }

}

int __ec_checkIsolate(ProcessContext *context, u16 family, int protocol, struct sockaddr *p_sockaddr)
{
    CB_ISOLATION_INTERCEPT_RESULT isolationResult;

    if (family == PF_INET)
    {
        struct sockaddr_in *as_in4 = (struct sockaddr_in *)p_sockaddr;

        TRACE(DL_VERBOSE, "%s: check iso ip=%x port=%d", __func__, ntohl(as_in4->sin_addr.s_addr), ntohs(as_in4->sin_port));
        ec_IsolationInterceptByAddrProtoPort(context, ntohl(as_in4->sin_addr.s_addr), true, protocol, as_in4->sin_port, &isolationResult);
        if (isolationResult.isolationAction == IsolationActionBlock)
        {
            //classifyOut->actionType = FWP_ACTION_BLOCK;
            //classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            TRACE(DL_NET, "%s: block ip=%x port=%d", __func__, as_in4->sin_addr.s_addr, as_in4->sin_port);
            g_cbIsolationStats.isolationBlockedInboundIp4Packets++;
            return -EPERM;
        } else if (isolationResult.isolationAction == IsolationActionAllow)
        {
            g_cbIsolationStats.isolationAllowedInboundIp4Packets++;
        }
    } else if (family == PF_INET6)
    {
        struct sockaddr_in6 *as_in6 = (struct sockaddr_in6 *)p_sockaddr;

        ec_IsolationInterceptByAddrProtoPort(context, as_in6->sin6_addr.s6_addr32[0], false, protocol, as_in6->sin6_port, &isolationResult);
        if (isolationResult.isolationAction == IsolationActionBlock)
        {
            //classifyOut->actionType = FWP_ACTION_BLOCK;
            //classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
            g_cbIsolationStats.isolationBlockedInboundIp6Packets++;
            return -EPERM;
        } else if (isolationResult.isolationAction == IsolationActionAllow)
        {
            g_cbIsolationStats.isolationAllowedInboundIp6Packets++;
        }
    }
    return 0;
}

LOCAL int my_socket_recvmsg_hook_counted(ProcessContext *context, struct socket *sock, struct my_user_msghdr *msg, int size, int flags)
{
    u16               family;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;
    ProcessHandle    *process_handle = NULL;
    uint16_t          proto = 0;
    pid_t             pid   = ec_getpid(current);
    int               xcode = 0;
    struct cmsghdr   *cmsg_kernel = NULL;

    // The MSG_UDP_HOOK flag is used skip the LSM hook so we can call our logic manually.
    TRY(!(flags & MSG_UDP_HOOK));

    TRY(CHECK_SOCKET(sock));
    TRY(pid != 0);
    TRY(msg != NULL);

    family = sock->sk->sk_family;
    proto = sock->sk->sk_protocol;

    // We can not trust msg->msg_name at all because it is possible that the caller has not
    //  initialized it properly.
    ec_getpeername(sock->sk, &remoteAddr, msg);

    // This is the first place in the syscall hook call stack, where in the routine starts accessing
    // dynamically initialized memory resources. As a pre-condition this check can only occur
    // after ensuring that the module is not disabled.

    TRY_SET_DO(-EPERM != __ec_checkIsolate(context, family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        ec_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "RECV", context);
    TRY(process_handle);

    pid = ec_process_tracking_exec_pid(process_handle, context);

    TRY(!ec_banning_IgnoreProcess(context, pid));

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    {
        int addressLength = sizeof(CB_SOCK_ADDR);

        kernel_getsockname(sock, &localAddr.sa_addr, &addressLength);
    }
#else  //}{
    kernel_getsockname(sock, &localAddr.sa_addr);
#endif  //}

    recvmsg_cnt += 1;
    if ((recvmsg_cnt % NETHOOK_RECVMSG_STAT_THROTTLE) == 0)
    {
        //pr_err("%s: recvmsg_cnt=%llu rcv_skb_cnt=%llu nethash_instance=%llu relnode_cnt=%llu\n", __FUNCTION__, recvmsg_cnt, rcv_skb_cnt, nethash_instance, relnode_cnt);
    }

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(ec_net_tracking_check_cache(context, pid, &localAddr, &remoteAddr, proto, CONN_IN));

    ec_event_send_net(process_handle,
                   "RECV",
                   CB_EVENT_TYPE_NET_ACCEPT,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
    ec_mem_cache_free_generic(cmsg_kernel);
    cmsg_kernel = NULL;
    return xcode;
}

LOCAL int my_socket_recvmsg(ProcessContext *context, struct socket *sock, struct my_user_msghdr *msg, int size, int flags)
{
    int ret = 0;

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);

    ret = my_socket_recvmsg_hook_counted(context, sock, msg, size, flags);

CATCH_DEFAULT:
    FINISH_MODULE_DISABLE_CHECK(context);
    return ret;
}

int ec_lsm_socket_recvmsg(struct socket *sock, struct my_user_msghdr *msg, int size, int flags)
{
    int xcode = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    xcode = g_original_ops_ptr->socket_recvmsg(sock, msg, size, flags);
    TRY(xcode >= 0);
#endif  //}
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // CB-10087, CB-9235
    // Some versions of netcat used a tricky way of reading UDP data.  (They were able to
    //  use the read function like a TCP connection which I did not know was possible.)
    //  This was able to get around my logic to hook UDP.
    // I fixed it by allowing the LSM hook to be called for UDP as well.  I was never happy
    //  handling all UDP from the LSM hook because I observed cases where the address
    //  information was not always filled in when I needed it. I now set a special flag
    //  in the receive hook that allows LSM to be skipped in those cases.
    TRY(CHECK_SOCKET(sock));

    TRY_SET(-EPERM != my_socket_recvmsg_hook_counted(&context, sock, msg, 0, flags), -EPERM);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

//#define PEEK(CONTEXT, call_recv_func, p_recv_arg_block, sock, msg_peek, sk_rcvtimeo_dlta, our_timeout, flags, return_code)

static int64_t my_peek(
    ProcessContext *context,
    long (*call_recv_func)(void *p_recv_arg_block),
    void *p_recv_arg_block,
    struct socket *sock,
    void *msg_peek,  // my_user_msghdr or my_kernel_msghdr
    long sk_rcvtimeo_dlta,
    bool our_timeout,
    unsigned int flags
)
{
    int32_t xcode;
    struct Bugbuf *const bugbuf = *(struct Bugbuf **)p_recv_arg_block;

    if (bugbuf && bugbuf->buffer) {
        int len = snprintf(&bugbuf->buffer[bugbuf->used], imax(0, bugbuf->avail), "%s\n", __func__);

        bugbuf->used  += len;
        bugbuf->avail -= len;
    }
    /* Execute a recv function to peek at the message */
    xcode = my_timed_recv(call_recv_func, p_recv_arg_block, sock, sk_rcvtimeo_dlta, our_timeout);

    /* TIMED_RECV may return if the module is exiting, in this case just return from this function */
    if (g_exiting)
    {
        goto CATCH_DEFAULT;
    }

    TRY(xcode >= 0);
    if (bugbuf && bugbuf->buffer) {
        int len = snprintf(&bugbuf->buffer[bugbuf->used], imax(0, bugbuf->avail), "ptB %x\n", xcode);

        bugbuf->used  += len;
        bugbuf->avail -= len;
    }
    TRY(sock && sock->sk);

    /* Call our local code to process the packet for event generation and isolation */
    TRY_SET(-EPERM != my_socket_recvmsg(context, sock, msg_peek, 0, flags), -EPERM);

    /* If we peeked at UDP message sk_rcvtimeo_dlta is what's left from original timeout value.
     * Unless a caller set original timeout value to 0 sk_rcvtimeo_dlta should be greater than 0 here
     * since we check return code of the recv call above and if it's less than 0 we exit from the function
     * as this means that either no data is received and timeout expired or
     * remote peer terminated connection.
     */
    if (our_timeout)
    {
        if (0 == sk_rcvtimeo_dlta || sk_rcvtimeo_dlta > UDP_PACKET_TIMEOUT)
        {
            sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;
        } else
        {
            sock->sk->sk_rcvtimeo = sk_rcvtimeo_dlta;
            our_timeout = false;
        }
    }
    if (bugbuf && bugbuf->buffer) {
        int len = snprintf(&bugbuf->buffer[bugbuf->used], imax(0, bugbuf->avail), "ptC %x\n", xcode);

        bugbuf->used  += len;
        bugbuf->avail -= len;
    }
    return  (0ul<<32) | (uint32_t)xcode;

CATCH_DEFAULT:
    if (bugbuf && bugbuf->buffer) {
        int len = snprintf(&bugbuf->buffer[bugbuf->used], imax(0, bugbuf->avail), "ptD %x\n", xcode);

        bugbuf->used  += len;
        bugbuf->avail -= len;
    }
    return (-1ul<<32) | (uint32_t)xcode;
}

// calculate new flags for UDP inspection
static unsigned int check_udp_peek(struct socket const *sock, unsigned const flags)
{
    if (CHECK_SOCKET(sock) && IPPROTO_UDP == sock->sk->sk_protocol)
        return (((MSG_ERRQUEUE & flags) ? 0 : MSG_PEEK) | MSG_UDP_HOOK | flags);  // MSG_PEEK is 2
    return ~MSG_UDP_HOOK & flags;
}

void __ec_udp_init_sockets(void);

bool ec_network_hooks_initialize(ProcessContext *context)
{
    // Configure any already running UDP sockets
    __ec_udp_init_sockets();

    return true;
}

void ec_network_hooks_shutdown(ProcessContext *context)
{
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    #define UDP_HTABLE_SIZE udp_table.mask
#endif


void ec_sk_nulls_for_each_rcu(struct hlist_nulls_head *head, bool (*callback)(struct sock *))
{
    struct sock *sk;
    struct hlist_nulls_node *node;

    sk_nulls_for_each_rcu(sk, node, head)
    {
        if (sk)
        {
            callback(sk);
        }
    }
}

void ec_sk_for_each_rcu(struct hlist_head *head, bool (*callback)(struct sock *))
{
#ifdef sk_for_each_rcu
    // Some older kernels do not have sk_for_each_rcu. (This function will never be called
    //  for those kernels anyway.)
    struct sock *sk;

    sk_for_each_rcu(sk, head)
    {
        if (sk)
        {
            callback(sk);
        }
    }
#endif
}

// In newer kernels the `udp_hslot` structure now uses `hlist_head` instead of `hlist_nulls_head`.
//  This figures out which type the variable is, and calls the correct function.  Note, we
//  have to use a static helper function here because `sk_for_each_rcu` and `ec_sk_nulls_for_each_rcu`
//  are MACRO expansions of a for loop.  (This does not play nicely with the __builtin.)
#define ec_for_each(head, callback)                                           \
    __builtin_choose_expr(__builtin_types_compatible_p(typeof(head), struct hlist_nulls_head*),         \
        ec_sk_nulls_for_each_rcu((struct hlist_nulls_head *)head, callback),  \
        ec_sk_for_each_rcu((struct hlist_head *)head, callback))

void __ec_udp_for_each(bool (*callback)(struct sock *))
{
    int slot;
    int size = UDP_HTABLE_SIZE;

    rcu_read_lock();

    for (slot = 0; slot < size; ++slot)
    {
        struct udp_hslot *hslot = &udp_table.hash[slot];

        ec_for_each(&hslot->head, callback);
    }
    rcu_read_unlock();
}

bool __ec_udp_configure_raddr(struct sock *sk)
{
    // TODO: Maybe remove this logic
    //       I found that this logic was no longer getting a valid address.  This
    //       may be because we are collecting the data with peek now.  We need to
    //       do some further testing with this .  (The test app is always using
    //       localhost from a single process, so it is difficult to tell if it is
    //       working correctly.)
    // Configure UDP sockets to extract the destination IP
    // const int      on     = 1;
    // kernel_setsockopt( sk->sk_socket, SOL_IP, IP_PKTINFO, (char*)&on, sizeof(on) );
    // kernel_setsockopt( sk->sk_socket, SOL_IPV6, IPV6_RECVPKTINFO, (char*)&on, sizeof(on) );

    return true;
}

void __ec_udp_init_sockets(void)
{
    __ec_udp_for_each(__ec_udp_configure_raddr);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)  //{
#  define IPV4_SOCKNAME(inet, a) ((inet)->inet_##a)
#  define IPV6_SOCKNAME(sk, a)   ((sk)->sk_v6_##a)
#else  //}{
#  define IPV4_SOCKNAME(inet, a) ((inet)->a)
#  define IPV6_SOCKNAME(sk, a)   (inet6_sk(sk)->a)
#endif  //}

void ec_getsockname(struct sock *sk, CB_SOCK_ADDR *localAddr, struct my_user_msghdr *msg)
{
    struct inet_sock *inet;

    CANCEL_VOID(sk);
    CANCEL_VOID(localAddr);
    CANCEL_VOID(msg);

    inet = inet_sk(sk);

    localAddr->sa_addr.sa_family = sk->sk_family;

    if (sk->sk_family == PF_INET)
    {
        localAddr->as_in4.sin_port        = IPV4_SOCKNAME(inet, sport);
        localAddr->as_in4.sin_addr.s_addr = IPV4_SOCKNAME(inet, saddr);
    } else {
        void              *sin = NULL;

        localAddr->as_in6.sin6_port = IPV4_SOCKNAME(inet, sport);

        sin = ipv6_addr_any(&IPV6_SOCKNAME(sk, rcv_saddr)) ? &inet6_sk(sk)->saddr : &IPV6_SOCKNAME(sk, rcv_saddr);
        memcpy(&localAddr->as_in6.sin6_addr, sin, sizeof(struct in6_addr));
    }
}

int ec_lsm_socket_post_create(struct socket *sock, int family, int type, int protocol, int kern)
{
    int xcode = 0;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_post_create(sock, family, type, protocol, kern);
    TRY(xcode >= 0);
#endif  //}
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(!ec_banning_IgnoreProcess(&context, ec_getpid(current)));

    //
    // We're only interested in TCP over IPv4 or IPv6
    //
    TRY(CHECK_SOCKET(sock));

    //	pr_err("%s: proc=%16s  pid=%d stype=%d proto=%d\n", __FUNCTION__, current->comm, current->pid, sock->type, sock->sk->sk_protocol);
    //	inode = ec_get_inode_from_file(sock->file);
    //	if (inode)
    //	{
    //		pr_err("%s:  socket inode=%lu\n", __FUNCTION__, inode->i_ino);
    //	}
    if (sock->sk->sk_protocol == IPPROTO_UDP)
    {
        __ec_udp_configure_raddr(sock->sk);
    }

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

// Not used for now
int ec_socket_bind(struct socket *sock, struct sockaddr *address, int addrlen)
{
    int xcode = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_bind(sock, address, addrlen);
    TRY(xcode >= 0);
#endif  //}
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);
    TRY(!ec_banning_IgnoreProcess(&context, ec_getpid(current)));

    //
    // We're only interested in TCP over IPv4 or IPv6
    //
    TRY(address->sa_family == AF_INET || address->sa_family == AF_INET6);

    //pr_err("%s: proc=%16s  pid=%d stype=%d proto=%d\n", __FUNCTION__, current->comm, current->pid, sock->type, sock->sk->sk_protocol);
    //inode = ec_get_inode_from_file(sock->file);
    //if (inode)
    //{
    //pr_err("%s:  socket inode=%lu\n", __FUNCTION__, inode->i_ino);
    //}

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

int ec_lsm_socket_sendmsg(struct socket *sock, struct my_user_msghdr *msg, int size)
{
    u16               family;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;
    ProcessHandle    *process_handle = NULL;
    pid_t             pid            = ec_getpid(current);
    int               xcode          = 0;

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_sendmsg(sock, msg, size);
    TRY(xcode >= 0);
#endif  //}

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    TRY(pid != 0);
    TRY(CHECK_SOCKET(sock));

    family = sock->sk->sk_family;
    // Only process IPv4/6 packets

    // In the send path we have to get the remote address from msg->msg_name.
    //  Unfortunately I have found cases where msg->msg_name has not been initialized correctly.
    //  I am attempting to combat this by making sure that msg->msg_namelen is a sane value.
    //  It is still possible that it could pass this test and still be bad.  I am copying it
    //  into a local variable to limit direct usage of msg->msg_name.
    ec_getpeername(sock->sk, &remoteAddr, msg);

    TRY_SET_DO(-EPERM != __ec_checkIsolate(&context, family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        ec_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "SEND", &context);
    TRY(process_handle);

    pid = ec_process_tracking_exec_pid(process_handle, &context);

    TRY(!ec_banning_IgnoreProcess(&context, pid));

    ec_getsockname(sock->sk, &localAddr, msg);

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(ec_net_tracking_check_cache(&context, pid, &localAddr, &remoteAddr, sock->sk->sk_protocol, CONN_OUT));

    ec_event_send_net(process_handle,
                   "SEND",
                   CB_EVENT_TYPE_NET_CONNECT_PRE,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   &context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, &context);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

int __ec_socket_recvmsg_hook_counted(ProcessContext *context, struct socket *sock, struct my_user_msghdr *msg, int size, int flags)
{
    u16               family;
    CB_SOCK_ADDR      localAddr;
    CB_SOCK_ADDR      remoteAddr;
    ProcessHandle    *process_handle = NULL;
    uint16_t          proto = 0;
    pid_t             pid   = ec_getpid(current);
    int               xcode = 0;
    struct cmsghdr   *cmsg_kernel = NULL;

    // The MSG_UDP_HOOK flag is used skip the LSM hook so we can call our logic manually.
    TRY(!(flags & MSG_UDP_HOOK));

    TRY(CHECK_SOCKET(sock));
    TRY(pid != 0);
    TRY(msg != NULL);

    family = sock->sk->sk_family;
    proto = sock->sk->sk_protocol;

    // We can not trust msg->msg_name at all because it is possible that the caller has not
    //  initialized it properly.
    ec_getpeername(sock->sk, &remoteAddr, msg);

    // This is the first place in the syscall hook call stack, where in the routine starts accessing
    // dynamically initialized memory resources. As a pre-condition this check can only occur
    // after ensuring that the module is not disabled.

    TRY_SET_DO(-EPERM != __ec_checkIsolate(context, family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        ec_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "RECV", context);
    TRY(process_handle);

    pid = ec_process_tracking_exec_pid(process_handle, context);

    TRY(!ec_banning_IgnoreProcess(context, pid));

    // For UDP this will probably just get the port
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    {
        int addressLength = sizeof(CB_SOCK_ADDR);

        kernel_getsockname(sock, &localAddr.sa_addr, &addressLength);
    }
#else  //}{
    kernel_getsockname(sock, &localAddr.sa_addr);
#endif  //}

    recvmsg_cnt += 1;
    if ((recvmsg_cnt % NETHOOK_RECVMSG_STAT_THROTTLE) == 0)
    {
        //pr_err("%s: recvmsg_cnt=%llu rcv_skb_cnt=%llu nethash_instance=%llu relnode_cnt=%llu\n", __FUNCTION__, recvmsg_cnt, rcv_skb_cnt, nethash_instance, relnode_cnt);
    }

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(ec_net_tracking_check_cache(context, pid, &localAddr, &remoteAddr, proto, CONN_IN));

    ec_event_send_net(process_handle,
                   "RECV",
                   CB_EVENT_TYPE_NET_ACCEPT,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, context);
    ec_mem_cache_free_generic(cmsg_kernel);
    cmsg_kernel = NULL;
    return xcode;
}

int __ec_socket_recvmsg(ProcessContext *context, struct socket *sock, struct my_user_msghdr *msg, int size, int flags)
{
    int ret = 0;

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(context, CATCH_DEFAULT);

    ret = __ec_socket_recvmsg_hook_counted(context, sock, msg, size, flags);

CATCH_DEFAULT:
    FINISH_MODULE_DISABLE_CHECK(context);
    return ret;
}

int ec_socket_recvmsg(struct socket *sock, struct my_user_msghdr *msg, int size, int flags)
{
    int xcode = 0;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    xcode = g_original_ops_ptr->socket_recvmsg(sock, msg, size, flags);
    TRY(xcode >= 0);
#endif  //}
    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // CB-10087, CB-9235
    // Some versions of netcat used a tricky way of reading UDP data.  (They were able to
    //  use the read function like a TCP connection which I did not know was possible.)
    //  This was able to get around my logic to hook UDP.
    // I fixed it by allowing the LSM hook to be called for UDP as well.  I was never happy
    //  handling all UDP from the LSM hook because I observed cases where the address
    //  information was not always filled in when I needed it. I now set a special flag
    //  in the receive hook that allows LSM to be skipped in those cases.
    TRY(CHECK_SOCKET(sock));

    TRY_SET(-EPERM != __ec_socket_recvmsg_hook_counted(&context, sock, msg, 0, flags), -EPERM);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

//
// Active, outgoing connect (pre)
//
int ec_lsm_socket_connect(struct socket *sock, struct sockaddr *addr, int addrlen)
{
    int                  xcode;
    CB_SOCK_ADDR         localAddr;
    CB_SOCK_ADDR         remoteAddr;
    ProcessHandle       *process_handle = NULL;
    pid_t                pid            = ec_getpid(current);

    DECLARE_ATOMIC_CONTEXT(context, pid);

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->socket_connect(sock, addr, addrlen);
    TRY(xcode >= 0);
#endif  //}
    TRY(sock);

    TRY(CHECK_SOCKET(sock));

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    memcpy(&remoteAddr.ss_addr, addr, addrlen);

    TRY_SET_DO(-EPERM != __ec_checkIsolate(&context, remoteAddr.sa_addr.sa_family, sock->sk->sk_protocol, &remoteAddr.sa_addr), -EPERM, {
        ec_print_address("Isolate Connection", sock->sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });

    process_handle = ec_get_procinfo_and_create_process_start_if_needed(pid, "CONNECT", &context);
    TRY(process_handle);

    pid = ec_process_tracking_exec_pid(process_handle, &context);

    TRY(!ec_banning_IgnoreProcess(&context, pid));

    //
    // We're only interested in TCP over IPv4 or IPv6 so we need to make sure that protocol is TCP
    // before reporting the netconn event. UDP is not supposed to be handled in this hook.
    //
    TRY(sock->sk->sk_protocol == IPPROTO_TCP);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    {
        int addressLength = sizeof(CB_SOCK_ADDR);

        kernel_getsockname(sock, &localAddr.sa_addr, &addressLength);
    }
#else  //}{
    kernel_getsockname(sock, &localAddr.sa_addr);
#endif  //}

    // Track this connection in the local table
    //  If it is a new connection, add an entry and send an event (return value of true)
    //  If it is a tracked connection, update the time and skip sending an event (return value of false)
    TRY(ec_net_tracking_check_cache(&context, pid, &localAddr, &remoteAddr, sock->sk->sk_protocol, CONN_OUT));

    ec_event_send_net(process_handle,
                   "CONNECT",
                   CB_EVENT_TYPE_NET_CONNECT_PRE,
                   &localAddr,
                   &remoteAddr,
                   sock->sk->sk_protocol,
                   sock->sk,
                   &context);

CATCH_DEFAULT:
    ec_process_tracking_put_handle(process_handle, &context);
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

//
// Active, outgoing connect (post). Not used for now
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!! IF DECIDE TO USE THIS HOOK, WILL NEED TO UPDATE IT TO SUPPORT MODULE_DISABLE CHECKS
// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//
void ec_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));
    u16 family = sk->sk_family;

    MODULE_GET(&context);

    /* handle mapped IPv4 packets arriving via IPv6 sockets */
    if ((family == PF_INET6 && skb->protocol == htons(ETH_P_IPV6))
        || (family == PF_INET && skb->protocol == htons(ETH_P_IP))
        )
    {
        ;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    g_original_ops_ptr->inet_conn_established(sk, skb);
#endif  //}
    MODULE_PUT(&context);
}

//
// Passive, incomming connect (Accept)
//
int ec_lsm_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
    int                           xcode           = 0;
    u16                           family          = 0;
    pid_t                         pid             = 0;
    uint16_t                      sport           = 0;
    uint32_t                      sip             = 0;
    CB_SOCK_ADDR                  localAddr;
    CB_SOCK_ADDR                  remoteAddr;

    DECLARE_NON_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)  //{
    // This will always be called anyway, so just do it first.
    xcode = g_original_ops_ptr->inet_conn_request(sk, skb, req);
    TRY(xcode >= 0);
#endif  //}

    BEGIN_MODULE_DISABLE_CHECK_IF_DISABLED_GOTO(&context, CATCH_DEFAULT);

    // Without valid structures, we're dead in the water so there is no sense in
    // attempting to continue.
    TRY_MSG(sk && skb && req,
             DL_NET, "%s:%d Got NULL garbage in the request.", __func__, __LINE__);



    family = sk->sk_family;
    pid    = ec_getpid(current);

    // Handle IPv4 over IPv6
    if (family == PF_INET6 && skb->protocol == htons(ETH_P_IP))
    {
        family = PF_INET;
    }

    // Only handle IPv4/6 TCP packets
    TRY(family == PF_INET6 || family == PF_INET);
    TRY(sk->sk_type == SOCK_STREAM);
    TRY(sk->sk_protocol == IPPROTO_TCP);

    //
    // Populate the event
    //
    if (family == PF_INET)
    {
        struct inet_request_sock *ireq = (struct inet_request_sock *)req;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        sport = ireq->ir_rmt_port;
        sip   = ireq->ir_rmt_addr;
#else
        sport = ireq->rmt_port;
        sip   = ireq->rmt_addr;
#endif

        localAddr.as_in4.sin_family      = PF_INET;
        localAddr.as_in4.sin_port        = sport;
        localAddr.as_in4.sin_addr.s_addr = sip;
    }
    memset(&remoteAddr, 0, sizeof(CB_SOCK_ADDR));

    TRY_SET_DO(-EPERM != __ec_checkIsolate(&context, family, sk->sk_protocol, &localAddr.sa_addr), -EPERM, {
        ec_print_address("Isolate Connection", sk, &localAddr.sa_addr, &remoteAddr.sa_addr);
    });
    ec_print_address("ACCEPT <SILENT>", sk, &localAddr.sa_addr, &remoteAddr.sa_addr);

CATCH_DEFAULT:
    MODULE_PUT_AND_FINISH_MODULE_DISABLE_CHECK(&context);
    return xcode;
}

// These will hold a copy of the old syscall so that it can be called from below and restored
//  when the module is unloaded.
long (*ec_orig_sys_recvfrom)(int fd, void __user *ubuf, size_t size, unsigned int flags,
                             struct sockaddr __user *addr, int __user *addr_len);
long (*ec_orig_sys_recvmsg)(int fd, struct my_user_msghdr __user *msg, unsigned int flags);
long (*ec_orig_sys_recvmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned int flags, struct timespec __user *timeout);

// The functions below replace the linux syscalls.  In most cases we will also call the original
//  syscall.
//
// !!!!! IMPORTANT NOTE AROUND SUPPORT FOR DISABLING MODULE !!!!!!!!!
// The checks to test if module is disabled are done in the inner function my_socket_recvmsg
// This works today because the outer routines don't access any of the memory resources, thus even
// in a disabled module its OK to run the body of the outer routine. If this rule is violated (as
// in the  outer calls do start accessing the memory resources) will have to refactor the checks
// for the disabled checks to work correctly.
//

struct recvmsg_argblock {
    struct Bugbuf *bugbuf;
    int fd;
    struct my_user_msghdr __user *msg;
    unsigned int flags;
};

static long call_ec_orig_sys_recvmsg(void *ab_arg)
{
    struct recvmsg_argblock *ab = ab_arg;

    return ec_orig_sys_recvmsg(ab->fd, ab->msg, ab->flags);
}

asmlinkage long ec_sys_recvmsg(int fd, struct my_user_msghdr __user *msg, unsigned int flags)
{
    int64_t        ycode;
    int            xcode = 0;
    struct socket *sock;
    unsigned int _flags;
    bool           weSetTimeout     = false;
    long           sk_rcvtimeo      = MAX_SCHEDULE_TIMEOUT;
    long           sk_rcvtimeo_dlta = 0;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    sock = sockfd_lookup(fd, &xcode);

    TRY(sock && sock->sk);

    // Always keep track of sk_rcvtimeo
    sk_rcvtimeo = sock->sk->sk_rcvtimeo;

    // For blocking sockets, check to see if the caller has set NO timeout value or one larger
    //  then ours.  If the value is smaller than ours, just let the system work as usual.
    // We want to always have a timeout so that the recv call does not block forever.  Otherwise
    //  we can never unload the module.
    if (!((flags & MSG_DONTWAIT) || (sock->file->f_flags & O_NONBLOCK)) &&
           (sk_rcvtimeo == 0 || sk_rcvtimeo > UDP_PACKET_TIMEOUT))
    {
        weSetTimeout          = true;
        sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;

        // If the caller has configured a timeout larger than ours we want to record it.
        //  Later in the loop we will use it.
        if (sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo;
        }
    }

    // CB-13480
    // In case of UDP IP address/port data that is needed to check for isolation is not always available
    // in the LSM hook, it becomes available only when UDP packet is read.
    // In case of TCP all data that is needed to check for isolation should be available in the LSM hook.
    // In general, we don't want to copy received data to the buffer provided by a caller before we check
    // for isolation because the caller may 'steal' the data from the buffer before
    // we zero it out prior to returning from this call which would allow a caller to bypass isolation.
    //
    // 1. TCP: call original syscall and check for isolation in the LSM hook.
    // 2. UDP, MSG_ERRQUEUE flag is not set by a caller:
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Set MSG_PEEK flag to peek at the data without consuming it
    //    - Allocate small buffer in kernel space and read data into it using original syscall
    //    - Get IP address/port info and check for isolation
    //    - If isolation check fails exit with EPERM error code
    //    - If isolation check is passed call original syscall with (original flags | MSG_UDP_HOOK)
    //      and user buffer
    //    - If a caller specified a timeout value calculate remaining time after exit from syscall
    //      with MSG_PEEK and pass it to the original syscall
    // 3. UDP, MSG_ERRQUEUE flag is set by a caller:
    //    - Assumption is that data from sk->sk_error_queue can be passed to a caller and no
    //      check for isolation is needed, and no need to report this connection either
    //    - MSG_PEEK flag doesn't work in this case, data from error queue is always consumed
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Call original syscall with original flags and user buffer

    // If the module is disabled, we want to avoid interactions with the messages that could affect
    // another active kernel module. This also saves some CPU cycles for disabled modules, as they
    // can jump right to handling the original syscall
    IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    _flags = check_udp_peek(sock, flags);
    if ((MSG_UDP_HOOK & _flags) && !(MSG_ERRQUEUE & _flags))
    {
        mm_segment_t oldfs;
        struct sockaddr_storage sock_addr_peek = {0};
        struct iovec iovec_peek = {0};
        struct my_user_msghdr msg_peek = {0};
        char iovec_peek_buf[IOV_FOR_MSG_PEEK_SIZE] = {0};
        char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};


        msg_peek.msg_iovlen = 1;
        msg_peek.msg_iov = &iovec_peek;
        msg_peek.msg_iov->iov_len = IOV_FOR_MSG_PEEK_SIZE;
        msg_peek.msg_iov->iov_base = iovec_peek_buf;
        msg_peek.msg_name = &sock_addr_peek;
        msg_peek.msg_namelen = sizeof(sock_addr_peek);
        msg_peek.msg_control = cbuf;
        msg_peek.msg_controllen = sizeof(cbuf);

        // We're going to work with msg_peek struct which is allocated in kernel space
        oldfs = get_fs();
        set_fs(get_ds());

        // Peek at the message to determine remote IP address and port
        {
            struct recvmsg_argblock ab = {NULL, fd, &msg_peek, _flags};

            ycode = my_peek(&context, call_ec_orig_sys_recvmsg, (void *)&ab,
                    sock, &msg_peek, sk_rcvtimeo_dlta, weSetTimeout, flags);

            TRY_DO(ycode >= 0, { xcode = (int32_t)ycode; });
        }
        set_fs(oldfs);
    }

    // If we set MSG_UDP_HOOK earlier that means we're dealing with UDP
    // and we either already checked for isolation or we read from ERRQUEUE,
    // In both cases we don't need to use LSM hook
    flags |= _flags & MSG_UDP_HOOK;

CATCH_DISABLED:
    // Get the actual data which will be copied to the buffer provided by caller
    {
        struct recvmsg_argblock ab = {NULL, fd, msg, flags};

        xcode = my_timed_recv(call_ec_orig_sys_recvmsg,  (void *)&ab, sock, sk_rcvtimeo_dlta, weSetTimeout);
    }

CATCH_DEFAULT:
    if (sock)
    {
        // Make sure that the timeout value is restored to where it is supposed to be.
        sock->sk->sk_rcvtimeo = sk_rcvtimeo;
        sockfd_put(sock);
    }
    MODULE_PUT(&context);

    return xcode;
}

struct recvmmsg_argblock {
    struct Bugbuf *bugbuf;
    int fd;
    struct mmsghdr __user *mmsghdr;
    int vlen;
    unsigned int flags;
    struct timespec __user *p_timeout;
};

static long call_ec_orig_sys_recvmmsg(void *ab_arg)
{
    struct recvmmsg_argblock *ab = ab_arg;
    struct Bugbuf *const bb = ab->bugbuf;

    if (bb) {
        int rv;
        struct mmsghdr mh = {{0}, 0};
        struct timespec ts = {0};

        rv = copy_from_user(&mh, ab->mmsghdr, sizeof(mh));
        if (rv)
            mh.msg_len = rv;
        if (ab->p_timeout) {
            rv = copy_from_user(&ts, ab->p_timeout, sizeof(ts));
            if (rv)
                ab->fd |= 1<<31;
        }
        rv = snprintf(&bb->buffer[bb->used], imax(0, bb->avail),
            "%s: fd=%d mmsghdr={msg_len=%d msg_hdr={_name=%d,%p _iov=%d,%p _control=%d,%p _flags=0x%x}}  vlen=%d  flags=0x%x timeout={%u.%u}\n",
            __func__, ab->fd, mh.msg_len,
            (int)mh.msg_hdr.msg_namelen,    mh.msg_hdr.msg_name,
            (int)mh.msg_hdr.msg_iovlen,     mh.msg_hdr.msg_iov,
            (int)mh.msg_hdr.msg_controllen, mh.msg_hdr.msg_control,
            mh.msg_hdr.msg_flags,
            (int)ab->vlen, ab->flags, (unsigned int)ts.tv_sec, (unsigned int)ts.tv_nsec);
        bb->used  += rv;
        bb->avail -= rv;
    }
    return ec_orig_sys_recvmmsg(ab->fd, ab->mmsghdr, ab->vlen, ab->flags, ab->p_timeout);
}

extern uint32_t ec_prsock_buflen;

asmlinkage long ec_sys_recvmmsg(int fd, struct mmsghdr __user *msg,
                                unsigned int vlen, unsigned int flags,
                                struct timespec __user *timeout)
{
    int64_t         ycode;
    int             xcode = 0;
    struct socket   *sock;
    struct timespec _timeout = {0, 0};
    unsigned int _flags;
    bool            weSetTimeout     = false;
    long            sk_rcvtimeo      = MAX_SCHEDULE_TIMEOUT;
    long            sk_rcvtimeo_arg  = MAX_SCHEDULE_TIMEOUT;
    long            sk_rcvtimeo_dlta = 0;
    struct Bugbuf bugbuf = {
        .avail = ec_prsock_buflen,
        .used  = 0,
        .buffer = __builtin_alloca(ec_prsock_buflen)
    };

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    if (!ec_prsock_buflen)
        bugbuf.buffer = NULL;

    MODULE_GET(&context);

    sock = sockfd_lookup(fd, &xcode);

    TRY(sock && sock->sk);

    // Always keep track of sk_rcvtimeo
    sk_rcvtimeo = sock->sk->sk_rcvtimeo;

    // struct timespec __user *timeout is a user space pointer.
    // NULL pointer means an infinite timeout, otherwise we need to copy
    // the timespec structure from user space to kernel space
    if (timeout)
    {
        TRY_SET(!copy_from_user(&_timeout, timeout, sizeof(_timeout)), -EINVAL);
    }

    // If the caller specified a timeout value I will take that one into account as well,
    //  but I will let one configured from setsocketopt take precedence.
    // Kernel's __sys_recvmmsg() calls __sys_recvmsg() in a loop to collect messages.
    // The socket timeout is used for __sys_recvmsg() calls only. The timeout structure that the caller
    // passes to recvmmsg() is used to determine when to exit the loop. If __sys_recvmsg() times out
    // the loop is terminated and __sys_recvmmsg() returns no matter what timeout value the caller specified
    // in the timespec structure. Given all that we don't need to modify timespec structure here, adjusting
    // socket timeout value so it doesn't block forever is enough.
    if (sk_rcvtimeo == MAX_SCHEDULE_TIMEOUT && timeout)
    {
        if (_timeout.tv_sec != 0 || _timeout.tv_nsec != 0)
        {
            __kernel_suseconds_t tv_usec = _timeout.tv_nsec / NSEC_PER_USEC;

            sk_rcvtimeo_arg = _timeout.tv_sec*HZ + (tv_usec+(1000000/HZ-1))/(1000000/HZ);
        }
    }

    // For blocking sockets, check to see if the caller has set NO timeout value or one larger
    //  then ours.  If the value is smaller than ours, just let the system work as usual.
    // We want to always have a timeout so that the recv call does not block forever.  Otherwise
    //  we can never unload the module.
    if (!((flags & MSG_DONTWAIT) || (sock->file->f_flags & O_NONBLOCK))
    && (sk_rcvtimeo == 0
       || (sk_rcvtimeo > UDP_PACKET_TIMEOUT && sk_rcvtimeo_arg > UDP_PACKET_TIMEOUT)))
    {
        weSetTimeout          = true;
        sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;

        // If the caller has configured a timeout larger than ours we want to record it.
        //  Later in the loop we will use it.
        if (sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo;
        } else if (sk_rcvtimeo_arg != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo_arg > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo_arg;
        }
    }

    // If the module is disabled, we want to avoid interactions with the messages that could affect
    // another active kernel module. This also saves some CPU cycles for disabled modules, as they
    // can jump right to handling the original syscall
    IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    _flags = check_udp_peek(sock, flags);
    if ((MSG_UDP_HOOK & _flags) && !(MSG_ERRQUEUE & _flags))
    {
        struct sockaddr_storage sock_addr_peek = {0};
        struct mmsghdr mmsg_peek = {{0}, 0};
        struct iovec iovec_peek = {0};
        char iovec_peek_buf[IOV_FOR_MSG_PEEK_SIZE] = {0};
        char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
        long sk_rcvtimeo_dlta_peek = 0;
        struct timespec *p_timeout = NULL;

        mmsg_peek.msg_hdr.msg_iovlen = 1;
        mmsg_peek.msg_hdr.msg_iov = &iovec_peek;
        mmsg_peek.msg_hdr.msg_iov->iov_len = IOV_FOR_MSG_PEEK_SIZE;
        mmsg_peek.msg_hdr.msg_iov->iov_base = iovec_peek_buf;
        mmsg_peek.msg_hdr.msg_name = &sock_addr_peek;
        mmsg_peek.msg_hdr.msg_namelen = sizeof(sock_addr_peek);
        mmsg_peek.msg_hdr.msg_control = cbuf;
        mmsg_peek.msg_hdr.msg_controllen = sizeof(cbuf);
        mmsg_peek.msg_len = 0;

        // Initial value of sk_rcvtimeo_dlta should be restored after peeking because socket timeout is used in recvmsg()
        // which is called by recvmmsg() internally in a loop and it should be the same value for all recvmsg() calls.
        // PEEK() calls TIMED_RECV() which adjusts sk_rcvtimeo_dlta, that's why we use sk_rcvtimeo_dlta_peek here to
        // preserved.nitial value of sk_rcvtimeo_dlta that will be passed to the non-peeking system call below.
        sk_rcvtimeo_dlta_peek = sk_rcvtimeo_dlta;

        // If the caller provided timeout value we need to use our kernel space copy of it for peeking because
        // we call set_fs(get_ds()) below before recvmmsg() syscall so kernel will accept pointers to kernel address space
        // which can be exploited if the caller provides such a pointer because recvmmsg() reads and writes timespec structure
        if (timeout)
        {
            p_timeout = &_timeout;
        }

        // Peek at the message to determine remote IP address and port.
        // timeout value will be updated with remaining time if recvmmsg() receives a datagram
        // We only need one message at this time as we're checking/reporting only the first received packet for now
        // TODO: CB-11228 - we need to check/report every packet we received, not only the first one
        {
            struct recvmmsg_argblock ab = {&bugbuf, fd, &mmsg_peek, 1, _flags, p_timeout};

            ycode = my_peek(&context, call_ec_orig_sys_recvmmsg, (void *)&ab,
                    sock, &mmsg_peek.msg_hdr, sk_rcvtimeo_dlta_peek, weSetTimeout, flags);

            TRY_DO(ycode >= 0, { xcode = (int32_t)ycode; });
        }

        // If the caller provided timeout our kernel space timespec structure was updated by the recvmmsg() syscall
        // Now we need to copy it back to the caller's structure
        if (timeout && p_timeout)
        {
            TRY_SET(!copy_to_user(timeout, p_timeout, sizeof(struct timespec)), -EINVAL);
        }
    }

    // If we set MSG_UDP_HOOK earlier that means we're dealing with UDP
    // and we either already checked for isolation or we read from ERRQUEUE,
    // In both cases we don't need to use LSM hook
    flags |= _flags & MSG_UDP_HOOK;

CATCH_DISABLED:
    // This call can block here for a long time if the caller passes a big timeout value or doesn't specify the timeout at all.
    // In this case recvmmsg() will call recvmsg() in a loop until either of the following conditions are met:
    // 1. Caller's timeout expires (if it's set)
    // 2. Socket timeout expires
    // 3. There are no more my_user_msghdr structures available to store incoming packets
    // We can't unload our kernel module until we exit from this call, so this behavior may cause delays when unloading the module.
    {
        struct recvmmsg_argblock ab = {&bugbuf, fd, msg, vlen, flags, timeout};

        xcode = my_timed_recv(call_ec_orig_sys_recvmmsg, (void *)&ab, sock, sk_rcvtimeo_dlta, weSetTimeout);
    }

CATCH_DEFAULT:
    if (sock)
    {
        // Make sure that the timeout value is restored to where it is supposed to be.
        sock->sk->sk_rcvtimeo = sk_rcvtimeo;
        sockfd_put(sock);
    }
    MODULE_PUT(&context);
    if (bugbuf.buffer) {
        pr_err("(used=%u avail=%d) xcode=0x%x: %s\n",
            bugbuf.used, bugbuf.avail, xcode, bugbuf.buffer);
    }
    return xcode;
}

struct kernel_recvmsg_argblock {
    struct Bugbuf *bugbuf;
    struct socket *sock;
    struct msghdr *msg;
    struct kvec *iov;
    int n;
    unsigned int flags;
    unsigned int _flags;
};

static long call_kernel_recvmsg(void *ab_arg)
{
    struct kernel_recvmsg_argblock *ab = ab_arg;

    return kernel_recvmsg(ab->sock, ab->msg, ab->iov, ab->n, ab->flags, ab->_flags);
}

struct recvfrom_argblock {
    struct Bugbuf *bugbuf;
    int fd;
    void __user *ubuf;
    size_t size;
    unsigned int flags;
    struct sockaddr __user *addr;
    int __user *addr_len;
};

static long call_ec_orig_sys_recvfrom(void *ab_arg)
{
    struct recvfrom_argblock *ab = ab_arg;

    return ec_orig_sys_recvfrom(ab->fd, ab->ubuf, ab->size, ab->flags, ab->addr, ab->addr_len);
}

asmlinkage long ec_sys_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags,
                             struct sockaddr __user *addr, int __user *addr_len)
{
    struct socket *sock;
    int64_t       ycode;
    int           xcode = 0;
    bool          weSetTimeout = false;
    long          sk_rcvtimeo  = MAX_SCHEDULE_TIMEOUT;
    long          sk_rcvtimeo_dlta = 0;
    unsigned int _flags;

    DECLARE_ATOMIC_CONTEXT(context, ec_getpid(current));

    MODULE_GET(&context);

    sock = sockfd_lookup(fd, &xcode);

    TRY(sock && sock->sk);

    // Always keep track of sk_rcvtimeo
    sk_rcvtimeo = sock->sk->sk_rcvtimeo;

    if (sock->file->f_flags & O_NONBLOCK)
    {
        flags |= MSG_DONTWAIT;
    }
    // For blocking sockets, check to see if the caller has set NO timeout value or one larger
    //  then ours.  If the value is smaller than ours, just let the system work as usual.
    // We want to always have a timeout so that the recv call does not block forever.  Otherwise
    //  we can never unload the module.
    else if (sk_rcvtimeo == 0 || sk_rcvtimeo > UDP_PACKET_TIMEOUT)
    {
        weSetTimeout          = true;
        sock->sk->sk_rcvtimeo = UDP_PACKET_TIMEOUT;

        // If the caller has configured a timeout larger than ours we want to record it.
        //  Later in the loop we will use it.
        if (sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT && sk_rcvtimeo > UDP_PACKET_TIMEOUT)
        {
            sk_rcvtimeo_dlta = sk_rcvtimeo;
        }
    }

    // CB-13703
    // In case of UDP IP address/port data that is needed to check for isolation is not always available
    // in the LSM hook, it becomes available only when UDP packet is read.
    // In case of TCP all data that is needed to check for isolation should be available in the LSM hook.
    // In general, we don't want to copy received data to the buffer provided by a caller before we check
    // for isolation.
    //
    // 1. TCP: call original syscall and check for isolation in the LSM hook.
    // 2. UDP, MSG_ERRQUEUE flag is not set by a caller:
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Set MSG_PEEK flag to peek at the data without consuming it
    //    - Allocate small buffer in kernel space and read data into it using kernel_recvmsg()
    //    - Get IP address/port info and check for isolation
    //    - If isolation check fails exit with EPERM error code
    //    - If isolation check is passed call original syscall with (original flags | MSG_UDP_HOOK)
    //      and user buffer
    //    - If a caller specified a timeout value calculate remaining time after exit from syscall
    //      with MSG_PEEK and pass it to the original syscall
    // 3. UDP, MSG_ERRQUEUE flag is set by a caller:
    //    - Assumption is that data from sk->sk_error_queue can be passed to a caller and no
    //      check for isolation is needed, and no need to report this connection either
    //    - MSG_PEEK flag doesn't work in this case, data from error queue is always consumed
    //    - Set MSG_UDP_HOOK flag to skip LSM hook
    //    - Call original syscall with original flags and user buffer
    // 4. Only handle the type of sockets we are interested in recvmsg. So pass the rest to
    //    the standard syscall. I need to do this because kernel_recvmsg logic below messes up some
    //    non-ip sockets (Specifically I noticed a problem with PF_NETLINK.)

    // If the module is disabled, we want to avoid interactions with the messages that could affect
    // another active kernel module. This also saves some CPU cycles for disabled modules, as they
    // can jump right to handling the original syscall
    IF_MODULE_DISABLED_GOTO(&context, CATCH_DISABLED);

    _flags = check_udp_peek(sock, flags);
    if ((MSG_UDP_HOOK & _flags) && !(MSG_ERRQUEUE & _flags))
    {
        // Unlike in the recvmsg and recvmmsg calls, we can not call the real syscall to get the packet
        //  because we need a struct my_user_msghdr object for our logic.  The code below has been adapted from
        //  the recvfrom call in the kernel source.
        struct iovec             iov;
        struct my_kernel_msghdr  msg;
        struct sockaddr_storage  address;
        char                     cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))] = {0};
        char                     peek_buf[IOV_FOR_MSG_PEEK_SIZE] = {0};

        msg.msg_flags      = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);
        msg.msg_control    = cbuf;
        msg.msg_controllen = sizeof(cbuf);
        msg.msg_name       = (struct sockaddr *)&address;
        msg.msg_namelen    = sizeof(address);
        iov.iov_len        = IOV_FOR_MSG_PEEK_SIZE;
        iov.iov_base       = peek_buf;

        // Get information needed for isolation check
        {
            struct kernel_recvmsg_argblock ab = {NULL, sock, &msg, (struct kvec *)&iov, 1, IOV_FOR_MSG_PEEK_SIZE, _flags};

            ycode = my_peek(&context, call_kernel_recvmsg, (void *)&ab,
                    sock, &msg, sk_rcvtimeo_dlta, weSetTimeout, flags);

            TRY_DO(ycode >= 0, { xcode = (int32_t)ycode; });
        }
    }

    // If we set MSG_UDP_HOOK earlier that means we're dealing with UDP
    // and we either already checked for isolation or we read from ERRQUEUE,
    // In both cases we don't need to use LSM hook
    flags |= _flags & MSG_UDP_HOOK;

CATCH_DISABLED:
    // Call original syscall which should populate all the buffers and variables that a caller passed in
    {
        struct recvfrom_argblock ab = {NULL, fd, ubuf, size, flags, addr, addr_len};

        xcode = my_timed_recv(call_ec_orig_sys_recvfrom, (void *)&ab, sock, sk_rcvtimeo_dlta, weSetTimeout);
    }

CATCH_DEFAULT:
    if (sock)
    {
        // Make sure that the timeout value is restored to where it is supposed to be.
        sock->sk->sk_rcvtimeo = sk_rcvtimeo;
        sockfd_put(sock);
    }
    MODULE_PUT(&context);
    return xcode;
}

#ifdef __NR_recv  //{
#warning "The sys_recv call is used, and we have not provided a hook for it."
#endif  //}
