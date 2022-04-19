// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "priv.h"
#include "net-helper.h"

#include <linux/inet.h>

#define IPV6_SCOPE_DELIMITER '%'
#define IPV6_SCOPE_ID_LEN sizeof("%nnnnnnnnnn")
size_t __ec_rpc_ntop6_noscopeid(const struct sockaddr *sap,
                                char *buf, const int buflen)
{
    const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;
    const struct in6_addr *addr = &sin6->sin6_addr;

    /*
     * RFC 4291, Section 2.2.2
     *
     * Shorthanded ANY address
     */
    if (ipv6_addr_any(addr))
        return snprintf(buf, buflen, "::");

    /*
     * RFC 4291, Section 2.2.2
     *
     * Shorthanded loopback address
     */
    if (ipv6_addr_loopback(addr))
        return snprintf(buf, buflen, "::1");

    /*
     * RFC 4291, Section 2.2.3
     *
     * Special presentation address format for mapped v4
     * addresses.
     */
    if (ipv6_addr_v4mapped(addr))
        return snprintf(buf, buflen, "::ffff:%pI4",
        &addr->s6_addr32[3]);

    /*
     * RFC 4291, Section 2.2.1
     */
    return snprintf(buf, buflen, "%pI6c", addr);
}


size_t __ec_rpc_ntop6(const struct sockaddr *sap,
                        char *buf, const size_t buflen)
{
    const struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sap;
    char scopebuf[IPV6_SCOPE_ID_LEN];
    size_t len;
    int rc;

    len = __ec_rpc_ntop6_noscopeid(sap, buf, buflen);
    if (unlikely(len == 0))
        return len;

    if (!(ipv6_addr_type(&sin6->sin6_addr) & IPV6_ADDR_LINKLOCAL))
        return len;
    if (sin6->sin6_scope_id == 0)
        return len;

    rc = snprintf(scopebuf, sizeof(scopebuf), "%c%u",
        IPV6_SCOPE_DELIMITER, sin6->sin6_scope_id);
    if (unlikely((size_t)rc > sizeof(scopebuf)))
        return 0;

    len += rc;
    if (unlikely(len > buflen))
        return 0;

    strcat(buf, scopebuf);
    return len;
}

int __ec_rpc_ntop4(const struct sockaddr *sap,
                     char *buf, const size_t buflen)
{
    const struct sockaddr_in *sin = (struct sockaddr_in *)sap;

    return snprintf(buf, buflen, "%pI4", &sin->sin_addr);
}

/**
 * rpc_ntop - construct a presentation address in @buf
 * @sap: socket address
 * @buf: construction area
 * @buflen: size of @buf, in bytes
 *
 * Plants a %NUL-terminated string in @buf and returns the length
 * of the string, excluding the %NUL.  Otherwise zero is returned.
 */
size_t ec_ntop(const struct sockaddr *sap, char *buf, const size_t buflen, uint16_t *port)
{
    switch (sap->sa_family) {
    case AF_INET:
       *port = ((struct sockaddr_in *)sap)->sin_port;
        return __ec_rpc_ntop4(sap, buf, buflen);
    case AF_INET6:
       *port = ((struct sockaddr_in6 *)sap)->sin6_port;
        return __ec_rpc_ntop6(sap, buf, buflen);
    }

    memset(buf, 0, buflen);
    *port = 0;
    return 0;
}

void ec_set_sockaddr_port(CB_SOCK_ADDR *addr, uint32_t port)
{
    if (addr->sa_addr.sa_family == AF_INET)
    {
        addr->as_in4.sin_port = port;
    } else
    {
        addr->as_in6.sin6_port = port;
    }
}

void ec_copy_sockaddr(CB_SOCK_ADDR *left, CB_SOCK_ADDR *right)
{
    if (right->sa_addr.sa_family == AF_INET)
    {
        ec_copy_sockaddr_in(&left->as_in4, &right->as_in4);
    } else
    {
        ec_copy_sockaddr_in6(&left->as_in6, &right->as_in6);
    }
}

void ec_copy_sockaddr_in(struct sockaddr_in *left, struct sockaddr_in *right)
{
    if (left && right)
    {
        left->sin_family = right->sin_family;
        left->sin_port   = right->sin_port;
        left->sin_addr   = right->sin_addr;
    }
}

void ec_copy_sockaddr_in6(struct sockaddr_in6 *left, struct sockaddr_in6 *right)
{
    if (left && right)
    {
        left->sin6_family = right->sin6_family;
        left->sin6_port   = right->sin6_port;
        memcpy(&left->sin6_addr, &right->sin6_addr, sizeof(struct in6_addr));
    }
}

void ec_print_address(
    char                  *msg,
    const struct sock     *sk,
    const struct sockaddr *localAddr,
    const struct sockaddr *remoteAddr)
{
    uint16_t  rport                         = 0;
    uint16_t  lport                         = 0;
    char      raddr_str[INET6_ADDRSTRLEN*2] = {0};
    char      laddr_str[INET6_ADDRSTRLEN*2] = {0};


    ec_ntop(remoteAddr, raddr_str, sizeof(raddr_str), &rport);
    ec_ntop(localAddr,  laddr_str, sizeof(laddr_str), &lport);
    TRACE(DL_NET, "%s proc=%s pid=%d %s-%s laddr=%s:%u raddr=%s:%u",
       (msg ? msg : ""),
       current->comm,
       current->pid,
       PROTOCOL_STR(sk->sk_protocol),
       TYPE_STR(sk->sk_type),
       laddr_str, ntohs(lport), raddr_str, ntohs(rport));
}
