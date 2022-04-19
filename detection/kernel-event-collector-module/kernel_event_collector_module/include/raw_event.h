/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#ifdef __KERNEL__
#include <linux/connector.h>
#include <linux/in.h>
#else
#include <netinet/in.h>
#include <limits.h>
#endif


//
// Defines stuff shared between kernel and user for logger events
//

#pragma pack(push, 1)

#define CB_EVENT_FILTER_PROCESSES 0x00000001
#define CB_EVENT_FILTER_MODULE_LOADS 0x00000002
#define CB_EVENT_FILTER_FILEMODS 0x00000004
#define CB_EVENT_FILTER_NETCONNS 0x00000008
#define CB_EVENT_FILTER_DATAFILEWRITES 0x00000010
#define CB_EVENT_FILTER_PROCESSUSER 0x00000020
#define CB_EVENT_FILTER_ALL 0x0000003F

typedef enum CB_CONFIG_OPTION {
    NO_CHANGE                 = 0,
    DISABLE                   = 1,
    ENABLE                    = 2,
    ALL_FORKS_AND_EXITS       = 3,
    EXECS_ONLY                = 4,
    COLLAPSED_EXITS_ALL_FORKS = 5,
    COLLAPSED_EXITS_NO_FORKS  = 6,
} CB_CONFIG_OPTION;

typedef struct CB_DRIVER_CONFIG {
    CB_CONFIG_OPTION processes;
    CB_CONFIG_OPTION module_loads;
    CB_CONFIG_OPTION file_mods;
    CB_CONFIG_OPTION net_conns;
    CB_CONFIG_OPTION report_process_user;
    CB_CONFIG_OPTION report_file_intent;

    #ifdef __cplusplus
        bool operator == (struct CB_DRIVER_CONFIG & other)
        {
            return (processes == other.processes &&
                module_loads == other.module_loads &&
                file_mods == other.file_mods &&
                net_conns == other.net_conns &&
                report_process_user == other.report_process_user);
        }
    #endif
} CB_DRIVER_CONFIG;

typedef enum CB_EVENT_ACTION_TYPE {
    CB_EVENT_ACTION_NONE = 0,
    CB_EVENT_ACTION_CLEAR_EVENT_QUEUE = 1,
    CB_EVENT_ACTION_DISABLE_EVENT_COLLECTOR = 2,
    CB_EVENT_ACTION_ENABLE_EVENT_COLLECTOR = 3,
    CB_EVENT_ACTION_REQUEST_PROCESS_DISCOVERY = 4
} CB_EVENT_ACTION_TYPE;

#define CB_MAX_CMDLINE_SIZE 1024

#define CB_PROCESS_START_BY_FORK     0x00000001
#define CB_PROCESS_START_BY_EXEC     0x00000002
#define CB_PROCESS_START_BY_DISCOVER 0x00000003

#define CMDLINE_MAX_PAGES 2
#define CMDLINE_MAX_SIZE (2 * 512)

typedef enum CB_EVENT_TYPE {
  CB_EVENT_TYPE_UNKNOWN = 0,

  CB_EVENT_TYPE_PROCESS_START = 1,
  CB_EVENT_TYPE_PROCESS_EXIT = 2,
  CB_EVENT_TYPE_MODULE_LOAD = 3,

  CB_EVENT_TYPE_FILE_CREATE = 10,
  CB_EVENT_TYPE_FILE_DELETE = 11,
  CB_EVENT_TYPE_FILE_WRITE = 12,
  CB_EVENT_TYPE_FILE_CLOSE = 13,
  // CB_EVENT_TYPE_DIR_CREATE          = 14,
  // CB_EVENT_TYPE_DIR_DELETE          = 15,
  CB_EVENT_TYPE_FILE_OPEN = 16,

  CB_EVENT_TYPE_NET_CONNECT_PRE = 20,
  CB_EVENT_TYPE_NET_CONNECT_POST = 21,
  CB_EVENT_TYPE_NET_ACCEPT = 22,

  CB_EVENT_TYPE_DNS_RESPONSE = 25,
  // CB_EVENT_TYPE_CHILDPROC_START     = 26,
  CB_EVENT_TYPE_PROC_ANALYZE = 27,
  CB_EVENT_TYPE_PROCESS_BLOCKED = 28,
  CB_EVENT_TYPE_PROCESS_NOT_BLOCKED = 29,

  CB_EVENT_TYPE_WEB_PROXY = 30,

  CB_EVENT_TYPE_HEARTBEAT = 31,

  CB_EVENT_TYPE_PROCESS_START_FORK = 32, /* internal type (not sent to user space) */
  CB_EVENT_TYPE_PROCESS_START_EXEC = 33, /* internal type (not sent to user space) */
  CB_EVENT_TYPE_PROCESS_LAST_EXIT = 34,

  CB_EVENT_TYPE_MAX
} CB_EVENT_TYPE;

typedef struct process_details {
    uint64_t          device;
    uint64_t          inode;
    pid_t             pid;
    time_t            start_time;
} ProcessDetails;

typedef enum PROC_RELATION {
    FORK = 0,
    FORK_PARENT = 1,
    FORK_GRANDPARENT = 2,
    EXEC = 3,
    EXEC_PARENT = 4,
    EXEC_GRANDPARENT = 5,
    MAX_RELATION = 5,
} PROC_RELATION;

// all the process details
typedef struct all_process_details {
    // wrap in a struct to allow copy by value
    ProcessDetails array[6];
} AllProcessDetails;

typedef struct _CB_EVENT_PROCESS_INFO {
    AllProcessDetails all_process_details;

    time_t event_time;         // Windows time this event occured

    char *path;
    uint16_t path_size;
    uint16_t path_offset;
    bool path_found;
} CB_EVENT_PROCESS_INFO, *PCB_EVENT_PROCESS_INFO;

typedef struct _CB_EVENT_PROC_ANALYZE {
    pid_t pid;
    char *path;
} CB_EVENT_PROC_ANALYZE, *PCB_EVENT_PROC_ANALYZE;

typedef struct _CB_EVENT_PROCESS_START {
    char *path;
    uint16_t path_size;
    uint16_t path_offset;
    uid_t uid;
    int start_action; // 1 = FORK 2 = EXEC 3 = DISCOVER
    bool observed; // Flag to identify if the start was actually observed, or this
                 // fake
} CB_EVENT_PROCESS_START, *PCB_EVENT_PROCESS_START;

typedef struct _CB_EVENT_MODULE_LOAD {
    char *path;
    uint16_t path_size;
    uint16_t path_offset;
    int64_t baseaddress;
    uint64_t device;
    uint64_t inode;
} CB_EVENT_MODULE_LOAD, *PCB_EVENT_MODULE_LOAD;

typedef struct _CB_EVENT_FILE_GENERIC {
    char *path;
    uint16_t path_size;
    uint16_t path_offset;
    uint64_t device;
    uint64_t inode;
} CB_EVENT_FILE_GENERIC, *PCB_EVENT_FILE_GENERIC;

typedef struct _CB_EVENT_HEARTBEAT {
    char *_reserved;
    size_t user_memory;
    size_t user_memory_peak;
    union {
        size_t kernel_memory; // for legacy kernel driver
        size_t counter;       // for ebpf driver
    };
    size_t kernel_memory_peak;
} CB_EVENT_HEARTBEAT, *PCB_EVENT_HEARTBEAT;

typedef struct _CB_EVENT_FILE_GENERIC CB_EVENT_FILE_CREATE,
    *PCB_EVENT_FILE_CREATE;
typedef struct _CB_EVENT_FILE_GENERIC CB_EVENT_FILE_DELETE,
    *PCB_EVENT_FILE_DELETE;
typedef struct _CB_EVENT_FILE_GENERIC CB_EVENT_DIR_CREATE,
    *PCB_EVENT_DIR_CREATE;
typedef struct _CB_EVENT_FILE_GENERIC CB_EVENT_DIR_DELETE,
    *PCB_EVENT_DIR_DELETE;
typedef struct _CB_EVENT_FILE_GENERIC CB_EVENT_FILE_WRITE,
    *PCB_EVENT_FILE_WRITE;

typedef union _CB_SOCK_ADDR {
  struct sockaddr_storage ss_addr;
  struct sockaddr sa_addr;
  struct sockaddr_in as_in4;
  struct sockaddr_in6 as_in6;

  #ifdef __cplusplus
  bool IsV4(void) const
  {
      return (ss_addr.ss_family == AF_INET);
  }

  const uint32_t & V4Address() const
  {
    return as_in4.sin_addr.s_addr;
  }

  uint16_t V4Port(void) const
  {
    return ntohs(as_in4.sin_port);
  }

  typedef uint8_t v6addr_t[16];
  const v6addr_t & V6Address() const
  {
    return as_in6.sin6_addr.s6_addr;
  }

  uint16_t V6Port(void) const
  {
    return ntohs(as_in6.sin6_port);
  }

  int Family(void) const
  {
      return ss_addr.ss_family;
  }

  const char *Family_ToString(void) const
  {
    if (IsV4())
        return "IpV4";
    else
        return "IpV6";
  }

  uint16_t Port(void) const
  {
    if (IsV4())
        return V4Port();
    else
        return V6Port();
  }

  const void *Address(void) const
  {
    if (IsV4())
        return &as_in4.sin_addr;
    else
        return &as_in6.sin6_addr;
  }
  #endif
} CB_SOCK_ADDR;

#define PROXY_SERVER_MAX_LEN 256
typedef struct _CB_EVENT_NETWORK_CONNECT {
    char *actual_server;
    uint16_t server_size;
    uint16_t server_offset;
    int32_t protocol;
    CB_SOCK_ADDR localAddr;
    CB_SOCK_ADDR remoteAddr;
    uint16_t actual_port;

    #ifdef __cplusplus
        bool is_v4(void) const { return localAddr.IsV4(); }
        const char *Family_ToString(void) const { return localAddr.Family_ToString(); }
        int Family(void) const { return localAddr.Family(); }
    #endif
} CB_EVENT_NETWORK_CONNECT, *PCB_EVENT_NETWORK_CONNECT;

struct dnshdr {
  u_int16_t id;
  u_int16_t flags;
  u_int16_t ques_num;
  u_int16_t ans_num;
  u_int16_t auth_rrs;
  u_int16_t addi_rrs;
};

#define DNS_MAX_NAME 256

// Basically http://subversion.assembla.com/svn/132531/indv/push_dns/trunk/poller/src/
// Status returned in a CB_DNS_RECORD
enum QTYPE
{
    QT_A     = 1,
    QT_NS    = 2,
    QT_CNAME = 5,
    QT_SOA   = 6,
    QT_PTR   = 0xC,
    QT_MX    = 0xf,
    QT_TXT   = 0x10,
    QT_AAAA  = 0x1c
};

// DNS Resource Record
typedef struct _CB_DNS_RECORD
{
    char     name[DNS_MAX_NAME];
    uint16_t dnstype;
    uint16_t dnsclass;
    uint32_t ttl;
    union {
        CB_SOCK_ADDR  A;
        CB_SOCK_ADDR  AAAA;
        char          CNAME[DNS_MAX_NAME];
    };
} CB_DNS_RECORD;

typedef struct _CB_EVENT_DNS_RESPONSE {
    CB_DNS_RECORD *records;
    uint16_t       xid;
    uint32_t       status;
    char           qname[DNS_MAX_NAME];
    uint16_t       qtype;
    uint16_t       record_count;
    uint16_t       record_offset;
    uint16_t       nscount;
    uint16_t       arcount;
} CB_EVENT_DNS_RESPONSE;

enum ProcessBlockType {
    BlockDuringProcessStartup, ///< We killed (or tried to kill) the process when
                               ///< its initial thread was being created
    ProcessTerminatedAfterStartup ///< We killed (or tried to kill) the process
                                  ///< after the process was running
};

/// @brief When we fail to terminate a process, we generate an event to the
/// server telling it why we couldn't
///   These enums help inform the server as to why
enum TerminateFailureReason {
    TerminateFailureReasonNone = 0, ///< Process was successfully terminated
    ProcessAllowed,     ///< We determined that the process was allowed
                        ///< (failure details will have the Reason)
    ProcessOpenFailure, ///< We failed to open a handle to the process (failure
                        ///< details will contain NT_STATUS error code)
    ProcessTerminateFailure, ///< ZwTerminateProcess failed (failure details will
                             ///< contain NT_STATUS error code)
};

typedef struct _CB_EVENT_BLOCK {
    char *path;
    uint16_t path_size;
    uint16_t path_offset;
    enum ProcessBlockType blockType;
    enum TerminateFailureReason failureReason;
    uint32_t failureReasonDetails;
    uid_t uid;
} CB_EVENT_BLOCK_RESPONSE, *PCB_EVENT_BLOCK_RESPONSE;

typedef struct _CB_EVENT_DATA {
    char   *data;
    size_t  size;
} CB_EVENT_DATA;

typedef enum CB_EVENT_API_VERSION {
  CB_EVENT_API_UNKNOWN = 0,
  CB_EVENT_API_1_0       = 0x0100,
  CB_EVENT_API_1_1       = 0x0101,
  CB_EVENT_API_1_2       = 0x0102,
  CB_EVENT_API_1_3       = 0x0103,
  CB_EVENT_API_1_4       = 0x0104,
  CB_EVENT_API_1_5       = 0x0105,
  CB_EVENT_API_1_6       = 0x0106,
  CB_EVENT_API_1_7       = 0x0107,
  CB_EVENT_API_2_0       = 0x0200,
  CB_EVENT_API_2_1       = 0x0201
} CB_EVENT_API_VERSION;

typedef struct _CB_EVENT_GENERIC_DATA {
    // This char* is aligned with the first item in every event type
    //  We use it as a generic means to get path data and such to copy into user memory
    char *data;
} CB_EVENT_GENERIC_DATA;

// intention of the event
typedef enum CB_INTENT_TYPE {
    INTENT_ACCESS_CHECK = 0, // we are requesting permission for this operation
    INTENT_REPORT = 1,       // we are reporting that an operation happened
    INTENT_PREACTION = 2,    // we are reporting an operation before it happened
} CB_INTENT_TYPE;

typedef struct CB_EVENT {
    CB_EVENT_API_VERSION apiVersion;
    CB_INTENT_TYPE intentType; // INTENT_ACCESS_CHECK or INTENT_REPORT
    CB_EVENT_TYPE eventType;
    CB_EVENT_PROCESS_INFO procInfo;

    union {
        CB_EVENT_GENERIC_DATA generic_data;
        CB_EVENT_PROCESS_START processStart;
        CB_EVENT_MODULE_LOAD moduleLoad;

        CB_EVENT_FILE_GENERIC fileGeneric;
        CB_EVENT_FILE_CREATE fileCreate;
        CB_EVENT_FILE_DELETE fileDelete;
        // CB_EVENT_FILE_WRITE     fileWrite;
        // CB_EVENT_DIR_CREATE     dirCreate;
        // CB_EVENT_DIR_DELETE     dirDelete;

        CB_EVENT_NETWORK_CONNECT netConnect;
        CB_EVENT_DNS_RESPONSE dnsResponse;
        CB_EVENT_BLOCK_RESPONSE blockResponse;
        CB_EVENT_HEARTBEAT heartbeat;
    };

    unsigned long canary;
} *PCB_EVENT;

struct CB_EVENT_UM {
    uint16_t          payload; // Total byte size containing whole event message
    struct CB_EVENT   event;
};

// This struct is meant for userspace until
// multiple events are sent through a single read.
struct CB_EVENT_UM_BLOB {
    uint16_t          payload;
    struct CB_EVENT   event;
    char              blob[PATH_MAX * 2];
};

typedef struct _CB_EVENT_DYNAMIC {
  size_t size;
  unsigned long data;
} CB_EVENT_DYNAMIC, *PCB_EVENT_DYNAMIC;

// @@TODO: populate and forward to management
typedef struct CB_LOGGER_STATS {
  uint64_t eventsAllocated;    // Total Number of events allocated
  uint64_t eventsFreed;        // Total Number of events freed
  uint64_t eventsQueued;       // Current Number of events queued for send
  uint64_t eventsSent;         // Total Number of events actually sent
  uint64_t eventsFailedOnSend; // Total Number of events that failed when trying
                               // to send
} *PCB_LOGGER_STATS;

typedef enum _CB_ISOLATION_MODE {
  IsolationModeOff = 0,
  IsolationModeOn = 1
} CB_ISOLATION_MODE,
    *PCB_ISOLATION_MODE;

typedef struct CB_ISOLATION_MODE_CONTROL {
  CB_ISOLATION_MODE isolationMode;
  uint32_t numberOfAllowedIpAddresses;
  uint32_t allowedIpAddresses[1];
} CB_ISOLATION_MODE_CONTROL, *PCB_ISOLATION_MODE_CONTROL;

#define PROTECTION_DISABLED 0
#define PROTECTION_ENABLED 1
typedef uint32_t CB_PROTECTION_ENABLED; // 1 == enabled default is enabled

typedef struct {
  int action;
  uint64_t device;
  uint64_t inode;
} protectionData;

#define KERNMSG_MAX 10
typedef struct {
  uint64_t count; // 1 - 10
  protectionData data[KERNMSG_MAX];
} CB_PROTECTION_CONTROL, *PCB_PROTECTION_CONTROL;

typedef struct CB_TRUSTED_PATH {
  char path[PATH_MAX + 1];
} *PCB_TRUSTED_PATH;

#define EBPF_MIN_KERN_MAJOR 4
#define EBPF_MIN_KERN_MINOR 4
#define max_cmd_buf_size 4104
typedef enum CB_DRIVER_REQUEST {
  CB_DRIVER_REQUEST_UNKNOWN = 0,

  CB_DRIVER_REQUEST_GET_VERSION = 1, // not used?
  CB_DRIVER_REQUEST_APPLY_FILTER = 2, // one way, called by WEB and driver-manger;
  CB_DRIVER_REQUEST_IGNORE_UID = 3, // one way
  CB_DRIVER_REQUEST_IGNORE_PID = 4, // one way
  CB_DRIVER_REQUEST_IGNORE_SERVER = 5,    // one way
  CB_DRIVER_REQUEST_SET_BANNED_PID = 6,   // not use?
  CB_DRIVER_REQUEST_SET_BANNED_INODE = 7, // one way, but called multiple times
  CB_DRIVER_REQUEST_SET_TRUSTED_PATH = 8, // onw way
  CB_DRIVER_REQUEST_ISOLATION_MODE_CONTROL = 9, // one way, called by WEB
  CB_DRIVER_REQUEST_CLR_BANNED_INODE = 10,      // one way
  CB_DRIVER_REQUEST_PROTECTION_ENABLED = 11,    // one way
  CB_DRIVER_REQUEST_SET_LOG_LEVEL = 12,         // one way
  CB_DRIVER_REQUEST_HEARTBEAT = 13,             // two way
  CB_DRIVER_REQUEST_ACTION = 14,             // two way
  CB_DRIVER_REQUEST_CONFIG = 15, // one way
  CB_DRIVER_REQUEST_SET_BANNED_INODE_WITHOUT_KILL = 16, // one way but called multiple times

  CB_DRIVER_REQUEST_MAX

} CB_DRIVER_REQUEST;

#define CB_REQUEST_PROTOCOL_VERSION 0x1

typedef struct CB_REQUEST_MESSAGE {
  CB_DRIVER_REQUEST request;

  union {
    struct {
      uint32_t eventFilter;
    } eventFilter;
  };
} *PCB_REQUEST_MESSAGE;

// Responses 
#define CB_PERM_RESPONSE_TYPE_ALLOW   0x00
#define CB_PERM_RESPONSE_TYPE_EPERM   0x01
#define CB_PERM_RESPONSE_TYPE_EACCES  0x02
#define CB_PERM_RESPONSE_TYPE_ENOENT  0x04


struct CB_PERM_RESPONSE {
    uint64_t perm_id;
    uint32_t cacheFlags;
    pid_t tid;
    CB_EVENT_TYPE eventType;
    uint8_t response;
};

#pragma pack(pop)
