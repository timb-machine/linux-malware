/* Copyright 2021 VMware Inc.  All rights reserved. */
/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#pragma once

#include <cstdint>




#define MAX_FNAME 255
#define CONTAINER_ID_LEN 64

namespace cb_endpoint {
namespace bpf_probe {

    static const uint8_t DNS_SEGMENT_LEN = 40;
    static const uint8_t DNS_SEGMENT_FLAGS_START = 0x01;
    static const uint8_t DNS_SEGMENT_FLAGS_END = 0x02;

    enum PP
    {
        PP_NO_EXTRA_DATA,
        PP_ENTRY_POINT,
        PP_PATH_COMPONENT,
        PP_FINALIZED,
        PP_APPEND,
        PP_DEBUG,
    };

    enum event_type
    {
        EVENT_PROCESS_EXEC_ARG,
        EVENT_PROCESS_EXEC_PATH,
        EVENT_PROCESS_EXEC_RESULT,
        EVENT_PROCESS_EXIT,
        EVENT_PROCESS_CLONE,
        EVENT_FILE_READ,
        EVENT_FILE_WRITE,
        EVENT_FILE_CREATE,
        EVENT_FILE_PATH,
        EVENT_FILE_MMAP,
        EVENT_FILE_TEST,
        EVENT_NET_CONNECT_PRE,
        EVENT_NET_CONNECT_ACCEPT,
        EVENT_NET_CONNECT_DNS_RESPONSE,
        EVENT_NET_CONNECT_WEB_PROXY,
        EVENT_FILE_DELETE,
        EVENT_FILE_CLOSE,
        EVENT_FILE_RENAME,
        EVENT_CONTAINER_CREATE
    };

    struct data_header {
        uint64_t event_time; // Time the event collection started.  (Same across message parts.)
        uint8_t  type;
        uint8_t  state;

        uint32_t tid;
        uint32_t pid;
        uint32_t uid;
        uint32_t ppid;
        uint32_t mnt_ns;
    };

    struct data {
        struct data_header header;
    };

    struct exec_data
    {
        struct data_header header;

        int retval;
    };

    struct file_data {
        struct data_header header;

        uint64_t inode;
        uint32_t device;
        uint64_t flags; // MMAP only
        uint64_t prot;  // MMAP only
    };

    struct container_data {
        struct data_header header;

        char container_id[CONTAINER_ID_LEN + 1];
    };

    struct path_data {
        struct data_header header;

        char size;
        char fname[];
    };

    struct net_data
    {
        struct data_header header;

        uint16_t ipver;
        uint16_t protocol;
        union {
            uint32_t local_addr;
            uint32_t local_addr6[4];
        };
        uint16_t local_port;
        union {
            uint32_t remote_addr;
            uint32_t remote_addr6[4];
        };
        uint16_t remote_port;
    };

    struct dns_data
    {
        struct data_header header;

        char dns[DNS_SEGMENT_LEN];
        uint32_t name_len;
    };

    struct rename_data {
        struct data_header header;

        uint64_t old_inode, new_inode;
        uint32_t old_device, new_device;
    };
}}
