/* SPDX-License-Identifier: GPL-2.0 */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#include "dns-parser.h"
#include "raw_event.h"

#include <linux/types.h>
#include <net/ip.h>

// Status returned in a CB_DNS_RECORD
#define DNS_STATUS_OK 0
#define DNS_STATUS_BAD_HANDLE 1
#define DNS_STATUS_MALFORMED_QUERY 2
#define DNS_STATUS_TIMEOUT 3
#define DNS_STATUS_SEND_FAILED 4
#define DNS_STATUS_RECEIVE_FAILED 5
#define DNS_STATUS_CONNECTION_FAILED 6
#define DNS_STATUS_WRONG_SERVER 7
#define DNS_STATUS_WRONG_XID 8
#define DNS_STATUS_WRONG_QUESTION 9
#define DNS_STATUS_EOF 10
#define DNS_STATUS_QUESTION 11

// DNS query / reply header
typedef struct
{
    uint16_t xid;

    uint8_t recursion_desired : 1;
    uint8_t truncation : 1;
    uint8_t authoritative : 1;
    uint8_t opcode : 4;
    uint8_t is_response : 1;

    uint8_t response_code : 4;
    uint8_t checking_disabled : 1;
    uint8_t authenticated_data : 1;
    uint8_t reserved : 1;
    uint8_t recursion_available : 1;

    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

#pragma pack(push)
#pragma pack(1)

// DNS resource information
typedef struct dns_resource_info
{
    uint16_t dnstype;
    uint16_t dnsclass;
    uint32_t ttl;
    uint16_t length;
} dns_resource_info_t;

// DNS extra info
typedef struct dns_question
{
    uint16_t qtype;
    uint16_t qclass;
} dns_question_t;

#pragma pack(pop)

// Linux did not like this and values without the high bits
// would pass txcodeough
// #define DNS_IS_INDIRECT( byte ) ( (byte) & 0xC0 )
#define DNS_IS_INDIRECT(byte) (((byte)&0xC0) == 0xC0)
#define DNS_INDIRECT_OFFSET(word) ((word) & ~0xC000)

int _dns_parse_name(char      *to,
                    uint8_t   *from,
                    uint8_t   *buf,
                    uint32_t   buf_len,
                    int       *_xcode);
int _dns_name_from_dns(char *name);
int _dns_check_overrun(uint8_t *buf,
                       uint8_t *bufPos,
                       uint32_t buf_len);
uint8_t *_dns_parse_record(CB_DNS_RECORD *record,
                           uint8_t       *bufPos,
                           uint8_t       *buf,
                           char          *record_name,
                           uint32_t       buf_len,
                           int           *_xcode);
void _dns_print_record(CB_DNS_RECORD *record);
