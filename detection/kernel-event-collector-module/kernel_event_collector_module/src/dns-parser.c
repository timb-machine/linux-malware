// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#include "dns-parser-private.h"

#include "priv.h"
#include "cb-test.h"
#include "net-helper.h"
#include "mem-cache.h"

#include <linux/inet.h>

//My defines
#define MAX_UDP_DATA_SIZE 65539 //max ushort + 4 bytes from the UDP header

#define S_OK 0
#define E_NOT_SUFFICIENT_BUFFER 1
#define DNS_ERROR_INVALID_DATA 2
#define E_UNEXPECTED 3
#define E_FAIL 4
#define E_INVALIDARG 5
#define E_OUTOFMEMORY 6
#define DNS_ERROR_NAME_DOES_NOT_EXIST 7
#define E_NOT_SUPPORTED 8

#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_NXDOMAIN 3

#define  DNS_PRINT_LEVEL DL_VERBOSE

const char *__ec_dns_type_to_str(int dns_type);
int __ec_dns_check_overrun(uint8_t *dns_data, uint8_t *dataPos, uint32_t dns_data_len);
int __ec_dns_parse_name(char     *to,
                        uint8_t  *from,
                        uint8_t  *dns_data,
                        uint32_t  dns_data_len,
                        int      *_xcode);
uint8_t *__ec_dns_parse_record(CB_DNS_RECORD *record,
                               uint8_t       *dataPos,
                               uint8_t       *dns_data,
                               char          *record_name,
                               uint32_t       dns_data_len,
                               int            *_xcode);
void __ec_dns_print_record(CB_DNS_RECORD *record);
int __ec_dns_name_from_dns(char *name);

int ec_dns_parse_data(char                *dns_data,
                   int                     dns_data_len,
                   CB_EVENT_DNS_RESPONSE  *response,
                   ProcessContext         *context)
{
    int             xcode  = E_UNEXPECTED;
    uint8_t        *dataPos = dns_data;
    dns_header_t   *header = (dns_header_t *)dataPos;
    dns_question_t *question;
    int             i;

    TRY(dns_data);
    TRY(dns_data_len >= 12 && dns_data_len <= 512);
    TRY(response);
    TRY(context);

    dataPos += sizeof(dns_header_t);
    TRY_SET(!__ec_dns_check_overrun(dns_data, dataPos, dns_data_len), E_NOT_SUFFICIENT_BUFFER);

    response->xid          = ntohs(header->xid);
    response->record_count = ntohs(header->ancount);
    response->nscount      = ntohs(header->nscount);
    response->arcount      = ntohs(header->arcount);

    TRY_SET_DO(header->is_response,
               E_INVALIDARG,
               { response->status = DNS_STATUS_QUESTION; });
    TRY_SET_DO(header->response_code != DNS_RCODE_NXDOMAIN,
               E_INVALIDARG,
               { response->status = DNS_ERROR_NAME_DOES_NOT_EXIST; });
    TRY_SET_DO(!(header->response_code != DNS_RCODE_NOERROR || ntohs(header->qdcount) != 1),
               E_INVALIDARG,
               { response->status = DNS_ERROR_NAME_DOES_NOT_EXIST; });

    response->status = DNS_STATUS_OK;

    dataPos += __ec_dns_parse_name(response->qname, dataPos, dns_data, dns_data_len, &xcode);
    TRY(xcode == S_OK);

    question = (dns_question_t *)dataPos;
    dataPos += sizeof(*question);
    TRY_SET(!__ec_dns_check_overrun(dns_data, dataPos, dns_data_len), E_NOT_SUFFICIENT_BUFFER);

    response->qtype = ntohs(question->qtype);

    response->records = ec_mem_cache_alloc_generic(response->record_count * sizeof(CB_DNS_RECORD), context);
    TRY(response->records);

    for (i = 0; i < response->record_count; i++)
    {
        dataPos = __ec_dns_parse_record(&response->records[i], dataPos, dns_data, response->qname, dns_data_len, &xcode);
        if (xcode != S_OK)
        {
            // This was not a record type we care about, so reduce the record_count and skip this.
            //  Note: Since we already allocated the memory, we will attempt to copy it later but it
            //        will be ignored.
            --response->record_count;
            continue;
        }

        __ec_dns_print_record(&response->records[i]);
    }

    // Make sure there was really DNS information we care about
    TRY(response->record_count > 0);

    xcode = S_OK;

CATCH_DEFAULT:
    return xcode;
}

int __ec_dns_parse_name(char     *to,
                    uint8_t  *from,
                    uint8_t  *dns_data,
                    uint32_t  dns_data_len,
                    int      *_xcode)
{
    int32_t   xcode               = E_UNEXPECTED;
    uint32_t  move_buf            = 0;
    uint32_t  pos                 = 0;
    uint32_t  move_increment      = 1;
    uint32_t  number_times_jumped = 0;
    uint8_t  *dataEnd             = dns_data + dns_data_len;
    uint16_t *curWord             = (uint16_t *)(from);

    TRY(to);
    TRY(from);
    TRY(dns_data);
    TRY(xcode);

    TRY_SET(!__ec_dns_check_overrun(dns_data, from, dns_data_len), E_NOT_SUFFICIENT_BUFFER);

    while (pos < DNS_MAX_NAME)
    {
        move_buf += move_increment;

        TRY_SET_MSG(from < dataEnd, DNS_ERROR_INVALID_DATA,
                    DL_ERROR, "DNS name too long for buffer.");

        if (*from == 0)
        {
            break;
        }

        if (DNS_IS_INDIRECT(*from))
        {
            // Watch out for an infinite loop by counting the number of times we jump around in
            // the same packet. This prevent one class of intentionally (or accidentally) DoS attacks
            //  on the endpoint.
            //
            // I can't imagine any legitimate packet needing to jump more than say, 20 times. In fact,
            // most probably shouldn't jump more than once, but error on the side of accepting too many
            // jumps rather than txcodeowing out too many packets.
            TRY_SET_MSG(number_times_jumped++ < 20,
                        DNS_ERROR_INVALID_DATA,
                        DL_WARNING, "Too many jumps in dns packet");

            // From the RFC demonstrating the use of the compression
            //
            // For example, a datagram might need to use the domain names F.ISI.ARPA,
            // FOO.F.ISI.ARPA, ARPA, and the root.  Ignoring the other fields of the
            // message, these domain names might be represented as:
            //
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 20 |           1           |           F           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 22 |           3           |           I           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 24 |           S           |           I           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 26 |           4           |           A           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 28 |           R           |           P           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 30 |           A           |           0           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 40 |           3           |           F           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 42 |           O           |           O           |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 44 | 1  1|                20                       |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 64 | 1  1|                26                       |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            // 92 |           0           |                       |
            //    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            //
            // The domain name for F.ISI.ARPA is shown at offset 20.  The domain name
            // FOO.F.ISI.ARPA is shown at offset 40; this definition uses a pointer to
            // concatenate a label for FOO to the previously defined F.ISI.ARPA.  The
            // domain name ARPA is defined at offset 64 using a pointer to the ARPA
            // component of the name F.ISI.ARPA at 20; note that this pointer relies on
            // ARPA being the last label in the string at 20.  The root domain name is
            // defined by a single octet of zeros at 92; the root domain name has no
            // labels.

            curWord = (uint16_t *)from;
            from    = dns_data + DNS_INDIRECT_OFFSET(ntohs(*curWord));

            // move_buf indicates how many bytes current "dataPos" location should be incremented
            // by. As soon as we make a jump to a different part of the buffer, we are no longer
            // consuming the string segment at the current location, so at that point we want to
            // stop the increments
            move_buf += move_increment;
            move_increment = 0;
        } else
        {
            to[pos++] = *(from++);
        }
    }

    TRY_SET_MSG(pos < DNS_MAX_NAME, DNS_ERROR_INVALID_DATA,
                DL_ERROR, "DNS name too long, pos: %d", pos);

    to[pos] = '\0';

    xcode = __ec_dns_name_from_dns(to);

CATCH_DEFAULT:
    if (_xcode)
    {
        *_xcode = xcode;
    }

    return move_buf;
}

int __ec_dns_name_from_dns(char *name)
{
    int xcode = E_UNEXPECTED;
    size_t  i;

    TRY(name);

    for (i = 0; i < DNS_MAX_NAME && name[i] != '\0'; i++)
    {
        int num = name[i];
        int j;

        TRY_SET_MSG(i >= 0, E_FAIL, DL_INFO, "Invalid buffer length detected in dns_name_from_dns.");

        for (j = 0; j < num; j++)
        {
            // Make sure we don't go past the last char which must be '\0'
            TRY_SET(++i < (DNS_MAX_NAME - 1), E_FAIL);

            name[i - 1] = name[i];
        }

        TRY_SET_MSG('\0' != name[i], E_FAIL, DL_INFO, "Unexpected NULL detected in dns_name_from_dns.");

        name[i] = '.';
    }

    // remove trailing '.' AND ensure the string is always NULL terminated
    if (i > 0)
    {
        name[i - 1] = '\0';
    }

    xcode = S_OK;

CATCH_DEFAULT:
    return xcode;
}

uint8_t *__ec_dns_parse_record(CB_DNS_RECORD *record,
                           uint8_t       *dataPos,
                           uint8_t       *dns_data,
                           char          *record_name,
                           uint32_t       dns_data_len,
                          int            *_xcode)
{
    int                  xcode = E_UNEXPECTED;
    dns_resource_info_t *rrHdr;

    TRY(record);
    TRY(dataPos);
    TRY(dns_data);
    TRY(record_name);
    TRY(xcode);

    record->name[0] = 0;
    dataPos += __ec_dns_parse_name(record->name, dataPos, dns_data, dns_data_len, &xcode);
    TRY(xcode == S_OK);

    rrHdr = (dns_resource_info_t *)dataPos;
    dataPos += sizeof(*rrHdr);

    TRY_SET(!__ec_dns_check_overrun(dns_data, dataPos, dns_data_len), E_NOT_SUFFICIENT_BUFFER);

    record->dnstype  = ntohs(rrHdr->dnstype);
    record->dnsclass = ntohs(rrHdr->dnsclass);
    record->ttl      = ntohl(rrHdr->ttl);

    if (record->dnstype == QT_A)
    {
        struct in_addr *addr = (struct in_addr *)dataPos;

        dataPos += sizeof(struct in_addr);
        TRY_SET(!__ec_dns_check_overrun(dns_data, dataPos, dns_data_len), E_NOT_SUFFICIENT_BUFFER);
        record->A.as_in4.sin_addr   = *addr;
        record->A.as_in4.sin_port   = 0;
        record->A.as_in4.sin_family = AF_INET;
    } else if (record->dnstype == QT_AAAA)
    {
        struct in6_addr *addr6 = (struct in6_addr *)dataPos;

        dataPos += sizeof(struct in6_addr);
        TRY_SET(!__ec_dns_check_overrun(dns_data, dataPos, dns_data_len), E_NOT_SUFFICIENT_BUFFER);
        memcpy(&record->AAAA.as_in6.sin6_addr, addr6, sizeof(record->AAAA.as_in6.sin6_addr));
        record->AAAA.as_in6.sin6_port   = 0;
        record->AAAA.as_in6.sin6_family = AF_INET6;
    } else if (record->dnstype == QT_CNAME)
    {
        dataPos += __ec_dns_parse_name(record->CNAME, dataPos, dns_data, dns_data_len, &xcode);
        TRY(xcode == S_OK);
    } else
    {
        // Skip any record type that we are not interested in
        TRACE(DNS_PRINT_LEVEL, "Unhandled DNS %s Record: %s", __ec_dns_type_to_str(record->dnstype), record->name);
        dataPos += ntohs(rrHdr->length);
        record->name[0] = 0;
        xcode = E_NOT_SUPPORTED;
    }

   TRY_SET(!__ec_dns_check_overrun(dns_data, dataPos, dns_data_len), E_NOT_SUFFICIENT_BUFFER);

CATCH_DEFAULT:
    if (_xcode)
    {
        *_xcode = xcode;
    }

    return dataPos;
}

int __ec_dns_check_overrun(uint8_t *dns_data, uint8_t *dataPos, uint32_t dns_data_len)
{
    return dataPos < dns_data || (uintptr_t)dataPos > ((uintptr_t)dns_data + dns_data_len)
           ? E_NOT_SUFFICIENT_BUFFER
           : S_OK;
}

void __ec_dns_print_record(CB_DNS_RECORD *record)
{
    uint16_t  port                         = 0;
    char      addr_str[INET6_ADDRSTRLEN*2] = {0};

    CANCEL_VOID(MAY_TRACE_LEVEL(DNS_PRINT_LEVEL));
    CANCEL_VOID(record);
    CANCEL_VOID(record->name[0] != 0);

    if (record->dnstype == QT_A)
    {
        ec_ntop(&record->A.sa_addr, addr_str, sizeof(addr_str), &port);
        TRACE(DNS_PRINT_LEVEL, "DNS A Record: %s -> %s", record->name, addr_str);
    } else if (record->dnstype == QT_AAAA)
    {
        ec_ntop(&record->AAAA.sa_addr, addr_str, sizeof(addr_str), &port);
        TRACE(DNS_PRINT_LEVEL, "DNS AAAA Record: %s -> %s", record->name, addr_str);
    } else if (record->dnstype == QT_CNAME)
    {
        TRACE(DNS_PRINT_LEVEL, "DNS CNAME Record: %s -> %s", record->name, record->CNAME);
    }
}

const char *__ec_dns_type_to_str(int dns_type)
{
    const char *value = "unknown";

    switch (dns_type)
    {
    case QT_A:     value = "A"; break;
    case QT_NS:    value = "NS"; break;
    case QT_CNAME: value = "CNAME"; break;
    case QT_SOA:   value = "SOA"; break;
    case QT_PTR:   value = "PTR"; break;
    case QT_MX:    value = "MX"; break;
    case QT_TXT:   value = "TXT"; break;
    case QT_AAAA:  value = "AAAA"; break;
    default: break;
    }

    return value;
}
