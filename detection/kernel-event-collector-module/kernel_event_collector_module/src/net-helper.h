/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
// Copyright (c) 2019-2020 VMware, Inc. All rights reserved.
// Copyright (c) 2016-2019 Carbon Black, Inc. All rights reserved.

#pragma once

#define CHECK_SK_FAMILY(sk)        ((sk) && \
                                     ((sk)->sk_family == PF_INET || (sk)->sk_family == PF_INET6) \
                                   )
#define CHECK_SK_FAMILY_INET(sk)   ((sk) && \
                                     (sk)->sk_family == PF_INET \
                                   )
#define CHECK_SK_FAMILY_INET6(sk)  ((sk) && \
                                     (sk)->sk_family == PF_INET6 \
                                   )
#define CHECK_SK_PROTO(sk)         ((sk) && \
                                     ((sk)->sk_protocol == IPPROTO_UDP || (sk)->sk_protocol == IPPROTO_TCP) \
                                   )
#define CHECK_SK_PROTO_UDP(sk)     ((sk) && \
                                     (sk)->sk_protocol == IPPROTO_UDP \
                                   )
#define CHECK_SK_PROTO_TCP(sk)     ((sk) && \
                                     (sk)->sk_protocol == IPPROTO_TCP \
                                   )
#define CHECK_SOCKET_TYPE(sock)    ((sock) && \
                                     ((sock)->type == SOCK_DGRAM || (sock)->type == SOCK_STREAM) \
                                   )
#define CHECK_SOCKET_FAMILY(sock)  ((sock) && CHECK_SK_FAMILY((sock)->sk))
#define CHECK_SOCKET_PROTO(sock)   ((sock) && CHECK_SK_PROTO((sock)->sk))
#define CHECK_SOCKET(sock)         (CHECK_SOCKET_FAMILY(sock) && CHECK_SOCKET_PROTO(sock) && CHECK_SOCKET_TYPE(sock))

#define PROTOCOL_STR(PROTOCOL) ((PROTOCOL) == IPPROTO_TCP ? "tcp" : (PROTOCOL) == IPPROTO_UDP ? "udp" : "??")
#define TYPE_STR(TYPE) ((TYPE) == SOCK_DGRAM ? "dgram" : (TYPE) == SOCK_STREAM ? "stream" : "??")

// ------------------------------------------------
// Network Helpers
//
size_t ec_ntop(const struct sockaddr *sap, char *buf, const size_t buflen, uint16_t *port);
void ec_set_sockaddr_port(CB_SOCK_ADDR *addr, uint32_t port);
void ec_copy_sockaddr(CB_SOCK_ADDR *left, CB_SOCK_ADDR *right);
void ec_copy_sockaddr_in(struct sockaddr_in *left, struct sockaddr_in *right);
void ec_copy_sockaddr_in6(struct sockaddr_in6 *left, struct sockaddr_in6 *right);
void ec_print_address(
    char                  *msg,
    const struct sock     *sk,
    const struct sockaddr *localAddr,
    const struct sockaddr *remoteAddr);
