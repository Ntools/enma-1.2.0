/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: addr_util.c 1425 2011-12-03 16:56:55Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: addr_util.c 1425 2011-12-03 16:56:55Z takahiko $");

#include <sys/types.h>
#include <sys/socket.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "addr_util.h"
#include "string_util.h"

/**
 * 対象の文字列が IPv6 であるかを判定する
 * ':' が存在するかどうかで判定する簡易版
 *
 * @param str
 * @return
 */
bool
isIpv6Loose(const char *str)
{
    assert(NULL != str);

    if (NULL == strchr(str, ':')) {
        return false;
    } else {
        return true;
    }
}

/**
 * アドレス構造体を文字列形式に変換する
 *
 * @param src
 * @param dst
 * @return
 */
bool
addrToIpStr(const struct sockaddr *src, char *dst)
{
    assert(NULL != src);
    assert(NULL != dst);

    switch (src->sa_family) {
    case AF_INET:;
        struct sockaddr_in *sa4 = (struct sockaddr_in *) src;
        if (NULL == inet_ntop(AF_INET, &(sa4->sin_addr), dst, INET_ADDRSTRLEN)) {
            return false;
        }
        break;
    case AF_INET6:;
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) src;
        if (NULL == inet_ntop(AF_INET6, &(sa6->sin6_addr), dst, INET6_ADDRSTRLEN)) {
            return false;
        }
        break;
    default:
        errno = EAFNOSUPPORT;
        return false;
    }
    return true;
}

/**
 * 文字列形式をアドレス構造体に変換する
 *
 * @param src
 * @param port
 * @param dst
 * @return
 */
bool
ipStrToAddr(const char *src, int port, struct sockaddr *dst)
{
    assert(NULL != src);
    assert(NULL != dst);

    if (!isIpv6Loose(src)) {
        // IPv4
        struct sockaddr_in *sa = (struct sockaddr_in *) dst;
        memset(sa, 0, sizeof(struct sockaddr_in));
        sa->sin_family = AF_INET;
        sa->sin_port = htons(port);
        if (inet_pton(sa->sin_family, src, &(sa->sin_addr)) <= 0) {
            return false;
        }
    } else {
        // IPv6
        struct sockaddr_in6 *sa = (struct sockaddr_in6 *) dst;
        memset(sa, 0, sizeof(struct sockaddr_in6));
        sa->sin6_family = AF_INET6;
        sa->sin6_port = htons(port);
        if (inet_pton(sa->sin6_family, src, &(sa->sin6_addr)) <= 0) {
            return false;
        }
    }
    return true;
}


/**
 * 指定のアドレスファミリーのループバックアドレスを得る
 *
 * @param sa_family
 * @return
 */
struct sockaddr *
loopbackAddrDup(sa_family_t sa_family)
{
    switch (sa_family) {
    case AF_INET:;
        struct sockaddr_in *sa_in4 = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
        if (NULL == sa_in4) {
            return NULL;
        }
        sa_in4->sin_family = AF_INET;
        sa_in4->sin_port = htons(0);
        sa_in4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return (struct sockaddr *) sa_in4;
    case AF_INET6:;
        struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *) malloc(sizeof(struct sockaddr_in6));
        if (NULL == sa_in6) {
            return NULL;
        }
        sa_in6->sin6_family = AF_INET6;
        sa_in6->sin6_port = htons(0);
        sa_in6->sin6_addr = in6addr_loopback;
        return (struct sockaddr *) sa_in6;
    default:
        errno = EAFNOSUPPORT;
        return NULL;
    }
}
