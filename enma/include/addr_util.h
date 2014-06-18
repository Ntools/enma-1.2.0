/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: addr_util.h 958 2009-06-01 00:51:36Z takahiko $
 */

#ifndef __ADDR_UTIL_H__
#define __ADDR_UTIL_H__

#include <stdbool.h>
#include <sys/socket.h>

extern bool isIpv6Loose(const char *str);
extern bool addrToIpStr(const struct sockaddr *src, char *dst);
extern bool ipStrToAddr(const char *str, int port, struct sockaddr *dst);
extern struct sockaddr *loopbackAddrDup(sa_family_t sa_family);

#endif
