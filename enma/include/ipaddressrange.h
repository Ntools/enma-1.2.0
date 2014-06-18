/*
 * Copyright (c) 2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: ipaddressrange.h 1461 2011-12-21 11:54:30Z takahiko $
 */

#ifndef __IPADDRESSRANGE_H__
#define __IPADDRESSRANGE_H__

#include <sys/types.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef struct IPAddressRange {
    sa_family_t sa_family;
    uint8_t netmask;
    union {
        struct in_addr addr4;
        struct in6_addr addr6;
    } ipaddr;
} IPAddressRange;

typedef struct IPAddressRangeList {
    size_t num;
    IPAddressRange data[];
} IPAddressRangeList;


extern IPAddressRange *IPAddressRange_new(void);
extern void IPAddressRange_free(IPAddressRange *self);
extern bool IPAddressRange_set(IPAddressRange *self, const char *address);
extern int IPAddressRange_toString(const IPAddressRange *self, char *buf, size_t buflen);
extern bool IPAddressRange_matchToAddress(const IPAddressRange *self, sa_family_t sa_family,
                                          const void *addr);
extern bool IPAddressRange_matchToSocket(const IPAddressRange *self, const struct sockaddr *sa);

extern IPAddressRangeList *IPAddressRangeList_new(size_t size);
extern void IPAddressRangeList_free(IPAddressRangeList *self);
extern size_t IPAddressRangeList_getCount(const IPAddressRangeList *self);
extern const IPAddressRange *IPAddressRangeList_get(const IPAddressRangeList *self, size_t pos);
extern bool IPAddressRangeList_set(IPAddressRangeList *self, size_t pos, const char *addr);
extern bool IPAddressRangeList_matchToAddress(const IPAddressRangeList *self, sa_family_t sa_family,
                                              const void *addr);
extern bool IPAddressRangeList_matchToSocket(const IPAddressRangeList *self,
                                             const struct sockaddr *sa);

#endif /* __IPADDRESSRANGE_H__ */
