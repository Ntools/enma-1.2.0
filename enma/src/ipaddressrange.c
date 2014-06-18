/*
 * Copyright (c) 2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: ipaddressrange.c 1463 2011-12-21 11:55:47Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: ipaddressrange.c 1463 2011-12-21 11:55:47Z takahiko $");

#include <sys/types.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ptrop.h"
#include "pstring.h"
#include "inet_ppton.h"
#include "bitmemcmp.h"
#include "ipaddressrange.h"


IPAddressRange *
IPAddressRange_new(void)
{
    IPAddressRange *self = (IPAddressRange *) malloc(sizeof(IPAddressRange));
    if (NULL == self) {
        return NULL;
    }
    memset(self, 0, sizeof(IPAddressRange));

    return self;
}


void
IPAddressRange_free(IPAddressRange *self)
{
    assert(NULL != self);

    free(self);
}


bool
IPAddressRange_set(IPAddressRange *self, const char *address)
{
    assert(NULL != self);
    assert(NULL != address);

    const char *head = address;
    const char *tail = STRTAIL(address);

    // check whether netmask exists or not
    const char *pnetmask = strpchr(head, tail, '/');
    const char *addr_tail = (NULL != pnetmask ? pnetmask : tail);

    // simple check whether address is IPv6 or not
    bool is_ipv6addr = (NULL != strpchr(head, addr_tail, ':'));
    self->sa_family = is_ipv6addr ? AF_INET6 : AF_INET;

    // parsing address literal
    int ret = inet_ppton(self->sa_family, head, addr_tail, &(self->ipaddr));
    if (1 != ret) {
        // invalid address literal
        return false;
    }
    // parsing netmask literal
    unsigned long max_netmask = (is_ipv6addr ? 128 : 32);
    if (NULL != pnetmask) {
        if ('\0' == *(pnetmask + 1)) {
            // terminated character is '/'
            return false;
        }
        const char *endptr = NULL;
        unsigned long netmask = strptoul(pnetmask + 1, tail, &endptr);
        if (endptr != tail || max_netmask < netmask) {
            // invalid netmask
            return false;
        }
        self->netmask = (uint8_t) netmask;
    } else {
        self->netmask = (uint8_t) max_netmask;
    }

    return true;
}


int
IPAddressRange_toString(const IPAddressRange *self, char *buf, size_t buflen)
{
    assert(NULL != self);
    assert(NULL != buf);

    if (NULL == inet_ntop(self->sa_family, &(self->ipaddr), buf, buflen)) {
        return -errno;
    }
    size_t addrlen = strlen(buf);
    if (buflen <= addrlen + 1) {
        return -ENOSPC;
    }
    size_t restbuflen = buflen - addrlen;
    int netmasklen = snprintf(buf + addrlen, restbuflen, "/%hhu", self->netmask);
    if (netmasklen < 0) {
        return -errno;
    } else if ((int) restbuflen <= netmasklen) {
        return -ENOSPC;
    }
    return addrlen + netmasklen;
}


bool
IPAddressRange_matchToAddress(const IPAddressRange *self, sa_family_t sa_family, const void *addr)
{
    assert(NULL != self);
    assert(NULL != addr);

    if (self->sa_family != sa_family) {
        return false;
    }

    return 0 == bitmemcmp(addr, &(self->ipaddr), self->netmask) ? true : false;
}


bool
IPAddressRange_matchToSocket(const IPAddressRange *self, const struct sockaddr *sa)
{
    assert(NULL != self);
    assert(NULL != sa);

    switch (sa->sa_family) {
    case AF_INET:
        return IPAddressRange_matchToAddress(self, AF_INET,
                                             &(((struct sockaddr_in *) sa)->sin_addr));
    case AF_INET6:
        return IPAddressRange_matchToAddress(self, AF_INET6,
                                             &(((struct sockaddr_in6 *) sa)->sin6_addr));
    }

    return false;
}


IPAddressRangeList *
IPAddressRangeList_new(size_t size)
{
    IPAddressRangeList *self =
        (IPAddressRangeList *) malloc(sizeof(IPAddressRangeList) + sizeof(IPAddressRange) * size);
    if (NULL == self) {
        return NULL;
    }
    memset(self, 0, sizeof(IPAddressRangeList) + sizeof(IPAddressRange) * size);
    self->num = size;

    return self;
}


void
IPAddressRangeList_free(IPAddressRangeList *self)
{
    assert(NULL != self);

    free(self);
}


size_t
IPAddressRangeList_getCount(const IPAddressRangeList *self)
{
    assert(NULL != self);

    return self->num;
}


const IPAddressRange *
IPAddressRangeList_get(const IPAddressRangeList *self, size_t pos)
{
    assert(NULL != self);

    return &(self->data[pos]);
}


bool
IPAddressRangeList_set(IPAddressRangeList *self, size_t pos, const char *addr)
{
    assert(NULL != self);
    assert(NULL != addr);

    return IPAddressRange_set(&(self->data[pos]), addr);
}


bool
IPAddressRangeList_matchToAddress(const IPAddressRangeList *self, sa_family_t sa_family,
                                  const void *addr)
{
    assert(NULL != self);
    assert(NULL != addr);

    for (int i = 0; i < (int) self->num; ++i) {
        if (IPAddressRange_matchToAddress(&(self->data[i]), sa_family, addr)) {
            return true;
        }
    }
    return false;
}


bool
IPAddressRangeList_matchToSocket(const IPAddressRangeList *self, const struct sockaddr *sa)
{
    assert(NULL != self);
    assert(NULL != sa);

    for (int i = 0; i < (int) self->num; ++i) {
        if (IPAddressRange_matchToSocket(&(self->data[i]), sa)) {
            return true;
        }
    }
    return false;
}
