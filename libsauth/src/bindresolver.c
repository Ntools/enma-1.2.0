/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: bindresolver.c 1429 2011-12-03 18:35:04Z takahiko $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "rcsid.h"
RCSID("$Id: bindresolver.c 1429 2011-12-03 18:35:04Z takahiko $");

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>   // as a substitute for stdint.h (Solaris 9 doesn't have)
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>

#include "stdaux.h"
#include "keywordmap.h"
#include "dnsresolv.h"
#include "dnsresolv_internal.h"

#if defined(USE_LIBRESOLV) && !defined(NS_MAXMSG)
# define NS_MAXMSG   65535   /* maximum message size */
#endif

struct DnsResolver {
    struct __res_state resolver;
    ns_msg msghanlde;
    dns_stat_t status;
    int msglen;
    unsigned char msgbuf[NS_MAXMSG];
};

struct DnsAResponse {
    size_t num;
    struct in_addr addr[];
};

struct DnsAaaaResponse {
    size_t num;
    struct in6_addr addr[];
};

struct DnsPtrResponse {
    size_t num;
    char *domain[];
};

struct DnsTxtResponse {
    size_t num;
    char *data[];
};

struct mxentry {
    uint16_t preference;
    char domain[];
};

struct DnsMxResponse {
    size_t num;
    struct mxentry *exchange[];
};

void
DnsResolver_free(DnsResolver *self)
{
    assert(NULL != self);
#ifndef USE_LIBRESOLV
    res_ndestroy(&self->resolver);
#else
    // res_nclose() in glibc 2.3.x or earlier will cause memory leak under the multithreaded environment
    // (and is not supposed to be called directly).
    // this section is *not* tested and activate at your own risk.
    res_nclose(&self->resolver);
#endif
    free(self);
}   // end function: DnsResolver_free

DnsResolver *
DnsResolver_new(void)
{
    DnsResolver *self = (DnsResolver *) malloc(sizeof(DnsResolver));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DnsResolver));
    if (NETDB_SUCCESS != res_ninit(&self->resolver)) {
        goto cleanup;
    }   // end if
    return self;

  cleanup:
    DnsResolver_free(self);
    return NULL;
}   // end function: DnsResolver_new

size_t
DnsAResponse_size(const DnsAResponse *self)
{
    return self->num;
}   // end function: DnsAResponse_free

const struct in_addr *
DnsAResponse_addr(const DnsAResponse *self, size_t index)
{
    return &(self->addr[index]);
}   // end function: DnsAResponse_addr

void
DnsAResponse_free(DnsAResponse *self)
{
    assert(NULL != self);
    free(self);
}   // end function: DnsAResponse_free

size_t
DnsAaaaResponse_size(const DnsAaaaResponse *self)
{
    return self->num;
}   // end function: DnsAaaaResponse_size

const struct in6_addr *
DnsAaaaResponse_addr(const DnsAaaaResponse *self, size_t index)
{
    return &(self->addr[index]);
}   // end function: DnsAaaaResponse_addr

void
DnsAaaaResponse_free(DnsAaaaResponse *self)
{
    assert(NULL != self);
    free(self);
}   // end function: DnsAaaaResponse_free

size_t
DnsMxResponse_size(const DnsMxResponse *self)
{
    return self->num;
}   // end function: DnsMxResponse_size

uint16_t
DnsMxResponse_preference(const DnsMxResponse *self, size_t index)
{
    return self->exchange[index]->preference;
}   // end function: DnsMxResponse_preference

const char *
DnsMxResponse_domain(const DnsMxResponse *self, size_t index)
{
    return self->exchange[index]->domain;
}   // end function: DnsMxResponse_domain

void
DnsMxResponse_free(DnsMxResponse *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->num; ++n) {
        free(self->exchange[n]);
    }   // end for
    free(self);
}   // end function: DnsMxResponse_free

size_t
DnsTxtResponse_size(const DnsTxtResponse *self)
{
    return self->num;
}   // end function: DnsTxtResponse_size

const char *
DnsTxtResponse_data(const DnsTxtResponse *self, size_t index)
{
    return self->data[index];
}   // end function: DnsTxtResponse_data

void
DnsTxtResponse_free(DnsTxtResponse *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->num; ++n) {
        free(self->data[n]);
    }   // end for
    free(self);
}   // end function: DnsTxtResponse_free

size_t
DnsSpfResponse_size(const DnsSpfResponse *self)
{
    return self->num;
}   // end function: DnsSpfResponse_size

const char *
DnsSpfResponse_data(const DnsSpfResponse *self, size_t index)
{
    return self->data[index];
}   // end function: DnsSpfResponse_data

void
DnsSpfResponse_free(DnsSpfResponse *self)
{
    DnsTxtResponse_free(self);
}   // end function: DnsSpfResponse_free

size_t
DnsPtrResponse_size(const DnsPtrResponse *self)
{
    return self->num;
}   // end function: DnsPtrResponse_size

const char *
DnsPtrResponse_domain(const DnsPtrResponse *self, size_t index)
{
    return self->domain[index];
}   // end function: DnsPtrResponse_domain

void
DnsPtrResponse_free(DnsPtrResponse *self)
{
    assert(NULL != self);
    for (size_t n = 0; n < self->num; ++n) {
        free(self->domain[n]);
    }   // end for
    free(self);
}   // end function: DnsPtrResponse_free

static dns_stat_t
DnsResolver_herrno2statcode(int herrno)
{
    switch (herrno) {
    case NETDB_INTERNAL:
        return DNS_STAT_RESOLVER_INTERNAL;
    case NETDB_SUCCESS:
        return DNS_STAT_NOERROR;
    case HOST_NOT_FOUND:
        return DNS_STAT_NXDOMAIN;
    case TRY_AGAIN:
        return DNS_STAT_SERVFAIL;
    case NO_RECOVERY:  // FORMERR, REFUSED, NOTIMP
        return DNS_STAT_FORMERR;
    case NO_DATA:
        return DNS_STAT_NODATA;
    default:
        return DNS_STAT_RESOLVER_INTERNAL;
    }   // end switch
}   // end function: DnsResolver_herrno2statcode

static dns_stat_t
DnsResolver_rcode2statcode(int rcode)
{
    switch (rcode) {
    case ns_r_noerror:
        return DNS_STAT_NOERROR;
    case ns_r_formerr:
        return DNS_STAT_FORMERR;
    case ns_r_servfail:
        return DNS_STAT_SERVFAIL;
    case ns_r_nxdomain:
        return DNS_STAT_NXDOMAIN;
    case ns_r_notimpl:
        return DNS_STAT_NOTIMPL;
    case ns_r_refused:
        return DNS_STAT_REFUSED;
    default:
        return DNS_STAT_RESOLVER;
    }   // end switch
}   // end function: DnsResolver_rcode2statcode

static dns_stat_t
DnsResolver_setHerrno(DnsResolver *self, int herrno)
{
    self->status = DnsResolver_herrno2statcode(herrno);
    return self->status;    // for caller's convenience
}   // end function: DnsResolver_setHerrno

static dns_stat_t
DnsResolver_setRcode(DnsResolver *self, int rcode)
{
    self->status = DnsResolver_rcode2statcode(rcode);
    return self->status;    // for caller's convenience
}   // end function: DnsResolver_setRcode

static dns_stat_t
DnsResolver_setError(DnsResolver *self, dns_stat_t status)
{
    self->status = status;
    return status;  // for caller's convenience
}   // end function: DnsResolver_setError

static void
DnsResolver_resetErrorState(DnsResolver *self)
{
    self->status = DNS_STAT_NOERROR;
}   // end function: DnsResolver_resetErrorState

static const char *
DnsResolver_statcode2string(dns_stat_t status)
{
    static const KeywordMap dns_stat_tbl[] = {
        {"NOERROR", DNS_STAT_NOERROR},
        {"FORMERR", DNS_STAT_FORMERR},
        {"SERVFAIL", DNS_STAT_SERVFAIL},
        {"NXDOMAIN", DNS_STAT_NXDOMAIN},
        {"NOTIMPL", DNS_STAT_NOTIMPL},
        {"REFUSED", DNS_STAT_REFUSED},
        {"YXDOMAIN", DNS_STAT_YXDOMAIN},
        {"YXRRSET", DNS_STAT_YXRRSET},
        {"NXRRSET", DNS_STAT_NXRRSET},
        {"NOTAUTH", DNS_STAT_NOTAUTH},
        {"NOTZONE", DNS_STAT_NOTZONE},
        {"RESERVED11", DNS_STAT_RESERVED11},
        {"RESERVED12", DNS_STAT_RESERVED12},
        {"RESERVED13", DNS_STAT_RESERVED13},
        {"RESERVED14", DNS_STAT_RESERVED14},
        {"RESERVED15", DNS_STAT_RESERVED15},
        {"SYSTEM", DNS_STAT_SYSTEM},
        {"NODATA", DNS_STAT_NODATA},
        {"NOMEMORY", DNS_STAT_NOMEMORY},
        {"RESOLVER_ERROR", DNS_STAT_RESOLVER},
        {"RESOLVER_INTERNAL", DNS_STAT_RESOLVER_INTERNAL},
        {"BADREQUEST", DNS_STAT_BADREQUEST},
        {NULL, 0},  // sentinel
    };
    return KeywordMap_lookupByValue(dns_stat_tbl, status);
}   // end function: DnsResolver_statcode2string

const char *
DnsResolver_getErrorString(const DnsResolver *self)
{
    return DnsResolver_statcode2string(self->status);
}   // end function: DnsResolver_getErrorString

/*
 * throw a DNS query and receive a response of it
 * @return
 */
static dns_stat_t
DnsResolver_query(DnsResolver *self, const char *domain, uint16_t rrtype)
{
    DnsResolver_resetErrorState(self);
    self->msglen = res_nquery(&self->resolver, domain, ns_c_in, rrtype, self->msgbuf, NS_MAXMSG);
    if (0 > self->msglen) {
        return DnsResolver_setHerrno(self, self->resolver.res_h_errno);
    }   // end if
    if (0 > ns_initparse(self->msgbuf, self->msglen, &self->msghanlde)) {
        return DnsResolver_setError(self, DNS_STAT_FORMERR);
    }   // end if
    int rcode_flag = ns_msg_getflag(self->msghanlde, ns_f_rcode);
    if (ns_r_noerror != rcode_flag) {
        return DnsResolver_setRcode(self, rcode_flag);
    }   // end if
    return DNS_STAT_NOERROR;
}   // end function: DnsResolver_query

dns_stat_t
DnsResolver_lookupA(DnsResolver *self, const char *domain, DnsAResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, ns_t_a);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsAResponse *respobj =
        (DnsAResponse *) malloc(sizeof(DnsAResponse) + msg_count * sizeof(struct in_addr));
    if (NULL == respobj) {
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsAResponse) + msg_count * sizeof(struct in_addr));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_a != ns_rr_type(rr)) {
            continue;
        }   // end if
        if (NS_INADDRSZ != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        memcpy(&(respobj->addr[respobj->num]), ns_rr_rdata(rr), NS_INADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsAResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsAResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NODATA);
}   // end function: DnsResolver_lookupA

dns_stat_t
DnsResolver_lookupAaaa(DnsResolver *self, const char *domain, DnsAaaaResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, ns_t_aaaa);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsAaaaResponse *respobj =
        (DnsAaaaResponse *) malloc(sizeof(DnsAaaaResponse) + msg_count * sizeof(struct in6_addr));
    if (NULL == respobj) {
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsAaaaResponse) + msg_count * sizeof(struct in6_addr));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_aaaa != ns_rr_type(rr)) {
            continue;
        }   // end if
        if (NS_IN6ADDRSZ != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        memcpy(&(respobj->addr[respobj->num]), ns_rr_rdata(rr), NS_IN6ADDRSZ);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsAaaaResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsAaaaResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NODATA);
}   // end function: DnsResolver_lookupAaaa

dns_stat_t
DnsResolver_lookupMx(DnsResolver *self, const char *domain, DnsMxResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, ns_t_mx);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsMxResponse *respobj =
        (DnsMxResponse *) malloc(sizeof(DnsMxResponse) + msg_count * sizeof(struct mxentry *));
    if (NULL == respobj) {
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsMxResponse) + msg_count * sizeof(struct mxentry *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_mx != ns_rr_type(rr)) {
            continue;
        }   // end if
        const unsigned char *rdata = ns_rr_rdata(rr);
        if (ns_rr_rdlen(rr) < NS_INT16SZ) {
            goto formerr;
        }   // end if

        int preference = ns_get16(rdata);
        rdata += NS_INT16SZ;

        // NOTE: Not sure that NS_MAXDNAME is enough size of buffer for ns_name_uncompress().
        // "dig" supplied with bind8 uses NS_MAXDNAME for this.
        char dnamebuf[NS_MAXDNAME];
        int dnamelen =
            ns_name_uncompress(self->msgbuf, self->msgbuf + self->msglen, rdata, dnamebuf,
                               sizeof(dnamebuf));
        if (NS_INT16SZ + dnamelen != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        size_t domainlen = strlen(dnamebuf);    // ns_name_uncompress() terminates dnamebuf with NULL character
        respobj->exchange[respobj->num] =
            (struct mxentry *) malloc(sizeof(struct mxentry) + sizeof(char[domainlen + 1]));
        if (NULL == respobj->exchange[respobj->num]) {
            goto noresource;
        }   // end if
        respobj->exchange[respobj->num]->preference = preference;
        memcpy(respobj->exchange[respobj->num]->domain, dnamebuf, domainlen + 1);
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsMxResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsMxResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NODATA);

  noresource:
    DnsMxResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
}   // end function: DnsResolver_lookupMx

/**
 * @return DNS_STAT_NOERROR on success.
 */
static int
DnsResolver_lookupTxtData(DnsResolver *self, uint16_t rrtype, const char *domain,
                          DnsTxtResponse **resp)
{
    int query_stat = DnsResolver_query(self, domain, rrtype);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsTxtResponse *respobj =
        (DnsTxtResponse *) malloc(sizeof(DnsTxtResponse) + msg_count * sizeof(char *));
    if (NULL == respobj) {
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsTxtResponse) + msg_count * sizeof(char *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (rrtype != ns_rr_type(rr)) {
            continue;
        }   // end if
        // the size of the TXT data should be smaller than RDLEN
        respobj->data[respobj->num] = (char *) malloc(ns_rr_rdlen(rr));
        if (NULL == respobj->data[respobj->num]) {
            goto noresource;
        }   // end if
        const unsigned char *rdata = ns_rr_rdata(rr);
        const unsigned char *rdata_tail = ns_rr_rdata(rr) + ns_rr_rdlen(rr);
        char *bufp = respobj->data[respobj->num];
        while (rdata < rdata_tail) {
            // check if the length octet is less than RDLEN
            if (rdata_tail < rdata + (*rdata) + 1) {
                free(respobj->data[respobj->num]);
                goto formerr;
            }   // end if
            memcpy(bufp, rdata + 1, *rdata);
            bufp += (size_t) *rdata;
            rdata += (size_t) *rdata + 1;
        }   // end while
        *bufp = '\0';   // terminate with NULL
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsTxtResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsTxtResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NODATA);

  noresource:
    DnsTxtResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
}   // end function: DnsResolver_lookupTxtData

dns_stat_t
DnsResolver_lookupTxt(DnsResolver *self, const char *domain, DnsTxtResponse **resp)
{
    return DnsResolver_lookupTxtData(self, ns_t_txt, domain, resp);
}   // end function: DnsResolver_lookupTxt

dns_stat_t
DnsResolver_lookupSpf(DnsResolver *self, const char *domain, DnsSpfResponse **resp)
{
    return DnsResolver_lookupTxtData(self, 99 /* as ns_t_spf */ , domain, resp);
}   // end function: DnsResolver_lookupSpf

/*
 * @attention the size of buflen must be DNS_IP4_REVENT_MAXLEN bytes or larger
 */
static bool
DnsResolver_expandReverseEntry4(const struct in_addr *addr4, char *buf, size_t buflen)
{
    const unsigned char *rawaddr = (const unsigned char *) addr4;
    int ret =
        snprintf(buf, buflen, "%hhu.%hhu.%hhu.%hhu." DNS_IP4_REVENT_SUFFIX, rawaddr[3], rawaddr[2],
                 rawaddr[1], rawaddr[0]);
    return bool_cast(ret < (int) buflen);
}   // end function: DnsResolver_expandReverseEntry4

/*
 * Convert an integer between 0 and 15 to a corresponding ascii character between '0' and 'f'.
 * @attention If an integer is less than 0 or greater than 15, the results are undefined.
 */
static char
xtoa(unsigned char p)
{
    return p < 0xa ? p + '0' : p + 'a' - 0xa;
}   // end function: xtoa

/*
 * @attention the size of buflen must be DNS_IP6_REVENT_MAXLEN bytes or larger
 */
static bool
DnsResolver_expandReverseEntry6(const struct in6_addr *addr6, char *buf, size_t buflen)
{
    if (buflen < DNS_IP6_REVENT_MAXLEN) {
        return false;
    }   // end if
    const unsigned char *rawaddr = (const unsigned char *) addr6;
    const unsigned char *rawaddr_tail = rawaddr + NS_IN6ADDRSZ;
    char *bufp = buf;
    for (; rawaddr < rawaddr_tail; ++rawaddr) {
        *(bufp++) = xtoa((*(rawaddr++) & 0xf0) >> 4);
        *(bufp++) = '.';
        *(bufp++) = xtoa(*(rawaddr++) & 0x0f);
        *(bufp++) = '.';
    }   // end for
    memcpy(bufp, DNS_IP6_REVENT_SUFFIX, sizeof(DNS_IP6_REVENT_SUFFIX)); // copy suffix including NULL terminator
    return true;
}   // end function: DnsResolver_expandReverseEntry6

dns_stat_t
DnsResolver_lookupPtr(DnsResolver *self, sa_family_t sa_family, const void *addr,
                      DnsPtrResponse **resp)
{
    char domain[DNS_IP6_REVENT_MAXLEN]; // enough size for IPv6 reverse DNS entry
    switch (sa_family) {
    case AF_INET:
        if (!DnsResolver_expandReverseEntry4(addr, domain, sizeof(domain))) {
            abort();
        }   // end if
        break;
    case AF_INET6:
        if (!DnsResolver_expandReverseEntry6(addr, domain, sizeof(domain))) {
            abort();
        }   // end if
        break;
    default:
        return DnsResolver_setError(self, DNS_STAT_BADREQUEST);
    }   // end if

    int query_stat = DnsResolver_query(self, domain, ns_t_ptr);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t msg_count = ns_msg_count(self->msghanlde, ns_s_an);
    DnsPtrResponse *respobj =
        (DnsPtrResponse *) malloc(sizeof(DnsPtrResponse) + msg_count * sizeof(char *));
    if (NULL == respobj) {
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsPtrResponse) + msg_count * sizeof(char *));
    respobj->num = 0;
    for (size_t n = 0; n < msg_count; ++n) {
        ns_rr rr;
        int parse_stat = ns_parserr(&self->msghanlde, ns_s_an, n, &rr);
        if (0 != parse_stat) {
            goto formerr;
        }   // end if
        if (ns_t_ptr != ns_rr_type(rr)) {
            continue;
        }   // end if
        // NOTE: Not sure that NS_MAXDNAME is enough size of buffer for ns_name_uncompress().
        // "dig" supplied with bind8 uses NS_MAXDNAME for this.
        char dnamebuf[NS_MAXDNAME];
        int dnamelen =
            ns_name_uncompress(self->msgbuf, self->msgbuf + self->msglen, ns_rr_rdata(rr), dnamebuf,
                               sizeof(dnamebuf));
        if (dnamelen != ns_rr_rdlen(rr)) {
            goto formerr;
        }   // end if
        respobj->domain[respobj->num] = strdup(dnamebuf);   // ns_name_uncompress() terminates dnamebuf with NULL character
        if (NULL == respobj->domain[respobj->num]) {
            goto noresource;
        }   // end if
        ++(respobj->num);
    }   // end for
    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    return DNS_STAT_NOERROR;

  formerr:
    DnsPtrResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_FORMERR);

  nodata:
    DnsPtrResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NODATA);

  noresource:
    DnsPtrResponse_free(respobj);
    return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
}   // end function: DnsResolver_lookupPtr
