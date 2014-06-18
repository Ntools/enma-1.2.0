/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: ldnsresolver.c 1351 2011-09-21 02:22:16Z takahiko $
 */

// ldns-1.6.0 or higher is required

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "rcsid.h"
RCSID("$Id: ldnsresolver.c 1351 2011-09-21 02:22:16Z takahiko $");

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/nameser.h>
#include <ldns/ldns.h>

#include "stdaux.h"
#include "keywordmap.h"
#include "dnsresolv.h"
#include "dnsresolv_internal.h"

struct DnsResolver {
    ldns_resolver *res;
    dns_stat_t status;
    ldns_status res_stat;
};

// The followings are aliases of ldns_rr_list:
struct DnsAResponse;
struct DnsAaaaResponse;

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

struct DnsPtrResponse {
    size_t num;
    char *domain[];
};

void
DnsResolver_free(DnsResolver *self)
{
    assert(NULL != self);
    ldns_resolver_deep_free(self->res);
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
    ldns_status stat = ldns_resolver_new_frm_file(&(self->res), _PATH_RESCONF);
    if (LDNS_STATUS_OK != stat) {
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
    return ldns_rr_list_rr_count((const ldns_rr_list *) self);
}   // end function: DnsAResponse_free

const struct in_addr *
DnsAResponse_addr(const DnsAResponse *self, size_t index)
{
    return (struct in_addr *)
        ldns_rdf_data(ldns_rr_rdf(ldns_rr_list_rr((const ldns_rr_list *) self, index), 0));
}   // end function: DnsAResponse_addr

void
DnsAResponse_free(DnsAResponse *self)
{
    assert(NULL != self);
    ldns_rr_list_deep_free((ldns_rr_list *) self);
}   // end function: DnsAResponse_free

size_t
DnsAaaaResponse_size(const DnsAaaaResponse *self)
{
    return ldns_rr_list_rr_count((const ldns_rr_list *) self);
}   // end function: DnsAaaaResponse_size

const struct in6_addr *
DnsAaaaResponse_addr(const DnsAaaaResponse *self, size_t index)
{
    return (struct in6_addr *)
        ldns_rdf_data(ldns_rr_rdf(ldns_rr_list_rr((const ldns_rr_list *) self, index), 0));
}   // end function: DnsAaaaResponse_addr

void
DnsAaaaResponse_free(DnsAaaaResponse *self)
{
    assert(NULL != self);
    ldns_rr_list_deep_free((ldns_rr_list *) self);
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
DnsResolver_rcode2statcode(ldns_pkt_rcode rcode)
{
    switch (rcode) {
    case LDNS_RCODE_NOERROR:
        return DNS_STAT_NOERROR;
    case LDNS_RCODE_FORMERR:
        return DNS_STAT_FORMERR;
    case LDNS_RCODE_SERVFAIL:
        return DNS_STAT_SERVFAIL;
    case LDNS_RCODE_NXDOMAIN:
        return DNS_STAT_NXDOMAIN;
    case LDNS_RCODE_NOTIMPL:
        return DNS_STAT_NOTIMPL;
    case LDNS_RCODE_REFUSED:
        return DNS_STAT_REFUSED;
    case LDNS_RCODE_YXDOMAIN:
        return DNS_STAT_YXDOMAIN;
    case LDNS_RCODE_YXRRSET:
        return DNS_STAT_YXRRSET;
    case LDNS_RCODE_NXRRSET:
        return DNS_STAT_NXRRSET;
    case LDNS_RCODE_NOTAUTH:
        return DNS_STAT_NOTAUTH;
    case LDNS_RCODE_NOTZONE:
        return DNS_STAT_NOTZONE;
    default:
        return DNS_STAT_RESOLVER_INTERNAL;
    }   // end switch

}   // end function: DnsResolver_rcode2statcode

static dns_stat_t
DnsResolver_setRcode(DnsResolver *self, ldns_pkt_rcode rcode)
{
    self->status = DnsResolver_rcode2statcode(rcode);
    return self->status;    // for caller's convenience
}   // end function: DnsResolver_setRcode

static dns_stat_t
DnsResolver_setError(DnsResolver *self, dns_stat_t status)
{
    self->status = status;
    return self->status;    // for caller's convenience
}   // end function: DnsResolver_setError

static dns_stat_t
DnsResolver_setResolverError(DnsResolver *self, ldns_status status)
{
    self->status = DNS_STAT_RESOLVER;
    self->res_stat = status;
    return self->status;    // for caller's convenience
}   // end function: DnsResolver_setResolverError

static void
DnsResolver_resetErrorState(DnsResolver *self)
{
    self->status = DNS_STAT_NOERROR;
    self->res_stat = LDNS_STATUS_OK;
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
    return (DNS_STAT_RESOLVER == self->status)
        ? ldns_get_errorstr_by_id(self->res_stat)
        : DnsResolver_statcode2string(self->status);
}   // end function: DnsResolver_getErrorString

/*
 * throw a DNS query and receive a response of it
 * @return
 */
static dns_stat_t
DnsResolver_query(DnsResolver *self, const char *domain, ldns_rr_type rrtype, ldns_rr_list **rrlist)
{
    DnsResolver_resetErrorState(self);
    ldns_rdf *rdf_domain = ldns_dname_new_frm_str(domain);
    if (NULL == rdf_domain) {
        return DnsResolver_setError(self, DNS_STAT_BADREQUEST);
    }   // end if
    ldns_pkt *packet = NULL;
    ldns_status status =
        ldns_resolver_send(&packet, self->res, rdf_domain, rrtype, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_rdf_deep_free(rdf_domain);
    if (status != LDNS_STATUS_OK) {
        return DnsResolver_setResolverError(self, status);
    }   // end if
    if (NULL == packet) {
        return DnsResolver_setError(self, DNS_STAT_RESOLVER_INTERNAL);
    }   // end if
    ldns_pkt_rcode rcode = ldns_pkt_get_rcode(packet);
    if (LDNS_RCODE_NOERROR != rcode) {
        ldns_pkt_free(packet);
        return DnsResolver_setRcode(self, rcode);
    }   // end if
    *rrlist = ldns_pkt_rr_list_by_type(packet, rrtype, LDNS_SECTION_ANSWER);
    if (NULL == *rrlist) {
        ldns_pkt_free(packet);
        return DnsResolver_setError(self, DNS_STAT_NODATA);
    }   // end if
    ldns_pkt_free(packet);
    return DNS_STAT_NOERROR;
}   // end function: DnsResolver_query

dns_stat_t
DnsResolver_lookupA(DnsResolver *self, const char *domain, DnsAResponse **resp)
{
    return DnsResolver_query(self, domain, LDNS_RR_TYPE_A, (ldns_rr_list **) resp);
}   // end function: DnsResolver_lookupA

dns_stat_t
DnsResolver_lookupAaaa(DnsResolver *self, const char *domain, DnsAaaaResponse **resp)
{
    return DnsResolver_query(self, domain, LDNS_RR_TYPE_AAAA, (ldns_rr_list **) resp);
}   // end function: DnsResolver_lookupAaaa

static bool
DnsResolver_expandDomainName(const ldns_rdf *rdf, char *bufp, size_t buflen)
{
    /*
     * [RFC1035] 3.3.
     * <domain-name> is a domain name represented as a series of labels, and
     * terminated by a label with zero length.
     */
    uint8_t *rdata = (uint8_t *) ldns_rdf_data(rdf);
    size_t rdflen = ldns_rdf_size(rdf);
    uint8_t *rdata_tail = rdata + rdflen;
    char *buf_tail = bufp + buflen;

    if (0 == rdflen) {
        return false;
    }   // end if

    /* special case: root label */
    if (1 == rdflen) {
        if (2 <= buflen) {
            *(bufp++) = '.';
            *(bufp++) = '\0';
            return true;
        } else {
            return false;
        }   // end if
    }   // end if

    uint8_t label_len = *(rdata++);

    // "rdata + label_len" includes the length field of the next label,
    // and "bufp + label_len" includes '.' or NULL terminator.
    while (rdata + label_len < rdata_tail && bufp + label_len < buf_tail) {
        memcpy(bufp, rdata, label_len);
        rdata += label_len;
        bufp += label_len;
        label_len = *(rdata++);
        if (0 == label_len) {
            *bufp = '\0';
            return true;
        }   // end if
        *(bufp++) = '.';
    }   // end while
    return false;
}   // end function: DnsResolver_expandDomainName

dns_stat_t
DnsResolver_lookupMx(DnsResolver *self, const char *domain, DnsMxResponse **resp)
{
    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = DnsResolver_query(self, domain, LDNS_RR_TYPE_MX, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    DnsMxResponse *respobj =
        (DnsMxResponse *) malloc(sizeof(DnsMxResponse) + rr_count * sizeof(struct mxentry *));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsPtrResponse) + rr_count * sizeof(struct mxentry *));
    respobj->num = 0;

    // expand compressed domain name
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        const ldns_rdf *rdf_pref = ldns_rr_rdf(rr, 0);
        const ldns_rdf *rdf_dname = ldns_rr_rdf(rr, 1);
        if (LDNS_RDF_TYPE_INT16 != ldns_rdf_get_type(rdf_pref) ||
            LDNS_RDF_TYPE_DNAME != ldns_rdf_get_type(rdf_dname)) {
            goto formerr;
        }   // end if

        size_t bufsize = MAX(ldns_rdf_size(rdf_dname), 2);
        size_t entrysize = sizeof(struct mxentry) + bufsize;
        // allocate memory
        struct mxentry *entryp = (struct mxentry *) malloc(entrysize);
        if (NULL == entryp) {
            goto noresource;
        }   // end if
        // concatenate
        respobj->exchange[respobj->num] = entryp;
        if (!DnsResolver_expandDomainName(rdf_dname, entryp->domain, bufsize)) {
            goto formerr;
        }   // end if
        entryp->preference = ntohs(*(uint16_t *) ldns_rdf_data(rdf_pref));
        ++(respobj->num);
    }   // end for

    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsMxResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsMxResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_NODATA);

  noresource:
    ldns_rr_list_deep_free(rrlist);
    DnsMxResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_NOMEMORY);
}   // end function: DnsResolver_lookupMx

/**
 * @return DNS_STAT_NOERROR on success.
 */
static dns_stat_t
DnsResolver_lookupTxtData(DnsResolver *self, ldns_rr_type rrtype, const char *domain,
                          DnsTxtResponse **resp)
{
    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = DnsResolver_query(self, domain, rrtype, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    DnsTxtResponse *respobj =
        (DnsTxtResponse *) malloc(sizeof(DnsTxtResponse) + rr_count * sizeof(char *));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsTxtResponse) + rr_count * sizeof(char *));
    respobj->num = 0;

    // concatenate multiple rdfs for each RR
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        // estimate buffer size
        size_t bufsize = 0;
        for (size_t rdfidx = 0; rdfidx < ldns_rr_rd_count(rr); ++rdfidx) {
            bufsize += ldns_rdf_size(ldns_rr_rdf(rr, rdfidx)) - 1;
        }   // end for
        ++bufsize;  // for NULL terminator
        // allocate memory
        char *bufp = (char *) malloc(bufsize);
        if (NULL == bufp) {
            goto noresource;
        }   // end if
        // concatenate
        respobj->data[respobj->num] = bufp;
        for (size_t rdfidx = 0; rdfidx < ldns_rr_rd_count(rr); ++rdfidx) {
            const ldns_rdf *rdf = ldns_rr_rdf(rr, rdfidx);
            if (LDNS_RDF_TYPE_STR != ldns_rdf_get_type(rdf)) {
                goto formerr;
            }   // end if
            const uint8_t *rdata = ldns_rdf_data(rdf);
            if (ldns_rdf_size(rdf) != (size_t) (*rdata) + 1) {
                goto formerr;
            }   // end if
            memcpy(bufp, rdata + 1, *rdata);
            bufp += (size_t) *rdata;
        }   // end for
        *bufp = '\0';   // terminate with NULL character
        ++(respobj->num);
    }   // end for

    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsTxtResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsTxtResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_NODATA);

  noresource:
    ldns_rr_list_deep_free(rrlist);
    DnsTxtResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_NOMEMORY);
}   // end function: DnsResolver_lookupTxtData

dns_stat_t
DnsResolver_lookupTxt(DnsResolver *self, const char *domain, DnsTxtResponse **resp)
{
    return DnsResolver_lookupTxtData(self, LDNS_RR_TYPE_TXT, domain, resp);
}   // end function: DnsResolver_lookupTxt

dns_stat_t
DnsResolver_lookupSpf(DnsResolver *self, const char *domain, DnsSpfResponse **resp)
{
    return DnsResolver_lookupTxtData(self, LDNS_RR_TYPE_SPF, domain, resp);
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

    ldns_rr_list *rrlist = NULL;
    dns_stat_t query_stat = DnsResolver_query(self, domain, LDNS_RR_TYPE_PTR, &rrlist);
    if (DNS_STAT_NOERROR != query_stat) {
        return query_stat;
    }   // end if
    size_t rr_count = ldns_rr_list_rr_count(rrlist);
    DnsPtrResponse *respobj =
        (DnsPtrResponse *) malloc(sizeof(DnsPtrResponse) + rr_count * sizeof(char *));
    if (NULL == respobj) {
        ldns_rr_list_deep_free(rrlist);
        return DnsResolver_setError(self, DNS_STAT_NOMEMORY);
    }   // end if
    memset(respobj, 0, sizeof(DnsPtrResponse) + rr_count * sizeof(char *));
    respobj->num = 0;

    // expand compressed domain name
    for (size_t rridx = 0; rridx < rr_count; ++rridx) {
        ldns_rr *rr = ldns_rr_list_rr(rrlist, rridx);
        const ldns_rdf *rdf = ldns_rr_rdf(rr, 0);
        if (LDNS_RDF_TYPE_DNAME != ldns_rdf_get_type(rdf)) {
            goto formerr;
        }   // end if

        size_t bufsize = MAX(ldns_rdf_size(rdf), 2);
        // allocate memory
        char *bufp = (char *) malloc(bufsize);
        if (NULL == bufp) {
            goto noresource;
        }   // end if
        // concatenate
        respobj->domain[respobj->num] = bufp;
        if (!DnsResolver_expandDomainName(rdf, bufp, bufsize)) {
            goto formerr;
        }   // end if
        ++(respobj->num);
    }   // end for

    if (0 == respobj->num) {
        goto nodata;
    }   // end if
    *resp = respobj;
    ldns_rr_list_deep_free(rrlist);
    return DNS_STAT_NOERROR;

  formerr:
    ldns_rr_list_deep_free(rrlist);
    DnsPtrResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_FORMERR);

  nodata:
    ldns_rr_list_deep_free(rrlist);
    DnsPtrResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_NODATA);

  noresource:
    ldns_rr_list_deep_free(rrlist);
    DnsPtrResponse_free(respobj);
    return DnsResolver_setResolverError(self, DNS_STAT_NOMEMORY);
}   // end function: DnsResolver_lookupPtr
