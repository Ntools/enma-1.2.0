/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimadsp.c 1231 2009-09-13 09:30:28Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimadsp.c 1231 2009-09-13 09:30:28Z takahiko $");

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "stdaux.h"
#include "ptrop.h"
#include "dkimlogger.h"
#include "inetdomain.h"
#include "dnsresolv.h"
#include "dkim.h"
#include "dkimspec.h"
#include "dkimenum.h"
#include "dkimtaglistobject.h"
#include "dkimconverter.h"
#include "dkimadsp.h"

struct DkimAdsp {
    DkimTagListObject_MEMBER;
    DkimAdspPractice practice;  // adsp-dkim-tag
};

static DkimStatus DkimAdsp_parse_dkim(DkimTagListObject *base, const DkimTagParseContext *context,
                                      const char **nextp);

static const DkimTagListObjectFieldMap dkim_adsp_field_table[] = {
    {"dkim", DkimAdsp_parse_dkim, true, NULL, 0x0001},
    {NULL, NULL, false, NULL, 0},   // sentinel
};

/*
 * [RFC5617] 4.2.1.
 * adsp-dkim-tag = %x64.6b.69.6d *WSP "=" *WSP
 *                 ("unknown" / "all" / "discardable" /
 *                  x-adsp-dkim-tag)
 * x-adsp-dkim-tag = hyphenated-word   ; for future extension
 * ; hyphenated-word is defined in RFC 4871
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 */
DkimStatus
DkimAdsp_parse_dkim(DkimTagListObject *base, const DkimTagParseContext *context, const char **nextp)
{
    DkimAdsp *self = (DkimAdsp *) base;

    /*
     * a "valid ADSP record" must starts with a valid "dkim" tag
     * [RFC5617] 4.2.1.
     * Every ADSP record
     * MUST start with an outbound signing-practices tag, so the first four
     * characters of the record are lowercase "dkim", followed by optional
     * whitespace and "=".
     */
    if (0 != context->tag_no) {
        *nextp = context->value_head;
        DkimLogPermFail(base->policy,
                        "adsp-dkim-tag appeared not at the front of ADSP record: near %.50s",
                        context->value_head);
        return DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION;
    }   // end if

    self->practice = DkimEnum_lookupPracticeByNameSlice(context->value_head, context->value_tail);
    if (DKIM_ADSP_PRACTICE_NULL == self->practice) {
        /*
         * [RFC5617] 4.2.1.
         * Any other values are treated as "unknown".
         */
        DkimLogInfo(base->policy,
                    "unsupported outbound signing practice (treated as \"unknown\"): dkim=%.*s",
                    (int) (context->value_tail - context->value_head), context->value_head);
        self->practice = DKIM_ADSP_PRACTICE_UNKNOWN;
    }   // end if
    *nextp = context->value_tail;
    return DSTAT_OK;
}   // end function: DkimAdsp_parse_dkim

////////////////////////////////////////////////////////////////////////

/**
 * @param policy
 * @param keyval
 * @param dstat
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_TAG_SYNTAX_VIOLATION tag-value syntax violation
 * @error DSTAT_PERMFAIL_MISSING_REQUIRED_TAG missing required tag
 * @error DSTAT_PERMFAIL_TAG_DUPLICATED multiple identical tags are found
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimAdsp *
DkimAdsp_build(const DkimPolicyBase *policy, const char *keyval, DkimStatus *dstat)
{
    assert(NULL != keyval);

    DkimAdsp *self = (DkimAdsp *) malloc(sizeof(DkimAdsp));
    if (NULL == self) {
        DkimLogNoResource(policy);
        SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimAdsp));
    self->policy = policy;
    self->ftbl = dkim_adsp_field_table;

    /*
     * [RFC5617] 4.1.
     * Note:   ADSP changes the "Tag=Value List" syntax from [RFC4871] to
     *         use WSP rather than FWS in its DNS records.
     */
    DkimStatus build_stat =
        DkimTagListObject_build((DkimTagListObject *) self, keyval, STRTAIL(keyval), true);
    if (DSTAT_OK != build_stat) {
        SETDEREF(dstat, build_stat);
        DkimAdsp_free(self);
        return NULL;
    }   // end if

    SETDEREF(dstat, DSTAT_OK);
    return self;
}   // end function: DkimAdsp_build

/**
 * release DkimAdsp object
 * @param self DkimAdsp object to release
 */
void
DkimAdsp_free(DkimAdsp *self)
{
    assert(NULL != self);
    free(self);
}   // end function: DkimAdsp_free

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_ADSP_NOT_EXIST ADSP record have not found
 * @error DSTAT_PERMFAIL_MULTIPLE_ADSP_RECORD multiple ADSP records are found
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimAdsp *
DkimAdsp_query(const DkimPolicyBase *policy, DnsResolver *resolver, const char *domain,
               DkimStatus *dstat)
{
    assert(NULL != resolver);
    assert(NULL != domain);

    // lookup ADSP record
    DnsTxtResponse *txt_rr = NULL;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(resolver, domain, &txt_rr);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:;
        // a TXT RR is found

        /*
         * [RFC5617] 4.3.
         * If the result of this query is a NOERROR response (rcode=0 in
         * [RFC1035]) with an answer that is a single record that is a valid
         * ADSP record, use that record, and the algorithm terminates.
         */
        if (0 == DnsTxtResponse_size(txt_rr)) {
            // no TXT records are found
            DnsTxtResponse_free(txt_rr);
            SETDEREF(dstat, DSTAT_INFO_ADSP_NOT_EXIST);
            break;
        } else if (1 < DnsTxtResponse_size(txt_rr)) {
            // multiple TXT records are found
            DnsTxtResponse_free(txt_rr);
            SETDEREF(dstat, DSTAT_PERMFAIL_MULTIPLE_ADSP_RECORD);
            break;
        }   // end if

        // only one TXT record is found, and now, try to parse as ADSP record
        DkimStatus build_stat;
        const char *txtrecord = DnsTxtResponse_data(txt_rr, 0);
        DkimAdsp *self = DkimAdsp_build(policy, txtrecord, &build_stat);
        if (NULL != self) {
            // parsed as a valid ADSP record
            DnsTxtResponse_free(txt_rr);
            SETDEREF(dstat, DSTAT_OK);
            return self;
        } else if (DSTAT_ISCRITERR(build_stat)) {
            // propagate system errors as-is
            DkimLogSysError
                (policy,
                 "System error has occurred while parsing ADSP record: domain=%s, err=%s, record=%s",
                 domain, DKIM_strerror(build_stat), NNSTR(txtrecord));
            SETDEREF(dstat, build_stat);
        } else if (DSTAT_ISPERMFAIL(build_stat)) {
            /*
             * treat syntax errors on ADSP record as DNS NODATA response
             *
             * [RFC5617] 4.1.
             * Records not in compliance with that syntax
             * or the syntax of individual tags described in Section 4.3 MUST be
             * ignored (considered equivalent to a NODATA result) for purposes of
             * ADSP, although they MAY cause the logging of warning messages via an
             * appropriate system logging mechanism.
             */
            DkimLogDebug(policy, "ADSP record candidate discarded: domain=%s, err=%s, record=%s",
                         domain, DKIM_strerror(build_stat), NNSTR(txtrecord));
            SETDEREF(dstat, DSTAT_INFO_ADSP_NOT_EXIST);
        } else {
            DkimLogNotice(policy, "DkimAdsp_build failed: domain=%s, err=%s, record=%s",
                          domain, DKIM_strerror(build_stat), NNSTR(txtrecord));
            SETDEREF(dstat, DSTAT_INFO_ADSP_NOT_EXIST);
        }   // end if

        // a TXT RR is not a valid ADSP record
        DnsTxtResponse_free(txt_rr);
        break;

    case DNS_STAT_NXDOMAIN:
    case DNS_STAT_NODATA:
        /*
         * no TXT (and ADSP) records are found
         *
         * [RFC5617] 4.3.
         * If the result of the query is NXDOMAIN or NOERROR with zero
         * records, there is no ADSP record.  If the result of the query
         * contains more than one record, or a record that is not a valid
         * ADSP record, the ADSP result is undefined.
         */
        DkimLogDebug(policy, "No ADSP record is found on DNS: domain=%s", domain);
        SETDEREF(dstat, DSTAT_INFO_ADSP_NOT_EXIST);
        break;

    case DNS_STAT_FORMERR:
    case DNS_STAT_SERVFAIL:
    case DNS_STAT_NOTIMPL:
    case DNS_STAT_REFUSED:
    case DNS_STAT_YXDOMAIN:
    case DNS_STAT_YXRRSET:
    case DNS_STAT_NXRRSET:
    case DNS_STAT_NOTAUTH:
    case DNS_STAT_NOTZONE:
    case DNS_STAT_RESERVED11:
    case DNS_STAT_RESERVED12:
    case DNS_STAT_RESERVED13:
    case DNS_STAT_RESERVED14:
    case DNS_STAT_RESERVED15:
        /*
         * [RFC5617] 4.3.
         * If a query results in a "SERVFAIL" error response (rcode=2 in
         * [RFC1035]), the algorithm terminates without returning a result;
         * possible actions include queuing the message or returning an SMTP
         * error indicating a temporary failure.
         */
        DkimLogInfo(policy, "DNS error on ADSP record look-up: domain=%s, type=txt, err=%s",
                    domain, DnsResolver_getErrorString(resolver));
        SETDEREF(dstat, DSTAT_TMPERR_DNS_ERROR_RESPONSE);
        break;

    case DNS_STAT_SYSTEM:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
        DkimLogSysError(policy, "error occurred during DNS lookup: domain=%s, type=txt, err=%s",
                        domain, DnsResolver_getErrorString(resolver));
        SETDEREF(dstat, DSTAT_SYSERR_DNS_LOOKUP_FAILURE);
        break;

    case DNS_STAT_NOMEMORY:
        DkimLogNoResource(policy);
        SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
        break;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError(policy,
                         "DnsResolver_lookupTxt returns unexpected value: value=0x%x, domain=%s, type=txt",
                         txtquery_stat, domain);
        SETDEREF(dstat, DSTAT_SYSERR_IMPLERROR);
        break;
    }   // end switch

    return NULL;
}   // end function: DkimAdsp_query

/**
 * Check whether a given Author Domain is within scope for ADSP.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_ADSP_NXDOMAIN Author Domain does not exist (NXDOMAIN)
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
static DkimStatus
DkimAdsp_checkDomainScope(const DkimPolicyBase *policy, DnsResolver *resolver, const char *domain)
{
    assert(NULL != resolver);
    assert(NULL != domain);

    /*
     * [RFC5617] 4.3.
     * The host MUST perform a DNS query for a record corresponding to
     * the Author Domain (with no prefix).  The type of the query can be
     * of any type, since this step is only to determine if the domain
     * itself exists in DNS.  This query MAY be done in parallel with the
     * query to fetch the named ADSP Record.  If the result of this query
     * is that the Author Domain does not exist in the DNS (often called
     * an NXDOMAIN error, rcode=3 in [RFC1035]), the algorithm MUST
     * terminate with an error indicating that the domain is out of
     * scope.  Note that a result with rcode=0 but no records (often
     * called NODATA) is not the same as NXDOMAIN.
     *
     *    NON-NORMATIVE DISCUSSION: Any resource record type could be
     *    used for this query since the existence of a resource record of
     *    any type will prevent an NXDOMAIN error.  MX is a reasonable
     *    choice for this purpose because this record type is thought to
     *    be the most common for domains used in email, and will
     *    therefore produce a result that can be more readily cached than
     *    a negative result.
     */

    DnsMxResponse *mx_rr = NULL;
    dns_stat_t mxquery_stat = DnsResolver_lookupMx(resolver, domain, &mx_rr);
    switch (mxquery_stat) {
    case DNS_STAT_NOERROR:
        DnsMxResponse_free(mx_rr);
        // fall through

    case DNS_STAT_NODATA:
        return DSTAT_OK;

    case DNS_STAT_NXDOMAIN:
        DkimLogPermFail(policy, "The author domain does not exist: domain=%s, type=mx, err=%s",
                        domain, DnsResolver_getErrorString(resolver));
        return DSTAT_INFO_ADSP_NXDOMAIN;

    case DNS_STAT_FORMERR:
    case DNS_STAT_SERVFAIL:
    case DNS_STAT_NOTIMPL:
    case DNS_STAT_REFUSED:
    case DNS_STAT_YXDOMAIN:
    case DNS_STAT_YXRRSET:
    case DNS_STAT_NXRRSET:
    case DNS_STAT_NOTAUTH:
    case DNS_STAT_NOTZONE:
    case DNS_STAT_RESERVED11:
    case DNS_STAT_RESERVED12:
    case DNS_STAT_RESERVED13:
    case DNS_STAT_RESERVED14:
    case DNS_STAT_RESERVED15:
        DkimLogPermFail(policy,
                        "DNS error on checking author domain existence: domain=%s, type=mx, err=%s",
                        domain, DnsResolver_getErrorString(resolver));
        return DSTAT_TMPERR_DNS_ERROR_RESPONSE;

    case DNS_STAT_SYSTEM:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
        DkimLogSysError(policy, "error occurred during DNS lookup: domain=%s, type=mx, err=%s",
                        domain, DnsResolver_getErrorString(resolver));
        return DSTAT_SYSERR_DNS_LOOKUP_FAILURE;

    case DNS_STAT_NOMEMORY:
        DkimLogNoResource(policy);
        return DSTAT_SYSERR_NORESOURCE;

    case DNS_STAT_BADREQUEST:
    default:
        DkimLogImplError(policy,
                         "DnsResolver_lookupMx returns unexpected value: value=0x%x, domain=%s, type=mx",
                         mxquery_stat, domain);
        return DSTAT_SYSERR_IMPLERROR;
    }   // end switch
}   // end function: DkimAdsp_checkDomainScope

static DkimAdsp *
DkimAdsp_fetch(const DkimPolicyBase *policy, DnsResolver *resolver, const char *authordomain,
               DkimStatus *dstat)
{
    // build domain name to look-up an ADSP record
    size_t dkimdomainlen =
        strlen(authordomain) + sizeof(DKIM_DNS_ADSP_SELECTOR "." DKIM_DNS_NAMESPACE ".");
    char dkimdomain[dkimdomainlen];

    int ret =
        snprintf(dkimdomain, dkimdomainlen, DKIM_DNS_ADSP_SELECTOR "." DKIM_DNS_NAMESPACE ".%s",
                 authordomain);
    if ((int) dkimdomainlen <= ret) {
        DkimLogImplError(policy, "buffer too small: bufsize=%u, writelen=%d, domain=%s",
                         dkimdomainlen, ret, authordomain);
        SETDEREF(dstat, DSTAT_SYSERR_IMPLERROR);
        return NULL;
    }   // end if

    return DkimAdsp_query(policy, resolver, dkimdomain, dstat);
}   // end function: DkimAdsp_fetch

/**
 * @error DSTAT_INFO_ADSP_NXDOMAIN Author Domain does not exist (NXDOMAIN)
 * @error DSTAT_INFO_ADSP_NOT_EXIST ADSP record have not found
 * @error DSTAT_PERMFAIL_MULTIPLE_ADSP_RECORD multiple ADSP records are found
 * @error DSTAT_TMPERR_DNS_ERROR_RESPONSE DNS lookup error (received error response)
 * @error DSTAT_SYSERR_DNS_LOOKUP_FAILURE DNS lookup error (failed to lookup itself)
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 */
DkimAdsp *
DkimAdsp_lookup(const DkimPolicyBase *policy, const char *authordomain, DnsResolver *resolver,
                DkimStatus *dstat)
{
    assert(NULL != authordomain);
    assert(NULL != resolver);

    // Check Domain Scope:
    DkimStatus check_stat = DkimAdsp_checkDomainScope(policy, resolver, authordomain);
    if (DSTAT_OK != check_stat) {
        SETDEREF(dstat, check_stat);
        return NULL;
    }   // end if

    // Fetch Named ADSP Record:
    return DkimAdsp_fetch(policy, resolver, authordomain, dstat);
}   // end function: DkimAdsp_lookup

////////////////////////////////////////////////////////////////////////
// accessor

DkimAdspPractice
DkimAdsp_getPractice(const DkimAdsp *self)
{
    return self->practice;
}   // end function: DkimAdsp_getPractice
