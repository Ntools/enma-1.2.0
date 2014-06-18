/*
 * Copyright (c) 2007-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfrequest.c 1343 2011-07-30 19:21:50Z takahiko $
 *
 * Modified by Ntools OSS Projects Nobby N Hirano <nob@ntools.net>
 * Copyright (c) 2014 Ntools OSS Projects Nobby N Hirano All rights reserved.
 * 
 */

#include "rcsid.h"


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <netdb.h>
#include <resolv.h>

#include "stdaux.h"
#include "ptrop.h"
#include "sidflogger.h"
#include "strarray.h"
#include "xskip.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "bitmemcmp.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "sidfenum.h"
#include "sidfrecord.h"
#include "sidfrequest.h"
#include "sidfmacro.h"

#define SIDF_REQUEST_DEFAULT_LOCALPART "postmaster"

typedef struct SidfRawRecord {
    const char *record_head;
    const char *record_tail;
    const char *scope_tail;
    SidfRecordScope scope;
} SidfRawRecord;

int arecord_null = 1;
int ipaddr_set = 0;

static SidfScore SidfRequest_checkHost(SidfRequest *self, const char *domain);

FILE *dbg_fp = NULL;

void debug_log(char *format, ...)
{
	va_list ap;

	if(dbg_fp == NULL) return;

	va_start(ap, format);
	vfprintf(dbg_fp, format, ap);
	va_end(ap);
	fflush(dbg_fp);
}

static void print_self_term(const SidfTerm *term)
{
	if(term->param.addr4.s_addr != INADDR_ANY) ++ipaddr_set;
	if(!ipaddr_set) debug_log("No IP4 detect\n");
}


static unsigned int
SidfRequest_getDepth(const SidfRequest *self)
{
    return self->redirect_depth + self->include_depth;
}   // end function: SidfRequest_getDepth

static SidfStat
SidfRequest_pushDomain(SidfRequest *self, const char *domain)
{
    if (0 <= StrArray_append(self->domain, domain)) {
        return SIDF_STAT_OK;
    } else {
        SidfLogNoResource(self->policy);
        return SIDF_STAT_NO_RESOURCE;
    }   // end if
}   // end function: SidfRequest_pushDomain

static void
SidfRequest_popDomain(SidfRequest *self)
{
    StrArray_unappend(self->domain);
}   // end function: SidfRequest_popDomain

const char *
SidfRequest_getDomain(const SidfRequest *self)
{
    size_t n = StrArray_getCount(self->domain);
    return 0 < n ? StrArray_get(self->domain, n - 1) : NULL;
}   // end function: SidfRequest_getDomain

static SidfScore
SidfRequest_getScoreByQualifier(SidfQualifier qualifier)
{
    // SidfQualifier は各スコアに対応する値を持たせているのでキャストするだけでよい
    return (SidfScore) qualifier;
}   // end function: SidfRequest_getScoreByQualifier

bool
SidfRequest_isSenderContext(const SidfRequest *self)
{
    return self->is_sender_context;
}   // end function: SidfRequest_isSenderContext

const char *
SidfRequest_getExplanation(const SidfRequest *self)
{
    return self->explanation;
}   // end function: SidfRequest_getExplanation

static SidfStat
SidfRequest_setExplanation(SidfRequest *self, const char *domain, const char *exp_macro)
{
    const char *nextp;
    XBuffer_reset(self->xbuf);
    SidfStat parse_stat =
        SidfMacro_parseExplainString(self, exp_macro, STRTAIL(exp_macro), &nextp, self->xbuf);
    if (SIDF_STAT_OK == parse_stat && STRTAIL(exp_macro) == nextp) {
        SidfLogDebug(self->policy, "explanation record: domain=%s, exp=%s", domain,
                     XBuffer_getString(self->xbuf));
        if (NULL != self->explanation) {
            // "exp=" の評価条件が重複している証拠なのでバグ
            SidfLogImplError(self->policy, "clean up existing explanation: exp=%s",
                             self->explanation);
            free(self->explanation);
            self->explanation = NULL;
        }   // end if
        // ignoring memory allocation error
        self->explanation = XBuffer_dupString(self->xbuf);
    } else {
        SidfLogInfo(self->policy, "explanation expansion failed: domain=%s, exp=%s", domain,
                    exp_macro);
    }   // end if
    return parse_stat;
}   // end function: SidfRequest_setExplanation

/**
 * スコープに一致する唯一つのレコードを選択する.
 * @return スコープに一致するレコードが唯一つ見つかった場合, または見つからなかった場合は SIDF_SCORE_NULL,
 *         スコープに一致するレコードが複数見つかった場合は SIDF_SCORE_PERMERROR.
 */
static SidfScore
SidfRequest_uniqueByScope(const SidfRawRecord *rawrecords, unsigned int recordnum,
                          SidfRecordScope scope, const SidfRawRecord **selected)
{
    assert(NULL == *selected);

    for (size_t n = 0; n < recordnum; ++n) {
        if (scope & rawrecords[n].scope) {
            if (NULL == *selected) {
                *selected = &(rawrecords[n]);
            } else {
                // スコープに一致する SIDF レコードが複数存在した
                return SIDF_SCORE_PERMERROR;
            }   // end if
        }   // end if
    }   // end for

    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_uniqueByScope

/**
 * @return 成功した場合は SIDF_SCORE_NULL, SPFレコード取得の際にエラーが発生した場合は SIDF_SCORE_NULL 以外.
 */
static SidfScore
SidfRequest_fetch(const SidfRequest *self, const char *domain, DnsTxtResponse **txtresp)
{
    if (self->policy->lookup_spf_rr) {
        dns_stat_t spfquery_stat = DnsResolver_lookupSpf(self->resolver, domain, txtresp);
        switch (spfquery_stat) {
        case DNS_STAT_NOERROR:
            /*
             * RFC4406, 4408 とも SPF RR が存在した場合は全ての TXT RR を破棄するので,
             * SPF RR が見つかった場合は TXT RR をルックアップせずにこのまま戻せばよい.
             * [RFC4406] 4.4.
             * 1. If any records of type SPF are in the set, then all records of
             *    type TXT are discarded.
             * [RFC4408] 4.5.
             * 2. If any records of type SPF are in the set, then all records of
             *    type TXT are discarded.
             */
            return SIDF_SCORE_NULL;
        case DNS_STAT_NODATA:  // NOERROR
            // SPF RR がないので TXT RR にフォールバック
            break;
        case DNS_STAT_NXDOMAIN:
            /*
             * [RFC4406] 4.3.
             * When performing the PRA version of the test, if the DNS query returns
             * "non-existent domain" (RCODE 3), then check_host() exits immediately
             * with the result "Fail".
             * [RFC4408] 4.3.
             * If the <domain> is malformed (label longer than 63 characters, zero-
             * length label not at the end, etc.) or is not a fully qualified domain
             * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
             * check_host() immediately returns the result "None".
             */
            return (self->scope & SIDF_RECORD_SCOPE_SPF2_PRA)
                ? SIDF_SCORE_HARDFAIL : SIDF_SCORE_NONE;
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
             * [RFC4408] 4.4.
             * If all DNS lookups that are made return a server failure (RCODE 2),
             * or other error (RCODE other than 0 or 3), or time out, then
             * check_host() exits immediately with the result "TempError".
             */
            return SIDF_SCORE_TEMPERROR;
        case DNS_STAT_BADREQUEST:
        case DNS_STAT_SYSTEM:
        case DNS_STAT_RESOLVER:
        case DNS_STAT_RESOLVER_INTERNAL:
        case DNS_STAT_NOMEMORY:
        default:
            return SIDF_SCORE_SYSERROR;
        }   // end switch
    }   // end if

    // TXT RR を引く
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(self->resolver, domain, txtresp);
    switch (txtquery_stat) {
    case DNS_STAT_NOERROR:
        return SIDF_SCORE_NULL;
    case DNS_STAT_NODATA:  // NOERROR
        /*
         * [RFC4406] 4.4.
         * If there are no matching records remaining after the initial DNS
         * query or any subsequent optional DNS queries, then check_host() exits
         * immediately with the result "None".
         * [RFC4408] 4.5.
         * If no matching records are returned, an SPF client MUST assume that
         * the domain makes no SPF declarations.  SPF processing MUST stop and
         * return "None".
         */
        return SIDF_SCORE_NONE;
    case DNS_STAT_NXDOMAIN:
        /*
         * [RFC4406] 4.3.
         * When performing the PRA version of the test, if the DNS query returns
         * "non-existent domain" (RCODE 3), then check_host() exits immediately
         * with the result "Fail".
         * [RFC4408] 4.3.
         * If the <domain> is malformed (label longer than 63 characters, zero-
         * length label not at the end, etc.) or is not a fully qualified domain
         * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
         * check_host() immediately returns the result "None".
         */
        return (self->scope & SIDF_RECORD_SCOPE_SPF2_PRA) ? SIDF_SCORE_HARDFAIL : SIDF_SCORE_NONE;
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
         * [RFC4408] 4.4.
         * If all DNS lookups that are made return a server failure (RCODE 2),
         * or other error (RCODE other than 0 or 3), or time out, then
         * check_host() exits immediately with the result "TempError".
         */
        return SIDF_SCORE_TEMPERROR;
    case DNS_STAT_BADREQUEST:
    case DNS_STAT_SYSTEM:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
    case DNS_STAT_NOMEMORY:
    default:
        return SIDF_SCORE_SYSERROR;
    }   // end switch
}   // end function: SidfRequest_fetch

static SidfScore
SidfRequest_lookupRecord(const SidfRequest *self, const char *domain, SidfRecord **record)
{
    DnsTxtResponse *txtresp = NULL;
    SidfScore fetch_score = SidfRequest_fetch(self, domain, &txtresp);
    if (SIDF_SCORE_NULL != fetch_score) {
        return fetch_score;
    }   // end if
    assert(NULL != txtresp);

    // 各レコードのスコープを調べる
    SidfRawRecord rawrecords[DnsTxtResponse_size(txtresp)];
    for (size_t n = 0; n < DnsTxtResponse_size(txtresp); ++n) {
        rawrecords[n].record_head = DnsTxtResponse_data(txtresp, n);
        rawrecords[n].record_tail = STRTAIL(DnsTxtResponse_data(txtresp, n));
        (void) SidfRecord_getSidfScope(self, rawrecords[n].record_head, rawrecords[n].record_tail,
                                       &(rawrecords[n].scope), &(rawrecords[n].scope_tail));
    }   // end for

    // SIDF なスコープを持つ場合は SIDF レコードを探す
    const SidfRawRecord *selected = NULL;
    if (self->scope & (SIDF_RECORD_SCOPE_SPF2_MFROM | SIDF_RECORD_SCOPE_SPF2_PRA)) {
        SidfScore select_score =
            SidfRequest_uniqueByScope(rawrecords, DnsTxtResponse_size(txtresp), self->scope,
                                      &selected);
        if (SIDF_SCORE_NULL != select_score) {
            SidfLogPermFail
                (self->policy, "multiple spf2 record found: domain=%s, spf2-mfrom=%s, spf2-pra=%s",
                 domain, self->scope & SIDF_RECORD_SCOPE_SPF2_MFROM ? "true" : "false",
                 self->scope & SIDF_RECORD_SCOPE_SPF2_PRA ? "true" : "false");
            DnsTxtResponse_free(txtresp);
            return select_score;
        }   // end if
    }   // end if

    // SPFv1 なスコープを持つ場合, SIDF なスコープを持つが SIDF レコードが見つからなかった場合は SPF レコードを探す
    if (NULL == selected) {
        SidfScore select_score = SidfRequest_uniqueByScope(rawrecords, DnsTxtResponse_size(txtresp),
                                                           SIDF_RECORD_SCOPE_SPF1,
                                                           &selected);
        if (SIDF_SCORE_NULL != select_score) {
            SidfLogPermFail(self->policy, "multiple spf1 record found: domain=%s, spf1=%s", domain,
                            self->scope & SIDF_RECORD_SCOPE_SPF1 ? "true" : "false");
            DnsTxtResponse_free(txtresp);
            return select_score;
        }   // end if
    }   // end if

    if (NULL == selected) {
        // スコープに一致する SPF/SIDF レコードが存在しなかった
        SidfLogDebug(self->policy,
                     "no spf record found: domain=%s, spf1=%s, spf2-mfrom=%s, spf2-pra=%s", domain,
                     self->scope & SIDF_RECORD_SCOPE_SPF1 ? "true" : "false",
                     self->scope & SIDF_RECORD_SCOPE_SPF2_MFROM ? "true" : "false",
                     self->scope & SIDF_RECORD_SCOPE_SPF2_PRA ? "true" : "false");
        DnsTxtResponse_free(txtresp);
        return SIDF_SCORE_NONE;
    }   // end if

    // スコープに一致する SPF/SIDF レコードが唯一つ存在した
    // レコードのパース
    SidfStat build_stat =
        SidfRecord_build(self, selected->scope, selected->scope_tail, selected->record_tail,
                         record);
    DnsTxtResponse_free(txtresp);
    switch (build_stat) {
    case SIDF_STAT_OK:
        return SIDF_SCORE_NULL;
    case SIDF_STAT_NO_RESOURCE:
        return SIDF_SCORE_SYSERROR;
    default:
        return SIDF_SCORE_PERMERROR;
    }   // end switch
}   // end function: SidfRequest_lookupRecord

static const char *
SidfRequest_getTargetName(const SidfRequest *self, const SidfTerm *term)
{
    return term->querydomain ? term->querydomain : SidfRequest_getDomain(self);
}   // end function: SidfRequest_getTargetName

/*
 * メカニズム評価中の DNS レスポンスエラーコードを SIDF のスコアにマップする.
 */
static SidfScore
SidfRequest_mapMechDnsResponseToSidfScore(dns_stat_t resolv_stat)
{
    /*
     * [RFC4408 5.]
     * Several mechanisms rely on information fetched from DNS.  For these
     * DNS queries, except where noted, if the DNS server returns an error
     * (RCODE other than 0 or 3) or the query times out, the mechanism
     * throws the exception "TempError".  If the server returns "domain does
     * not exist" (RCODE 3), then evaluation of the mechanism continues as
     * if the server returned no error (RCODE 0) and zero answer records.
     */
    switch (resolv_stat) {
    case DNS_STAT_NOERROR:
    case DNS_STAT_NXDOMAIN:
    case DNS_STAT_NODATA:
        return SIDF_SCORE_NULL;
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
        return SIDF_SCORE_TEMPERROR;
    case DNS_STAT_BADREQUEST:
    case DNS_STAT_SYSTEM:
    case DNS_STAT_RESOLVER:
    case DNS_STAT_RESOLVER_INTERNAL:
    case DNS_STAT_NOMEMORY:
    default:
        return SIDF_SCORE_SYSERROR;
    }   // end switch
}   // end function: SidfRequest_mapMechDnsResponseToSidfScore

static SidfScore
SidfRequest_incrementDnsMechCounter(SidfRequest *self)
{
    if (++(self->dns_mech_count) <= self->policy->max_dns_mech) {
        return SIDF_SCORE_NULL;
    } else {
        SidfLogPermFail(self->policy,
                        "over %d mechanisms with dns look up evaluated: sender=%s, domain=%s",
                        self->policy->max_dns_mech, InetMailbox_getDomain(self->sender),
                        SidfRequest_getDomain(self));
        return SIDF_SCORE_PERMERROR;
    }   // end if
}   // end function: SidfRequest_incrementDnsMechCounter

static SidfScore
SidfRequest_checkMaliceOfCidrLength(const SidfRequest *self, char ip_version,
                                    unsigned short cidr_length, unsigned char malicious_cidr_length,
                                    SidfCustomAction action_on_malicious_cidr_length)
{
    if (SIDF_CUSTOM_ACTION_NULL != action_on_malicious_cidr_length
        && cidr_length <= malicious_cidr_length) {
        switch (action_on_malicious_cidr_length) {
        case SIDF_CUSTOM_ACTION_NULL:
        case SIDF_CUSTOM_ACTION_SCORE_NONE:
        case SIDF_CUSTOM_ACTION_SCORE_NEUTRAL:
        case SIDF_CUSTOM_ACTION_SCORE_PASS:
        case SIDF_CUSTOM_ACTION_SCORE_POLICY:
        case SIDF_CUSTOM_ACTION_SCORE_HARDFAIL:
        case SIDF_CUSTOM_ACTION_SCORE_SOFTFAIL:
        case SIDF_CUSTOM_ACTION_SCORE_TEMPERROR:
        case SIDF_CUSTOM_ACTION_SCORE_PERMERROR:
            return (SidfScore) action_on_malicious_cidr_length;
        case SIDF_CUSTOM_ACTION_LOGGING:
            // XXX to be refined
            SidfLogInfo(self->policy,
                        "Found malicious ip%c-cidr-length in SPF record: domain=%s, ip%c-cidr-length=%hu, threshold=%hhu",
                        ip_version, SidfRequest_getDomain(self), ip_version, malicious_cidr_length,
                        cidr_length);
            break;
        default:
            abort();
        }   // end switch
    }   // end if
    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_checkMaliceOfCidrLength

static SidfScore
SidfRequest_checkMaliceOfIp4CidrLength(const SidfRequest *self, const SidfTerm *term)
{
	print_self_term(term);
    return SidfRequest_checkMaliceOfCidrLength(self, '4', term->ip4cidr,
                                               self->policy->malicious_ip4_cidr_length,
                                               self->policy->action_on_malicious_ip4_cidr_length);
}   // end function: SidfRequest_checkMaliceOfIp4CidrLength

static SidfScore
SidfRequest_checkMaliceOfIp6CidrLength(const SidfRequest *self, const SidfTerm *term)
{
    return SidfRequest_checkMaliceOfCidrLength(self, '6', term->ip6cidr,
                                               self->policy->malicious_ip6_cidr_length,
                                               self->policy->action_on_malicious_ip6_cidr_length);
}   // end function: SidfRequest_checkMaliceOfIp6CidrLength

static SidfScore
SidfRequest_checkMaliceOfDualCidrLength(const SidfRequest *self, const SidfTerm *term)
{
    SidfScore score = SidfRequest_checkMaliceOfIp4CidrLength(self, term);
    if (SIDF_SCORE_NULL != score) {
        return score;
    }   // end if
    return SidfRequest_checkMaliceOfIp6CidrLength(self, term);
}   // end function: SidfRequest_checkMaliceOfDualCidrLength

static SidfScore
SidfRequest_checkPlusAllDirective(const SidfRequest *self, const SidfTerm *term)
{
    if (SIDF_CUSTOM_ACTION_NULL != self->policy->action_on_plus_all_directive
        && SIDF_QUALIFIER_PLUS == term->qualifier) {
        switch (self->policy->action_on_plus_all_directive) {
        case SIDF_CUSTOM_ACTION_NULL:
        case SIDF_CUSTOM_ACTION_SCORE_NONE:
        case SIDF_CUSTOM_ACTION_SCORE_NEUTRAL:
        case SIDF_CUSTOM_ACTION_SCORE_PASS:
        case SIDF_CUSTOM_ACTION_SCORE_POLICY:
        case SIDF_CUSTOM_ACTION_SCORE_HARDFAIL:
        case SIDF_CUSTOM_ACTION_SCORE_SOFTFAIL:
        case SIDF_CUSTOM_ACTION_SCORE_TEMPERROR:
        case SIDF_CUSTOM_ACTION_SCORE_PERMERROR:
            return (SidfScore) self->policy->action_on_plus_all_directive;
        case SIDF_CUSTOM_ACTION_LOGGING:
            // XXX to be refined
            SidfLogInfo(self->policy, "Found +all directive in SPF record: domain=%s",
                        SidfRequest_getDomain(self));
            break;
        default:
            abort();
        }   // end switch
    }   // end if
    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_checkPlusAllDirective

static SidfScore
SidfRequest_evalMechAll(const SidfRequest *self, const SidfTerm *term)
{
    SidfScore score = SidfRequest_checkPlusAllDirective(self, term);
    if (score != SIDF_SCORE_NULL) {
        return score;
    }   // end if

    return SIDF_SCORE_NULL == self->policy->overwrite_all_directive_score
        ? SidfRequest_getScoreByQualifier(term->qualifier)
        : self->policy->overwrite_all_directive_score;
}   // end function: SidfRequest_evalMechAll

static SidfScore
SidfRequest_evalMechInclude(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    ++(self->include_depth);
    SidfScore eval_score = SidfRequest_checkHost(self, term->querydomain);
    --(self->include_depth);
    /*
     * [RFC4408] 5.2.
     * Whether this mechanism matches, does not match, or throws an
     * exception depends on the result of the recursive evaluation of
     * check_host():
     *
     * +---------------------------------+---------------------------------+
     * | A recursive check_host() result | Causes the "include" mechanism  |
     * | of:                             | to:                             |
     * +---------------------------------+---------------------------------+
     * | Pass                            | match                           |
     * |                                 |                                 |
     * | Fail                            | not match                       |
     * |                                 |                                 |
     * | SoftFail                        | not match                       |
     * |                                 |                                 |
     * | Neutral                         | not match                       |
     * |                                 |                                 |
     * | TempError                       | throw TempError                 |
     * |                                 |                                 |
     * | PermError                       | throw PermError                 |
     * |                                 |                                 |
     * | None                            | throw PermError                 |
     * +---------------------------------+---------------------------------+
     */
    switch (eval_score) {
    case SIDF_SCORE_PASS:
        return SidfRequest_getScoreByQualifier(term->qualifier);    // match
    case SIDF_SCORE_HARDFAIL:
    case SIDF_SCORE_SOFTFAIL:
    case SIDF_SCORE_NEUTRAL:
        return SIDF_SCORE_NULL; // not match
    case SIDF_SCORE_TEMPERROR:
        return SIDF_SCORE_TEMPERROR;    // throw TempError
    case SIDF_SCORE_PERMERROR:
    case SIDF_SCORE_NONE:
        return SIDF_SCORE_PERMERROR;    // throw PermError
    case SIDF_SCORE_SYSERROR:
        return SIDF_SCORE_SYSERROR;
    case SIDF_SCORE_NULL:
    default:
        abort();
    }   // end switch
}   // end function: SidfRequest_evalMechInclude

/*
 * "a" メカニズムと "mx" メカニズムの共通部分を実装する関数
 */
static SidfScore
SidfRequest_evalByALookup(SidfRequest *self, const char *domain, const SidfTerm *term)
{
    size_t n;
    switch (self->sa_family) {
    case AF_INET:;
        DnsAResponse *resp4;
        dns_stat_t query4_stat = DnsResolver_lookupA(self->resolver, domain, &resp4);
        if (DNS_STAT_NOERROR != query4_stat) {
            SidfLogDnsError(self->policy, "DNS lookup failure: rrtype=a, domain=%s, err=%s", domain,
                            DnsResolver_getErrorString(self->resolver));
            return SidfRequest_mapMechDnsResponseToSidfScore(query4_stat);
        }   // end if

        for (n = 0; n < DnsAResponse_size(resp4); ++n) {
			print_self_term(term);
            if (0 == bitmemcmp(&(self->ipaddr.addr4), DnsAResponse_addr(resp4, n), term->ip4cidr)) {
                DnsAResponse_free(resp4);
                return SidfRequest_getScoreByQualifier(term->qualifier);
            }   // end if
        }   // end for
        DnsAResponse_free(resp4);
        break;

    case AF_INET6:;
        DnsAaaaResponse *resp6;
        dns_stat_t query6_stat = DnsResolver_lookupAaaa(self->resolver, domain, &resp6);
        if (DNS_STAT_NOERROR != query6_stat) {
            SidfLogDnsError(self->policy, "DNS lookup failure: rrtype=aaaa, domain=%s, err=%s",
                            domain, DnsResolver_getErrorString(self->resolver));
            return SidfRequest_mapMechDnsResponseToSidfScore(query6_stat);
        }   // end if

        for (n = 0; n < DnsAaaaResponse_size(resp6); ++n) {
            if (0 ==
                bitmemcmp(&(self->ipaddr.addr6), DnsAaaaResponse_addr(resp6, n), term->ip6cidr)) {
                DnsAaaaResponse_free(resp6);
                return SidfRequest_getScoreByQualifier(term->qualifier);
            }   // end if
        }   // end for
        DnsAaaaResponse_free(resp6);
        break;

    default:
        abort();
    }   // end if

    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalByALookup

static SidfScore
SidfRequest_evalMechA(SidfRequest *self, const SidfTerm *term)
{
	assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

	SidfScore score = SidfRequest_checkMaliceOfDualCidrLength(self, term);
    if (score != SIDF_SCORE_NULL) {
        return score;
    }   // end if

	const char *domain = SidfRequest_getTargetName(self, term);
	score = SidfRequest_evalByALookup(self, domain, term);
	return score;
}   // end function: SidfRequest_evalMechA

static SidfScore
SidfRequest_evalMechMx(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

    SidfScore score = SidfRequest_checkMaliceOfDualCidrLength(self, term);
    if (score != SIDF_SCORE_NULL) {
        return score;
    }   // end if

    const char *domain = SidfRequest_getTargetName(self, term);
    DnsMxResponse *respmx;
    dns_stat_t mxquery_stat = DnsResolver_lookupMx(self->resolver, domain, &respmx);
    if (DNS_STAT_NOERROR != mxquery_stat) {
        SidfLogDnsError(self->policy, "DNS lookup failure: rrtype=mx, domain=%s, err=%s", domain,
                        DnsResolver_getErrorString(self->resolver));
        return SidfRequest_mapMechDnsResponseToSidfScore(mxquery_stat);
    }   // end if

    /*
     * [RFC4408] 5.4.
     * check_host() first performs an MX lookup on the <target-name>.  Then
     * it performs an address lookup on each MX name returned.  The <ip> is
     * compared to each returned IP address.  To prevent Denial of Service
     * (DoS) attacks, more than 10 MX names MUST NOT be looked up during the
     * evaluation of an "mx" mechanism (see Section 10).  If any address
     * matches, the mechanism matches.
     */
    for (size_t n = 0; n < MIN(DnsMxResponse_size(respmx), self->policy->max_mxrr_per_mxmech); ++n) {
        SidfScore score = SidfRequest_evalByALookup(self, DnsMxResponse_domain(respmx, n), term);
        if (SIDF_SCORE_NULL != score) {
            DnsMxResponse_free(respmx);
            return score;
        }   // end if
    }   // end for
    DnsMxResponse_free(respmx);
    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalMechMx

/**
 * @param request SidfRequest object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses doesn't match.
 *         -1 if DNS error occurred.
 */
static int
SidfRequest_isValidatedDomainName4(const SidfRequest *self, const char *revdomain)
{
    DnsAResponse *resp;
    dns_stat_t query_stat = DnsResolver_lookupA(self->resolver, revdomain, &resp);
    if (DNS_STAT_NOERROR != query_stat) {
        SidfLogDnsError(self->policy, "DNS lookup failure: rrtype=a, domain=%s, err=%s",
                        revdomain, DnsResolver_getErrorString(self->resolver));
        return -1;
    }   // end if
    for (size_t m = 0; m < DnsAResponse_size(resp); ++m) {
        if (0 == memcmp(DnsAResponse_addr(resp, m), &(self->ipaddr.addr4), NS_INADDRSZ)) {
            DnsAResponse_free(resp);
            return 1;
        }   // end if
    }   // end for
    DnsAResponse_free(resp);
    return 0;
}   // end function: SidfRequest_isValidatedDomainName4

/**
 * @param request SidfRequest object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses doesn't match.
 *         -1 if DNS error occurred.
 */
static int
SidfRequest_isValidatedDomainName6(const SidfRequest *self, const char *revdomain)
{
    DnsAaaaResponse *resp;
    dns_stat_t query_stat = DnsResolver_lookupAaaa(self->resolver, revdomain, &resp);
    if (DNS_STAT_NOERROR != query_stat) {
        SidfLogDnsError(self->policy,
                        "DNS lookup failure (ignored): rrtype=aaaa, domain=%s, err=%s", revdomain,
                        DnsResolver_getErrorString(self->resolver));
        return -1;
    }   // end if
    for (size_t m = 0; m < DnsAaaaResponse_size(resp); ++m) {
        if (0 == memcmp(DnsAaaaResponse_addr(resp, m), &(self->ipaddr.addr6), NS_IN6ADDRSZ)) {
            DnsAaaaResponse_free(resp);
            return 1;
        }   // end if
    }   // end for
    DnsAaaaResponse_free(resp);
    return 0;
}   // end function: SidfMacro_isValidatedDomainName6

/*
 * @param request SidfRequest object.
 * @param revdomain
 * @return 1 if IP addresses match.
 *         0 if IP addresses doesn't match.
 *         -1 if DNS error occurred.
 */
int
SidfRequest_isValidatedDomainName(const SidfRequest *self, const char *revdomain)
{
    switch (self->sa_family) {
    case AF_INET:
        return SidfRequest_isValidatedDomainName4(self, revdomain);
    case AF_INET6:
        return SidfRequest_isValidatedDomainName6(self, revdomain);
    default:
        abort();
    }   // end switch
}   // end function: SidfRequest_isValidatedDomainName

static SidfScore
SidfRequest_evalMechPtr(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    const char *domain = SidfRequest_getTargetName(self, term);
    DnsPtrResponse *respptr;
    dns_stat_t ptrquery_stat =
        DnsResolver_lookupPtr(self->resolver, self->sa_family, &(self->ipaddr), &respptr);
    if (DNS_STAT_NOERROR != ptrquery_stat) {
        /*
         * [RFC4408] 5.5.
         * If a DNS error occurs while doing the PTR RR lookup, then this
         * mechanism fails to match.
         */
        char addrbuf[INET6_ADDRSTRLEN];
        (void) inet_ntop(self->sa_family, &(self->ipaddr), addrbuf, sizeof(addrbuf));
        SidfLogDnsError(self->policy, "DNS lookup failure (ignored): rrtype=ptr, ipaddr=%s, err=%s",
                        addrbuf, DnsResolver_getErrorString(self->resolver));
        return SIDF_SCORE_NULL;
    }   // end if

    /*
     * [RFC4408] 5.5.
     * First, the <ip>'s name is looked up using this procedure: perform a
     * DNS reverse-mapping for <ip>, looking up the corresponding PTR record
     * in "in-addr.arpa." if the address is an IPv4 one and in "ip6.arpa."
     * if it is an IPv6 address.  For each record returned, validate the
     * domain name by looking up its IP address.  To prevent DoS attacks,
     * more than 10 PTR names MUST NOT be looked up during the evaluation of
     * a "ptr" mechanism (see Section 10).  If <ip> is among the returned IP
     * addresses, then that domain name is validated.
     */
    size_t resp_num_limit = MIN(DnsPtrResponse_size(respptr), self->policy->max_ptrrr_per_ptrmech);
    for (size_t n = 0; n < resp_num_limit; ++n) {
        // アルゴリズムをよく読むと validated domain が <target-name> で終わっているかどうかの判断を
        // 先におこなった方が DNS ルックアップの回数が少なくて済む場合があることがわかる.
        /*
         * [RFC4408] 5.5.
         * Check all validated domain names to see if they end in the
         * <target-name> domain.  If any do, this mechanism matches.  If no
         * validated domain name can be found, or if none of the validated
         * domain names end in the <target-name>, this mechanism fails to match.
         */
        if (!InetDomain_isParent(domain, DnsPtrResponse_domain(respptr, n))) {
            continue;
        }   // end if

        int validation_stat =
            SidfRequest_isValidatedDomainName(self, DnsPtrResponse_domain(respptr, n));
        /*
         * [RFC4408] 5.5.
         * If a DNS error occurs while doing an A RR
         * lookup, then that domain name is skipped and the search continues.
         */
        if (1 == validation_stat) {
            DnsPtrResponse_free(respptr);
            return SidfRequest_getScoreByQualifier(term->qualifier);
        }   // end if
    }   // end for
    DnsPtrResponse_free(respptr);
    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalMechPtr

static SidfScore
SidfRequest_evalMechIp4(const SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_IP4 == term->attr->param_type);
    SidfScore score = SidfRequest_checkMaliceOfIp4CidrLength(self, term);
    if (score != SIDF_SCORE_NULL) {
        return score;
    }   // end if nnnn
	print_self_term(term);
    return (AF_INET == self->sa_family
            && 0 == bitmemcmp(&(self->ipaddr.addr4), &(term->param.addr4), term->ip4cidr))
        ? SidfRequest_getScoreByQualifier(term->qualifier) : SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalMechIp4

static SidfScore
SidfRequest_evalMechIp6(const SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_IP6 == term->attr->param_type);
    SidfScore score = SidfRequest_checkMaliceOfIp6CidrLength(self, term);
    if (score != SIDF_SCORE_NULL) {
        return score;
    }   // end if
    return (AF_INET6 == self->sa_family
            && 0 == bitmemcmp(&(self->ipaddr.addr6), &(term->param.addr6), term->ip6cidr))
        ? SidfRequest_getScoreByQualifier(term->qualifier) : SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalMechIp6

static SidfScore
SidfRequest_evalMechExists(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    DnsAResponse *resp;
    dns_stat_t aquery_stat = DnsResolver_lookupA(self->resolver, term->querydomain, &resp);
    if (DNS_STAT_NOERROR != aquery_stat) {
        SidfLogDnsError(self->policy, "DNS lookup failure: rrtype=a, domain=%s, err=%s",
                        term->querydomain, DnsResolver_getErrorString(self->resolver));
        return SidfRequest_mapMechDnsResponseToSidfScore(aquery_stat);
    }   // end if

    size_t num = DnsAResponse_size(resp);
    DnsAResponse_free(resp);
    return (0 < num) ? SidfRequest_getScoreByQualifier(term->qualifier) : SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalMechExists

static SidfScore
SidfRequest_evalModRedirect(SidfRequest *self, const SidfTerm *term)
{
    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);
    SidfScore incr_stat = SidfRequest_incrementDnsMechCounter(self);
    if (SIDF_SCORE_NULL != incr_stat) {
        return incr_stat;
    }   // end if
    ++(self->redirect_depth);
    SidfScore eval_score = SidfRequest_checkHost(self, term->querydomain);
    --(self->redirect_depth);
    /*
     * [RFC4408] 6.1.
     * The result of this new evaluation of check_host() is then considered
     * the result of the current evaluation with the exception that if no
     * SPF record is found, or if the target-name is malformed, the result
     * is a "PermError" rather than "None".
     */
    return SIDF_SCORE_NONE == eval_score ? SIDF_SCORE_PERMERROR : eval_score;
}   // end function: SidfRequest_evalModRedirect

static SidfStat
SidfRequest_evalModExplanation(SidfRequest *self, const SidfTerm *term)
{
    /*
     * [RFC4408] 6.2.
     * If <domain-spec> is empty, or there are any DNS processing errors
     * (any RCODE other than 0), or if no records are returned, or if more
     * than one record is returned, or if there are syntax errors in the
     * explanation string, then proceed as if no exp modifier was given.
     */

    assert(SIDF_TERM_PARAM_DOMAINSPEC == term->attr->param_type);

    DnsTxtResponse *resp;
    dns_stat_t txtquery_stat = DnsResolver_lookupTxt(self->resolver, term->querydomain, &resp);
    if (DNS_STAT_NOERROR != txtquery_stat) {
        SidfLogDnsError(self->policy, "DNS lookup failure: rrtype=txt, domain=%s, err=%s",
                        term->querydomain, DnsResolver_getErrorString(self->resolver));
        return SIDF_STAT_OK;
    }   // end if

    if (1 != DnsTxtResponse_size(resp)) {
        DnsTxtResponse_free(resp);
        return SIDF_STAT_OK;
    }   // end if

    SidfStat expand_stat =
        SidfRequest_setExplanation(self, term->querydomain, DnsTxtResponse_data(resp, 0));
    DnsTxtResponse_free(resp);
    return expand_stat;
}   // end function: SidfRequest_evalModExplanation

static SidfScore
SidfRequest_evalMechanism(SidfRequest *self, const SidfTerm *term)
{
    assert(NULL != term);
    assert(NULL != term->attr);

    if (term->attr->involve_dnslookup) {
        SidfScore incr_stat = SidfRequest_incrementDnsMechCounter(self);
        if (SIDF_SCORE_NULL != incr_stat) {
            return incr_stat;
        }   // end if
    }   // end if

    switch (term->attr->type) {
    case SIDF_TERM_MECH_ALL:
        return SidfRequest_evalMechAll(self, term);
    case SIDF_TERM_MECH_INCLUDE:
        return SidfRequest_evalMechInclude(self, term);
    case SIDF_TERM_MECH_A:
        return SidfRequest_evalMechA(self, term);
    case SIDF_TERM_MECH_MX:
        return SidfRequest_evalMechMx(self, term);
    case SIDF_TERM_MECH_PTR:
        return SidfRequest_evalMechPtr(self, term);
    case SIDF_TERM_MECH_IP4:
        return SidfRequest_evalMechIp4(self, term);
    case SIDF_TERM_MECH_IP6:
        return SidfRequest_evalMechIp6(self, term);
    case SIDF_TERM_MECH_EXISTS:
        return SidfRequest_evalMechExists(self, term);
    default:
        abort();
    }   // end switch
}   // end function: SidfRequest_evalMechanism

static SidfScore
SidfRequest_checkDomain(const SidfRequest *self, const char *domain)
{
    /*
     * 引数 <domain> の検証
     *
     * [RFC4408] 4.3.
     * If the <domain> is malformed (label longer than 63 characters, zero-
     * length label not at the end, etc.) or is not a fully qualified domain
     * name, or if the DNS lookup returns "domain does not exist" (RCODE 3),
     * check_host() immediately returns the result "None".
     */
    const char *p = domain;
    const char *domain_tail = STRTAIL(domain);
    while (p < domain_tail) {
        // 同時に文字種のチェック. 2821-Domain だとキツいのでちょっと緩め.
        int label_len = XSkip_atextBlock(p, domain_tail, &p);
        if (label_len <= 0) {
            break;
        } else if ((int) self->policy->max_label_len < label_len) {
            SidfLogPermFail(self->policy,
                            "label length of <domain> argument of check_host exceeds its limit: length=%u, limit=%u, domain(256)=%.256",
                            (unsigned int) label_len, self->policy->max_label_len, domain);
            return SIDF_SCORE_NONE;
        }   // end if
        if (0 >= XSkip_char(p, domain_tail, '.', &p)) {
            /*
             * <domain-spec> may end with '.' (dot, 0x2e)
             * [RFC4408] 8.1.
             * domain-spec      = macro-string domain-end
             * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
             */
            break;
        }   // end if
    }   // end while
    if (domain_tail != p) {
        SidfLogPermFail(self->policy,
                        "<domain> argument of check_host doesn't match domain-name: domain=%s",
                        domain);
        return SIDF_SCORE_NONE;
    }   // end if

    // "include" mechanism や "redirect=" modifier でループを形成していないかチェックする.
    if (0 <= StrArray_linearSearchIgnoreCase(self->domain, domain)) {
        SidfLogPermFail(self->policy, "evaluation loop detected: domain=%s", domain);
        return SIDF_SCORE_PERMERROR;
    }   // end if

    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_checkDomain

static SidfScore
SidfRequest_evalDirectives(SidfRequest *self, const PtrArray *directives)
{
    const char *domain = SidfRequest_getDomain(self);
    unsigned int directive_num = PtrArray_getCount(directives);
    for (unsigned int i = 0; i < directive_num; ++i) {
        SidfTerm *term = PtrArray_get(directives, i);
        SidfScore eval_score = SidfRequest_evalMechanism(self, term);
        if (SIDF_SCORE_NULL != eval_score) {
            SidfLogDebug(self->policy, "mechanism match: domain=%s, mech%02u=%s, score=%s",
                         domain, i, term->attr->name, SidfEnum_lookupScoreByValue(eval_score));
            return eval_score;
        }   // end if
        SidfLogDebug(self->policy, "mechanism not match: domain=%s, mech_no=%u, mech=%s",
                     domain, i, term->attr->name);
    }   // end if
    return SIDF_SCORE_NULL;
}   // end function: SidfRequest_evalDirectives

static SidfScore
SidfRequest_evalLocalPolicy(SidfRequest *self)
{
    // 再帰評価 (include や redirect) の内側にいない場合のみ, ローカルポリシーの評価をおこなう
    if (0 < SidfRequest_getDepth(self) || NULL == self->policy->local_policy
        || self->local_policy_mode) {
        return SIDF_SCORE_NULL;
    }   // end if

    SidfLogDebug(self->policy, "evaluating local policy: policy=%s", self->policy->local_policy);
    // SPF/SIDF 評価過程で遭遇した DNS をひくメカニズムのカウンタをクリア
    SidfRecord *local_policy_record = NULL;
    SidfStat build_stat = SidfRecord_build(self, self->scope, self->policy->local_policy,
                                           STRTAIL(self->policy->local_policy),
                                           &local_policy_record);
    if (SIDF_STAT_OK != build_stat) {
        SidfLogConfigError(self->policy, "failed to build local policy record: policy=%s",
                           self->policy->local_policy);
        return SIDF_SCORE_NULL;
    }   // end if
    self->dns_mech_count = 0;   // 本物のレコード評価中に遭遇した DNS ルックアップを伴うメカニズムの数は忘れる
    self->local_policy_mode = true; // ローカルポリシー評価中に, さらにローカルポリシーを適用して無限ループに入らないようにフラグを立てる.
    SidfScore local_policy_score =
        SidfRequest_evalDirectives(self, local_policy_record->directives);
    self->local_policy_mode = false;
    SidfRecord_free(local_policy_record);

    switch (local_policy_score) {
    case SIDF_SCORE_PERMERROR:
    case SIDF_SCORE_TEMPERROR:
        // ローカルポリシー評価中の temperror, permerror は無視する
        SidfLogDebug(self->policy, "ignoring local policy score: score=%s",
                     SidfEnum_lookupScoreByValue(local_policy_score));
        return SIDF_SCORE_NULL;
    default:
        SidfLogDebug(self->policy, "applying local policy score: score=%s",
                     SidfEnum_lookupScoreByValue(local_policy_score));
        return local_policy_score;
    }   // end switch
}   // end function: SidfRequest_evalLocalPolicy

/**
 * The check_host() Function as defined in Section 4 of RFC4408
 * @param self SidfRequest object.
 * @param domain <domain> parameter of the check_host() function
 */
static SidfScore
SidfRequest_checkHost(SidfRequest *self, const char *domain)
{
    // check <domain> parameter
    SidfScore precond_score = SidfRequest_checkDomain(self, domain);
    if (SIDF_SCORE_NULL != precond_score) {
        return precond_score;
    }   // end if

    // register <domain> parameter
    SidfStat push_stat = SidfRequest_pushDomain(self, domain);
    if (SIDF_STAT_OK != push_stat) {
        return SIDF_SCORE_SYSERROR;
    }   // end if

    SidfRecord *record = NULL;
    SidfScore lookup_score = SidfRequest_lookupRecord(self, SidfRequest_getDomain(self), &record);
    if (SIDF_SCORE_NULL != lookup_score) {
        SidfRequest_popDomain(self);
        return lookup_score;
    }   // end if

    // mechanism evaluation
    SidfScore eval_score = SidfRequest_evalDirectives(self, record->directives);
    if (SIDF_SCORE_NULL != eval_score) {
        /*
         * SidfPolicy で "exp=" を取得するようの指定されている場合に "exp=" を取得する.
         * ただし, 以下の点に注意する:
         * - include メカニズム中の exp= は評価しない.
         * - redirect 評価中に元のドメインの exp= は評価しない.
         * [RFC4408] 6.2.
         * Note: During recursion into an "include" mechanism, an exp= modifier
         * from the <target-name> MUST NOT be used.  In contrast, when executing
         * a "redirect" modifier, an exp= modifier from the original domain MUST
         * NOT be used.
         *
         * <target-name> は メカニズムの引数で指定されている <domain-spec>,
         * 指定されていない場合は check_host() 関数の <domain>.
         * [RFC4408] 4.8.
         * Several of these mechanisms and modifiers have a <domain-spec>
         * section.  The <domain-spec> string is macro expanded (see Section 8).
         * The resulting string is the common presentation form of a fully-
         * qualified DNS name: a series of labels separated by periods.  This
         * domain is called the <target-name> in the rest of this document.
         */
        if (self->policy->lookup_exp && SIDF_SCORE_HARDFAIL == eval_score
            && 0 == self->include_depth && NULL != record->modifiers.exp) {
            (void) SidfRequest_evalModExplanation(self, record->modifiers.exp);
        }   // end if
        goto finally;
    }   // end if

    /*
     * レコード中の全てのメカニズムにマッチしなかった場合
     * [RFC4408] 4.7.
     * If none of the mechanisms match and there is no "redirect" modifier,
     * then the check_host() returns a result of "Neutral", just as if
     * "?all" were specified as the last directive.  If there is a
     * "redirect" modifier, check_host() proceeds as defined in Section 6.1.
     */

    // "redirect=" modifier evaluation
    if (NULL != record->modifiers.rediect) {
        SidfLogDebug(self->policy, "redirect: from=%s, to=%s", domain,
                     record->modifiers.rediect->param.domain);
        eval_score = SidfRequest_evalModRedirect(self, record->modifiers.rediect);
        goto finally;
    }   // end if

    eval_score = SidfRequest_evalLocalPolicy(self);
    if (SIDF_SCORE_NULL != eval_score) {
        // exp= を評価する条件は directive によってスコアが決定する場合とほぼ同じ.
        // 違いは local_policy_explanation を使用する点.
        if (self->policy->lookup_exp && SIDF_SCORE_HARDFAIL == eval_score
            && 0 == self->include_depth && NULL != self->policy->local_policy_explanation) {
            // local policy 専用の explanation をセットする.
            (void) SidfRequest_setExplanation(self, domain, self->policy->local_policy_explanation);
        }   // end if
        goto finally;
    }   // end if

    // returns "Neutral" as default socre
    eval_score = SIDF_SCORE_NEUTRAL;
    SidfLogDebug(self->policy, "default score applied: domain=%s", domain);

  finally:
    SidfRequest_popDomain(self);
    SidfRecord_free(record);
    return eval_score;
}   // end function: SidfRequest_checkHost

/**
 * HELO は指定必須. sender が指定されていない場合, postmaster@(HELOとして指定したドメイン) を sender として使用する.
 * @return SIDF_SCORE_NULL: 引数がセットされていない.
 *         SIDF_SCORE_SYSERROR: メモリの確保に失敗した.
 *         それ以外の場合は評価結果.
 */
SidfScore
SidfRequest_eval(SidfRequest *self, SidfRecordScope scope)
{
    assert(NULL != self);

    self->scope = scope;
    self->dns_mech_count = 0;
    if (0 == self->sa_family || NULL == self->helo_domain) {
        return SIDF_SCORE_NULL;
    }   // end if
    if (NULL == self->sender) {
        /*
         * [RFC4408] 4.3.
         * If the <sender> has no localpart, substitute the string "postmaster"
         * for the localpart.
         */
        self->sender = InetMailbox_build(SIDF_REQUEST_DEFAULT_LOCALPART, self->helo_domain);
        if (NULL == self->sender) {
            SidfLogNoResource(self->policy);
            return SIDF_SCORE_SYSERROR;
        }   // end if
        self->is_sender_context = false;
    } else {
        self->is_sender_context = true;
    }   // end if
    self->redirect_depth = 0;
    self->include_depth = 0;
    return SidfRequest_checkHost(self, InetMailbox_getDomain(self->sender));
}   // end function: SidfRequest_eval

/**
 * This function sets an IP address to the SidfRequest object via sockaddr structure.
 * The IP address is used as <ip> parameter of check_host function.
 * @param self SidfRequest object.
 * @param sa_family address family. AF_INET for IPv4, AF_INET6 for IPv6.
 * @param addr a pointer to the sockaddr_in structure for IPv4,
 *             sockaddr_in6 structure for IPv6.
 * @return true on successful completion, false otherwise.
 *         If sa_family is specified correctly, this function won't fail.
 */
bool
SidfRequest_setIpAddr(SidfRequest *self, sa_family_t sa_family, const struct sockaddr *addr)
{
    assert(NULL != self);
    assert(NULL != addr);

    self->sa_family = sa_family;
    switch (sa_family) {
    case AF_INET:
        memcpy(&(self->ipaddr.addr4), &(((const struct sockaddr_in *) addr)->sin_addr),
               sizeof(struct in_addr));
        return true;
    case AF_INET6:
        memcpy(&(self->ipaddr.addr6), &(((const struct sockaddr_in6 *) addr)->sin6_addr),
               sizeof(struct in6_addr));
        return true;
    default:
        return false;
    }   // end switch
}   // end function: SidfRequest_setIpAddr

/**
 * This function sets an IP address to the SidfRequest object with string representation.
 * The IP address is used as <ip> parameter of check_host function.
 * @param self SidfRequest object.
 * @param sa_family address family. AF_INET for IPv4, AF_INET6 for IPv6.
 * @param address a null-terminated string represents an IP address.
 * @return true on successful completion, false otherwise.
 *         If sa_family is specified correctly, this function won't fail.
 */
bool
SidfRequest_setIpAddrString(SidfRequest *self, sa_family_t sa_family, const char *address)
{
    assert(NULL != self);
    assert(NULL != address);

    self->sa_family = sa_family;
    switch (sa_family) {
    case AF_INET:
        return bool_cast(1 == inet_pton(AF_INET, address, &(self->ipaddr.addr4)));
    case AF_INET6:
        return bool_cast(1 == inet_pton(AF_INET6, address, &(self->ipaddr.addr6)));
    default:
        return false;
    }   // end switch
}   // end function: SidfRequest_setIpAddrString

/**
 * 送信者のメールアドレスを SidfRequest にセットする.
 * check_host() 関数の引数 <sender> やマクロの展開の際に用いられる.
 * @return 成功した場合は true, メモリの確保に失敗した場合は false.
 */
bool
SidfRequest_setSender(SidfRequest *self, const InetMailbox *sender)
{
    assert(NULL != self);

    InetMailbox *mailbox = NULL;
    if (NULL != sender) {
        mailbox = InetMailbox_duplicate(sender);
        if (NULL == mailbox) {
            return false;
        }   // end if
    }   // end if

    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
    }   // end if

    self->sender = mailbox;
    return true;
}   // end function: SidfRequest_setSender

/**
 * HELO ドメインを SidfRequest にセットする.
 * <sender> がセットされていない場合に check_host() 関数の引数 <sender> として使用される.
 * また, マクロの展開の際にも用いられる.
 * @return 成功した場合は true, メモリの確保に失敗した場合は false.
 */
bool
SidfRequest_setHeloDomain(SidfRequest *self, const char *domain)
{
    assert(NULL != self);

    char *tmp = NULL;
    if (NULL != domain && NULL == (tmp = strdup(domain))) {
        return false;
    }   // end if
    free(self->helo_domain);
    self->helo_domain = tmp;
    return true;
}   // end function: SidfRequest_setHeloDomain

void
SidfRequest_reset(SidfRequest *self)
{
    assert(NULL != self);
    self->scope = SIDF_RECORD_SCOPE_NULL;
    self->sa_family = 0;
    memset(&(self->ipaddr), 0, sizeof(union ipaddr46));
    if (NULL != self->domain) {
        StrArray_reset(self->domain);
    }   // end if
    self->dns_mech_count = 0;
    self->is_sender_context = false;
    self->local_policy_mode = false;
    if (NULL != self->xbuf) {
        XBuffer_reset(self->xbuf);
    }   // end if
    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
        self->sender = NULL;
    }   // end if
    if (NULL != self->helo_domain) {
        free(self->helo_domain);
        self->helo_domain = NULL;
    }   // end if
    if (NULL != self->explanation) {
        free(self->explanation);
        self->explanation = NULL;
    }   // end if
}   // end function: SidfRequest_reset

/**
 * release SidfRequest object
 * @param self SidfRequest object to release
 */
void
SidfRequest_free(SidfRequest *self)
{
    assert(NULL != self);
    if (NULL != self->domain) {
        StrArray_free(self->domain);
    }   // end if
    if (NULL != self->xbuf) {
        XBuffer_free(self->xbuf);
    }   // end if
    if (NULL != self->sender) {
        InetMailbox_free(self->sender);
    }   // end if
    if (NULL != self->helo_domain) {
        free(self->helo_domain);
    }   // end if
    if (NULL != self->explanation) {
        free(self->explanation);
    }   // end if
    free(self);
}   // end function: SidfRequest_free

/**
 * create SidfRequest object
 * @return initialized SidfRequest object, or NULL if memory allocation failed.
 */
SidfRequest *
SidfRequest_new(const SidfPolicy *policy, DnsResolver *resolver)
{
    SidfRequest *self = (SidfRequest *) malloc(sizeof(SidfRequest));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SidfRequest));
    self->domain = StrArray_new(0);
    if (NULL == self->domain) {
        goto cleanup;
    }   // end if
    self->xbuf = XBuffer_new(0);
    if (NULL == self->xbuf) {
        goto cleanup;
    }   // end if
    self->policy = policy;
    self->resolver = resolver;
    self->is_sender_context = false;
    self->local_policy_mode = false;
    return self;

  cleanup:
    SidfRequest_free(self);
    return NULL;
}   // end function: SidfRequest_new
