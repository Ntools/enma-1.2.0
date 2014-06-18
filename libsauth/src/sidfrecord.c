/*
 * Copyright (c) 2007-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfrecord.c 1346 2011-08-10 02:15:43Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfrecord.c 1346 2011-08-10 02:15:43Z takahiko $");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "ptrop.h"
#include "inet_ppton.h"
#include "sidflogger.h"
#include "pstring.h"
#include "keywordmap.h"
#include "xskip.h"
#include "inetdomain.h"
#include "sidf.h"
#include "sidfmacro.h"
#include "sidfrecord.h"

#define SIDF_RECORD_SPF1_PREFIX "v=spf1"
#define SIDF_RECORD_SIDF20_PREFIX "spf2.0"

// maximum value of ip4-cidr-length
#define SIDF_IP4_MAX_CIDR_LENGTH 32
// maximum value of ip6-cidr-length
#define SIDF_IP6_MAX_CIDR_LENGTH 128
// the number of digits to represent cidr-length decimally
// 128 が最大値なので3桁あれば十分
#define SIDF_RECORD_CIDRLEN_MAX_WIDTH 3
#define SIDF_MACRO_EXPANSION_MAX_LENGTH 253

/*
 * [RFC4408]
 * record           = version terms *SP
 * version          = "v=spf1"
 *
 * terms            = *( 1*SP ( directive / modifier ) )
 *
 * directive        = [ qualifier ] mechanism
 * qualifier        = "+" / "-" / "?" / "~"
 * mechanism        = ( all / include
 *                    / A / MX / PTR / IP4 / IP6 / exists )
 * modifier         = redirect / explanation / unknown-modifier
 * unknown-modifier = name "=" macro-string
 *
 * name             = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
 *
 * all              = "all"
 * include          = "include"  ":" domain-spec
 * A                = "a"      [ ":" domain-spec ] [ dual-cidr-length ]
 * MX               = "mx"     [ ":" domain-spec ] [ dual-cidr-length ]
 * PTR              = "ptr"    [ ":" domain-spec ]
 * IP4              = "ip4"      ":" ip4-network   [ ip4-cidr-length ]
 * IP6              = "ip6"      ":" ip6-network   [ ip6-cidr-length ]
 * exists           = "exists"   ":" domain-spec
 *
 * redirect         = "redirect" "=" domain-spec
 * explanation      = "exp" "=" domain-spec
 *
 * ip4-cidr-length  = "/" 1*DIGIT
 * ip6-cidr-length  = "/" 1*DIGIT
 * dual-cidr-length = [ ip4-cidr-length ] [ "/" ip6-cidr-length ]
 */

/*
 * domain-spec      = macro-string domain-end
 * domain-end       = ( "." toplabel [ "." ] ) / macro-expand
 *
 * toplabel         = ( *alphanum ALPHA *alphanum ) /
 *                    ( 1*alphanum "-" *( alphanum / "-" ) alphanum )
 *                    ; LDH rule plus additional TLD restrictions
 *                    ; (see [RFC3696], Section 2)
 * alphanum         = ALPHA / DIGIT
 *
 * explain-string   = *( macro-string / SP )
 *
 * macro-string     = *( macro-expand / macro-literal )
 * macro-expand     = ( "%{" macro-letter transformers *delimiter "}" )
 *                    / "%%" / "%_" / "%-"
 * macro-literal    = %x21-24 / %x26-7E
 *                    ; visible characters except "%"
 * macro-letter     = "s" / "l" / "o" / "d" / "i" / "p" / "h" /
 *                    "c" / "r" / "t"
 * transformers     = *DIGIT [ "r" ]
 * delimiter        = "." / "-" / "+" / "," / "/" / "_" / "="
 */

static const SidfTermAttribute sidf_mech_attr_table[] = {
    {"all", SIDF_TERM_MECH_ALL, true, SIDF_TERM_PARAM_NONE,
     false, '\0', false, SIDF_TERM_CIDR_OPTION_NONE},
    {"include", SIDF_TERM_MECH_INCLUDE, true, SIDF_TERM_PARAM_DOMAINSPEC,
     true, ':', true, SIDF_TERM_CIDR_OPTION_NONE},
    // first match なので "a" は "all" より後になければならない
    {"a", SIDF_TERM_MECH_A, true, SIDF_TERM_PARAM_DOMAINSPEC,
     true, ':', false, SIDF_TERM_CIDR_OPTION_DUAL},
    {"mx", SIDF_TERM_MECH_MX, true, SIDF_TERM_PARAM_DOMAINSPEC,
     true, ':', false, SIDF_TERM_CIDR_OPTION_DUAL},
    {"ptr", SIDF_TERM_MECH_PTR, true, SIDF_TERM_PARAM_DOMAINSPEC,
     true, ':', false, SIDF_TERM_CIDR_OPTION_NONE},
    {"ip4", SIDF_TERM_MECH_IP4, true, SIDF_TERM_PARAM_IP4,
     false, ':', true, SIDF_TERM_CIDR_OPTION_IP4},
    {"ip6", SIDF_TERM_MECH_IP6, true, SIDF_TERM_PARAM_IP6,
     false, ':', true, SIDF_TERM_CIDR_OPTION_IP6},
    {"exists", SIDF_TERM_MECH_EXISTS, true, SIDF_TERM_PARAM_DOMAINSPEC,
     true, ':', true, SIDF_TERM_CIDR_OPTION_NONE},
    // sentinel
    {NULL, SIDF_TERM_MECH_NULL, false, SIDF_TERM_PARAM_NONE,
     false, '\0', false, SIDF_TERM_CIDR_OPTION_NONE},
};

static const SidfTermAttribute sidf_mod_attr_table[] = {
    {"redirect", SIDF_TERM_MOD_REDIRECT, false, SIDF_TERM_PARAM_DOMAINSPEC,
     true, '=', true, SIDF_TERM_CIDR_OPTION_NONE},
    {"exp", SIDF_TERM_MOD_EXPLANATION, false, SIDF_TERM_PARAM_DOMAINSPEC,
     false, '=', true, SIDF_TERM_CIDR_OPTION_NONE},
    // sentinel
    {NULL, SIDF_TERM_MECH_NULL, false, SIDF_TERM_PARAM_NONE,
     false, '\0', false, SIDF_TERM_CIDR_OPTION_NONE},
};

typedef struct SidfQualifierMap {
    const char symbol;
    SidfQualifier qualifier;
} SidfQualifierMap;

static const SidfQualifierMap sidf_qualifier_table[] = {
    {'+', SIDF_QUALIFIER_PLUS},
    {'-', SIDF_QUALIFIER_MINUS},
    {'?', SIDF_QUALIFIER_QUESTION},
    {'~', SIDF_QUALIFIER_TILDE},
    {'\0', SIDF_QUALIFIER_NULL},    // sentinel
};

/*
 * SIDF レコードのスコープ文字列から列挙体の値をひく.
 * @return RFC4406 で定義されているスコープの場合は SIDF_RECORD_SCOPE_SPF2_* を,
 *         未定義のスコープの場合は SIDF_RECORD_SCOPE_UNKNOWN を,
 *         長さが0の場合やスコープ名として認識できない場合は SIDF_RECORD_SCOPE_NULL を返す.
 *
 * [RFC4406]
 * scope-id    = "mfrom" / "pra" / name
 * [RFC4408]
 * name        = ALPHA *( ALPHA / DIGIT / "-" / "_" / "." )
 */
static SidfRecordScope
SidfRecord_lookupSidfScope(const char *head, const char *tail, const char **nextp)
{
    static const KeywordMap sidf_scope_table[] = {
        {"mfrom", SIDF_RECORD_SCOPE_SPF2_MFROM},
        {"pra", SIDF_RECORD_SCOPE_SPF2_PRA},
        {NULL, SIDF_RECORD_SCOPE_UNKNOWN},  // sentinel
    };

    if (0 < XSkip_spfName(head, tail, nextp)) {
        return KeywordMap_lookupByCaseStringSlice(sidf_scope_table, head, *nextp);
    } else {
        *nextp = head;
        return SIDF_RECORD_SCOPE_NULL;
    }   // end if
}   // end function: SidfRecord_lookupSidfScope

/*
 * [RFC4406]
 * record      = version terms *SP
 * version     = "v=spf1" | ( "spf2." ver-minor scope)
 * ver-minor   = 1*DIGIT
 * scope       = "/" scope-id *( "," scope-id )
 * scope-id    = "mfrom" / "pra" / name
 */
static SidfStat
SidfRecord_parseVersion(const SidfRequest *request, const char *head, const char *tail,
                        const char **nextp, SidfRecordScope *scope)
{
    // SPF レコードかチェック
    if (0 < XSkip_casestring(head, tail, SIDF_RECORD_SPF1_PREFIX, nextp)) {
        *scope = SIDF_RECORD_SCOPE_SPF1;
        return SIDF_STAT_OK;
    }   // end if

    // SIDF レコードかチェック
    const char *p;
    if (0 < XSkip_casestring(head, tail, SIDF_RECORD_SIDF20_PREFIX, &p)
        && 0 < XSkip_char(p, tail, '/', &p)) {
        SidfRecordScope record_scope = 0;
        const char *scope_tail;
        do {
            SidfRecordScope current_scope = SidfRecord_lookupSidfScope(p, tail, &scope_tail);
            switch (current_scope) {
            case SIDF_RECORD_SCOPE_NULL:
                SidfLogPermFail(request->policy, "invalid record for scope format: scope=%.*s",
                                (int) (tail - head), head);
                goto parsefail;
            case SIDF_RECORD_SCOPE_UNKNOWN:
                // 無効なスコープは無視する
                SidfLogInfo(request->policy, "unsupported scope specified (ignored): scope=%.*s",
                            (int) (scope_tail - p), p);
                // fall through
            default:
                // もしスコープが重複指定されていても, RFC4408 で明示的に禁止されていないので許容する.
                record_scope |= current_scope;
                break;
            }   // end switch
        } while (0 < XSkip_char(scope_tail, tail, ',', &p));
        *nextp = p;
        *scope = record_scope;
        return SIDF_STAT_OK;
    }   // end if

    // fall through

  parsefail:
    *nextp = head;
    *scope = SIDF_RECORD_SCOPE_NULL;
    return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
}   // end function: SidfRecord_parseVersion

static SidfQualifier
SidfRecord_parseQualifier(const char *head, const char *tail, const char **nextp)
{
    if (tail <= head) {
        *nextp = head;
        return SIDF_QUALIFIER_NULL;
    }   // end if

    const SidfQualifierMap *p;
    for (p = sidf_qualifier_table; '\0' != p->symbol; ++p) {
        if (*head == p->symbol) {
            *nextp = head + 1;
            return p->qualifier;
        }   // end if
    }   // end if

    *nextp = head;
    return p->qualifier;
}   // end function: SidfRecord_parseQualifier

static SidfStat
SidfRecord_parseDomainSpec(SidfRecord *self, const char *head, const char *tail, SidfTerm *term,
                           const char **nextp)
{
    XBuffer_reset(self->request->xbuf);
    SidfStat parse_stat =
        SidfMacro_parseDomainSpec(self->request, head, tail, nextp, self->request->xbuf);
    if (SIDF_STAT_OK == parse_stat) {
        SidfLogParseTrace("    domainspec: %.*s as [%s]\n",
                          *nextp - head, head, XBuffer_getString(self->request->xbuf));
        if (0 != XBuffer_status(self->request->xbuf)) {
            SidfLogNoResource(self->request->policy);
            return SIDF_STAT_NO_RESOURCE;
        }   // end if
        term->param.domain = XBuffer_dupString(self->request->xbuf);
        if (NULL == term->param.domain) {
            SidfLogNoResource(self->request->policy);
            return SIDF_STAT_NO_RESOURCE;
        }   // end if

        /*
         * 展開結果が253文字を越える場合はそれ以下に丸める.
         * クエリを引く直前に丸める選択もあったが, domain-spec を引数にとる mechanism は
         * 全てそれに基づいてクエリを引くので domain-spec を解釈する時点で丸めることにした.
         *
         * [RFC4408] 8.1.
         * When the result of macro expansion is used in a domain name query, if
         * the expanded domain name exceeds 253 characters (the maximum length
         * of a domain name), the left side is truncated to fit, by removing
         * successive domain labels until the total length does not exceed 253
         * characters.
         */
        term->querydomain = term->param.domain;
        while (SIDF_MACRO_EXPANSION_MAX_LENGTH < strlen(term->querydomain)) {
            term->querydomain = InetDomain_upward(term->querydomain);
            if (NULL == term->querydomain) {
                // サブドメインなしで 253 文字を突破していた場合
                SidfLogPermFail
                    (self->request->policy,
                     "macro expansion exceeds limits of its length: domain=%s, domain-spec=[%.*s]",
                     self->domain, (int) (*nextp - head), head);
                return SIDF_STAT_MALICIOUS_MACRO_EXPANSION;
            }   // end if
        }   // end while
        if (term->querydomain != term->param.domain) {
            SidfLogInfo(self->request->policy,
                        "domain-spec truncated: domain=%s, %s=%s, domain-spec=%s", self->domain,
                        term->attr->is_mechanism ? "mech" : "mod", term->attr->name,
                        term->querydomain);
        }   // end if
    }   // end if
    return parse_stat;
}   // end function: SidfRecord_parseDomainSpec

static SidfStat
SidfRecord_parseIp4Addr(const char *head, const char *tail, SidfTerm *term, const char **nextp)
{
    const char *p = head;
    for (++p; p < tail && (isdigit(*p) || '.' == *p); ++p);
    if (head < p && 1 == inet_ppton(AF_INET, head, p, &(term->param.addr4))) {
        *nextp = p;
        SidfLogParseTrace("    ip4addr: %.*s\n", *nextp - head, head);
        return SIDF_STAT_OK;
    } else {
        *nextp = head;
        return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if
}   // end function: SidfRecord_parseIp4Addr

static SidfStat
SidfRecord_parseIp6Addr(const char *head, const char *tail, SidfTerm *term, const char **nextp)
{
    const char *p = head;
    for (++p; p < tail && (isxdigit(*p) || ':' == *p || '.' == *p); ++p);
    if (head < p && 1 == inet_ppton(AF_INET6, head, p, &(term->param.addr6))) {
        *nextp = p;
        SidfLogParseTrace("    ip6addr: %.*s\n", *nextp - head, head);
        return SIDF_STAT_OK;
    } else {
        *nextp = head;
        return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if
}   // end function: SidfRecord_parseIp6Addr

static SidfStat
SidfRecord_parsebackCidrLength(const char *head, const char *tail,
                               const char **prevp, unsigned short *cidrlength)
{
    // cidr-length は 3桁を越えることはないので, 3桁以上はパースしない.
    const char *cidr_head =
        (head < tail - SIDF_RECORD_CIDRLEN_MAX_WIDTH) ? tail - SIDF_RECORD_CIDRLEN_MAX_WIDTH : head;
    const char *p = tail - 1;
    unsigned short cidr_value = 0;
    for (unsigned short base = 1; cidr_head <= p && isdigit(*p); --p, base *= 10) {
        cidr_value += (*p - '0') * base;
    }   // end for
    if (p < tail - 1 && head <= p && '/' == *p) {
        *prevp = p;
        *cidrlength = cidr_value;
        return SIDF_STAT_OK;
    } else {
        *prevp = tail;
        *cidrlength = 0;
        return SIDF_STAT_RECORD_NOT_MATCH;
    }   // end if
}   // end function: SidfRecord_parsebackCidrLength

/**
 * @return SIDF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SIDF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SIDF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SidfStat
SidfRecord_parsebackSingleCidrLength(const SidfPolicy *policy, const char *head, const char *tail,
                                     const char *mechname, unsigned short maxcidrlen,
                                     const char **prevp, unsigned short *cidrlength)
{
    SidfStat parse_stat = SidfRecord_parsebackCidrLength(head, tail, prevp, cidrlength);
    switch (parse_stat) {
    case SIDF_STAT_OK:
        SidfLogParseTrace("    %scidr: %.*s\n", mechname, tail - *prevp, *prevp);
        if (0 == *cidrlength || maxcidrlen < *cidrlength) {
            SidfLogPermFail(policy, "invalid cidr-length specified: mech=%s, cidr-length=%hu",
                            mechname, *cidrlength);
            return SIDF_STAT_RECORD_INVALID_CIDR_LENGTH;
        }   // end if
        return SIDF_STAT_OK;
    case SIDF_STAT_RECORD_NOT_MATCH:
        return SIDF_STAT_RECORD_NOT_MATCH;
    default:
        abort();
    }   // end switch
}   // end function: SidfRecord_parsebackSingleCidrLength

/**
 * @return SIDF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SIDF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SIDF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SidfStat
SidfRecord_parsebackIp4CidrLength(const SidfPolicy *policy, const char *head, const char *tail,
                                  SidfTerm *term, const char **prevp)
{
    unsigned short cidrlength;
    SidfStat parse_stat = SidfRecord_parsebackSingleCidrLength(policy, head, tail, term->attr->name,
                                                               SIDF_IP4_MAX_CIDR_LENGTH,
                                                               prevp,
                                                               &cidrlength);
    term->ip4cidr = (SIDF_STAT_OK == parse_stat) ? cidrlength : SIDF_IP4_MAX_CIDR_LENGTH;
    return parse_stat;
}   // end function: SidfRecord_parsebackIp4CidrLength

/**
 * @return SIDF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SIDF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SIDF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SidfStat
SidfRecord_parsebackIp6CidrLength(const SidfPolicy *policy, const char *head, const char *tail,
                                  SidfTerm *term, const char **prevp)
{
    unsigned short cidrlength;
    SidfStat parse_stat = SidfRecord_parsebackSingleCidrLength(policy, head, tail, term->attr->name,
                                                               SIDF_IP6_MAX_CIDR_LENGTH,
                                                               prevp,
                                                               &cidrlength);
    term->ip6cidr = (SIDF_STAT_OK == parse_stat) ? cidrlength : SIDF_IP6_MAX_CIDR_LENGTH;
    return parse_stat;
}   // end function: SidfRecord_parsebackIp6CidrLength

/**
 * @return SIDF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SIDF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SIDF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SidfStat
SidfRecord_parsebackDualCidrLength(const SidfPolicy *policy, const char *head, const char *tail,
                                   SidfTerm *term, const char **prevp)
{
    const char *p;
    unsigned short cidrlength;
    SidfStat parse_stat = SidfRecord_parsebackCidrLength(head, tail, &p, &cidrlength);
    switch (parse_stat) {
    case SIDF_STAT_OK:
        if (head <= p - 1 && '/' == *(p - 1)) {
            // ip6-cidr-length
            SidfLogParseTrace("    ip6cidr: %.*s\n", tail - p, p);
            if (0 == cidrlength || SIDF_IP6_MAX_CIDR_LENGTH < cidrlength) {
                SidfLogPermFail(policy,
                                "invalid ip6-cidr-length specified: mech=%s, cidr-length=%hu",
                                term->attr->name, cidrlength);
                return SIDF_STAT_RECORD_INVALID_CIDR_LENGTH;
            }   // end if
            term->ip6cidr = cidrlength;
            return SidfRecord_parsebackIp4CidrLength(policy, head, p - 1, term, prevp);
        } else {
            // ip4-cidr-length
            SidfLogParseTrace("    ip4cidr: %.*s\n", tail - p, p);
            if (0 == cidrlength || SIDF_IP4_MAX_CIDR_LENGTH < cidrlength) {
                SidfLogPermFail(policy,
                                "invalid ip4-cidr-length specified: mech=%s, cidr-length=%hu",
                                term->attr->name, cidrlength);
                return SIDF_STAT_RECORD_INVALID_CIDR_LENGTH;
            }   // end if
            term->ip4cidr = cidrlength;
            term->ip6cidr = SIDF_IP6_MAX_CIDR_LENGTH;
            *prevp = p;
        }   // end if
        break;
    case SIDF_STAT_RECORD_NOT_MATCH:
        // ip4, ip6 ともデフォルト値を使用する
        term->ip4cidr = SIDF_IP4_MAX_CIDR_LENGTH;
        term->ip6cidr = SIDF_IP6_MAX_CIDR_LENGTH;
        *prevp = p;
        break;
    default:
        abort();
    }   // end switch
    return parse_stat;
}   // end function: SidfRecord_parsebackDualCidrLength

/**
 * @return SIDF_STAT_OK: maxcidrlen 以下の cidr-length を取得した.
 *         SIDF_STAT_RECORD_INVALID_CIDR_LENGTH: cidr-length が指定されていたが値が不正だった.
 *         SIDF_STAT_RECORD_SYNTAX_VIOLATION: cidr-length の文法にマッチするものは見つからなかった.
 */
static SidfStat
SidfRecord_parseCidrLength(const SidfPolicy *policy, SidfTermCidrOption cidr_type, const char *head,
                           const char *tail, SidfTerm *term, const char **prevp)
{
    switch (cidr_type) {
    case SIDF_TERM_CIDR_OPTION_NONE:
        *prevp = tail;
        return SIDF_STAT_OK;
    case SIDF_TERM_CIDR_OPTION_DUAL:
        return SidfRecord_parsebackDualCidrLength(policy, head, tail, term, prevp);
    case SIDF_TERM_CIDR_OPTION_IP4:
        return SidfRecord_parsebackIp4CidrLength(policy, head, tail, term, prevp);
    case SIDF_TERM_CIDR_OPTION_IP6:
        return SidfRecord_parsebackIp6CidrLength(policy, head, tail, term, prevp);
    default:
        abort();
    }   // end switch
}   // end function: SidfRecord_parseCidrLength

static SidfStat
SidfRecord_parseTermTargetName(SidfRecord *self, SidfTermParamType param_type, const char *head,
                               const char *tail, SidfTerm *term, const char **nextp)
{
    switch (param_type) {
    case SIDF_TERM_PARAM_NONE:
        *nextp = tail;
        return SIDF_STAT_OK;
    case SIDF_TERM_PARAM_DOMAINSPEC:
        return SidfRecord_parseDomainSpec(self, head, tail, term, nextp);
    case SIDF_TERM_PARAM_IP4:
        return SidfRecord_parseIp4Addr(head, tail, term, nextp);
    case SIDF_TERM_PARAM_IP6:
        return SidfRecord_parseIp6Addr(head, tail, term, nextp);
    default:
        abort();
    }   // end switch
}   // end function: SidfRecord_parseTermTargetName

static SidfTerm *
SidfTerm_new(SidfTermParamType param_type)
{
    size_t contentsize;
    switch (param_type) {
    case SIDF_TERM_PARAM_NONE:
        contentsize = 0;
        break;
    case SIDF_TERM_PARAM_DOMAINSPEC:
        contentsize = 0;
        break;
    case SIDF_TERM_PARAM_IP4:
        contentsize = sizeof(struct in_addr);
        break;
    case SIDF_TERM_PARAM_IP6:
        contentsize = sizeof(struct in6_addr);
        break;
    default:
        abort();
    }   // end switch
    SidfTerm *self = (SidfTerm *) malloc(sizeof(SidfTerm) + contentsize);
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SidfTerm) + contentsize);
    return self;
}   // end function: SidfTerm_new

static void
SidfTerm_free(SidfTerm *self)
{
    assert(NULL != self);
    if (SIDF_TERM_PARAM_DOMAINSPEC == self->attr->param_type && NULL != self->param.domain) {
        free(self->param.domain);
    }   // end if
    free(self);
}   // end function: SidfTerm_free

static const SidfTermAttribute *
SidfRecord_lookupMechanismAttribute(const char *head, const char *tail)
{
    const struct SidfTermAttribute *q;
    for (q = sidf_mech_attr_table; NULL != q->name; ++q) {
        /*
         * [RFC4408] 4.6.1.
         * As per the definition of the ABNF notation in [RFC4234], mechanism
         * and modifier names are case-insensitive.
         */
        const char *mech_tail;
        if (0 < XSkip_casestring(head, tail, q->name, &mech_tail) && mech_tail == tail) {
            return q;
        }   // end if
    }   // end for
    return NULL;
}   // end function: SidfRecord_lookupMechanismAttribute

static const SidfTermAttribute *
SidfRecord_lookupModifierAttribute(const char *head, const char *tail)
{
    const struct SidfTermAttribute *q;
    for (q = sidf_mod_attr_table; NULL != q->name; ++q) {
        /*
         * [RFC4408] 4.6.1.
         * As per the definition of the ABNF notation in [RFC4234], mechanism
         * and modifier names are case-insensitive.
         */
        const char *mod_tail;
        if (0 < XSkip_casestring(head, tail, q->name, &mod_tail) && mod_tail == tail) {
            return q;
        }   // end if
    }   // end for
    return NULL;
}   // end function: SidfRecord_lookupModifierAttribute

/**
 * @param head メカニズムの直後を指すポインタ
 */
static SidfStat
SidfRecord_buildTerm(SidfRecord *self, const char *head, const char *tail,
                     const SidfTermAttribute *termattr, SidfQualifier qualifier)
{
    SidfTerm *term = SidfTerm_new(termattr->param_type);
    if (NULL == term) {
        SidfLogNoResource(self->request->policy);
        return SIDF_STAT_NO_RESOURCE;
    }   // end if
    term->attr = termattr;
    const char *param_tail;

    // parse cidr-length
    SidfStat cidr_stat =
        SidfRecord_parseCidrLength(self->request->policy, termattr->cidr, head, tail, term,
                                   &param_tail);
    switch (cidr_stat) {
    case SIDF_STAT_RECORD_INVALID_CIDR_LENGTH:
        SidfTerm_free(term);
        return cidr_stat;
    case SIDF_STAT_OK:
    case SIDF_STAT_RECORD_NOT_MATCH:   // cidr-length は全てオプショナルなので失敗してもパースは続行する.
        break;
    default:
        abort();
    }   // end switch

    // parse target-name
    const char *param_head = head;
    if ('\0' != termattr->parameter_delimiter && SIDF_TERM_PARAM_NONE != termattr->param_type) {
        if (0 < XSkip_char(param_head, param_tail, termattr->parameter_delimiter, &param_head)) {
            // パラメーターが指定されている場合
            SidfStat parse_stat =
                SidfRecord_parseTermTargetName(self, termattr->param_type, param_head, param_tail,
                                               term, &param_head);
            if (SIDF_STAT_OK != parse_stat) {
                SidfTerm_free(term);
                return parse_stat;
            }   // end if
        } else {
            // no parameter is specified
            if (termattr->required_parameter) {
                // 必須のパラメーターが指定されていない
                SidfLogPermFail(self->request->policy,
                                "parameter missing: domain=%s, %s=%s, near=[%.*s]", self->domain,
                                termattr->is_mechanism ? "mech" : "mod", termattr->name,
                                (int) (tail - head), head);
                SidfTerm_free(term);
                return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if
        }   // end if
    }   // end if

    // mechanism に余りがないか確認
    if (param_head != param_tail) {
        SidfLogParseTrace("  => parse failed: [%.*s]\n", tail - head, head);
        SidfLogPermFail(self->request->policy, "unparsable term: domain=%s, %s=%s, near=[%.*s]",
                        self->domain, termattr->is_mechanism ? "mech" : "mod", termattr->name,
                        (int) (tail - param_head), param_head);
        SidfTerm_free(term);
        return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if

    if (termattr->is_mechanism) {
        SidfLogParseTrace("    type: mechanism\n");
        term->qualifier = (SIDF_QUALIFIER_NULL != qualifier) ? qualifier : SIDF_QUALIFIER_PLUS;
        SidfLogParseTrace("    qualifier: %d\n", qualifier);
        if (0 > PtrArray_append(self->directives, term)) {
            SidfLogNoResource(self->request->policy);
            SidfTerm_free(term);
            return SIDF_STAT_NO_RESOURCE;
        }   // end if
    } else {
        SidfLogParseTrace("    type: modifier\n");
        /*
         * "redirect", "exp" が同一レコード中で複数回指定されている場合は
         * SPF, SID 共に PermError.
         *
         * [RFC4408] 6.
         * The modifiers defined in this document ("redirect" and "exp") MAY
         * appear anywhere in the record, but SHOULD appear at the end, after
         * all mechanisms.  Ordering of these two modifiers does not matter.
         * These two modifiers MUST NOT appear in a record more than once each.
         * If they do, then check_host() exits with a result of "PermError".
         *
         * [RFC4406] 3.3.
         * The modifiers "redirect" and "exp" described in Section 6 of
         * [RFC4408] are global and singular.
         */
        term->qualifier = SIDF_QUALIFIER_NULL;
        switch (termattr->type) {
        case SIDF_TERM_MOD_REDIRECT:
            if (NULL != self->modifiers.rediect) {
                SidfLogPermFail(self->request->policy,
                                "redirect modifier specified repeatedly: domain=%s, near=[%.*s]",
                                self->domain, (int) (tail - head), head);
                SidfTerm_free(term);
                return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if
            self->modifiers.rediect = term;
            break;
        case SIDF_TERM_MOD_EXPLANATION:
            if (NULL != self->modifiers.exp) {
                SidfLogPermFail(self->request->policy,
                                "exp modifier specified repeatedly: domain=%s, near=[%.*s]",
                                self->domain, (int) (tail - head), head);
                SidfTerm_free(term);
                return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
            }   // end if
            self->modifiers.exp = term;
            break;
        case SIDF_TERM_MOD_UNKNOWN:
            // SidfRecord_parseTerms() 内で処理されるのでここは通らないハズ
            SidfTerm_free(term);
            break;
        default:
            abort();
        }   // end switch
    }   // end if

    return SIDF_STAT_OK;
}   // end function: SidfRecord_parseTermParam

static SidfStat
SidfRecord_parse(SidfRecord *self, const char *head, const char *tail)
{
    const char *term_head = head;
    const char *term_tail = NULL;
    while (true) {
        // SP (0x20) を目標に directive の切れ目を探す
        term_tail = strpchr(term_head, tail, ' ');
        if (NULL == term_tail) {
            term_tail = tail;
        }   // end if

        const char *mech_head, *mech_tail, *dummy;
        SidfQualifier qualifier = SidfRecord_parseQualifier(term_head, term_tail, &mech_head);
        XSkip_spfName(mech_head, term_tail, &mech_tail);
        const SidfTermAttribute *termattr;
        if (0 == XSkip_char(mech_tail, term_tail, '=', &dummy)) {
            // '=' が続かない場合は mechanism
            termattr = SidfRecord_lookupMechanismAttribute(mech_head, mech_tail);
            if (NULL == termattr) {
                SidfLogPermFail(self->request->policy,
                                "unsupported mechanism: domain=%s, near=[%.*s]", self->domain,
                                (int) (term_tail - term_head), term_head);
                return SIDF_STAT_RECORD_UNSUPPORTED_MECHANISM;
            }   // end if
        } else if (SIDF_QUALIFIER_NULL == qualifier) {
            // qualifier が付いていない場合は modifer
            termattr = SidfRecord_lookupModifierAttribute(mech_head, mech_tail);
            if (NULL == termattr) {
                /*
                 * ignore unrecognized modifiers
                 * [RFC4408] 6.
                 * Unrecognized modifiers MUST be ignored no matter where in a record,
                 * or how often.  This allows implementations of this document to
                 * gracefully handle records with modifiers that are defined in other
                 * specifications.
                 */
                SidfLogDebug(self->request->policy,
                             "unknown modifier (ignored): domain=%s, near=[%.*s]", self->domain,
                             (int) (term_tail - term_head), term_head);
            }   // end if
        } else {
            // qualifier が付いていて, '=' が続かない場合は構文違反
            SidfLogPermFail(self->request->policy, "invalid term: domain=%s, near=[%.*s]",
                            self->domain, (int) (term_tail - term_head), term_head);
            return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
        }   // end if

        if (NULL != termattr) {
            SidfLogParseTrace("  term: %.*s\n", mech_tail - term_head, term_head);
            SidfStat parse_stat =
                SidfRecord_buildTerm(self, mech_tail, term_tail, termattr, qualifier);
            if (SIDF_STAT_OK != parse_stat) {
                return parse_stat;
            }   // end if
        } else {
            // termattr が NULL になるのは unknown modifier に遭遇した場合のみ.
            // unknown modifier は無視する仕様なので何もしない
        }   // end if

        if (0 >= XSkip_spBlock(term_tail, tail, &term_head) || term_head == tail) {
            // レコードの終端に達したか予期しない文字に遭遇
            break;
        }   // end if
    }   // end while

    // 余りがないか確認する
    if (term_head == tail) {
        return SIDF_STAT_OK;
    } else {
        // abort parsing the record
        SidfLogPermFail(self->request->policy, "unparsable term: domain=%s, near=[%.*s]",
                        self->domain, (int) (tail - term_head), term_head);
        return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
    }   // end if
}   // end function: SidfRecord_parseTerms

/**
 * release SidfRecord object
 * @param self SidfRecord object to release
 */
void
SidfRecord_free(SidfRecord *self)
{
    assert(NULL != self);
    if (NULL != self->directives) {
        PtrArray_free(self->directives);
    }   // end if
    if (NULL != self->modifiers.rediect) {
        SidfTerm_free(self->modifiers.rediect);
    }   // end if
    if (NULL != self->modifiers.exp) {
        SidfTerm_free(self->modifiers.exp);
    }   // end if
    free(self);
}   // end function: SidfRecord_free

/**
 * create SidfRecord object
 * @return initialized SidfRecord object, or NULL if memory allocation failed.
 */
static SidfRecord *
SidfRecord_new(const SidfRequest *request)
{
    SidfRecord *self = (SidfRecord *) malloc(sizeof(SidfRecord));
    if (NULL == self) {
        SidfLogNoResource(request->policy);
        return NULL;
    }   // end if
    memset(self, 0, sizeof(SidfRecord));
    self->directives = PtrArray_new(0, (void (*)(void *)) SidfTerm_free);
    if (NULL == self->directives) {
        SidfLogNoResource(request->policy);
        goto cleanup;
    }   // end if
    self->request = request;

    return self;

  cleanup:
    SidfRecord_free(self);
    return NULL;
}   // end function: SidfRecord_new

/**
 * SPFレコードのスコープを除いた部分をパースして, SidfRecord オブジェクトを構築する.
 * @param scope 構築する SidfRecord オブジェクトに設定するスコープ.
 *              ここで指定するスコープとレコードの実際のスコープとの一貫性は呼び出し側が保証する必要がある.
 */
SidfStat
SidfRecord_build(const SidfRequest *request, SidfRecordScope scope, const char *record_head,
                 const char *record_tail, SidfRecord **recordobj)
{
    assert(NULL != request);
    assert(NULL != record_head);
    assert(NULL != record_tail);
    assert(NULL != recordobj);

    SidfLogDebug(request->policy, "Record: %s [%.*s]",
                 NULL != request ? SidfRequest_getDomain(request) : "(null)",
                 (int) (record_tail - record_head), record_head);

    SidfRecord *self = SidfRecord_new(request);
    if (NULL == self) {
        SidfLogNoResource(request->policy);
        return SIDF_STAT_NO_RESOURCE;
    }   // end if
    self->domain = SidfRequest_getDomain(request);
    self->scope = scope;

    SidfStat build_stat = SidfRecord_parse(self, record_head, record_tail);
    if (SIDF_STAT_OK == build_stat) {
        *recordobj = self;
    } else {
        SidfRecord_free(self);
    }   // end if
    return build_stat;
}   // end function: SidfRecord_build

/**
 * 指定した SPF/SIDF レコードのスコープを取得する.
 * スコープを取得できた場合はそのスコープを, 取得できなかった場合は
 * SIDF_RECORD_SCOPE_NULL を scope にセットする.
 */
SidfStat
SidfRecord_getSidfScope(const SidfRequest *request, const char *record_head,
                        const char *record_tail, SidfRecordScope *scope, const char **scope_tail)
{
    SidfStat parse_stat =
        SidfRecord_parseVersion(request, record_head, record_tail, scope_tail, scope);
    if (SIDF_STAT_OK != parse_stat) {
        return parse_stat;
    }   // end if

    // version の次の文字が SP かレコードの終端であることを確認
    if (*scope_tail == record_tail || 0 < XSkip_spBlock(*scope_tail, record_tail, scope_tail)) {
        return SIDF_STAT_OK;
    } else {
        *scope = SIDF_RECORD_SCOPE_NULL;
        return SIDF_STAT_RECORD_SYNTAX_VIOLATION;
    }   //end if
}   // end function: SidfRecord_getSidfScope
