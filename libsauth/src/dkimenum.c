/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimenum.c 1365 2011-10-16 08:08:36Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimenum.c 1365 2011-10-16 08:08:36Z takahiko $");

#include <stdio.h>
#include <string.h>

#include "xskip.h"
#include "keywordmap.h"
#include "dkim.h"
#include "dkimtaglistobject.h"
#include "dkimenum.h"

static const KeywordMap dkim_c14n_algorithm_table[] = {
    {"simple", DKIM_C14N_ALGORITHM_SIMPLE},
    {"relaxed", DKIM_C14N_ALGORITHM_RELAXED},
    {"nowsp", DKIM_C14N_ALGORITHM_NOWSP},   // obsolete
    {NULL, DKIM_C14N_ALGORITHM_NULL},
};

static const KeywordMap dkim_key_type_table[] = {
    {"rsa", DKIM_KEY_TYPE_RSA},
    {NULL, DKIM_KEY_TYPE_NULL},
};

static const KeywordMap dkim_hash_algorithm_table[] = {
    {"sha1", DKIM_HASH_ALGORITHM_SHA1},
    {"sha256", DKIM_HASH_ALGORITHM_SHA256},
    {NULL, DKIM_HASH_ALGORITHM_NULL},
};

static const KeywordMap dkim_service_type_table[] = {
    {"*", DKIM_SERVICE_TYPE_ANY},
    {"email", DKIM_SERVICE_TYPE_EMAIL},
    {NULL, DKIM_SERVICE_TYPE_NULL},
};

static const KeywordMap dkim_selector_flag_table[] = {
    {"y", DKIM_SELECTOR_FLAG_TESTING},
    {"s", DKIM_SELECTOR_FLAG_PROHIBIT_SUBDOMAIN},
    {NULL, DKIM_SELECTOR_FLAG_NULL},
};

static const KeywordMap dkim_query_method_table[] = {
    {"dns/txt", DKIM_QUERY_METHOD_DNS_TXT},
    // {"dns/dkk", DKIM_QUERYMETHOD_DNS_DKK},
    {"dns", DKIM_QUERY_METHOD_DNS_TXT}, // for backward compatibility
    {NULL, DKIM_QUERY_METHOD_NULL},
};

static const KeywordMap dkim_practice_table[] = {
    {"unknown", DKIM_ADSP_PRACTICE_UNKNOWN},
    {"all", DKIM_ADSP_PRACTICE_ALL},
    {"discardable", DKIM_ADSP_PRACTICE_DISCARDABLE},
    {NULL, DKIM_ADSP_PRACTICE_NULL},
};

static const KeywordMap dkim_score_table[] = {
    {"none", DKIM_BASE_SCORE_NONE},
    {"pass", DKIM_BASE_SCORE_PASS},
    {"fail", DKIM_BASE_SCORE_FAIL},
    {"policy", DKIM_BASE_SCORE_POLICY},
    {"neutral", DKIM_BASE_SCORE_NEUTRAL},
    {"temperror", DKIM_BASE_SCORE_TEMPERROR},
    {"permerror", DKIM_BASE_SCORE_PERMERROR},
    {NULL, DKIM_BASE_SCORE_NULL},
};

static const KeywordMap dkim_adsp_score_table[] = {
    {"none", DKIM_ADSP_SCORE_NONE},
    {"pass", DKIM_ADSP_SCORE_PASS},
    {"unknown", DKIM_ADSP_SCORE_UNKNOWN},
    {"fail", DKIM_ADSP_SCORE_FAIL},
    {"discard", DKIM_ADSP_SCORE_DISCARD},
    {"nxdomain", DKIM_ADSP_SCORE_NXDOMAIN},
    {"temperror", DKIM_ADSP_SCORE_TEMPERROR},
    {"permerror", DKIM_ADSP_SCORE_PERMERROR},
    {NULL, DKIM_ADSP_SCORE_NULL},
};

/*
 * [RFC6376] 3.2.
 * Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
 * processed as case sensitive unless the specific tag description of
 * semantics specifies case insensitivity.
 */

////////////////////////////////////////////////////////////

DkimC14nAlgorithm
DkimEnum_lookupC14nAlgorithmByName(const char *keyword)
{
    return (DkimC14nAlgorithm) KeywordMap_lookupByCaseString(dkim_c14n_algorithm_table, keyword);
}   // end function: DkimEnum_lookupC14nAlgorithmByName

DkimC14nAlgorithm
DkimEnum_lookupC14nAlgorithmByNameSlice(const char *head, const char *tail)
{
    return (DkimC14nAlgorithm) KeywordMap_lookupByCaseStringSlice(dkim_c14n_algorithm_table, head,
                                                                  tail);
}   // end function: DkimEnum_lookupC14nAlgorithmByNameSlice

const char *
DkimEnum_lookupC14nAlgorithmByValue(DkimC14nAlgorithm value)
{
    return KeywordMap_lookupByValue(dkim_c14n_algorithm_table, value);
}   // end function: DkimEnum_lookupC14nAlgorithmByValue

////////////////////////////////////////////////////////////

DkimKeyType
DkimEnum_lookupKeyTypeByName(const char *keyword)
{
    return (DkimKeyType) KeywordMap_lookupByCaseString(dkim_key_type_table, keyword);
}   // end function: DkimEnum_lookupKeyTypeByName

DkimKeyType
DkimEnum_lookupKeyTypeByNameSlice(const char *head, const char *tail)
{
    return (DkimKeyType) KeywordMap_lookupByCaseStringSlice(dkim_key_type_table, head, tail);
}   // end function: DkimEnum_lookupKeyTypeByNameSlice

const char *
DkimEnum_lookupKeyTypeByValue(DkimKeyType value)
{
    return KeywordMap_lookupByValue(dkim_key_type_table, value);
}   // end function: DkimEnum_lookupKeyTypeByValue

////////////////////////////////////////////////////////////

DkimHashAlgorithm
DkimEnum_lookupHashAlgorithmByName(const char *keyword)
{
    return (DkimHashAlgorithm) KeywordMap_lookupByCaseString(dkim_hash_algorithm_table, keyword);
}   // end function: DkimEnum_lookupHashAlgorithmByName

DkimHashAlgorithm
DkimEnum_lookupHashAlgorithmByNameSlice(const char *head, const char *tail)
{
    return (DkimHashAlgorithm) KeywordMap_lookupByCaseStringSlice(dkim_hash_algorithm_table, head,
                                                                  tail);
}   // end function: DkimEnum_lookupHashAlgorithmByNameSlice

const char *
DkimEnum_lookupHashAlgorithmByValue(DkimHashAlgorithm value)
{
    return KeywordMap_lookupByValue(dkim_hash_algorithm_table, value);
}   // end function: DkimEnum_lookupHashAlgorithmByValue

////////////////////////////////////////////////////////////

DkimServiceType
DkimEnum_lookupServiceTypeByName(const char *keyword)
{
    return (DkimServiceType) KeywordMap_lookupByCaseString(dkim_service_type_table, keyword);
}   // end function: DkimEnum_lookupServiceTypeByName

DkimServiceType
DkimEnum_lookupServiceTypeByNameSlice(const char *head, const char *tail)
{
    return (DkimServiceType) KeywordMap_lookupByCaseStringSlice(dkim_service_type_table, head,
                                                                tail);
}   // end function: DkimEnum_lookupServiceTypeByNameSlice

const char *
DkimEnum_lookupServiceTypeByValue(DkimServiceType value)
{
    return KeywordMap_lookupByValue(dkim_service_type_table, value);
}   // end function: DkimEnum_lookupServiceTypeByValue

////////////////////////////////////////////////////////////

DkimSelectorFlag
DkimEnum_lookupSelectorFlagByName(const char *keyword)
{
    return (DkimSelectorFlag) KeywordMap_lookupByCaseString(dkim_selector_flag_table, keyword);
}   // end function: DkimEnum_lookupSelectorFlagByName

DkimSelectorFlag
DkimEnum_lookupSelectorFlagByNameSlice(const char *head, const char *tail)
{
    return (DkimSelectorFlag) KeywordMap_lookupByCaseStringSlice(dkim_selector_flag_table, head,
                                                                 tail);
}   // end function: DkimEnum_lookupSelectorFlagByNameSlice

const char *
DkimEnum_lookupSelectorFlagByValue(DkimSelectorFlag value)
{
    return KeywordMap_lookupByValue(dkim_selector_flag_table, value);
}   // end function: DkimEnum_lookupSelectorFlagByValue

////////////////////////////////////////////////////////////

DkimQueryMethod
DkimEnum_lookupQueryMethodByName(const char *keyword)
{
    return (DkimQueryMethod) KeywordMap_lookupByCaseString(dkim_query_method_table, keyword);
}   // end function: DkimEnum_lookupQueryMethodByName

DkimQueryMethod
DkimEnum_lookupQueryMethodByNameSlice(const char *head, const char *tail)
{
    return (DkimQueryMethod) KeywordMap_lookupByCaseStringSlice(dkim_query_method_table, head,
                                                                tail);
}   // end function: DkimEnum_lookupQueryMethodByNameSlice

const char *
DkimEnum_lookupQueryMethodByValue(DkimQueryMethod value)
{
    return KeywordMap_lookupByValue(dkim_query_method_table, value);
}   // end function: DkimEnum_lookupQueryMethodByValue

////////////////////////////////////////////////////////////

DkimAdspPractice
DkimEnum_lookupPracticeByName(const char *keyword)
{
    return (DkimAdspPractice) KeywordMap_lookupByCaseString(dkim_practice_table, keyword);
}   // end function: DkimEnum_lookupPracticeByName

DkimAdspPractice
DkimEnum_lookupPracticeByNameSlice(const char *head, const char *tail)
{
    return (DkimAdspPractice) KeywordMap_lookupByCaseStringSlice(dkim_practice_table, head, tail);
}   // end function: DkimEnum_lookupPracticeByNameSlice

const char *
DkimEnum_lookupPracticeByValue(DkimAdspPractice value)
{
    return KeywordMap_lookupByValue(dkim_practice_table, value);
}   // end function: DkimEnum_lookupPracticeByValue

////////////////////////////////////////////////////////////

DkimBaseScore
DkimEnum_lookupScoreByName(const char *keyword)
{
    return (DkimBaseScore) KeywordMap_lookupByCaseString(dkim_score_table, keyword);
}   // end function: DkimEnum_lookupScoreByName

DkimBaseScore
DkimEnum_lookupScoreByNameSlice(const char *head, const char *tail)
{
    return (DkimBaseScore) KeywordMap_lookupByCaseStringSlice(dkim_score_table, head, tail);
}   // end function: DkimEnum_lookupScoreByNameSlice

const char *
DkimEnum_lookupScoreByValue(DkimBaseScore value)
{
    return KeywordMap_lookupByValue(dkim_score_table, value);
}   // end function: DkimEnum_lookupScoreByValue

////////////////////////////////////////////////////////////

DkimAdspScore
DkimEnum_lookupAdspScoreByName(const char *keyword)
{
    return (DkimAdspScore) KeywordMap_lookupByCaseString(dkim_adsp_score_table, keyword);
}   // end function: DkimEnum_lookupAdspScoreByName

DkimAdspScore
DkimEnum_lookupAdspScoreByNameSlice(const char *head, const char *tail)
{
    return (DkimAdspScore) KeywordMap_lookupByCaseStringSlice(dkim_adsp_score_table, head, tail);
}   // end function: DkimEnum_lookupAdspScoreByNameSlice

const char *
DkimEnum_lookupAdspScoreByValue(DkimAdspScore value)
{
    return KeywordMap_lookupByValue(dkim_adsp_score_table, value);
}   // end function: DkimEnum_lookupAdspScoreByValue

////////////////////////////////////////////////////////////

typedef struct DkimStatusMap {
    DkimStatus code;
    const char *string;
} DkimStatusMap;

#define CODE2STRMAP(s) {s, #s}

static const DkimStatusMap dstat_code_table[] = {
#include "dstat.map"
    {0, NULL},
};

static const char *
DkimEnum_lookupDkimStatByValue(DkimStatus value)
{
    const DkimStatusMap *p;
    for (p = dstat_code_table; NULL != p->string; ++p) {
        if (p->code == value) {
            return p->string;
        }   // end if
    }   // end for
    return NULL;
}   // end function: DkimEnum_lookupDkimStatByValue

extern const char *
DKIM_strerror(DkimStatus code)
{
    const char *errstr = DkimEnum_lookupDkimStatByValue(code);
    return NULL != errstr ? errstr : "unexpected dkim status";
}   // end function: DKIM_strerror

////////////////////////////////////////////////////////////
