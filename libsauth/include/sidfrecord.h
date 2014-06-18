/*
 * Copyright (c) 2007-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfrecord.h 1144 2009-08-29 18:07:12Z takahiko $
 */

#ifndef __SIDFRECORD_H__
#define __SIDFRECORD_H__

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ptrarray.h"
#include "xbuffer.h"
#include "sidf.h"
#include "sidfenum.h"
#include "sidfrequest.h"

typedef enum SidfTermCidrOption {
    SIDF_TERM_CIDR_OPTION_NONE,
    SIDF_TERM_CIDR_OPTION_IP4,
    SIDF_TERM_CIDR_OPTION_IP6,
    SIDF_TERM_CIDR_OPTION_DUAL
} SidfTermCidrOption;

typedef struct SidfTermAttribute {
    const char *name;
    SidfTermType type;
    bool is_mechanism;
    SidfTermParamType param_type;
    bool involve_dnslookup;
    const char parameter_delimiter;
    bool required_parameter;
    SidfTermCidrOption cidr;
} SidfTermAttribute;

typedef struct SidfTerm {
    SidfQualifier qualifier;
    const SidfTermAttribute *attr;
    unsigned short ip4cidr;
    unsigned short ip6cidr;
    union {
        struct in_addr addr4;
        struct in6_addr addr6;
        char *domain;
    } param;
    // DNS query を投げるための 253 文字以下に丸めたドメイン.
    // param.domain 内のどこかへの参照を保持し, 通常は先頭を指す.
    // RFC4408 (8.1.) defines this as 253. DO NOT TOUCH NORMALLY.
    const char *querydomain;
} SidfTerm;

typedef struct SidfRecord {
    // マクロを展開してから保持する選択をしたので, リクエストに依存するのは避けられない
    const SidfRequest *request;
    SidfRecordScope scope;
    const char *domain;
    PtrArray *directives;
    struct spf_modifiers {
        SidfTerm *rediect;
        SidfTerm *exp;
    } modifiers;
    // PtrArray *modifiers;
} SidfRecord;

extern SidfStat SidfRecord_build(const SidfRequest *request, SidfRecordScope scope,
                                 const char *record_head, const char *record_tail,
                                 SidfRecord **recordobj);
extern void SidfRecord_free(SidfRecord *self);
extern SidfStat SidfRecord_getSidfScope(const SidfRequest *request, const char *record_head,
                                        const char *record_tail, SidfRecordScope *scope,
                                        const char **scope_tail);

#endif /* __SIDFRECORD_H__ */
