/*
 * Copyright (c) 2007-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidf.h 1161 2009-08-31 09:11:48Z takahiko $
 */

#ifndef __SIDF_H__
#define __SIDF_H__

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "inetmailbox.h"
#include "mailheaders.h"
#include "dnsresolv.h"

#ifdef  __cplusplus
extern "C" {
#endif

typedef enum SidfStat {
    SIDF_STAT_OK = 0,
    SIDF_STAT_NO_RESOURCE,
    SIDF_STAT_RECORD_VERSION_MISMATCH,
    SIDF_STAT_RECORD_UNSUPPORTED_MECHANISM,
    SIDF_STAT_RECORD_UNSUPPORTED_MODIFIER,
    SIDF_STAT_RECORD_UNSUPPORTED_QUALIFIER,
    SIDF_STAT_RECORD_UNSUPPORTED_MACRO,
    SIDF_STAT_RECORD_DELIMITER_DUPLICATED,
    SIDF_STAT_RECORD_SYNTAX_VIOLATION,  // syntax violation that causes errors
    SIDF_STAT_RECORD_NOT_MATCH, // status which is not an error but does not satisfy the syntax (internal use)
    SIDF_STAT_RECORD_INVALID_CIDR_LENGTH,
    SIDF_STAT_MALICIOUS_MACRO_EXPANSION,
    SIDF_STAT_DNS_NO_DATA,
    SIDF_STAT_DNS_HOST_NOT_FOUND,
    SIDF_STAT_DNS_TRY_AGAIN,
    SIDF_STAT_DNS_NO_RECOVERY,
} SidfStat;

typedef enum SidfRecordScope {
    SIDF_RECORD_SCOPE_NULL = 0x0000,
    SIDF_RECORD_SCOPE_SPF1 = 0x0001,
    SIDF_RECORD_SCOPE_SPF2_MFROM = 0x0002,
    SIDF_RECORD_SCOPE_SPF2_PRA = 0x0004,
    SIDF_RECORD_SCOPE_UNKNOWN = 0x0008,
} SidfRecordScope;

typedef enum SidfScore {
    SIDF_SCORE_NULL = 0,
    SIDF_SCORE_NONE,
    SIDF_SCORE_NEUTRAL,
    SIDF_SCORE_PASS,
    SIDF_SCORE_POLICY,
    SIDF_SCORE_HARDFAIL,
    SIDF_SCORE_SOFTFAIL,
    SIDF_SCORE_TEMPERROR,
    SIDF_SCORE_PERMERROR,
    SIDF_SCORE_SYSERROR,    // mostly equals to memory allocation error
    SIDF_SCORE_MAX, // the number of SidfScore enumeration constants
} SidfScore;

typedef enum SidfCustomAction {
    SIDF_CUSTOM_ACTION_NULL = 0,
    SIDF_CUSTOM_ACTION_SCORE_NONE = SIDF_SCORE_NONE,
    SIDF_CUSTOM_ACTION_SCORE_NEUTRAL = SIDF_SCORE_NEUTRAL,
    SIDF_CUSTOM_ACTION_SCORE_PASS = SIDF_SCORE_PASS,
    SIDF_CUSTOM_ACTION_SCORE_POLICY = SIDF_SCORE_POLICY,
    SIDF_CUSTOM_ACTION_SCORE_HARDFAIL = SIDF_SCORE_HARDFAIL,
    SIDF_CUSTOM_ACTION_SCORE_SOFTFAIL = SIDF_SCORE_SOFTFAIL,
    SIDF_CUSTOM_ACTION_SCORE_TEMPERROR = SIDF_SCORE_TEMPERROR,
    SIDF_CUSTOM_ACTION_SCORE_PERMERROR = SIDF_SCORE_PERMERROR,
    SIDF_CUSTOM_ACTION_LOGGING,
} SidfCustomAction;

typedef struct SidfPolicy SidfPolicy;
typedef struct SidfRequest SidfRequest;

// SidfPolicy
extern SidfPolicy *SidfPolicy_new(void);
extern void SidfPolicy_free(SidfPolicy *self);
extern void SidfPolicy_setSpfRRLookup(SidfPolicy *self, bool flag);
extern SidfStat SidfPolicy_setCheckingDomain(SidfPolicy *self, const char *domain);
extern SidfStat SidfPolicy_setLocalPolicyDirectives(SidfPolicy *self, const char *policy);
extern SidfStat SidfPolicy_setLocalPolicyExplanation(SidfPolicy *self, const char *explanation);
extern void SidfPolicy_setLogger(SidfPolicy *self,
                                 void (*logger) (int priority, const char *message, ...));
extern void SidfPolicy_setExplanationLookup(SidfPolicy *self, bool flag);

// SidfRequest
extern SidfRequest *SidfRequest_new(const SidfPolicy *policy, DnsResolver *resolver);
extern void SidfRequest_reset(SidfRequest *self);
extern void SidfRequest_free(SidfRequest *self);
extern bool SidfRequest_isSenderContext(const SidfRequest *self);
extern const char *SidfRequest_getExplanation(const SidfRequest *self);
extern SidfScore SidfRequest_eval(SidfRequest *self, SidfRecordScope scope);
extern bool SidfRequest_setSender(SidfRequest *self, const InetMailbox *sender);
extern bool SidfRequest_setHeloDomain(SidfRequest *self, const char *domain);
extern bool SidfRequest_setIpAddr(SidfRequest *self, sa_family_t sa_family,
                                  const struct sockaddr *addr);
extern bool SidfRequest_setIpAddrString(SidfRequest *self, sa_family_t sa_family,
                                        const char *address);

// SidfEnum
extern SidfScore SidfEnum_lookupScoreByKeyword(const char *keyword);
extern SidfScore SidfEnum_lookupScoreByKeywordSlice(const char *head, const char *tail);
extern const char *SidfEnum_lookupScoreByValue(SidfScore value);

// SidfPra
extern bool SidfPra_extract(const SidfPolicy *policy, const MailHeaders *headers,
                            int *pra_index, InetMailbox **pra_mailbox);

#ifdef __cplusplus
}
#endif

#endif /* __SIDF_H__ */
