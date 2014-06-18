/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfpolicy.c 1343 2011-07-30 19:21:50Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfpolicy.c 1343 2011-07-30 19:21:50Z takahiko $");

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <syslog.h>

#include "sidf.h"
#include "sidfpolicy.h"

#define SIDF_POLICY_DEFAULT_MACRO_EXPANSION_LIMIT 10240
#define SIDF_EVAL_MAX_DNSMECH 10
#define SIDF_EVAL_MXMECH_MXRR_MAXNUM 10
#define SIDF_EVAL_PTRMECH_PTRRR_MAXNUM 10
#define SIDF_REQUEST_LABEL_MAX_LENGTH 63

/**
 * create SidfPolicy object
 * @return initialized SidfPolicy object, or NULL if memory allocation failed.
 */
SidfPolicy *
SidfPolicy_new(void)
{
    SidfPolicy *self = (SidfPolicy *) malloc(sizeof(SidfPolicy));
    if (NULL == self) {
        return NULL;
    }   // end if
    self->lookup_spf_rr = true;
    self->lookup_exp = false;
    self->checking_domain = NULL;
    self->local_policy = NULL;
    self->local_policy_explanation = NULL;
    self->macro_expansion_limit = SIDF_POLICY_DEFAULT_MACRO_EXPANSION_LIMIT;
    self->max_dns_mech = SIDF_EVAL_MAX_DNSMECH;
    self->max_label_len = SIDF_REQUEST_LABEL_MAX_LENGTH;
    self->max_mxrr_per_mxmech = SIDF_EVAL_MXMECH_MXRR_MAXNUM;
    self->max_ptrrr_per_ptrmech = SIDF_EVAL_PTRMECH_PTRRR_MAXNUM;
    self->overwrite_all_directive_score = SIDF_SCORE_NULL;
    self->action_on_plus_all_directive = SIDF_CUSTOM_ACTION_NULL;
    self->action_on_malicious_ip4_cidr_length = SIDF_CUSTOM_ACTION_NULL;
    self->malicious_ip4_cidr_length = 0;
    self->action_on_malicious_ip6_cidr_length = SIDF_CUSTOM_ACTION_NULL;
    self->malicious_ip6_cidr_length = 0;
    self->logger = syslog;
    return self;
}   // end function: SidfPolicy_new

void
SidfPolicy_setSpfRRLookup(SidfPolicy *self, bool flag)
{
    self->lookup_spf_rr = flag;
}   // end function: SidfPolicy_setSpfRRLookup

static SidfStat
SidfPolicy_replaceString(const char *src, char **pdest)
{
    char *new = NULL;
    if (NULL != src && NULL == (new = strdup(src))) {
        return SIDF_STAT_NO_RESOURCE;
    }   // end if
    free(*pdest);
    *pdest = new;
    return SIDF_STAT_OK;
}   // end function: SidfPolicy_replaceString

/**
 * %{r} macro of SPF record
 */
SidfStat
SidfPolicy_setCheckingDomain(SidfPolicy *self, const char *domain)
{
    return SidfPolicy_replaceString(domain, &(self->checking_domain));
}   // end function: SidfPolicy_setCheckingDomain

SidfStat
SidfPolicy_setLocalPolicyDirectives(SidfPolicy *self, const char *policy)
{
    return SidfPolicy_replaceString(policy, &(self->local_policy));
}   // end function: SidfPolicy_setLocalPolicyDirectives

SidfStat
SidfPolicy_setLocalPolicyExplanation(SidfPolicy *self, const char *explanation)
{
    return SidfPolicy_replaceString(explanation, &(self->local_policy_explanation));
}   // end function: SidfPolicy_setLocalPolicyExplanation

void
SidfPolicy_setLogger(SidfPolicy *self, void (*logger) (int priority, const char *message, ...))
{
    self->logger = logger;
}   // end function: SidfPolicy_setLogger

void
SidfPolicy_setExplanationLookup(SidfPolicy *self, bool flag)
{
    self->lookup_exp = flag;
}   // end function: SidfPolicy_setExplanationLogging

/**
 * release SidfPolicy object
 * @param self SidfPolicy object to release
 */
void
SidfPolicy_free(SidfPolicy *self)
{
    assert(NULL != self);
    if (NULL != self->checking_domain) {
        free(self->checking_domain);
    }   // end if
    if (NULL != self->local_policy) {
        free(self->local_policy);
    }   // end if
    if (NULL != self->local_policy_explanation) {
        free(self->local_policy_explanation);
    }   // end if
    free(self);
}   // end function: SidfPolicy_free
