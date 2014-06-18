/*
 * Copyright (c) 2009-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimpolicybase.c 1370 2011-11-07 02:58:25Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimpolicybase.c 1370 2011-11-07 02:58:25Z takahiko $");

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>
#include "strarray.h"
#include "dkim.h"
#include "dkimlogger.h"
#include "dkimpolicybase.h"

void
DkimPolicyBase_init(DkimPolicyBase *self)
{
    self->suppose_leadeing_header_space = false;
    self->rfc4871_compatible = false;
    self->author_priority = NULL;
    self->logger = syslog;
}   // end function: DkimPolicyBase_init

void
DkimPolicyBase_cleanup(DkimPolicyBase *self)
{
    if (NULL != self->author_priority) {
        StrArray_free(self->author_priority);
    }   // end if
}   // end function: DkimPolicyBase_cleanup

void
DkimPolicyBase_setLogger(DkimPolicyBase *self,
                         void (*logger) (int priority, const char *message, ...))
{
    self->logger = logger;
}   // end function: DkimPolicyBase_setLogger

void
DkimPolicyBase_supposeLeadingHeaderValueSpace(DkimPolicyBase *self, bool flag)
{
    self->suppose_leadeing_header_space = flag;
}   // end function: DkimPolicyBase_supposeLeadingHeaderValueSpace

/**
 * enable/disable RFC4871-compatible mode.
 * Disabled by default (which means RFC6376-compliant).
 * @param enable true to enable RFC4871 compatible mode, false to disable.
 */
void
DkimPolicyBase_getRfc4871Compatible(DkimPolicyBase *self, bool enable)
{
    assert(NULL != self);
    self->rfc4871_compatible = enable;
}   // end function: DkimPolicyBase_getRfc4871Compatible

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimPolicyBase_setAuthorPriority(DkimPolicyBase *self, const char *record, const char *delim)
{
    assert(NULL != self);

    if (NULL == record) {
        DkimLogConfigError(self, "empty value specified for author extraction priority");
        return DSTAT_CFGERR_EMPTY_VALUE;
    }   // end if

    if (NULL != self->author_priority) {
        // release if already set
        StrArray_free(self->author_priority);
    }   // end if
    self->author_priority = StrArray_split(record, delim, true);
    if (NULL == self->author_priority) {
        DkimLogNoResource(self);
        return DSTAT_SYSERR_NORESOURCE;
    }   // end if
    return DSTAT_OK;
}   // end function: DkimPolicyBase_setAuthorPriority
