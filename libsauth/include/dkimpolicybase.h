/*
 * Copyright (c) 2009-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimpolicybase.h 1368 2011-11-07 02:09:09Z takahiko $
 */

#ifndef __DKIM_POLICYBASE_H__
#define __DKIM_POLICYBASE_H__

#include <stdbool.h>
#include "strarray.h"

#define DkimPolicyBase_MEMBER           \
    bool suppose_leadeing_header_space; \
    bool rfc4871_compatible;            \
    StrArray *author_priority;          \
    void (*logger) (int priority, const char *message, ...)

struct DkimPolicyBase {
    DkimPolicyBase_MEMBER;
};

extern void DkimPolicyBase_init(DkimPolicyBase *self);
extern void DkimPolicyBase_cleanup(DkimPolicyBase *self);

#endif /* __DKIM_POLICYBASE_H__ */
