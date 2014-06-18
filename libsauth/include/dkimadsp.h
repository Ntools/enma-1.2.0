/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimadsp.h 1144 2009-08-29 18:07:12Z takahiko $
 */

#ifndef __DKIM_ADSP_H__
#define __DKIM_ADSP_H__

#include <stdbool.h>
#include "dnsresolv.h"
#include "dkim.h"

typedef struct DkimAdsp DkimAdsp;

extern DkimAdsp *DkimAdsp_build(const DkimPolicyBase *policy, const char *keyval,
                                DkimStatus *dstat);
extern DkimAdsp *DkimAdsp_lookup(const DkimPolicyBase *policy, const char *policydomain,
                                 DnsResolver *resolver, DkimStatus *dstat);
extern void DkimAdsp_free(DkimAdsp *self);
extern DkimAdspPractice DkimAdsp_getPractice(const DkimAdsp *self);

#endif /* __DKIM_ADSP_H__ */
