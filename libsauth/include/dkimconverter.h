/*
 * Copyright (c) 2006-2010 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimconverter.h 1366 2011-10-16 08:13:40Z takahiko $
 */

#ifndef __DKIM_CONVERTER_H__
#define __DKIM_CONVERTER_H__

#include "xbuffer.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimpolicybase.h"

extern XBuffer *DkimConverter_decodeBase64(const DkimPolicyBase *policy, const char *head,
                                           const char *tail, const char **nextp, DkimStatus *dstat);
extern XBuffer *DkimConverter_encodeBase64(const DkimPolicyBase *policy, const void *s, size_t size,
                                           DkimStatus *dstat);
extern XBuffer *DkimConverter_encodeLocalpartToDkimQuotedPrintable(const DkimPolicyBase *policy,
                                                                   const void *s, size_t size,
                                                                   DkimStatus *dstat);
extern long long DkimConverter_longlong(const char *head, const char *tail, unsigned int digits,
                                        const char **nextp);

#endif /* __DKIM_CONVERTER_H__ */
