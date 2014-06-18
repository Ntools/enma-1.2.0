/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfmacro.h 579 2009-01-12 16:19:17Z takahiko $
 */

#ifndef __SIDFMACRO_H__
#define __SIDFMACRO_H__

#include "xbuffer.h"
#include "sidf.h"
#include "sidfrecord.h"

extern SidfStat SidfMacro_parseDomainSpec(const SidfRequest *request, const char *head,
                                          const char *tail, const char **nextp, XBuffer *xbuf);
extern SidfStat SidfMacro_parseExplainString(const SidfRequest *request, const char *head,
                                             const char *tail, const char **nextp, XBuffer *xbuf);

#endif /* __SIDFMACRO_H__ */
