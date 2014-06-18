/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimwildcard.h 1368 2011-11-07 02:09:09Z takahiko $
 */

#ifndef __DKIM_WILDCARD_H__
#define __DKIM_WILDCARD_H__

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdbool.h>

extern bool DkimWildcard_matchPubkeyGranularity(const char *patternhead, const char *patterntail,
                                                const char *inputhead, const char *inputtail);

#endif /* __DKIM_WILDCARD_H__ */
