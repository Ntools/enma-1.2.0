/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: string_util.h 1462 2011-12-21 11:55:05Z takahiko $
 */

#ifndef __STRING_UTIL_H__
#define __STRING_UTIL_H__

#include <stdbool.h>

extern long int strtolstrict(const char *string, bool *errflag);
extern char *strlstrip(char *string);
extern char *strrstrip(char *string);
extern char *strstrip(char *string);

#endif /* __STRING_UTIL_H__ */
