/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: strtokarray.h 1144 2009-08-29 18:07:12Z takahiko $
 */

#ifndef __STRTOKARRAY_H__
#define __STRTOKARRAY_H__

extern size_t strccount(const char *s, char c);
extern char **strtokarray(char *s, char sep);

#endif /* __STRTOKARRAY_H__ */
