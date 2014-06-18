/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: pstring.h 1144 2009-08-29 18:07:12Z takahiko $
 */

#ifndef __PSTRING_H__
#define __PSTRING_H__

extern char *strpdup(const char *head, const char *tail);
extern char *strpchr(const char *head, const char *tail, char c);
extern char *strprchr(const char *head, const char *tail, char c);
extern unsigned long long strptoull(const char *head, const char *tail, const char **endptr);
extern unsigned long strptoul(const char *head, const char *tail, const char **endptr);

#endif /* __PSTRING_H__ */
