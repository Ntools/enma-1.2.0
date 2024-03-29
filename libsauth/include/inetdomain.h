/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: inetdomain.h 1144 2009-08-29 18:07:12Z takahiko $
 */

#ifndef __INET_DOMAIN_H__
#define __INET_DOMAIN_H__

#include <sys/types.h>
#include <stdbool.h>

extern const char *InetDomain_parent(const char *domain, size_t depth);
extern const char *InetDomain_upward(const char *domain);
extern bool InetDomain_isParent(const char *parent, const char *child);
extern bool InetDomain_equals(const char *domain1, const char *domain2);

#endif /* __INET_DOMAIN_H__ */
