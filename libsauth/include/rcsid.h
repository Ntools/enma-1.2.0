/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: rcsid.h 579 2009-01-12 16:19:17Z takahiko $
 */

#ifndef __RCSID_H__
#define __RCSID_H__

#undef RCSID

#if defined(__GNUC__) && (__GNUC__ > 2)
# define RCSID(x) static const char __attribute__((used)) rcsid[] = x
#else
# define RCSID(x) static const char rcsid[] = x
#endif

#endif /* __RCSID_H__ */
