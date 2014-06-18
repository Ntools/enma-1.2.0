/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: daemonize.h 579 2009-01-12 16:19:17Z takahiko $
 */

#ifndef __DAEMONIZE_H__
#define __DAEMONIZE_H__

#include <stdbool.h>

bool daemonize_init(const char *username, const char *chdirpath, const char *pidfile);
bool daemonize_finally(const char *pidfile);

#endif
