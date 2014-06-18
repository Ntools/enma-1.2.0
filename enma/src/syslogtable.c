/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: syslogtable.c 579 2009-01-12 16:19:17Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: syslogtable.c 579 2009-01-12 16:19:17Z takahiko $");

#include <string.h>
#include <strings.h>
#include <syslog.h>

#include "keywordmap.h"

///  文字列と syslog facility 値の対応を表すマップ
static const KeywordMap facilitytbl[] = {
// generic facilities
    {"KERN", LOG_KERN},
    {"USER", LOG_USER},
    {"MAIL", LOG_MAIL},
    {"DAEMON", LOG_DAEMON},
    {"AUTH", LOG_AUTH},
    {"SYSLOG", LOG_SYSLOG},
    {"LPR", LOG_LPR},
    {"NEWS", LOG_NEWS},
    {"UUCP", LOG_UUCP},
    {"CRON", LOG_CRON},
    {"LOCAL0", LOG_LOCAL0},
    {"LOCAL1", LOG_LOCAL1},
    {"LOCAL2", LOG_LOCAL2},
    {"LOCAL3", LOG_LOCAL3},
    {"LOCAL4", LOG_LOCAL4},
    {"LOCAL5", LOG_LOCAL5},
    {"LOCAL6", LOG_LOCAL6},
    {"LOCAL7", LOG_LOCAL7},

// FreeBSD
#ifdef LOG_AUTHPRIV
    {"AUTHPRIV", LOG_AUTHPRIV},
#endif

#ifdef LOG_FTP
    {"FTP", LOG_FTP},
#endif

#ifdef LOG_NTP
    {"NTP", LOG_NTP},
#endif

#ifdef LOG_SECURITY
    {"SECURITY", LOG_SECURITY},
#endif

#ifdef LOG_CONSOLE
    {"CONSOLE", LOG_CONSOLE},
#endif

// Solaris
#ifdef LOG_AUDIT
    {"AUDIT", LOG_AUDIT},
#endif

    {NULL, -1}, // sentinel
};

///  文字列と syslog log-level 値の対応を表すマップ
static const KeywordMap prioritytbl[] = {
    {"EMERG", LOG_EMERG},
    {"ALERT", LOG_ALERT},
    {"CRIT", LOG_CRIT},
    {"ERR", LOG_ERR},
    {"WARNING", LOG_WARNING},
    {"NOTICE", LOG_NOTICE},
    {"INFO", LOG_INFO},
    {"DEBUG", LOG_DEBUG},
    {NULL, -1}, // sentinel
};


/**
 * syslog facility の名前から定数を引く
 *
 * @param facility_name
 * @return	指定された文字列に対応する facility の定数
 */
int
lookup_facility_const(const char *facility_name)
{
    return KeywordMap_lookupByCaseString(facilitytbl, facility_name);
}


/**
 * syslog facility の定数から名前を引く
 *
 * @param facility_const
 * @return	指定された定数に対応する facility の文字列
 */
const char *
lookup_facility_name(const int facility_const)
{
    return KeywordMap_lookupByValue(facilitytbl, facility_const);
}


/**
 * syslog priority の名前から定数を引く
 *
 * @param priority_name
 * @return	指定された文字列に対応する priority の定数
 */
int
lookup_priority_const(const char *priority_name)
{
    return KeywordMap_lookupByCaseString(prioritytbl, priority_name);
}


/**
 * syslog priority の名前から定数を引く
 *
 * @param priority_const
 * @return	指定された定数に対応する priority の文字列
 */
const char *
lookup_priority_name(const int priority_const)
{
    return KeywordMap_lookupByValue(prioritytbl, priority_const);
}
