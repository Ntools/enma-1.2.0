/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: loghandler.c 753 2009-03-16 02:20:56Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: loghandler.c 753 2009-03-16 02:20:56Z takahiko $");

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <pthread.h>

#include "loghandler.h"

// LogHandler_init() を1度しか呼ばせないために
static pthread_once_t LogHandler_init_once = PTHREAD_ONCE_INIT;

// ログの先頭に付ける文字列を格納するためのスレッドローカルストレージ
static pthread_key_t LogHandler_prefix_key;

#define LOG_BUFFER_SIZE 1024

static void
LogHandler_initImpl(void)
{
    pthread_key_create(&LogHandler_prefix_key, free);
}   // end function : LogHandler_initImpl

void
LogHandler_init(void)
{
    pthread_once(&LogHandler_init_once, LogHandler_initImpl);
}   // end function : LogHandler_init

/**
 * @attention LogHandler_init() をよんでいない場合の動作は未定義
 */
void
LogHandler_cleanup(void)
{
    pthread_key_delete(LogHandler_prefix_key);
}   // end function : LogHandler_cleanup

/**
 * @attention LogHandler_init() をよんでいない場合の動作は未定義
 */
bool
LogHandler_setPrefix(const char *prefix)
{
    // 新しい prefix のメモリを確保
    char *new_prefix;
    if (NULL != prefix) {
        new_prefix = strdup(prefix);
        if (NULL == new_prefix) {
            return false;
        }   // end if
    } else {
        new_prefix = NULL;
    }   // end if

    // 古い prefix を取得
    char *old_prefix = pthread_getspecific(LogHandler_prefix_key);

    // 新しい prefix を設定
    if (0 != pthread_setspecific(LogHandler_prefix_key, new_prefix)) {
        free(new_prefix);
    }   // end if

    // pthread_setspecific の成功を確認してから古い prefix を解放
    if (NULL != old_prefix) {
        free(old_prefix);
    }   // end if

    return true;
}   // end function : LogHandler_setPrefix

/**
 * @attention LogHandler_init() をよんでいない場合の動作は未定義
 */
const char *
LogHandler_getPrefix(void)
{
    const char *prefix = pthread_getspecific(LogHandler_prefix_key);
    return prefix ? prefix : "-";
}   // end function : LogHandler_getPrefix

void
LogHandler_syslog(int priority, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsyslog(priority, format, args);
    va_end(args);
}   // end function : LogHandler_syslog

/**
 * @attention prefix がセットされている場合 LOG_BUFFER_SIZE を超えるバイト数を出力できない
 */
void
LogHandler_syslogWithPrefix(int priority, const char *format, ...)
{
    const char *prefix = pthread_getspecific(LogHandler_prefix_key);

    va_list args;
    va_start(args, format);
    if (NULL != prefix) {
        char buffer[LOG_BUFFER_SIZE];
        vsnprintf(buffer, sizeof(buffer), format, args);
        syslog(priority, "[%s] %s", prefix, buffer);
    } else {
        vsyslog(priority, format, args);
    }   // end if
    va_end(args);
}   // end function : LogHandler_syslogWithPrefix
