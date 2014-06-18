/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimlogger.h 1168 2009-09-02 12:30:56Z takahiko $
 */

#ifndef __DKIMLOGGER_H__
#define __DKIMLOGGER_H__

#include <syslog.h>

#define DkimLogHandler_log(__dkimpolicy, __priority, __format, ...) \
	(__dkimpolicy)->logger((__priority), __format, ##__VA_ARGS__)

#define DkimLogHandler_logWithLineInfo(__dkimpolicy, __priority, __format, ...) \
	(__dkimpolicy)->logger((__priority), "%s: %d %s(): " __format, __FILE__, __LINE__, __func__, ##__VA_ARGS__)


#define DkimLogDebug(__dkimpolicy, __format, ...) \
	DkimLogHandler_logWithLineInfo(__dkimpolicy, LOG_DEBUG, __format, ##__VA_ARGS__)

#define DkimLogInfo(__dkimpolicy, __format, ...) \
	DkimLogHandler_log(__dkimpolicy, LOG_INFO, __format, ##__VA_ARGS__)

#define DkimLogNotice(__dkimpolicy, __format, ...) \
	DkimLogHandler_log(__dkimpolicy, LOG_NOTICE, __format, ##__VA_ARGS__)

#define DkimLogWarning(__dkimpolicy, __format, ...) \
	DkimLogHandler_logWithLineInfo(__dkimpolicy, LOG_WARNING, __format, ##__VA_ARGS__)

#define DkimLogError(__dkimpolicy, __format, ...) \
	DkimLogHandler_logWithLineInfo(__dkimpolicy, LOG_ERR, __format, ##__VA_ARGS__)


#define DkimLogEvent(event, __format, ...) \
	DkimLogInfo(__dkimpolicy, "[" event "] " __format, ##__VA_ARGS__)

#define DkimLogNoResource(__dkimpolicy) \
	DkimLogError(__dkimpolicy, "memory allocation failed")

#define DkimLogImplError(__dkimpolicy, __format, ...) \
	DkimLogError(__dkimpolicy, __format, ##__VA_ARGS__)

#define DkimLogSysError(__dkimpolicy, __format, ...) \
	DkimLogError(__dkimpolicy, __format, ##__VA_ARGS__)

#define DkimLogConfigError(__dkimpolicy, __format, ...) \
	DkimLogError(__dkimpolicy, __format, ##__VA_ARGS__)

#define DkimLogPermFail(__dkimpolicy, __format, ...) \
	DkimLogInfo(__dkimpolicy, __format, ##__VA_ARGS__)

#define DkimLogParseTrace(__format, ...) \
    // fprintf(stderr, __format, ##__VA_ARGS__)

#endif /* __DKIMLOGGER_H__ */
