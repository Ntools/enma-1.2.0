/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidflogger.h 583 2009-01-17 19:02:45Z takahiko $
 */

#ifndef __SIDFLOGGER_H__
#define __SIDFLOGGER_H__

#include <syslog.h>

#define SidfLogHandler_log(__sidfpolicy, __priority, __format, ...) \
	(__sidfpolicy)->logger((__priority), __format, ##__VA_ARGS__)

#define SidfLogHandler_logWithLineInfo(__sidfpolicy, __priority, __format, ...) \
	(__sidfpolicy)->logger((__priority), "%s: %d %s(): " __format, __FILE__, __LINE__, __func__, ##__VA_ARGS__)


#define SidfLogDebug(__sidfpolicy, __format, ...) \
	SidfLogHandler_logWithLineInfo(__sidfpolicy, LOG_DEBUG, __format, ##__VA_ARGS__)

#define SidfLogInfo(__sidfpolicy, __format, ...) \
	SidfLogHandler_log(__sidfpolicy, LOG_INFO, __format, ##__VA_ARGS__)

#define SidfLogNotice(__sidfpolicy, __format, ...) \
	SidfLogHandler_log(__sidfpolicy, LOG_NOTICE, __format, ##__VA_ARGS__)

#define SidfLogWarning(__sidfpolicy, __format, ...) \
	SidfLogHandler_logWithLineInfo(__sidfpolicy, LOG_WARNING, __format, ##__VA_ARGS__)

#define SidfLogError(__sidfpolicy, __format, ...) \
	SidfLogHandler_logWithLineInfo(__sidfpolicy, LOG_ERR, __format, ##__VA_ARGS__)


#define SidfLogEvent(event, __format, ...) \
	SidfLogInfo(__sidfpolicy, "[" event "] " __format, ##__VA_ARGS__)

#define SidfLogNoResource(__sidfpolicy) \
	SidfLogError(__sidfpolicy, "memory allocation failed")

#define SidfLogImplError(__sidfpolicy, __format, ...) \
	SidfLogError(__sidfpolicy, __format, ##__VA_ARGS__)

#define SidfLogSysError(__sidfpolicy, __format, ...) \
	SidfLogError(__sidfpolicy, __format, ##__VA_ARGS__)

#define SidfLogConfigError(__sidfpolicy, __format, ...) \
	SidfLogError(__sidfpolicy, __format, ##__VA_ARGS__)

#define SidfLogPermFail(__sidfpolicy, __format, ...) \
	SidfLogInfo(__sidfpolicy, __format, ##__VA_ARGS__)

#define SidfLogDnsError(__sidfpolicy, __format, ...) \
	SidfLogInfo(__sidfpolicy, __format, ##__VA_ARGS__)

#define SidfLogParseTrace(__format, ...) \
    // fprintf(stderr, __format, ##__VA_ARGS__)

#endif /* __SIDFLOGGER_H__ */
