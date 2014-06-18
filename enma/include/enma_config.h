/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_config.h 1371 2011-11-07 03:18:02Z takahiko $
 */

#ifndef __ENMA_CONFIG_H__
#define __ENMA_CONFIG_H__

#include <sys/types.h>
#include <assert.h>
#include <stdbool.h>

#include "ipaddressrange.h"

typedef struct EnmaConfig {
    // milter
    int milter_verbose;         //boolean
    char *milter_conffile;
    char *milter_socket;
    const char *milter_user;
    const char *milter_pidfile;
    const char *milter_chdir;
    int milter_timeout;
    int milter_loglevel;
    int milter_sendmail813;     //boolean
    int milter_postfix;         //boolean
    // syslog
    const char *syslog_ident;
    int syslog_facility;
    int syslog_logmask;
    // common
    IPAddressRangeList *common_exclusion_addresses;
    // sender authentication
    int spf_auth;               //boolean
    int spf_explog;             //boolean
    int sidf_auth;              //boolean
    int sidf_explog;            //boolean
    int dkim_auth;              //boolean
    int dkim_signheader_limit;
    int dkim_accept_expired_signature;  //boolean
    int dkim_rfc4871_compatible;    //boolean
    int dkimadsp_auth;          //boolean
    // authentication-results
    const char *authresult_identifier;
} EnmaConfig;

extern bool EnmaConfig_setConfig(EnmaConfig *self, int argc, char **argv);
extern EnmaConfig *EnmaConfig_new(void);
extern void EnmaConfig_free(EnmaConfig *self);

#endif
