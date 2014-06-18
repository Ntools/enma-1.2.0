/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma.c 1371 2011-11-07 03:18:02Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma.c 1371 2011-11-07 03:18:02Z takahiko $");

#include <stdio.h>
#include <assert.h>
#include <sysexits.h>
#include <stdlib.h>
#include <syslog.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <libmilter/mfapi.h>

#include "loghandler.h"
#include "sidf.h"
#include "dkim.h"

#include "cryptomutex.h"
#include "consolehandler.h"
#include "enma_config.h"
#include "enma_mfi.h"
#include "daemonize.h"
#include "enma.h"


/* definition of global variable */
SidfPolicy *g_sidf_policy = NULL;   // sidf policy variable
DkimVerificationPolicy *g_dkim_vpolicy = NULL;  // dkim verify policy variable
EnmaConfig *g_enma_config = NULL;   // configuration variable of ENMA


/**
 * usage of ENMA
 *
 * @param out
 */
static void
enma_usage(FILE *out)
{
    fprintf(out, "Usage:\n");
    fprintf(out, "\tenma [options] [conffile]\n");
    fflush(out);
}


/**
 * initialize configuration
 *
 * @param argc
 * @param argv
 * @return
 */
static int
config_init(int argc, char **argv)
{
    g_enma_config = EnmaConfig_new();
    if (NULL == g_enma_config) {
        return EX_OSERR;
    }

    if (!EnmaConfig_setConfig(g_enma_config, argc, argv)) {
        EnmaConfig_free(g_enma_config);
        enma_usage(stderr);
        return EX_USAGE;
    }

    return 0;
}


/**
 * initialize SIDF policy
 *
 * @param enma_config
 * @return
 */
static SidfPolicy *
sidf_init(const EnmaConfig *enma_config)
{
    SidfPolicy *sidf_policy = SidfPolicy_new();
    if (NULL == sidf_policy) {
        return NULL;
    }
    SidfPolicy_setSpfRRLookup(sidf_policy, false);
    SidfPolicy_setExplanationLookup(sidf_policy, false);
    SidfPolicy_setLogger(sidf_policy, LogHandler_syslogWithPrefix);

    if (SIDF_STAT_OK !=
        SidfPolicy_setCheckingDomain(sidf_policy, enma_config->authresult_identifier)) {
        return NULL;
    }

    return sidf_policy;
}

/**
 * initialize DKIM policy
 *
 * @param *enma_config
 * @return
 */
static DkimVerificationPolicy *
dkim_init(const EnmaConfig *enma_config)
{
    DkimStatus set_stat;

    DkimVerificationPolicy *dkim_vpolicy = DkimVerificationPolicy_new();
    if (NULL == dkim_vpolicy) {
        return NULL;
    }   // end if

    set_stat = DkimVerificationPolicy_setAuthorPriority(dkim_vpolicy, "From", ":");
    if (DSTAT_OK != set_stat) {
        return NULL;
    }   // end if

    DkimVerificationPolicy_setSignHeaderLimit(dkim_vpolicy, enma_config->dkim_signheader_limit);
    DkimVerificationPolicy_acceptExpiredSignature(dkim_vpolicy,
                                                  enma_config->dkim_accept_expired_signature);
    DkimVerificationPolicy_getRfc4871Compatible(dkim_vpolicy, enma_config->dkim_rfc4871_compatible);
    DkimVerificationPolicy_supposeLeadingHeaderValueSpace(dkim_vpolicy,
                                                          enma_config->milter_sendmail813);
    DkimVerificationPolicy_setLogger(dkim_vpolicy, LogHandler_syslogWithPrefix);
    return dkim_vpolicy;
}


/**
 * main function
 *
 * @param argc
 * @param argv
 * @return
 */
int
main(int argc, char **argv)
{
    int result = 0;
    // initialize configuration
    if (0 != (result = config_init(argc, argv))) {
        ConsoleError("enma starting up failed: error=config_init failed");
        exit(result);
    }
    // initialize log handler
    openlog(g_enma_config->syslog_ident, LOG_PID | LOG_NDELAY, g_enma_config->syslog_facility);
    setlogmask(LOG_UPTO(g_enma_config->syslog_logmask));
    LogHandler_init();

    // initialize OpenSSL
    ERR_load_crypto_strings();
    Crypto_mutex_init();

    // initialize SIDF Policy
    if (NULL == (g_sidf_policy = sidf_init(g_enma_config))) {
        ConsoleError("enma starting up failed: error=sidf_init failed");
        exit(EX_OSERR);
    }
    // initialize DKIM Policy
    if (NULL == (g_dkim_vpolicy = dkim_init(g_enma_config))) {
        ConsoleError("enma starting up failed: error=dkim_init failed");
        exit(EX_OSERR);
    }
    // initialize milter
    if (!EnmaMfi_init
        (g_enma_config->milter_socket, g_enma_config->milter_timeout,
         g_enma_config->milter_loglevel)) {
        ConsoleError("enma starting up failed: error=EnmaMfi_init failed");
        exit(EX_OSERR);
    }
    // daemonize
    if (!daemonize_init
        (g_enma_config->milter_user, g_enma_config->milter_chdir, g_enma_config->milter_pidfile)) {
        ConsoleError("enma starting up failed: error=daemonize_init failed");
        LogError("enma starting up failed: error=daemonize_init failed");
        exit(EX_OSERR);
    }

    LogInfo("enma starting up");
    int smfi_return_val = smfi_main();
    LogInfo("enma shutting down: result=%d", smfi_return_val);

    if (!daemonize_finally(g_enma_config->milter_pidfile)) {
        LogError("daemonize_finally failed");
        exit(EX_OSERR);
    }

    SidfPolicy_free(g_sidf_policy);
    DkimVerificationPolicy_free(g_dkim_vpolicy);
    EnmaConfig_free(g_enma_config);

    // OpenSSL cleanup
    Crypto_mutex_cleanup();
    ERR_free_strings();
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();

    LogHandler_cleanup();
    closelog();

    return smfi_return_val;
}
