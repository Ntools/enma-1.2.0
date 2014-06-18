/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_config.c 1371 2011-11-07 03:18:02Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma_config.c 1371 2011-11-07 03:18:02Z takahiko $");

#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <sysexits.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>

#include "ptrop.h"

#include "consolehandler.h"
#include "config_loader.h"
#include "enma.h"
#include "enma_config.h"

// *INDENT-OFF*

static ConfigEntry ConfigEntry_table[] = {
    {"milter.verbose", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, milter_verbose),
        "verbose mode. same option as '-v' (boolean)"},
    {"milter.conffile", CONFIGTYPE_STRING, NULL, offsetof(EnmaConfig, milter_conffile),
        "configuration file on startup. same option as '-c filename' (filename)"},
    // libmilter
    {"milter.user", CONFIGTYPE_STRING, NULL, offsetof(EnmaConfig, milter_user),
        "user/group id of daemon startup (username)"},
    {"milter.pidfile", CONFIGTYPE_STRING, "/var/run/" ENMA_MILTER_NAME "/" ENMA_MILTER_NAME ".pid", offsetof(EnmaConfig, milter_pidfile),
        "path to pid file (filename)"},
    {"milter.chdir", CONFIGTYPE_STRING, "/var/tmp/", offsetof(EnmaConfig, milter_chdir),
        "change working directory (dirname)"},
    {"milter.socket", CONFIGTYPE_STRING, "inet:10025@127.0.0.1", offsetof(EnmaConfig, milter_socket),
        "address of milter socket"},
    {"milter.timeout", CONFIGTYPE_INTEGER, "7210", offsetof(EnmaConfig, milter_timeout),
        "I/O timeout (seconds)"},
    {"milter.loglevel", CONFIGTYPE_INTEGER, "0", offsetof(EnmaConfig, milter_loglevel),
        "log level of libmilter (integer)"},
    {"milter.sendmail813", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, milter_sendmail813),
        "compatible mode with sendmail 8.13 or earlier (boolean)"},
    {"milter.postfix", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, milter_postfix),
        "use postfix's milter (boolean)"},
    // syslog
    {"syslog.ident", CONFIGTYPE_STRING, ENMA_MILTER_NAME, offsetof(EnmaConfig, syslog_ident),
        "syslog identifier"},
    {"syslog.facility", CONFIGTYPE_SYSLOG_FACILITY, "local4", offsetof(EnmaConfig, syslog_facility),
        "specify the type of daemon"},
    {"syslog.logmask", CONFIGTYPE_SYSLOG_PRIORITY, "info", offsetof(EnmaConfig, syslog_logmask),
        "syslog priority mask"},
    // common
    {"common.exclusion_addresses", CONFIGTYPE_IP_ADDRESS_LIST, "127.0.0.1,::1", offsetof(EnmaConfig, common_exclusion_addresses),
        "ignore source address list"},
    // spf
    {"spf.auth", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, spf_auth),
        "enable SPF authentication (boolean)"},
    {"spf.explog", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, spf_explog),
        "record explanation of SPF (boolean)"},
    // sidf
    {"sidf.auth", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, sidf_auth),
        "enable SIDF authentication (boolean)"},
    {"sidf.explog", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, sidf_explog),
        "record the explanation of SIDF (boolean)"},
    // dkim
    {"dkim.auth", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, dkim_auth),
        "enable DKIM authentication (boolean)"},
    {"dkim.signheader_limit", CONFIGTYPE_INTEGER, "10", offsetof(EnmaConfig, dkim_signheader_limit),
        "maximum number of DKIM signature headers to be verified (rests are ignored)"},
    {"dkim.accept_expired_signature", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, dkim_accept_expired_signature),
        "accept expired dkim signature (boolean)"},
    {"dkim.rfc4871_compatible", CONFIGTYPE_BOOLEAN, "false", offsetof(EnmaConfig, dkim_rfc4871_compatible),
        "RFC4871 compatible mode (boolean)"},
    // dkim adsp
    {"dkimadsp.auth", CONFIGTYPE_BOOLEAN, "true", offsetof(EnmaConfig, dkimadsp_auth),
        "enable DKIM ADSP authentication (boolean)"},
    // authresult
    {"authresult.identifier", CONFIGTYPE_STRING, "localhost", offsetof(EnmaConfig, authresult_identifier),
        "identifier of Authentication-Results header"},
    {NULL, 0, NULL, 0, NULL}
};

// *INDENT-ON*


/**
 * usage of ENMA
 *
 * @param out: output to the stream
 */
static void
EnmaConfig_usage(FILE *out)
{
    assert(NULL != out);

    fprintf(out, "Options[with default]:\n");
    fprintf(out, "  -h\t: show this message\n");
    fprintf(out, "  -v\t: verbose mode\n");
    fprintf(out, "  -c filename\t: configuration file on startup\n");
    fprintf(out, "\n");
    for (const ConfigEntry *p = ConfigEntry_table; NULL != p->config_name; ++p) {
        fprintf(out, "  -o %s\t: %s [%s]\n", p->config_name, p->description,
                NNSTR(p->default_value));
    }
    fflush(out);
}


/**
 * set configuration entries from command-line arguments
 *
 * @param self
 * @param argc
 * @param argv
 * @return
 */
static bool
EnmaConfig_getopt(EnmaConfig *self, int argc, char **argv)
{
    assert(NULL != self);
    assert(0 < argc);
    assert(NULL != argv);

    int c;
    while (-1 != (c = getopt(argc, argv, "o:c:vh"))) {
        switch (c) {
        case 'o':
            if (!ConfigLoader_setEqualStringOptionValue(ConfigEntry_table, optarg, self)) {
                return false;
            }
            break;
        case 'c':
            if (!ConfigLoader_setOptionValue(ConfigEntry_table, "milter.conffile", optarg, self)) {
                return false;
            }
            break;
        case 'v':
            if (!ConfigLoader_setOptionValue(ConfigEntry_table, "milter.verbose", "true", self)) {
                return false;
            }
            break;
        case 'h':
            EnmaConfig_usage(stderr);
            exit(EX_USAGE);
        default:
            EnmaConfig_usage(stderr);
            exit(EX_USAGE);
        }
    }

    return true;
}


/**
 * set configuration entries
 *
 * @param self
 * @param argc
 * @param argv
 * @return
 */
bool
EnmaConfig_setConfig(EnmaConfig *self, int argc, char **argv)
{
    assert(NULL != self);
    assert(0 < argc);
    assert(NULL != argv);

    // set configuration entries from command-line arguments
    if (!EnmaConfig_getopt(self, argc, argv)) {
        ConsoleNotice("config getopt value set failed");
        return false;
    }
    // check arguments error
    argc -= optind;
    argv += optind;
    if (0 < argc) {
        ConsoleNotice("too many arguments.");
        return false;
    }
    // set configuration entries from configuration file
    if (NULL != g_enma_config->milter_conffile) {
        if (!ConfigLoader_setConfigValue(ConfigEntry_table, g_enma_config->milter_conffile, self)) {
            ConsoleNotice("config file load faild");
            return false;
        }
    }
    // set configuration entries from default values
    if (!ConfigLoader_setDefaultValue(ConfigEntry_table, self)) {
        ConsoleNotice("config default value set failed");
        return false;
    }

    if (self->milter_verbose) {
        ConfigLoader_dump(ConfigEntry_table, self, stderr);
    }
    return true;
}


/**
 * initialize the EnmaConfig
 *
 * @return
 */
EnmaConfig *
EnmaConfig_new(void)
{
    EnmaConfig *self = (EnmaConfig *) malloc(sizeof(EnmaConfig));
    if (NULL == self) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return NULL;
    }

    ConfigLoader_init(ConfigEntry_table, self);

    return self;
}


/**
 * free the EnmaConfig
 *
 * @param self
 */
void
EnmaConfig_free(EnmaConfig *self)
{
    assert(NULL != self);

    ConfigLoader_free(ConfigEntry_table, self);
    free(self);
}
