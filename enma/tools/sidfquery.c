/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfquery.c 1426 2011-12-03 17:14:40Z takahiko $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "rcsid.h"
RCSID("$Id: sidfquery.c 1426 2011-12-03 17:14:40Z takahiko $");

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "ptrop.h"
#include "dnsresolv.h"
#include "sidf.h"

bool g_verbose_mode = false;

static void
usage(FILE *fp)
{
    fprintf(fp, "\nUsage: sidfquery [-46mpsv] username@domain IP-address1 IP-address2 ...\n\n");
    fprintf(fp, "handling of IP address:\n");
    fprintf(fp, "  -4    handle \"IP-address\" as IPv4 address\n");
    fprintf(fp, "  -6    handle \"IP-address\" as IPv6 address\n\n");
    fprintf(fp, "evaluation mode:\n");
    fprintf(fp, "  -s  SPF mode (default)\n");
    fprintf(fp, "  -m  Sender ID (mfrom) mode\n");
    fprintf(fp, "  -p  Sender ID (pra) mode\n");
    fprintf(fp, "features:\n");
    fprintf(fp, "  -v  verbose mode\n");
    exit(EX_USAGE);
}   // end functiion : usage

static void
stdout_logger(int priority, const char *message, ...)
{
    if (!g_verbose_mode && LOG_DEBUG == priority) {
        return;
    }

    va_list args;
    va_start(args, message);
    vfprintf(stdout, message, args);
    putc('\n', stdout);
    va_end(args);
}   // end functiion : stdout_logger

int
main(int argc, char **argv)
{
    int af = AF_UNSPEC;
    int ai_flags = 0;
    SidfRecordScope scope = SIDF_RECORD_SCOPE_SPF1;

    int c;
    while (-1 != (c = getopt(argc, argv, "46mnpshv"))) {
        switch (c) {
        case '4':  // IPv4
            af = AF_INET;
            break;
        case '6':  // IPv6
            af = AF_INET6;
            break;
        case 'm':  // SIDF/mfrom
            scope = SIDF_RECORD_SCOPE_SPF2_MFROM;
            break;
        case 'n':  // to prevent DNS-querying at getaddrinfo()
            ai_flags |= AI_NUMERICHOST;
            break;
        case 'p':  // SIDF/pra
            scope = SIDF_RECORD_SCOPE_SPF2_PRA;
            break;
        case 's':  // SPF
            scope = SIDF_RECORD_SCOPE_SPF1;
            break;
        case 'h':
            usage(stdout);
            break;
        case 'v':
            g_verbose_mode = true;
            break;
        default:
            fprintf(stdout, "[Error] illegal option: -%c\n", c);
            usage(stdout);
            break;
        }   // end switch
    }   // end while

    argc -= optind;
    argv += optind;

    if (argc < 2) {
        usage(stdout);
    }   // end if

    DnsResolver *resolver = DnsResolver_new();
    if (NULL == resolver) {
        fprintf(stdout, "[Error] resolver initialization failed: error=%s\n", strerror(errno));
        exit(EX_OSERR);
    }   // end if

    const char *mailbox = argv[0];

    SidfPolicy *policy = SidfPolicy_new();
    if (NULL == policy) {
        fprintf(stdout, "[Error] SidfPolicy_new failed: error=%s\n", strerror(errno));
        exit(EX_OSERR);
    }   // end if
    SidfPolicy_setSpfRRLookup(policy, true);
    SidfPolicy_setLogger(policy, stdout_logger);

    SidfRequest *request = SidfRequest_new(policy, resolver);
    if (NULL == request) {
        fprintf(stdout, "[Error] SidfRequest_new failed: error=%s\n", strerror(errno));
        exit(EX_OSERR);
    }   // end if

    const char *dummy;
    InetMailbox *envfrom = InetMailbox_build2822Mailbox(mailbox, STRTAIL(mailbox), &dummy, NULL);
    if (NULL == envfrom) {
        fprintf(stdout, "[Error] mailbox is not RFC2822 compliant: mailbox=%s\n", mailbox);
        usage(stdout);
    }   // end if

    struct addrinfo ai_hints, *ai_result, *ai_current;
    memset(&ai_hints, 0, sizeof(struct addrinfo));
    ai_hints.ai_flags |= ai_flags;
    ai_hints.ai_family = af;
    ai_hints.ai_socktype = SOCK_STREAM;

    for (int i = 1; i < argc; ++i) {
        int gai_error = getaddrinfo(argv[i], NULL, &ai_hints, &ai_result);
        if (0 != gai_error) {
            fprintf(stdout, "[Error] invalid IP address: ip-address=%s, error=%s\n", argv[i],
                    gai_strerror(gai_error));
            if (EAI_NONAME == gai_error) {
                continue;
#ifdef EAI_NODATA
            } else if (EAI_NODATA == gai_error) {
                // some platforms have EAI_NODATA as a return code of getaddrinfo()
                continue;
#endif  // EAI_NODATA
            } else {
                exit(EX_OSERR);
            }   // end if
        }   // end if

        for (ai_current = ai_result; NULL != ai_current; ai_current = ai_current->ai_next) {
            if (AF_INET != ai_current->ai_family && AF_INET6 != ai_current->ai_family) {
                continue;
            }   // end if

            char addr_string[INET6_ADDRSTRLEN];
            if (AF_INET == ai_current->ai_family) {
                (void) inet_ntop(AF_INET, &((struct sockaddr_in *) ai_current->ai_addr)->sin_addr,
                                 addr_string, sizeof(addr_string));
            } else {
                (void) inet_ntop(AF_INET6,
                                 &((struct sockaddr_in6 *) ai_current->ai_addr)->sin6_addr,
                                 addr_string, sizeof(addr_string));
            }   // end if

            SidfRequest_reset(request);
            if (!SidfRequest_setIpAddr(request, ai_current->ai_family, ai_current->ai_addr)) {
                fprintf(stdout, "[Error] SidfRequest_setIpAddr failed: address_family=0x%x\n",
                        ai_current->ai_family);
                usage(stdout);
            }   // end if

            SidfRequest_setSender(request, envfrom);
            SidfRequest_setHeloDomain(request, InetMailbox_getDomain(envfrom));

            // SPF/Sender ID evaluation
            SidfScore score = SidfRequest_eval(request, scope);
            const char *spfresultexp = SidfEnum_lookupScoreByValue(score);
            fprintf(stdout, "%s %s %s\n", mailbox, addr_string, spfresultexp);
        }   //end for

        freeaddrinfo(ai_result);
    }   // end for

    // clean up
    InetMailbox_free(envfrom);
    SidfRequest_free(request);
    SidfPolicy_free(policy);
    DnsResolver_free(resolver);

    exit(EX_OK);
}   // end function : main
