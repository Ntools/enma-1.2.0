/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_sidf.h 787 2009-03-25 01:09:55Z takahiko $
 */

#ifndef __ENMA_SIDF_H__
#define __ENMA_SIDF_H__

#include <stdbool.h>
#include <sys/socket.h>

#include "inetmailbox.h"
#include "mailheaders.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "authresult.h"

extern bool EnmaSpf_evaluate(SidfPolicy *policy, DnsResolver *resolver, AuthResult *authresult,
                             const struct sockaddr *hostaddr, const char *ipaddr,
                             const char *helohost, const char *raw_envfrom,
                             const InetMailbox *envfrom, bool explog);
extern bool EnmaSidf_evaluate(SidfPolicy *policy, DnsResolver *resolver, AuthResult *authresult,
                              const struct sockaddr *hostaddr, const char *ipaddr,
                              const char *helohost, const MailHeaders *headers, bool explog);

#endif
