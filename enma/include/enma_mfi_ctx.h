/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_mfi_ctx.h 1098 2009-08-03 02:20:19Z takahiko $
 */

#ifndef __ENMA_MFI_CTX_H__
#define __ENMA_MFI_CTX_H__

#include <netinet/in.h>

#include <libmilter/mfapi.h>

#include "intarray.h"
#include "inetmailbox.h"
#include "mailheaders.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "dkim.h"
#include "authresult.h"

typedef struct EnmaMfiCtx {
    // for connections
    char *hostname;
    char *helohost;
    char *ipaddr;
    _SOCK_ADDR *hostaddr;
    DnsResolver *resolver;
    // for message
    char *raw_envfrom;
    char *qid;
    InetMailbox *envfrom;
    MailHeaders *headers;
    DkimVerifier *dkimverifier;
    AuthResult *authresult;
    // for Authentication-Results headers
    int authhdr_count;          // the number of existing Authentication-Results headers
    IntArray *delauthhdr;       // array of Authentication-Results headers to delete
} EnmaMfiCtx;

extern EnmaMfiCtx *EnmaMfiCtx_new(void);
extern void EnmaMfiCtx_reset(EnmaMfiCtx *self);
extern void EnmaMfiCtx_free(EnmaMfiCtx *self);

#endif
