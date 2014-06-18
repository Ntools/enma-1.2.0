/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_mfi_ctx.c 1098 2009-08-03 02:20:19Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma_mfi_ctx.c 1098 2009-08-03 02:20:19Z takahiko $");

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "ptrop.h"
#include "intarray.h"
#include "mailheaders.h"
#include "authresult.h"
#include "sidf.h"
#include "dkim.h"

#include "enma_mfi_ctx.h"

/**
 * libmilterで利用するコンテキストの初期化
 */
EnmaMfiCtx *
EnmaMfiCtx_new(void)
{
    EnmaMfiCtx *self = (EnmaMfiCtx *) malloc(sizeof(EnmaMfiCtx));
    if (NULL == self) {
        return NULL;
    }
    memset(self, 0, sizeof(EnmaMfiCtx));

    self->hostname = NULL;
    self->helohost = NULL;
    self->ipaddr = NULL;
    self->hostaddr = NULL;
    self->resolver = DnsResolver_new();
    if (NULL == self->resolver) {
        goto error_free;
    }

    self->raw_envfrom = NULL;
    self->qid = NULL;
    self->envfrom = NULL;
    self->headers = MailHeaders_new(0);
    if (NULL == self->headers) {
        goto error_free;
    }
    self->dkimverifier = NULL;
    self->authresult = AuthResult_new();
    if (NULL == self->authresult) {
        goto error_free;
    }

    self->authhdr_count = 0;
    self->delauthhdr = IntArray_new(0);
    if (NULL == self->delauthhdr) {
        goto error_free;
    }

    return self;

  error_free:
    EnmaMfiCtx_free(self);
    return NULL;
}


/**
 * SMTPトランザクション毎に開放する処理
 *
 * @param self
 */
void
EnmaMfiCtx_reset(EnmaMfiCtx *self)
{
    assert(NULL != self);

    PTRINIT(self->raw_envfrom);
    PTRINIT(self->qid);
    if (NULL != self->envfrom) {
        InetMailbox_free(self->envfrom);
        self->envfrom = NULL;
    }
    if (NULL != self->headers) {
        MailHeaders_reset(self->headers);
    }
    if (NULL != self->dkimverifier) {
        DkimVerifier_free(self->dkimverifier);
        self->dkimverifier = NULL;
    }
    if (NULL != self->authresult) {
        AuthResult_reset(self->authresult);
    }

    self->authhdr_count = 0;
    if (NULL != self->delauthhdr) {
        IntArray_reset(self->delauthhdr);
    }
}


/**
 * SMTPコネクション毎に開放する変数
 *
 * @param self
 */
void
EnmaMfiCtx_free(EnmaMfiCtx *self)
{
    assert(NULL != self);

    free(self->hostname);
    free(self->helohost);
    free(self->ipaddr);
    free(self->hostaddr);
    if (NULL != self->resolver) {
        DnsResolver_free(self->resolver);
    }

    free(self->raw_envfrom);
    free(self->qid);
    if (NULL != self->envfrom) {
        InetMailbox_free(self->envfrom);
    }
    if (NULL != self->headers) {
        MailHeaders_free(self->headers);
    }
    if (NULL != self->dkimverifier) {
        DkimVerifier_free(self->dkimverifier);
    }
    if (NULL != self->authresult) {
        AuthResult_free(self->authresult);
    }

    if (NULL != self->delauthhdr) {
        IntArray_free(self->delauthhdr);
    }
    free(self);
}
