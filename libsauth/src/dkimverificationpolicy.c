/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimverificationpolicy.c 1370 2011-11-07 02:58:25Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimverificationpolicy.c 1370 2011-11-07 02:58:25Z takahiko $");

#include <sys/types.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <openssl/evp.h>

#include "dkimlogger.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimverificationpolicy.h"

/**
 * create DkimVerificationPolicy object
 * @return initialized DkimVerificationPolicy object, or NULL if memory allocation failed.
 */
DkimVerificationPolicy *
DkimVerificationPolicy_new(void)
{
    DkimVerificationPolicy *self =
        (DkimVerificationPolicy *) malloc(sizeof(DkimVerificationPolicy));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimVerificationPolicy));

    DkimPolicyBase_init((DkimPolicyBase *) self);
    self->accept_expired_signature = false;

    return self;
}   // end function: DkimVerificationPolicy_new

/**
 * release DkimVerificationPolicy object
 * @param self DkimVerificationPolicy object to release
 */
void
DkimVerificationPolicy_free(DkimVerificationPolicy *self)
{
    assert(NULL != self);
    DkimPolicyBase_cleanup((DkimPolicyBase *) self);
    free(self);
}   // end function: DkimVerificationPolicy_free

/**
 * set the maximum number of DKIM-Signature headers to verify.
 * DKIM-Signature headers exceed this limit are ignored.
 * @param header_limit the maximum number of DKIM-Signature headers to verify
 *                     0 for unlimited (default).
 */
void
DkimVerificationPolicy_setSignHeaderLimit(DkimVerificationPolicy *self, size_t header_limit)
{
    assert(NULL != self);
    self->sign_header_limit = header_limit;
}   // end function: DkimVerificationPolicy_setSignHeaderLimit

/**
 * set whether or not to treat expired DKIM signatures as valid
 * @param accept true to accept, false to reject
 */
void
DkimVerificationPolicy_acceptExpiredSignature(DkimVerificationPolicy *self, bool accept)
{
    assert(NULL != self);
    self->accept_expired_signature = accept;
}   // end function: DkimVerificationPolicy_acceptExpiredSignature
