/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimverificationpolicy.h 1374 2011-11-07 03:31:49Z takahiko $
 */

#ifndef __DKIM_VERIFICATIONPOLICY_H__
#define __DKIM_VERIFICATIONPOLICY_H__

#include <sys/types.h>
#include <stdbool.h>
#include "dkimpolicybase.h"

struct DkimVerificationPolicy {
    DkimPolicyBase_MEMBER;
    // maximum number of the DKIM signature headers to verify.
    // They are evaluated from the top,
    // and are ignored if the number reaches the limit.
    // 0 for unlimited
    size_t sign_header_limit;
    // whether or not to treat expired DKIM signatures as valid
    bool accept_expired_signature;
};

#endif /* __DKIM_VERIFICATIONPOLICY_H__ */
