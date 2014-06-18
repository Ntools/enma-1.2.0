/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimpublickey.h 1210 2009-09-12 13:16:31Z takahiko $
 */

#ifndef __DKIM_PUBLICKEY_H__
#define __DKIM_PUBLICKEY_H__

#include <stdbool.h>
#include <openssl/evp.h>

#include "dnsresolv.h"
#include "dkim.h"
#include "dkimpolicybase.h"
#include "dkimtaglistobject.h"
#include "dkimsignature.h"

typedef struct DkimPublicKey DkimPublicKey;

extern DkimPublicKey *DkimPublicKey_build(const DkimPolicyBase *policy, const char *keyval,
                                          const char *domain, DkimStatus *dstat);
extern void DkimPublicKey_free(DkimPublicKey *self);
extern DkimPublicKey *DkimPublicKey_lookup(const DkimPolicyBase *policy,
                                           const DkimSignature *signature, DnsResolver *resolver,
                                           DkimStatus *dstat);
extern EVP_PKEY *DkimPublicKey_getPublicKey(const DkimPublicKey *self);
extern bool DkimPublicKey_isTesting(const DkimPublicKey *self);
extern bool DkimPublicKey_isSubdomainProhibited(const DkimPublicKey *self);
extern bool DkimPublicKey_isEMailServiceUsable(const DkimPublicKey *self);
extern DkimKeyType DkimPublicKey_getKeyType(const DkimPublicKey *self);
extern const char *DkimPublicKey_getGranularity(const DkimPublicKey *self);

#endif /* __DKIM_PUBKEY_H__ */
