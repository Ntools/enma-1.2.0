/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimspec.h 1365 2011-10-16 08:08:36Z takahiko $
 */

// Constants defined in RFC6376, RFC5617

#ifndef __DKIMSPEC_H__
#define __DKIMSPEC_H__

// header field name of From header (as Author)
#define FROMHEADER          "From"

// header field name of Sender header (as Author)
// #define  SENDERHEADER       "Sender"

// header field name of DKIM signature header
#define DKIM_SIGNHEADER     "DKIM-Signature"

// DNS namespace literal to look up DKIM public key records
#define DKIM_DNS_NAMESPACE  "_domainkey"

// DNS namespace literal to look up ADSP records
#define DKIM_DNS_ADSP_SELECTOR  "_adsp"

// version string of DKIM public key records
#define DKIM1_VERSION_TAG   "DKIM1"

// max length of sig-l-tag value
#define DKIM_SIG_L_TAG_LEN  76
// max length of sig-t-tag value
#define DKIM_SIG_T_TAG_LEN  12
// max length of sig-x-tag value
#define DKIM_SIG_X_TAG_LEN  12

#endif /* __DKIMSPEC_H__ */
