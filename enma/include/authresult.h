/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: authresult.h 1327 2011-04-30 13:24:07Z takahiko $
 */

#ifndef __AUTH_RESULT_H__
#define __AUTH_RESULT_H__

#include <stdbool.h>
#include "foldstring.h"
#include "inetmailbox.h"

/// Authentication-Results header field name
#define AUTHRESULTSHDR	"Authentication-Results"

// http://www.iana.org/assignments/email-auth/email-auth.xml
// method
#define AUTHRES_METHOD_AUTH	"auth"
#define AUTHRES_METHOD_DKIM	"dkim"
#define AUTHRES_METHOD_DKIMADSP	"dkim-adsp"
#define AUTHRES_METHOD_DOMAINKEYS	"domainkeys"
#define AUTHRES_METHOD_IPREV	"iprev"
#define AUTHRES_METHOD_SENDERID	"sender-id"
#define AUTHRES_METHOD_SPF	"spf"
#define AUTHRES_METHOD_VBR	"vbr"

// ptype
#define AUTHRES_PTYPE_NULL	""
#define AUTHRES_PTYPE_SMTP	"smtp"
#define AUTHRES_PTYPE_HEADER	"header"
#define AUTHRES_PTYPE_BODY	"body"
#define AUTHRES_PTYPE_POLICY	"policy"

// property
#define AUTHRES_PROPERTY_NULL	""
#define AUTHRES_PROPERTY_AUTH	"auth"
#define AUTHRES_PROPERTY_B	"b"
#define AUTHRES_PROPERTY_D	"d"
#define AUTHRES_PROPERTY_I	"i"
#define AUTHRES_PROPERTY_FROM	"from"
#define AUTHRES_PROPERTY_SENDER	"sender"
#define AUTHRES_PROPERTY_MAILFROM	"mailfrom"
#define AUTHRES_PROPERTY_HELO	"helo"
#define AUTHRES_PROPERTY_MD	"md"
#define AUTHRES_PROPERTY_MV	"mv"

typedef FoldString AuthResult;

extern const char *AuthResult_getFieldName(void);
extern AuthResult *AuthResult_new(void);
extern bool AuthResult_appendAuthServId(AuthResult *self, const char *authserv_id);
extern bool AuthResult_appendMethodSpec(AuthResult *self, const char *method, const char *result);
extern bool AuthResult_appendPropSpecWithToken(AuthResult *self, const char *ptype,
                                               const char *property, const char *value);
extern bool AuthResult_appendPropSpecWithAddrSpec(AuthResult *self, const char *ptype,
                                                  const char *property, const InetMailbox *mailbox);
extern bool AuthResult_compareAuthservId(const char *field, const char *hostname);

#define AuthResult_free(a)	FoldString_free(a)
#define AuthResult_reset(a)	FoldString_reset(a)
#define AuthResult_status(a)	FoldString_status(a)
#define AuthResult_getFieldBody(a)	FoldString_getString(a)

#endif /*__AUTH_RESULT_H__*/
