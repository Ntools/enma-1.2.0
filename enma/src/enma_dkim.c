/*
 * Copyright (c) 2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_dkim.c 1127 2009-08-20 03:05:56Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma_dkim.c 1127 2009-08-20 03:05:56Z takahiko $");

#include <assert.h>
#include <stdbool.h>
#include <sys/types.h>

#include "loghandler.h"
#include "authresult.h"
#include "inetmailbox.h"
#include "dkim.h"

#include "enma_dkim.h"

bool
EnmaDkim_evaluate(DkimVerifier *dkimverifier, AuthResult *authresult)
{
    DkimStatus vstat = DkimVerifier_verify(dkimverifier);
    if (DSTAT_ISCRITERR(vstat)) {
        LogError("DkimVerifier_verify failed: err=%s", DKIM_strerror(vstat));
        return false;
    } else if (DSTAT_OK == vstat) {
        size_t signum = DkimVerifier_getFrameCount(dkimverifier);
        for (size_t sigidx = 0; sigidx < signum; ++sigidx) {
            const InetMailbox *identity;
            DkimBaseScore score = DkimVerifier_getFrameResult(dkimverifier, sigidx, &identity);
            const char *scoreexp = DkimEnum_lookupScoreByValue(score);
            (void) AuthResult_appendMethodSpec(authresult, AUTHRES_METHOD_DKIM, scoreexp);
            if (NULL != identity) {
                (void) AuthResult_appendPropSpecWithAddrSpec(authresult, AUTHRES_PTYPE_HEADER,
                                                             AUTHRES_PROPERTY_I, identity);
                LogEvent("DKIM-auth", "%s.%s=%s@%s, score=%s", AUTHRES_PTYPE_HEADER,
                         AUTHRES_PROPERTY_I, InetMailbox_getLocalPart(identity),
                         InetMailbox_getDomain(identity), scoreexp);
            } else {
                LogEvent("DKIM-auth", "score=%s", scoreexp);
            }
        }
    } else {
        DkimBaseScore session_score = DkimVerifier_getSessionResult(dkimverifier);
        assert(DKIM_BASE_SCORE_NULL != session_score);
        const char *scoreexp = DkimEnum_lookupScoreByValue(session_score);
        (void) AuthResult_appendMethodSpec(authresult, AUTHRES_METHOD_DKIM, scoreexp);
        LogEvent("DKIM-auth", "score=%s", scoreexp);
    }
    return true;
}

bool
EnmaDkimAdsp_evaluate(DkimVerifier *dkimverifier, AuthResult *authresult)
{
    DkimAdspScore adsp_score = DkimVerifier_checkAdsp(dkimverifier);
    if (DKIM_ADSP_SCORE_NULL == adsp_score) {
        LogError("DkimVerifier_evalAdsp failed");
        return false;
    }   // end if
    const char *authorFieldName = DkimVerifier_getAuthorHeaderName(dkimverifier);
    const InetMailbox *authorMailbox = DkimVerifier_getAuthorMailbox(dkimverifier);
    const char *scoreexp = DkimEnum_lookupAdspScoreByValue(adsp_score);
    (void) AuthResult_appendMethodSpec(authresult, AUTHRES_METHOD_DKIMADSP, scoreexp);
    if (NULL != authorFieldName && NULL != authorMailbox) {
        (void) AuthResult_appendPropSpecWithAddrSpec(authresult, AUTHRES_PTYPE_HEADER,
                                                     authorFieldName, authorMailbox);
        LogEvent("DKIM-ADSP-auth", "%s.%s=%s@%s, score=%s", AUTHRES_PTYPE_HEADER,
                 authorFieldName, InetMailbox_getLocalPart(authorMailbox),
                 InetMailbox_getDomain(authorMailbox), scoreexp);
    } else {
        LogEvent("DKIM-ADSP-auth", "score=%s", scoreexp);
    }
    return true;
}
