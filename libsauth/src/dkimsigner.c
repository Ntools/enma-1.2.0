/*
 * Copyright (c) 2006-2010 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimsigner.c 1293 2010-02-23 07:24:28Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimsigner.c 1293 2010-02-23 07:24:28Z takahiko $");

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <sys/param.h>

#include "dkimlogger.h"
#include "strarray.h"
#include "mailheaders.h"
#include "ptrop.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "dkim.h"
#include "dkimdigester.h"
#include "dkimsignpolicy.h"

struct DkimSigner {
    const DkimSignPolicy *spolicy;
    DkimStatus status;
    const MailHeaders *headers;

    DkimDigester *digester;
    DkimSignature *signature;
};

/**
 * create DkimSigner object
 * @param spolicy DkimSignPolicy object to be associated with the created DkimSigner object.
 *                This object can be shared between multiple threads.
 * @return initialized DkimSigner object, or NULL if memory allocation failed.
 */
DkimSigner *
DkimSigner_new(const DkimSignPolicy *spolicy)
{
    assert(NULL != spolicy);

    DkimSigner *self = (DkimSigner *) malloc(sizeof(DkimSigner));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimSigner));

    // minimum initialization
    self->signature = DkimSignature_new((const DkimPolicyBase *) spolicy);
    if (NULL == self->signature) {
        goto cleanup;
    }   // end if

    self->spolicy = spolicy;
    return self;

  cleanup:
    DkimSigner_free(self);
    return NULL;
}   // end function: DkimSigner_new

/**
 * release DkimSigner object
 * @param self DkimSigner object to be released
 */
void
DkimSigner_free(DkimSigner *self)
{
    assert(NULL != self);

    if (NULL != self->signature) {
        DkimSignature_free(self->signature);
    }   // end if
    if (NULL != self->digester) {
        DkimDigester_free(self->digester);
    }   // end if
    free(self);
}   // end function: DkimSigner_free

/**
 * @param self DkimSigner object
 * @param auid mail address to be used as AUID
 * @param sdid domain name to be used as SDID
 * @param headers MailHeaders object that stores all headers to be signed with DKIM.
 *                Key of MailHeaders object is treated as header field name excepting ':'.
 *                Value of MailHeaders object is treated as header field value excepting ':',
 *                and it is switchable by DkimSignPolicy_supposeLeadingHeaderValueSpace()
 *                whether or not SP (space) character after ':' is included in header field values.
 *                (sendmail 8.13 or earlier does not include SP in header field value,
 *                sendmail 8.14 or later includes it.)
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_PERMFAIL_UNSUPPORTED_HASH_ALGORITHM unsupported digest algorithm
 * @error DSTAT_PERMFAIL_UNSUPPORTED_KEY_ALGORITHM unsupported public key algorithm
 */
DkimStatus
DkimSigner_setup(DkimSigner *self, const InetMailbox *auid, const char *sdid,
                 const MailHeaders *headers, const StrArray *signed_header_fields)
{
    assert(NULL != self);
    assert(NULL != auid || NULL != sdid);
    assert(NULL != headers);
    assert(NULL == self->headers);

    self->headers = headers;

    // get time to use as signature timestamp (sig-t-tag)
    time_t epoch;
    if (0 > time(&epoch)) {
        DkimLogSysError(self->spolicy, "time(2) failed: err=%s", strerror(errno));
        self->status = DSTAT_SYSERR_IMPLERROR;
        return self->status;
    }   // end if

    // construct and configure DkimSignature object
    const DkimSignPolicy *spolicy = self->spolicy;
    DkimSignature_setHashAlgorithm(self->signature, spolicy->hashalg);
    DkimSignature_setKeyType(self->signature, spolicy->keytype);
    DkimSignature_setHeaderC14nAlgorithm(self->signature, spolicy->canon_method_header);
    DkimSignature_setBodyC14nAlgorithm(self->signature, spolicy->canon_method_body);
    DkimSignature_setBodyLengthLimit(self->signature, -1LL);    // disable body length limit explicitly

    // set SDID (sig-d-tag)
    DkimStatus ret =
        DkimSignature_setSdid(self->signature, PTROR(sdid, InetMailbox_getDomain(auid)));
    if (DSTAT_OK != ret) {
        self->status = ret;
        return self->status;
    }   // end if

    // set AUID (sig-i-tag)
    if (NULL != auid) {
        ret = DkimSignature_setAuid(self->signature, auid);
        if (DSTAT_OK != ret) {
            self->status = ret;
            return self->status;
        }   // end if
    }   // end if

    DkimSignature_setTimestamp(self->signature, (long long) epoch);
    DkimSignature_setTTL(self->signature, spolicy->signature_ttl);

    if (NULL != signed_header_fields) {
        DkimStatus set_stat =
            DkimSignature_setSignedHeaderFields(self->signature, signed_header_fields);
        if (DSTAT_OK != set_stat) {
            self->status = set_stat;
            return self->status;
        }   // end if
    } else {
        size_t headernum = MailHeaders_getCount(self->headers);
        for (size_t headeridx = 0; headeridx < headernum; ++headeridx) {
            const char *headerf, *headerv;
            MailHeaders_get(self->headers, headeridx, &headerf, &headerv);
            if (NULL == headerf || NULL == headerv) {
                DkimLogWarning(self->spolicy, "ignore an invalid header: no=%d, name=%s, value=%s",
                               headeridx, NNSTR(headerf), NNSTR(headerv));
                continue;
            }   // end if

            // register all headers to be signed with DKIM stored in "headers"
            DkimStatus add_stat = DkimSignature_addSignedHeaderField(self->signature, headerf);
            if (DSTAT_OK != add_stat) {
                self->status = add_stat;
                return self->status;
            }   // end if
        }   // end for
    }   // end if

    self->digester =
        DkimDigester_newWithSignature((const DkimPolicyBase *) self->spolicy, self->signature,
                                      &ret);
    if (NULL == self->digester) {
        self->status = ret;
        return self->status;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimSigner_setup

/**
 * @param self DkimSigner object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
DkimStatus
DkimSigner_updateBody(DkimSigner *self, const unsigned char *bodyp, size_t len)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    self->status = DkimDigester_updateBody(self->digester, bodyp, len);
    return self->status;
}   // end function: DkimSigner_updateBody

/**
 * finalize message body update, and generate the DKIM-Signature header.
 * @param self DkimSigner object
 * @param selector selector
 * @param pkey private key
 * @param headerf a pointer to a variable to receive the header field name.
 *                Buffer is allocated inside the DkimSigner object
 *                and is available until destruction of the DkimSigner object.
 *                "DKIM-Signature" is returned normally.
 * @param headerv a pointer to a variable to receive the header field value.
 *                Buffer is allocated inside the DkimSigner object
 *                and is available until destruction of the DkimSigner object.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 * @error DSTAT_SYSERR_IMPLERROR obvious implementation error
 * @error DSTAT_SYSERR_DIGEST_UPDATE_FAILURE error on digest update (returned by OpenSSL EVP_DigestUpdate())
 */
DkimStatus
DkimSigner_sign(DkimSigner *self, const char *selector, EVP_PKEY *privatekey,
                const char **headerf, const char **headerv)
{
    assert(NULL != self);
    assert(NULL != selector);
    assert(NULL != privatekey);

    if (DSTAT_OK != self->status) {
        return self->status;    // return status code if an error occurred
    }   // end if

    DkimStatus ret = DkimSignature_setSelector(self->signature, selector);
    if (DSTAT_OK != ret) {
        self->status = ret;
        return self->status;
    }   // end if

    ret = DkimDigester_signMessage(self->digester, self->headers, self->signature, privatekey);
    if (DSTAT_OK != ret) {
        self->status = ret;
        return self->status;
    }   // end if
    self->status =
        DkimSignature_buildRawHeader(self->signature, false, self->spolicy->sign_header_with_crlf,
                                     headerf, headerv);
    return self->status;
}   // end function: DkimSigner_sign

/**
 * @param self DkimSigner object
 * @attention for debugging use only.
 * @attention must be called after DkimSigner_setup() and before the first call of DkimSigner_updateBody()
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimSigner_enableC14nDump(DkimSigner *self, const char *basedir, const char *prefix)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    char header_filename[MAXPATHLEN];
    char body_filename[MAXPATHLEN];

    snprintf(header_filename, MAXPATHLEN, "%s/%s.header", basedir, prefix);
    snprintf(body_filename, MAXPATHLEN, "%s/%s.body", basedir, prefix);
    return DkimDigester_enableC14nDump(self->digester, header_filename, body_filename);
}   // end function: DkimSigner_enableC14nDump
