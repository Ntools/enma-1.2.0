/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimverifier.c 1355 2011-10-15 16:47:16Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimverifier.c 1355 2011-10-15 16:47:16Z takahiko $");

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <sys/param.h>
#include <sys/types.h>
#include <stdbool.h>

#include "intarray.h"
#include "strarray.h"
#include "pstring.h"
#include "ptrop.h"
#include "inetdomain.h"
#include "inetmailbox.h"
#include "mailheaders.h"
#include "dkimlogger.h"
#include "dkim.h"
#include "dkimenum.h"
#include "dkimspec.h"
#include "dkimpublickey.h"
#include "dkimadsp.h"
#include "dkimsignature.h"
#include "dkimdigester.h"
#include "dkimverificationpolicy.h"

typedef struct DkimVerificationFrame {
    /// status of the verification process for each DKIM-Signature header
    DkimStatus status;
    /// DkimSignature object build by parsing the corresponding DKIM-Signature header
    DkimSignature *signature;
    /// DkimPublicKey object corresponding to the DKIM-Signature header
    DkimPublicKey *publickey;
    /// DkimDigester object to computes a message hash
    DkimDigester *digester;
    /// DKIM score (as cache)
    DkimBaseScore score;
} DkimVerificationFrame;

struct DkimVerifier {
    /// Verification policy
    const DkimVerificationPolicy *vpolicy;
    /// status of whole of the verification process
    DkimStatus status;

    // DNS resolver
    DnsResolver *resolver;

    /// the number of DKIM-Signature headers included in the MailHeaders object referenced by "headers" field
    /// this number may be more than the number of DkimVerificationFrame
    size_t sigheader_num;

    /// reference to MailHeaders object
    const MailHeaders *headers;
    /// Array of DkimVerificationFrame
    PtrArray *frame;
    /// ADSP record
    DkimAdsp *adsp;
    /// DKIM ADSP score (as cache)
    DkimAdspScore adsp_score;

    // author
    InetMailbox *author;
    size_t author_header_index;
    const char *raw_author_field;   // this holds the reference, DO NOT RELEASE
    const char *raw_author_value;   // this holds the reference, DO NOT RELEASE
};

/**
 * create DkimVerificationFrame object
 * @return initialized DkimVerificationFrame object, or NULL if memory allocation failed.
 */
static DkimVerificationFrame *
DkimVerificationFrame_new(void)
{
    DkimVerificationFrame *frame = (DkimVerificationFrame *) malloc(sizeof(DkimVerificationFrame));
    if (NULL == frame) {
        return NULL;
    }   // end if
    memset(frame, 0, sizeof(DkimVerificationFrame));

    frame->status = DSTAT_OK;
    frame->score = DKIM_BASE_SCORE_NULL;

    return frame;
}   // end function: DkimVerificationFrame_new

/**
 * release DkimVerificationFrame object
 * @param self DkimVerificationFrame object to be released
 */
static void
DkimVerificationFrame_free(DkimVerificationFrame *frame)
{
    assert(NULL != frame);

    if (NULL != frame->digester) {
        DkimDigester_free(frame->digester);
    }   // end if
    if (NULL != frame->signature) {
        DkimSignature_free(frame->signature);
    }   // end if
    if (NULL != frame->publickey) {
        DkimPublicKey_free(frame->publickey);
    }   // end if
    free(frame);
}   // end function: DkimVerificationFrame_free

/**
 * create DkimVerifier object
 * @param vpolicy DkimVerificationPolicy object to be associated with the created DkimVerifier object.
 *                This object can be shared between multiple threads.
 * @param resolver DnsResolver object to look-up public keys record and ADSP records.
 *                This object can *NOT* be shared between multiple threads.
 * @return initialized DkimVerifier object, or NULL if memory allocation failed.
 */
DkimVerifier *
DkimVerifier_new(const DkimVerificationPolicy *vpolicy, DnsResolver *resolver)
{
    assert(NULL != vpolicy);

    DkimVerifier *self = (DkimVerifier *) malloc(sizeof(DkimVerifier));
    if (NULL == self) {
        return NULL;
    }   // end if
    memset(self, 0, sizeof(DkimVerifier));

    // minimum initialization
    self->frame = PtrArray_new(0, (void (*)(void *)) DkimVerificationFrame_free);
    if (NULL == self->frame) {
        goto cleanup;
    }   // end if

    self->sigheader_num = 0;
    self->vpolicy = vpolicy;
    self->adsp_score = DKIM_ADSP_SCORE_NULL;
    self->resolver = resolver;

    return self;

  cleanup:
    DkimVerifier_free(self);
    return NULL;
}   // end function: DkimVerifier_new

/**
 * release DkimVerifier object
 * @param self DkimVerifier object to release
 */
void
DkimVerifier_free(DkimVerifier *self)
{
    assert(NULL != self);

    if (NULL != self->frame) {
        PtrArray_free(self->frame);
    }   // end if
    if (NULL != self->adsp) {
        DkimAdsp_free(self->adsp);
    }   // end if
    if (NULL != self->author) {
        InetMailbox_free(self->author);
    }   // end if

    free(self);
}   // end function: DkimVerifier_free

/**
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
static DkimStatus
DkimVerifier_setupFrame(DkimVerifier *self, const char *headerf, const char *headerv)
{
    DkimStatus ret;

    // create a verification frame
    DkimVerificationFrame *frame = DkimVerificationFrame_new();
    if (NULL == frame) {
        DkimLogNoResource(self->vpolicy);
        self->status = DSTAT_SYSERR_NORESOURCE;
        return self->status;
    }   // end if

    // register DkimVerificationFrame immediately even if corresponding
    // DKIM-Signature header is invalid as a result.
    if (0 > PtrArray_append(self->frame, frame)) {
        DkimVerificationFrame_free(frame);
        DkimLogNoResource(self->vpolicy);
        self->status = DSTAT_SYSERR_NORESOURCE;
        return self->status;
    }   // end if

    // parse and verify DKIM-Signature header
    frame->signature =
        DkimSignature_build((const DkimPolicyBase *) self->vpolicy, headerf, headerv, &ret);
    if (NULL == frame->signature) {
        frame->status = ret;
        return frame->status;
    }   // end if

    // check expiration of the signature if an expired signature is unacceptable.
    if (!self->vpolicy->accept_expired_signature) {
        frame->status = DkimSignature_isExpired(frame->signature);
        if (DSTAT_OK != frame->status) {
            return frame->status;
        }   // end if
    }   // end if

    // The DKIM-Signature header has been confirmed as syntactically valid.
    // log the essentials of the signature accepted
    DkimLogInfo
        (self->vpolicy,
         "DKIM-Signature[%u]: domain=%s, selector=%s, pubkeyalg=%s, digestalg=%s, hdrcanon=%s, bodycanon=%s",
         (unsigned int) self->sigheader_num,
         InetMailbox_getDomain(DkimSignature_getAuid(frame->signature)),
         DkimSignature_getSelector(frame->signature),
         DkimEnum_lookupKeyTypeByValue(DkimSignature_getKeyType(frame->signature)),
         DkimEnum_lookupHashAlgorithmByValue(DkimSignature_getHashAlgorithm(frame->signature)),
         DkimEnum_lookupC14nAlgorithmByValue(DkimSignature_getHeaderC14nAlgorithm
                                             (frame->signature)),
         DkimEnum_lookupC14nAlgorithmByValue(DkimSignature_getBodyC14nAlgorithm(frame->signature)));

    // retrieve public key
    frame->publickey =
        DkimPublicKey_lookup((const DkimPolicyBase *) self->vpolicy, frame->signature,
                             self->resolver, &ret);
    if (NULL == frame->publickey) {
        frame->status = ret;
        return frame->status;
    }   // end if

    // create DkimDigester object
    frame->digester =
        DkimDigester_newWithSignature((const DkimPolicyBase *) self->vpolicy, frame->signature,
                                      &ret);
    if (NULL == frame->digester) {
        frame->status = ret;
        return frame->status;
    }   // end if

    return DSTAT_OK;
}   // end function: DkimVerifier_setupFrame

/**
 * registers the message headers and checks if the message has any valid signatures.
 * @param self DkimVerifier object
 * @param headers MailHeaders object that stores all headers.
 *                Key of MailHeaders object is treated as header field name excepting ':'.
 *                Value of MailHeaders object is treated as header field value excepting ':',
 *                and it is switchable by DkimSignPolicy_supposeLeadingHeaderValueSpace()
 *                whether or not SP (space) character after ':' is included in header field values.
 *                (sendmail 8.13 or earlier does not include SP in header field value,
 *                sendmail 8.14 or later includes it.)
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_INFO_NO_SIGNHEADER No DKIM-Signature headers are found.
 * @error other errors
 */
DkimStatus
DkimVerifier_setup(DkimVerifier *self, const MailHeaders *headers)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    assert(NULL == self->headers);
    self->headers = headers;

    // setup verification frames as many as DKIM-Signature headers
    size_t headernum = MailHeaders_getCount(self->headers);
    for (size_t headeridx = 0; headeridx < headernum; ++headeridx) {
        const char *headerf, *headerv;
        MailHeaders_get(self->headers, headeridx, &headerf, &headerv);
        if (NULL == headerf || NULL == headerv) {
            continue;
        }   // end if

        if (0 != strcasecmp(DKIM_SIGNHEADER, headerf)) {
            // headerf is not DKIM-Signature
            continue;
        }   // end if

        // A DKIM-Signature header is found
        ++(self->sigheader_num);

        /*
         * confirm that the number of DKIM-Signature headers included in "headers"
         * is less than or equal to its limit specified by DkimVerificationPolicy.
         *
         * [RFC6376] 6.1.
         * A Verifier MAY limit the number of
         * signatures it tries, in order to avoid denial-of-service attacks
         */
        if (0 < self->vpolicy->sign_header_limit
            && self->vpolicy->sign_header_limit < self->sigheader_num) {
            DkimLogInfo(self->vpolicy, "too many signature headers: count=%u, limit=%u",
                        self->sigheader_num, self->vpolicy->sign_header_limit);
            break;
        }   // end if

        DkimStatus setup_stat = DkimVerifier_setupFrame(self, headerf, headerv);
        if (DSTAT_ISCRITERR(setup_stat)) {
            // return on system errors
            self->status = setup_stat;
            return self->status;
        }   // end if
    }   // end for

    // Are one or more DKIM-Signature headers found?
    size_t framenum = PtrArray_getCount(self->frame);
    if (0 == framenum) {
        // message is not DKIM-signed
        self->status = DSTAT_INFO_NO_SIGNHEADER;
        return self->status;
    }   // end if

    // message is DKIM-signed
    self->status = DSTAT_OK;
    return self->status;
}   // end function: DkimVerifier_setup

/**
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_updateBody(DkimVerifier *self, const unsigned char *bodyp, size_t len)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    // update digest for each verification frame
    size_t framenum = PtrArray_getCount(self->frame);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame =
            (DkimVerificationFrame *) PtrArray_get(self->frame, frameidx);
        // skip verification frames with errors
        if (DSTAT_OK != frame->status) {
            continue;
        }   // end if

        frame->status = DkimDigester_updateBody(frame->digester, bodyp, len);
        if (DSTAT_OK != frame->status) {
            DkimLogPermFail(self->vpolicy, "body digest update failed for signature no.%u",
                            (unsigned int) frameidx);
            // doesn't return to continue the other verification frames
        }   // end if
    }   // end if

    return DSTAT_OK;
}   // end function: DkimVerifier_updateBody

/**
 * @param self DkimVerifier object
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_verify(DkimVerifier *self)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return self->status;
    }   // end if

    size_t framenum = PtrArray_getCount(self->frame);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame =
            (DkimVerificationFrame *) PtrArray_get(self->frame, frameidx);
        // skip verification frames with errors
        if (DSTAT_OK != frame->status) {
            continue;
        }   // end if

        frame->status =
            DkimDigester_verifyMessage(frame->digester, self->headers, frame->signature,
                                       DkimPublicKey_getPublicKey(frame->publickey));
    }   // end for

    return DSTAT_OK;
}   // end function: DkimVerifier_verify

/**
 * @param self DkimVerifier object
 * @return If verification process successfully completed, DKIM_SCORE_NULL is returned
 *         and call DkimVerifier_getFrameResult() for each result.
 *         Otherwise status code that indicates error.
 */
DkimBaseScore
DkimVerifier_getSessionResult(const DkimVerifier *self)
{
    assert(NULL != self);

    // check the status of whole of the verification process
    switch (self->status) {
    case DSTAT_OK:
        return DKIM_BASE_SCORE_NULL;
    case DSTAT_INFO_NO_SIGNHEADER:
        /*
         * "none" if no DKIM-Signature headers are found
         * [RFC5451] 2.4.1.
         * none:  The message was not signed.
         */
        return DKIM_BASE_SCORE_NONE;
    case DSTAT_SYSERR_NORESOURCE:
    default:
        return DKIM_BASE_SCORE_TEMPERROR;
    }   // end switch
}   // end function: DkimVerifier_getSessionResult

/**
 * perform ADSP check and return the result score of it.
 * @param self DkimVerifier object
 * @return ADSP score, or DKIM_ADSP_SCORE_NULL if a critical/system error occurred.
 */
DkimAdspScore
DkimVerifier_checkAdsp(DkimVerifier *self)
{
    assert(NULL != self);

    // return ADSP score cache if available
    if (DKIM_ADSP_SCORE_NULL != self->adsp_score) {
        return self->adsp_score;
    }   // end if

    // extract Author
    DkimStatus ext_stat = DkimAuthor_extract((const DkimPolicyBase *) self->vpolicy, self->headers,
                                             &(self->author_header_index),
                                             &(self->raw_author_field),
                                             &(self->raw_author_value), &(self->author));
    switch (ext_stat) {
    case DSTAT_OK:
        // Author header successfully extracted
        assert(NULL != self->author);
        break;
    case DSTAT_PERMFAIL_AUTHOR_AMBIGUOUS:
    case DSTAT_PERMFAIL_AUTHOR_UNPARSABLE:
        /*
         * "permerror" if no or multiple appropriate "Author" headers is found
         * [draft-kucherawy-sender-auth-header-20] 2.4.2.
         * permerror:  A DKIM policy could not be retrieved due to some error
         *    which is likely not transient in nature, such as a permanent DNS
         *    error.  A later attempt is unlikely to produce a final result.
         */
        return self->adsp_score = DKIM_ADSP_SCORE_PERMERROR;
    case DSTAT_SYSERR_NORESOURCE:
        DkimLogNoResource(self->vpolicy);
        return self->adsp_score = DKIM_ADSP_SCORE_NULL;
    default:
        abort();
    }   // end switch

    const char *author_domain = InetMailbox_getDomain(self->author);

    // aggregate the results of each verification frame
    bool have_author_signature = false;
    bool have_temporary_error = false;
    bool have_system_error = false;
    size_t framenum = PtrArray_getCount(self->frame);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame =
            (DkimVerificationFrame *) PtrArray_get(self->frame, frameidx);
        if (DSTAT_INFO_DIGEST_MATCH == frame->status) {
            /*
             * [RFC5617] 2.7.
             * An "Author Domain Signature" is a Valid Signature in which the domain
             * name of the DKIM signing entity, i.e., the d= tag in the DKIM-
             * Signature header field, is the same as the domain name in the Author
             * Address.  Following [RFC5321], domain name comparisons are case
             * insensitive.
             */
            const char *sdid = DkimSignature_getSdid(frame->signature);
            if (InetDomain_equals(sdid, author_domain)) {
                // Author Domain Signature (= First Party Signature)
                have_author_signature = true;
            } else {
                // Third Party Signature
                DkimLogInfo(self->vpolicy, "third party signature: sdid=%s, author=%s@%s", sdid,
                            InetMailbox_getLocalPart(self->author), author_domain);
            }   // end if
        } else if (DSTAT_ISTMPERR(frame->status)) {
            have_temporary_error = true;
        } else if (DSTAT_ISSYSERR(frame->status)) {
            have_system_error = true;
        }   // end if
    }   // end for

    if (have_author_signature) {
        /*
         * [draft-kucherawy-sender-auth-header-20] 2.4.2.
         * pass:  This message had an author signature which validated.  (An
         *    ADSP check is not strictly required to be performed for this
         *    result, since a valid author domain signature satisfies all
         *    possible ADSP policies.)
         */
        return self->adsp_score = DKIM_ADSP_SCORE_PASS;
    } else if (have_temporary_error || have_system_error) {
        // SPEC: dkim-adsp score on system error is "temperror"
        return self->adsp_score = DKIM_ADSP_SCORE_TEMPERROR;
    }   // end if

    // retrieving ADSP record if the message doesn't have an author domain signature
    if (NULL == self->adsp) {
        DkimStatus adsp_stat;
        self->adsp =
            DkimAdsp_lookup((const DkimPolicyBase *) self->vpolicy,
                            author_domain, self->resolver, &adsp_stat);
        switch (adsp_stat) {
        case DSTAT_OK:
            // do nothing
            break;
        case DSTAT_INFO_ADSP_NXDOMAIN:
            /*
             * A DNS query for Author Domain returns NXDOMAIN error.
             * [draft-kucherawy-sender-auth-header-20] 2.4.2.
             * nxdomain:  Evaluating the ADSP for the author's DNS domain indicated
             *    that the author's DNS domain does not exist.
             */
            DkimLogInfo(self->vpolicy, "Author domain seems not to exist (NXDOMAIN): domain=%s",
                        author_domain);
            return self->adsp_score = DKIM_ADSP_SCORE_NXDOMAIN;
        case DSTAT_INFO_ADSP_NOT_EXIST:
            /*
             * no valid ADSP records are found
             * [draft-kucherawy-sender-auth-header-20] 2.4.2.
             * none:  No DKIM author domain signing practises (ADSP) record was
             *    published.
             */
            DkimLogDebug(self->vpolicy, "no valid DKIM ADSP records are found: domain=%s",
                         author_domain);
            return self->adsp_score = DKIM_ADSP_SCORE_NONE;
        case DSTAT_PERMFAIL_MULTIPLE_ADSP_RECORD:
            /*
             * multiple ADSP records are found
             * [draft-kucherawy-sender-auth-header-20] 2.4.2.
             * permerror:  A DKIM policy could not be retrieved due to some error
             *    which is likely not transient in nature, such as a permanent DNS
             *    error.  A later attempt is unlikely to produce a final result.
             */
            DkimLogInfo(self->vpolicy, "multiple DKIM ADSP records are found: domain=%s",
                        author_domain);
            return self->adsp_score = DKIM_ADSP_SCORE_PERMERROR;
        case DSTAT_TMPERR_DNS_ERROR_RESPONSE:
        case DSTAT_SYSERR_DNS_LOOKUP_FAILURE:
            /*
             * temporary DNS error, DNS lookup failure
             * [draft-kucherawy-sender-auth-header-20] 2.4.2.]
             * temperror:  A DKIM policy could not be retrieved due to some error
             *    which is likely transient in nature, such as a temporary DNS
             *    error.  A later attempt may produce a final result.
             */
            DkimLogInfo(self->vpolicy,
                        "DNS lookup error has occurred while retrieving the ADSP record: domain=%s",
                        author_domain);
            return self->adsp_score = DKIM_ADSP_SCORE_TEMPERROR;
        case DSTAT_SYSERR_NORESOURCE:
            DkimLogSysError(self->vpolicy,
                            "System error occurred while retrieving the ADSP record: domain=%s",
                            author_domain);
            return DKIM_ADSP_SCORE_NULL;
        case DSTAT_SYSERR_IMPLERROR:
        default:
            DkimLogImplError
                (self->vpolicy,
                 "unexpected error occurred while retrieving the ADSP record: domain=%s, err=%s",
                 author_domain, DKIM_strerror(adsp_stat));
            return self->adsp_score = DKIM_ADSP_SCORE_TEMPERROR;
        }   // end switch
    }   // end if

    // log ADSP record
    DkimAdspPractice outbound_practice = DkimAdsp_getPractice(self->adsp);
    DkimLogDebug(self->vpolicy, "valid DKIM ADSP record is found: domain=%s, practice=%s",
                 author_domain, DkimEnum_lookupPracticeByValue(outbound_practice));

    // determine ADSP score according to outbound signing practice
    switch (outbound_practice) {
    case DKIM_ADSP_PRACTICE_ALL:
        /*
         * [RFC5617] 4.2.1.
         * all       All mail from the domain is signed with an Author
         *           Domain Signature.
         *
         * [draft-kucherawy-sender-auth-header-20] 2.4.2.
         * fail:  No valid author signature was found on the message and the
         *    published ASDP record indicated an "all" policy.
         */
        self->adsp_score = DKIM_ADSP_SCORE_FAIL;
        break;
    case DKIM_ADSP_PRACTICE_DISCARDABLE:
        /*
         * [RFC5617] 4.2.1.
         * discardable
         *              All mail from the domain is signed with an
         *              Author Domain Signature.  Furthermore, if a
         *              message arrives without a valid Author Domain
         *              Signature due to modification in transit,
         *              submission via a path without access to a
         *              signing key, or any other reason, the domain
         *              encourages the recipient(s) to discard it.
         *
         * [draft-kucherawy-sender-auth-header-20] 2.4.2.
         * discard:  No valid author signature was found on the message and the
         *    published ADSP record indicated a "discardable" policy.
         */
        self->adsp_score = DKIM_ADSP_SCORE_DISCARD;
        break;
    case DKIM_ADSP_PRACTICE_UNKNOWN:
        /*
         * [RFC5617] 4.2.1.
         * unknown   The domain might sign some or all email.
         *
         * [draft-kucherawy-sender-auth-header-20] 2.4.2.
         * unknown:  No valid author signature was found on the message and the
         *    published ADSP was "unknown".
         */
        self->adsp_score = DKIM_ADSP_SCORE_UNKNOWN;
        break;
    case DKIM_ADSP_PRACTICE_NULL:
    default:
        abort();
    }   // end switch

    return self->adsp_score;
}   // end function: DkimVerifier_checkAdsp

/**
 * return the number of DKIM signatures targeted to verify.
 * in other words, the number of DKIM verification frames.
 * @param self DkimVerifier object
 * @return the number of DKIM signatures targeted to verify.
 */
size_t
DkimVerifier_getFrameCount(const DkimVerifier *self)
{
    assert(NULL != self);
    return PtrArray_getCount(self->frame);
}   // end function: DkimVerifier_getFrameCount

/**
 * @param self DkimVerifier object
 */
static DkimBaseScore
DkimVerifier_getFrameScore(DkimVerificationFrame *frame)
{
    // If score is cached, return it
    if (DKIM_BASE_SCORE_NULL != frame->score) {
        return frame->score;
    }   // end if

    if (DSTAT_ISTMPERR(frame->status) || DSTAT_ISSYSERR(frame->status)) {
        return frame->score = DKIM_BASE_SCORE_TEMPERROR;
    }   // end if

    switch (frame->status) {
    case DSTAT_INFO_DIGEST_MATCH:
        /*
         * [RFC5451] 2.4.1.
         * pass:  The message was signed, the signature or signatures were
         *    acceptable to the verifier, and the signature(s) passed
         *    verification tests.
         */
        return frame->score = DKIM_BASE_SCORE_PASS;
    case DSTAT_PERMFAIL_SIGNATURE_DID_NOT_VERIFY:
    case DSTAT_PERMFAIL_BODY_HASH_DID_NOT_VERIFY:
        /*
         * [RFC5451] 2.4.1.
         * fail:  The message was signed and the signature or signatures were
         *    acceptable to the verifier, but they failed the verification
         *    test(s).
         */
        return frame->score = DKIM_BASE_SCORE_FAIL;
    default:
        /*
         * [RFC5451] 2.4.1.
         * neutral:  The message was signed but the signature or signatures
         *    contained syntax errors or were not otherwise able to be
         *    processed.  This result SHOULD also be used for other failures not
         *    covered elsewhere in this list.
         */
        return frame->score = DKIM_BASE_SCORE_NEUTRAL;
    }   // end switch
}   // end function: DkimVerifier_getFrameScore

/**
 * return the result of specified verification frame.
 * @param self DkimVerifier object
 */
DkimBaseScore
DkimVerifier_getFrameResult(const DkimVerifier *self, size_t signo, const InetMailbox **auid)
{
    assert(NULL != self);
    assert(NULL != auid);

    size_t framenum = PtrArray_getCount(self->frame);
    DkimVerificationFrame *frame = (DkimVerificationFrame *) PtrArray_get(self->frame, signo);
    DkimBaseScore rawscore;

    if (signo < framenum) {
        rawscore = DkimVerifier_getFrameScore(frame);
    } else if (signo < self->sigheader_num) {
        /*
         * SPEC: dkim score is "policy" if the number of DKIM-Signature header exceeds
         * its limit specified by DkimVerificationPolicy.
         *
         * [RFC5451] 2.4.1.
         * policy:  The message was signed but the signature or signatures were
         *    not acceptable to the verifier.
         */
        rawscore = DKIM_BASE_SCORE_POLICY;
    } else {
        abort();
    }   // end if

    *auid = (NULL != frame->signature ? DkimSignature_getAuid(frame->signature) : NULL);
    return rawscore;
}   // end function: DkimVerifier_getFrameResult

/**
 * @param self DkimVerifier object
 * @attention for debugging use only.
 * @attention must be called after DkimVerifier_setup() and before the first call of DkimVerifier_updateBody()
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 */
DkimStatus
DkimVerifier_enableC14nDump(DkimVerifier *self, const char *basedir, const char *prefix)
{
    assert(NULL != self);

    if (DSTAT_OK != self->status) {
        // do nothing
        return DSTAT_OK;
    }   // end if

    // Canonicalized messages vary from one DKIM-Signature header to another.
    // So canonicalized messages should be dumped for every verification frame.
    size_t framenum = PtrArray_getCount(self->frame);
    for (size_t frameidx = 0; frameidx < framenum; ++frameidx) {
        DkimVerificationFrame *frame =
            (DkimVerificationFrame *) PtrArray_get(self->frame, frameidx);
        char header_filename[MAXPATHLEN];
        char body_filename[MAXPATHLEN];

        if (DSTAT_OK != frame->status) {
            continue;
        }   // end if
        snprintf(header_filename, MAXPATHLEN, "%s/%s.%02zu.header", basedir, prefix, frameidx);
        snprintf(body_filename, MAXPATHLEN, "%s/%s.%02zu.body", basedir, prefix, frameidx);

        DkimStatus open_stat =
            DkimDigester_enableC14nDump(frame->digester, header_filename, body_filename);
        if (DSTAT_OK != open_stat) {
            return open_stat;
        }   // end if
    }   // end for
    return DSTAT_OK;
}   // end function: DkimVerifier_enableC14nDump

////////////////////////////////////////////////////////////////////////
// accessor

/**
 * @attention must be called after DkimVerifier_checkAdsp()
 * @param self DkimVerifier object
 */
const char *
DkimVerifier_getAuthorHeaderName(const DkimVerifier *self)
{
    assert(NULL != self);
    return self->raw_author_field;
}   // end function: DkimVerifier_getAuthorHeaderName

/**
 * @attention must be called after DkimVerifier_checkAdsp()
 * @param self DkimVerifier object
 */
const InetMailbox *
DkimVerifier_getAuthorMailbox(const DkimVerifier *self)
{
    assert(NULL != self);
    return self->author;
}   // end function: DkimVerifier_getAuthorMailbox
