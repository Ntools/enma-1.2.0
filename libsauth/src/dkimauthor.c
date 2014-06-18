/*
 * Copyright (c) 2006-2010 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimauthor.c 1366 2011-10-16 08:13:40Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimauthor.c 1366 2011-10-16 08:13:40Z takahiko $");

#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

#include "dkimlogger.h"
#include "inetmailbox.h"
#include "ptrop.h"
#include "xskip.h"
#include "strarray.h"
#include "dkim.h"
#include "dkimpolicybase.h"
#include "mailheaders.h"

/**
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_AUTHOR_UNPARSABLE unable to parse Author header field value
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
static DkimStatus
DkimAuthor_parse(const DkimPolicyBase *policy, const char *head, const char *tail,
                 InetMailbox **mailbox)
{
    assert(NULL != head);
    assert(NULL != tail);
    assert(NULL != mailbox);

    const char *p, *errptr;
    InetMailbox *build_mailbox = InetMailbox_build2822Mailbox(head, tail, &p, &errptr);

    if (NULL == build_mailbox) {
        if (NULL != errptr) {   // parse error
            DkimLogPermFail(policy, "Mailbox parse error: near %.50s", p);
            return DSTAT_PERMFAIL_AUTHOR_UNPARSABLE;
        } else {    // memory allocation error
            DkimLogNoResource(policy);
            return DSTAT_SYSERR_NORESOURCE;
        }   // end if
    }   // end if

    XSkip_fws(p, tail, &p); // ignore trailing FWS
    if (p == tail) {
        *mailbox = build_mailbox;
        return DSTAT_OK;
    } else {
        // Though the parsing has succeeded, unmatched sequence has been left.
        DkimLogPermFail(policy, "Author field has unused portion: %d bytes, near %.50s", tail - p,
                        head);
        InetMailbox_free(build_mailbox);
        return DSTAT_PERMFAIL_AUTHOR_UNPARSABLE;
    }   // end if
}   // end function: DkimAuthor_parse

/**
 * @param header_index A pointer to a variable to receive the index of the header field
 *                     extracted as "Author" in the "headers" object.
 *                     Undefined if the return value is not DSTAT_OK.
 * @param header_field A pointer to a variable to receive the header field name
 *                     in the "headers" object.
 *                     Undefined if the return value is not DSTAT_OK.
 * @param header_value A pointer to a variable to receive the header field value
 *                     in the "headers" object.
 *                     Undefined if the return value is not DSTAT_OK.
 * @param mailbox A pointer to a variable to receive the InetMailbox object
 *                build from the extracted "Author" header.
 *                Undefined if the return value is not DSTAT_OK.
 * @return DSTAT_OK for success, otherwise status code that indicates error.
 * @error DSTAT_PERMFAIL_AUTHOR_AMBIGUOUS No or multiple Author headers are found
 * @error DSTAT_PERMFAIL_AUTHOR_UNPARSABLE unable to parse Author header field value
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
DkimStatus
DkimAuthor_extract(const DkimPolicyBase *policy, const MailHeaders *headers, size_t *header_index,
                   const char **header_field, const char **header_value, InetMailbox **mailbox)
{
    assert(NULL != policy);
    assert(NULL != headers);
    assert(NULL != mailbox);

    size_t num = StrArray_getCount(policy->author_priority);
    for (size_t i = 0; i < num; ++i) {
        const char *targetField = StrArray_get(policy->author_priority, i);

        bool multiple;
        int index = MailHeaders_getHeaderIndex(headers, targetField, &multiple);
        if (index < 0) {
            // No headers looking for are found. Try next "Author"-candidate header.
            continue;
        }   // end if
        if (multiple) {
            // Multiple "Author"-candidate headers are found. It must be unique.
            DkimLogPermFail(policy, "Multiple %s Header is found, unable to extract Author",
                            targetField);
            return DSTAT_PERMFAIL_AUTHOR_AMBIGUOUS;
        }   // end if

        // An unique "Author" header is found.

        // Extracts "mailbox" by parsing the found "Author" header.
        const char *headerf, *headerv;
        MailHeaders_get(headers, index, &headerf, &headerv);
        DkimStatus dstat = DkimAuthor_parse(policy, headerv, STRTAIL(headerv), mailbox);
        if (DSTAT_OK == dstat) {
            // set the references to the original values if the parsing has succeeded.
            SETDEREF(header_index, index);
            SETDEREF(header_field, headerf);
            SETDEREF(header_value, headerv);
        }   // end if
        // If the parsing fails, this function returns an error
        // whether or not next "Author"-candidate header is found.
        return dstat;
    }   // end for

    DkimLogPermFail(policy, "No Author header found");
    return DSTAT_PERMFAIL_AUTHOR_AMBIGUOUS;
}   // end function: DkimAuthor_extract
