/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfpra.c 1140 2009-08-29 15:41:08Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfpra.c 1140 2009-08-29 15:41:08Z takahiko $");

#include <assert.h>
#include <stdio.h>
#include <strings.h>

#include "ptrop.h"
#include "mailheaders.h"
#include "inetmailbox.h"
#include "xskip.h"
#include "sidf.h"
#include "sidfpolicy.h"
#include "sidflogger.h"

#define SIDF_PRA_RESENT_SENDER_HEADER "Resent-Sender"
#define SIDF_PRA_RESENT_FROM_HEADER "Resent-From"
#define SIDF_PRA_SENDER_HEADER "Sender"
#define SIDF_PRA_FROM_HEADER "From"

#define SIDF_PRA_RECEIVED_HEADER "Received"
#define SIDF_PRA_RETURN_PATH_HEADER "Return-Path"

static int
SidfPra_lookup(const SidfPolicy *policy, const MailHeaders *headers)
{
    bool multiple;
    int resent_sender_pos =
        MailHeaders_getNonEmptyHeaderIndex(headers, SIDF_PRA_RESENT_SENDER_HEADER, &multiple);
    int resent_from_pos =
        MailHeaders_getNonEmptyHeaderIndex(headers, SIDF_PRA_RESENT_FROM_HEADER, &multiple);

    if (0 <= resent_sender_pos) {
        if (0 <= resent_from_pos && resent_from_pos < resent_sender_pos) {
            for (int i = resent_from_pos + 1; i < resent_sender_pos; ++i) {
                const char *headerf, *headerv;
                MailHeaders_get(headers, i, &headerf, &headerv);
                if (0 == strcasecmp(headerf, SIDF_PRA_RECEIVED_HEADER)
                    || 0 == strcasecmp(headerf, SIDF_PRA_RETURN_PATH_HEADER)) {
                    // RFC4407 では, Resent-From と　Resent-Sender の間に
                    // Received や Return-Path ヘッダが存在する場合は step 2 に進めとあるが,
                    // ここでは Resent-From の存在を確認しているので, resent_from_pos を返せばよい.
                    return resent_from_pos;
                }   // end if
            }   // end for
        }   // end if
        return resent_sender_pos;
    }   // end if

    if (0 <= resent_from_pos) {
        return resent_from_pos;
    }   // end if

    int pos = MailHeaders_getNonEmptyHeaderIndex(headers, SIDF_PRA_SENDER_HEADER, &multiple);
    if (0 <= pos) {
        if (multiple) {
            SidfLogDebug(policy, "multiple Sender header found");
            return -1;
        }   // end if
        return pos;
    }   // end if

    pos = MailHeaders_getNonEmptyHeaderIndex(headers, SIDF_PRA_FROM_HEADER, &multiple);
    if (0 <= pos) {
        if (multiple) {
            SidfLogDebug(policy, "multiple From header found");
            return -1;
        }   // end if
        return pos;
    }   // end if

    SidfLogDebug(policy, "No (Resent-)Sender/From header found");
    return -1;
}   // end function: SidfPra_lookup

/**
 * PRA に従ってヘッダを選択する.
 * @param pra_index PRA によって選択されたヘッダへのインデックスを格納する変数へのポインタ.
 *                  該当するヘッダが存在しなかった場合は -1 が格納される.
 * @param pra_mailbox PRA によって選択されたヘッダのメールアドレスを保持する
 *                    InetMailbox オブジェクトを格納する変数へのポインタ.
 *                    該当するヘッダが存在しなかった場合, ヘッダが存在したがフォーマットが不正だった場合は NULL が格納される.
 * @return ヘッダの探索を完了した場合は true, 途中でエラーが発生した場合は false.
 */
bool
SidfPra_extract(const SidfPolicy *policy, const MailHeaders *headers, int *pra_index,
                InetMailbox **pra_mailbox)
{
    assert(NULL != headers);

    int index = SidfPra_lookup(policy, headers);
    *pra_index = index;
    if (index < 0) {
        SidfLogPermFail(policy, "No PRA header selected");
        *pra_mailbox = NULL;
        return true;
    }   // end if

    const char *headerf, *headerv;
    MailHeaders_get(headers, index, &headerf, &headerv);

    const char *p, *errptr = NULL;
    const char *headerv_tail = STRTAIL(headerv);
    XSkip_fws(headerv, headerv_tail, &p);
    InetMailbox *mailbox = InetMailbox_build2822Mailbox(p, headerv_tail, &p, &errptr);
    if (NULL == mailbox) {
        *pra_mailbox = NULL;
        if (NULL == p) {
            SidfLogNoResource(policy);
            return false;
        } else {
            SidfLogPermFail(policy, "PRA header violates 2822-mailbox format: %s: %s", headerf,
                            headerv);
            return true;
        }   // end if
    }   // end if

    XSkip_fws(p, headerv_tail, &p);
    if (p == headerv_tail) {
        *pra_mailbox = mailbox;
        return true;
    } else {
        SidfLogPermFail(policy, "PRA header violates 2822-mailbox format: %s: %s", headerf,
                        headerv);
        *pra_mailbox = NULL;
        InetMailbox_free(mailbox);
        return true;
    }   // end if
}   // end function: SidfPra_extract
