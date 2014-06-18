/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: authresult.c 1126 2009-08-20 02:44:19Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: authresult.c 1126 2009-08-20 02:44:19Z takahiko $");

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "loghandler.h"
#include "ptrop.h"
#include "stdaux.h"
#include "xbuffer.h"
#include "foldstring.h"
#include "xskip.h"
#include "inetmailbox.h"
#include "authresult.h"

#define AUTHRES_WIDTH	78
#define AUTHRES_DEFAULT_BUFLEN 256

/*
 * [RFC5451] 2.2.
 * authres-header = "Authentication-Results:" [CFWS] authserv-id
 *          [ CFWS version ]
 *          ( [CFWS] ";" [CFWS] "none" / 1*resinfo ) [CFWS] CRLF
 * authserv-id = dot-atom
 * version = 1*DIGIT [CFWS]
 * resinfo = [CFWS] ";" methodspec [ CFWS reasonspec ]
 *           *( CFWS propspec )
 * methodspec = [CFWS] method [CFWS] "=" [CFWS] result
 * reasonspec = "reason" [CFWS] "=" [CFWS] value
 * propspec = ptype [CFWS] "." [CFWS] property [CFWS] "=" pvalue
 * method = dot-atom [ [CFWS] "/" [CFWS] version ]
 * result = dot-atom
 * ptype = "smtp" / "header" / "body" / "policy"
 * property = dot-atom
 * pvalue = [CFWS] ( value / [ [ local-part ] "@" ] domain-name )
 *          [CFWS]
 */

const char *
AuthResult_getFieldName(void)
{
    return AUTHRESULTSHDR;
}   // end function : AuthResult_getFieldName

AuthResult *
AuthResult_new(void)
{
    AuthResult *self = FoldString_new(AUTHRES_WIDTH);
    if (NULL == self) {
        return NULL;
    }   // end if

    // 1 行あたり 78 byte を越えないように頑張る
    FoldString_setLineLengthLimits(self, AUTHRES_WIDTH);
    // folding の際に CR は使用しない
    FoldString_setFoldingCR(self, false);
    // "Authentication-Results: " の分のスペースを確保
    FoldString_consumeLineSpace(self, strlen(AUTHRESULTSHDR ": "));

    return self;
}   // end function : AuthResult_new

bool
AuthResult_appendAuthServId(AuthResult *self, const char *servid)
{
    // authserv-id
    return 0 == FoldString_appendBlock(self, true, servid) ? true : false;
}   // end function : AuthResult_appendAuthServId

bool
AuthResult_appendMethodSpec(AuthResult *self, const char *method, const char *result)
{
    // methodspec
    (void) FoldString_appendChar(self, false, ';');
    (void) FoldString_appendFormatBlock(self, true, " %s=%s", method, result);
    return EOK == FoldString_status(self) ? true : false;
}   // end function : AuthResult_appendMethodSpec

bool
AuthResult_appendPropSpecWithToken(AuthResult *self, const char *ptype, const char *property,
                                   const char *value)
{
    // propspec
    return 0 == FoldString_appendFormatBlock(self, true, " %s.%s=%s", ptype, property,
                                             value) ? true : false;
}   // end function : AuthResult_appendPropSpecWithToken

bool
AuthResult_appendPropSpecWithAddrSpec(AuthResult *self, const char *ptype, const char *property,
                                      const InetMailbox *mailbox)
{
    assert(NULL != mailbox);

    XBuffer *buf = XBuffer_new(AUTHRES_DEFAULT_BUFLEN);
    if (NULL == buf) {
        return false;
    }   // end if
    int write_stat = InetMailbox_writeMailbox(mailbox, buf);
    if (EOK != write_stat) {
        goto cleanup;
    }   // end if

    bool append_stat =
        AuthResult_appendPropSpecWithToken(self, ptype, property, XBuffer_getString(buf));
    XBuffer_free(buf);
    return append_stat;

  cleanup:
    XBuffer_free(buf);
    return false;
}   // end function : AuthResult_appendPropSpecWithMailbox

/**
 * Authentication-Results ヘッダのフィールド値に含まれる authserv-id が servid に一致するか調べる.
 * @param field Authentication-Results ヘッダの値部分
 * @param servid 削除対象の条件とするホスト名
 * @return ホスト名が一致した場合は真, 一致しなかった場合は偽
 */
bool
AuthResult_compareAuthservId(const char *field, const char *servid)
{
    // Authentication-Results 全体の終端
    const char *field_tail = STRTAIL(field);

    // Authentication-Results ヘッダから authserv-id を抜き出す
    const char *servid_head, *servid_tail;
    (void) XSkip_cfws(field, field_tail, &servid_head);
    if (0 >= XSkip_dotAtomText(servid_head, field_tail, &servid_tail)) {
        // authserv-id が dot-atom-text ではない
        LogDebug("authserv-id doesn't seem dot-atom-text: field=%s", field);
        return false;
    }   // end if

    // dot-atom-text の後で単語が切れていることを確認する.
    // 古い Authentication-Results のヘッダの仕様では authserv_id の後は CFWS だったので,
    // authserv_id の後に CFWS がある場合は ';' がなくても authserv_id であると見なす.
    const char *tail;
    if (servid_tail == field_tail || 0 < XSkip_cfws(servid_tail, field_tail, &tail)
        || 0 < XSkip_char(tail, field_tail, ';', &tail)) {
        // Authentication-Results ヘッダから抜き出した authserv-id と servid を比較する.
        const char *nextp;
        XSkip_casestring(servid_head, servid_tail, servid, &nextp);
        return servid_tail == nextp ? true : false;
    }   // end if

    LogDebug("authserv-id doesn't seem dot-atom-text: field=%s", field);
    return false;
}   // end function : AuthResult_compareAuthservId
