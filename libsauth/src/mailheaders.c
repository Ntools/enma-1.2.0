/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: mailheaders.c 1144 2009-08-29 18:07:12Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: mailheaders.c 1144 2009-08-29 18:07:12Z takahiko $");

#include <assert.h>
#include <sys/types.h>
#include <strings.h>

#include "ptrop.h"
#include "xskip.h"
#include "strpairarray.h"
#include "mailheaders.h"

/**
 * create MailHeaders object
 * @return initialized MailHeaders object, or NULL if memory allocation failed.
 */
MailHeaders *
MailHeaders_new(size_t size)
{
    return StrPairArray_new(size);
}   // end function: MailHeaders_new

/**
 * MailHeader オブジェクトから最初に fieldname にマッチするヘッダへのインデックスを返す.
 * @param multiple マッチするヘッダが複数存在することを示すフラグを受け取る変数へのポインタ.
 * @return fieldname に最初にマッチしたヘッダへのインデックス. 見つからなかった場合は -1.
 *
 */
static int
MailHeaders_getHeaderIndexImpl(const MailHeaders *self, const char *fieldname,
                               bool ignore_empty_header, bool *multiple)
{
    int keyindex = -1;
    int headernum = MailHeaders_getCount(self);
    for (int i = 0; i < headernum; ++i) {
        const char *headerf, *headerv;
        MailHeaders_get(self, i, &headerf, &headerv);
        if (0 != strcasecmp(headerf, fieldname)) {
            continue;
        }   // end if

        // Header Field Name が一致した

        if (ignore_empty_header) {
            // Header Field Value が non-empty であることを確認する

            // [RFC4407 2.]
            // For the purposes of this algorithm, a header field is "non-empty" if
            // and only if it contains any non-whitespace characters.  Header fields
            // that are otherwise relevant but contain only whitespace are ignored
            // and treated as if they were not present.

            const char *nextp;
            const char *headerv_tail = STRTAIL(headerv);
            XSkip_fws(headerv, headerv_tail, &nextp);
            if (nextp == headerv_tail) {
                // empty header は無視する
                continue;
            }   // end if
        }   // end if

        if (0 <= keyindex) {
            // 2個目のヘッダが見つかった
            *multiple = true;
            return keyindex;
        }   // end if

        keyindex = i;
        // 他にもマッチするヘッダが存在しないか確かめるため, 検索は続行
    }   // end for

    *multiple = false;
    return keyindex;
}   // end function: MailHeaders_getHeaderIndexImpl

/**
 * MailHeader オブジェクトから最初に fieldname にマッチするヘッダへのインデックスを返す.
 * @param multiple マッチするヘッダが複数存在することを示すフラグを受け取る変数へのポインタ.
 * @return fieldname に最初にマッチしたヘッダへのインデックス. 見つからなかった場合は -1.
 * TODO: ユニットテスト
 */
int
MailHeaders_getHeaderIndex(const MailHeaders *self, const char *fieldname, bool *multiple)
{
    assert(NULL != self);
    assert(NULL != fieldname);

    return MailHeaders_getHeaderIndexImpl(self, fieldname, false, multiple);
}   // end function: MailHeaders_getHeaderIndex

/**
 * MailHeader オブジェクトから最初に fieldname にマッチする空でないヘッダへのインデックスを返す.
 * @param multiple マッチするヘッダが複数存在することを示すフラグを受け取る変数へのポインタ.
 * @return fieldname に最初にマッチしたヘッダへのインデックス. 見つからなかった場合は -1.
 * TODO: ユニットテスト
 */
int
MailHeaders_getNonEmptyHeaderIndex(const MailHeaders *self, const char *fieldname, bool *multiple)
{
    assert(NULL != self);
    assert(NULL != fieldname);

    return MailHeaders_getHeaderIndexImpl(self, fieldname, true, multiple);
}   // end function: MailHeaders_getNonEmptyHeaderIndex
