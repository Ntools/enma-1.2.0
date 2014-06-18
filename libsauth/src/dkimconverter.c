/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimconverter.c 1365 2011-10-16 08:08:36Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: dkimconverter.c 1365 2011-10-16 08:08:36Z takahiko $");

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>

#include "dkimlogger.h"
#include "ptrop.h"
#include "pstring.h"
#include "xbuffer.h"
#include "xskip.h"

#include "dkim.h"
#include "dkimenum.h"
#include "dkimconverter.h"

/**
 * [RFC6376]
 * ALPHADIGITPS    =  (ALPHA / DIGIT / "+" / "/")
 * base64string    =  ALPHADIGITPS *([FWS] ALPHADIGITPS)
 *                    [ [FWS] "=" [ [FWS] "=" ] ]
 *
 * @param dstat a pointer to a variable to receive the status code if an error occurred.
 *              possible value of status codes are listed with error tags below.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
XBuffer *
DkimConverter_decodeBase64(const DkimPolicyBase *policy, const char *head, const char *tail,
                           const char **nextp, DkimStatus *dstat)
{

// *INDENT-OFF*

    static const unsigned char b64decmap[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff, 0xff, 0x3f,
        0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,

        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };

// *INDENT-ON*

    XBuffer *xbuf;
    const char *p = head;
    unsigned char stock_octet[3];
    size_t stock_b64len = 0;    // 読み込み済みだが，xbuf に格納していない base64 文字列の長さ

    // 必要に応じて拡張されるので，最初に確保する領域のサイズはざっくりでよい
    xbuf = XBuffer_new((tail - head) / 4 * 3);
    if (NULL == xbuf) {
        DkimLogNoResource(policy);
        SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
        return NULL;
    }   // end if

    while (p < tail && *p != '\0') {
        unsigned char octet = b64decmap[(const unsigned char) *p];
        if (0xff == octet) {
            // BASE64 文字ではない場合
            if (0 < XSkip_fws(p, tail, &p)) {
                // FWS なら FWS 部分をスキップししてループの先頭に戻る
                SETDEREF(nextp, p);
                continue;
            } else {
                // FWS でもない場合は BASE64 列の終了なのでループを抜ける
                break;
            }   // end if
        }   // end if

        // *p は BASE64 文字として読み込んだので, p を1バイト進める.
        ++p;

        switch (stock_b64len) {
        case 0:
            stock_octet[0] = octet << 2;
            stock_b64len = 1;
            break;

        case 1:
            stock_octet[0] |= (octet & 0x30) >> 4;
            stock_octet[1] = (octet & 0x0f) << 4;
            stock_b64len = 2;
            break;

        case 2:
            stock_octet[1] |= (octet & 0x3c) >> 2;
            stock_octet[2] = (octet & 0x03) << 6;
            stock_b64len = 3;
            break;

        case 3:
            stock_octet[2] |= octet & 0x3f;
            if (0 > XBuffer_appendBytes(xbuf, stock_octet, 3)) {
                DkimLogNoResource(policy);
                SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
                goto cleanup;
            }   // end if
            SETDEREF(nextp, p);
            stock_b64len = 0;
            break;

        default:
            abort();
        }   // end switch
    }   // end while

    switch (stock_b64len) {
    case 0:
    case 1:
        // 1バイトもストックがないので，何もしない
        break;

    case 2:
        // "==" が続くか否かに依らず，ストックを吐き出す
        if (0 > XBuffer_appendByte(xbuf, *stock_octet)) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if
        // '=' が2個続くはず
        if (0 >= XSkip_char(p, tail, '=', &p)) {
            // 本当は '=' で残りを埋める必要があるんだよ警告
            DkimLogInfo(policy, "missing padding \'=\' character: near %.50s", head);
        }   // end if
        XSkip_fws(p, tail, &p);
        if (0 >= XSkip_char(p, tail, '=', &p)) {
            // 本当は '=' で残りを埋める必要があるんだよ警告
            DkimLogInfo(policy, "missing padding \'=\' character: near %.50s", head);
        }   // end if
        XSkip_fws(p, tail, &p);
        SETDEREF(nextp, p);
        break;

    case 3:
        // '=' が続くか否かに依らず，ストックを吐き出す
        if (0 > XBuffer_appendBytes(xbuf, stock_octet, 2)) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if
        // '=' が1個続くはず
        if (0 >= XSkip_char(p, tail, '=', &p)) {
            // 本当は '=' で残りを埋める必要があるんだよ警告
            DkimLogInfo(policy, "missing trailing \'=\' character: near %.50s", head);
        }   // end if
        XSkip_fws(p, tail, &p);
        SETDEREF(nextp, p);
        break;

    default:
        abort();
    }   // end switch

    SETDEREF(dstat, DSTAT_OK);
    return xbuf;

  cleanup:
    XBuffer_free(xbuf);
    SETDEREF(nextp, head);
    return NULL;
}   // end function: DkimConverter_decodeBase64

/**
 * @param dstat a pointer to a variable to receive the status code if an error occurred.
 *              possible value of status codes are listed with error tags below.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
XBuffer *
DkimConverter_encodeBase64(const DkimPolicyBase *policy, const void *s, size_t size,
                           DkimStatus *dstat)
{
    assert(NULL != s);
    assert(0 < size);

// *INDENT-OFF*

    static const char b64encmap[] = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/',
    };

// *INDENT-ON*

    XBuffer *xbuf;
    size_t n;
    int ret;
    int stocklen = 0;
    unsigned char bit6 = 0, storebit = 0;
    const unsigned char *src = (const unsigned char *) s;

    xbuf = XBuffer_new(((size - 1) / 3 + 1) * 4);   // 確保する領域のサイズはざっくり
    if (NULL == xbuf) {
        DkimLogNoResource(policy);
        SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
        return NULL;
    }   // end if

    for (n = 0; n < size; ++n) {
        switch (stocklen) {
        case 0:
            bit6 = (src[n] >> 2) & 0x3f;
            storebit = (src[n] << 4) & 0x30;
            stocklen = 1;
            break;

        case 1:
            bit6 = storebit | ((src[n] >> 4) & 0x0f);
            storebit = (src[n] << 2) & 0x3c;
            stocklen = 2;
            break;

        case 2:
            bit6 = storebit | ((src[n] >> 6) & 0x03);
            storebit = src[n] & 0x3f;
            stocklen = 0;
            break;

        default:
            abort();
        }   // end switch

        ret = XBuffer_appendByte(xbuf, b64encmap[bit6]);
        if (0 > ret) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if

        if (stocklen == 0) {
            ret = XBuffer_appendByte(xbuf, b64encmap[storebit]);
            if (0 > ret) {
                DkimLogNoResource(policy);
                SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
                goto cleanup;
            }   // end if
        }   // end if
    }   // end for

    // 終端処理. 端数がある場合に "=" を付加する.
    switch (stocklen) {
    case 0:
        // do nothing
        break;

    case 1:
        ret = XBuffer_appendByte(xbuf, b64encmap[storebit]);
        if (0 > ret) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if

        ret = XBuffer_appendStringN(xbuf, "==", 2);
        if (0 > ret) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if
        break;

    case 2:
        ret = XBuffer_appendByte(xbuf, b64encmap[storebit]);
        if (0 > ret) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if

        ret = XBuffer_appendChar(xbuf, '=');
        if (0 > ret) {
            DkimLogNoResource(policy);
            SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
            goto cleanup;
        }   // end if
        break;

    default:
        abort();
    }   // end switch

    SETDEREF(dstat, DSTAT_OK);
    return xbuf;

  cleanup:
    XBuffer_free(xbuf);
    return NULL;
}   // end function: DkimConverter_encodeBase64

/**
 * 指定した文字を Local-part (RFC2821) とみなし,
 * Local-part に適合しない文字を dkim-quoted-printable でエンコードする.
 * @param dstat a pointer to a variable to receive the status code if an error occurred.
 *              possible value of status codes are listed with error tags below.
 * @error DSTAT_SYSERR_NORESOURCE memory allocation error
 */
XBuffer *
DkimConverter_encodeLocalpartToDkimQuotedPrintable(const DkimPolicyBase *policy, const void *s,
                                                   size_t size, DkimStatus *dstat)
{
    XBuffer *xbuf = XBuffer_new(size);  // 初期サイズは大体でよい
    const unsigned char *src;
    const unsigned char *tail = s + size;
    for (src = s; src < tail; ++src) {
        // Local-part に入るようにエンコードしたいので atext + '.'
        if (IS_ATEXT(*src) || '.' == *src) {
            XBuffer_appendChar(xbuf, *src);
        } else {
            XBuffer_appendFormatString(xbuf, "=%02X", *src);
        }   // end if
    }   // end for

    if (0 != XBuffer_status(xbuf)) {
        XBuffer_free(xbuf);
        DkimLogNoResource(policy);
        SETDEREF(dstat, DSTAT_SYSERR_NORESOURCE);
        return NULL;
    }   // end if
    SETDEREF(dstat, DSTAT_OK);
    return xbuf;
}   // end function: DkimConverter_encodeLocalpartToDkimQuotedPrintable

/*
 * 数字でない文字に遭遇するか, 指定した桁数に達する, オーバーフローする直前のいずれかの条件を満たすまで,
 * 文字列を数字だとみなしてパースする.
 * @param errptr エラー情報を返す. メモリの確保に失敗した場合は NULL をセットする.
 *               parse に失敗した場合は失敗した位置へのポインタを返す.
 * @return parse に成功した場合は 0 以上の値, 数字が1文字も含まれていない場合は -1.
 */
long long
DkimConverter_longlong(const char *head, const char *tail, unsigned int digits, const char **nextp)
{
    const char *p;
    static const long long multmax = LLONG_MAX / 10LL;
    long long v = 0LL, retv = -1LL;

    for (p = head; p < tail && isdigit(*p) && p < (head + digits); ++p) {
        // 10 倍しても安全か確認
        if (v > multmax) {
            // 10倍したらオーバーフローする
            break;
        }   // end if
        v *= 10LL;
        long long dec = (long long) (*p - '0');
        // 1の位を足しても安全か確認
        if (LLONG_MAX - v < dec) {
            // 1の位を足したらオーバーフローする
            break;
        }   // end if
        retv = v += dec;
    }   // end for
    SETDEREF(nextp, p);
    return retv;
}   // end function: DkimConverter_longlong
