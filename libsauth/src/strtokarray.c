/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: strtokarray.c 1176 2009-09-03 19:39:19Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: strtokarray.c 1176 2009-09-03 19:39:19Z takahiko $");

#include <string.h>
#include <stdlib.h>

#include "strtokarray.h"

/**
 * 文字列 s 中に存在する文字 c の数を数える
 * @param s 被調査対象の文字列
 * @param c 調査対象の文字
 * @return 文字列 s 中に存在する文字 c の数
 */
size_t
strccount(const char *s, char c)
{
    int n;

    for (n = 0; *s != '\0'; ++s)
        if (*s == c)
            ++n;
    return n;
}   // end function: strcount

/**
 * 与えられた文字列の領域をセパレーターで区切り，2次元配列を構築する．
 * s 内の sep を NULL で置き換え，各要素の先頭を示すポインタからなる配列を返す．
 * @param s sep によって区切られた文字列
 * @param sep セパレーター
 * @attention s は上書きされる
 * @attention The returned string should be released with free() when no longer needed.
 */
char **
strtokarray(char *s, char sep)
{
    size_t n;
    int i = 0;
    char *last;
    char **r;
    char psep[2];

    // メモリの確保
    n = strccount(s, sep) + 2;  // 配列のサイズを見積もる
    r = (char **) malloc(n * sizeof(char *));
    if (NULL == r)
        return NULL;

    psep[0] = sep;
    psep[1] = '\0';

    r[i] = strtok_r(s, psep, &last);
    while (r[i]) {
        r[++i] = strtok_r(NULL, psep, &last);
    }   // end while
    return r;
}   // end function: strtokarray
