/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: inetdomain.c 1151 2009-08-30 06:00:39Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: inetdomain.c 1151 2009-08-30 06:00:39Z takahiko $");

#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include "inetdomain.h"

/**
 * 上から指定した深さのドメインを切り出す
 * @param depth 切り出すドメインの深さ，1以上を指定すること
 * @return domain のうち, 指定した深さのドメインを示すような文字列へのポインタ
 */
const char *
InetDomain_parent(const char *domain, size_t depth)
{
    assert(NULL != domain);
    assert(0 < depth);

    const char *p = domain + strlen(domain) - 1;    // p を domain の末尾に移動する
    if (p < domain) {   // 長さ 0 の文字列を排除
        return domain;
    }   // end if
    if ('.' == *p) {    // 末尾の '.' は数に入れない
        --p;
    }   // end if

    for (; 0 < depth && domain <= p; --p) { // domain の先頭に達するか
        if ('.' == *p && 0 == --depth) {    // '.' が depth 回出現したら終了
            break;
        }   // end if
    }   // end for

    return p + 1;
}   // end function: InetDomain_parent

/**
 * return a reference to the immediate parent domain
 * @param domain target domain
 * @return pointer to the substring of "domain" represents immediate parent domain of "domain"
 *         NULL if "domain" doen't have parent domain (e.g. top-level domain)
 */
const char *
InetDomain_upward(const char *domain)
{
    assert(NULL != domain);
    const char *p = strchr(domain, '.');
    return (NULL != p && '\0' != *(p + 1)) ? p + 1 : NULL;
}   // end function: InetDomain_upward

/*
 * check if parent_domain is parent domain of child_domain
 * @return true if parent_domain is parent of or same as child_domain domain,
 *         false otherwise
 */
bool
InetDomain_isParent(const char *parent_domain, const char *child_domain)
{
    size_t parentlen = strlen(parent_domain);
    if ('.' == parent_domain[parentlen - 1]) {
        --parentlen;
    }   // end if

    size_t childlen = strlen(child_domain);
    const char *childpart = child_domain + childlen - parentlen;
    if ('.' == child_domain[childlen - 1]) {
        --childpart;
    }   // end if

    if (childpart < child_domain) {
        return false;
    }   // end if

    if (0 != strncasecmp(childpart, parent_domain, parentlen)) {
        return false;
    }   // end if

    if (child_domain < childpart && '.' != *(childpart - 1)) {
        return false;
    }   // end if

    return true;
}   // end function: InetDomain_isParent

/*
 * check if domain1 and domain2 are same domain
 * @return true if domain1 and domain2 are same domain, false otherwise.
 */
bool
InetDomain_equals(const char *domain1, const char *domain2)
{
    size_t domlen1 = strlen(domain1);
    if ('.' == domain1[domlen1 - 1]) {
        --domlen1;
    }   // end if

    size_t domlen2 = strlen(domain2);
    if ('.' == domain2[domlen2 - 1]) {
        --domlen2;
    }   // end if

    if (domlen1 != domlen2) {
        return false;
    }   // end if

    if (0 != strncasecmp(domain1, domain2, domlen1)) {
        return false;
    }   // end if

    return true;
}   // end function: InetDomain_equals
