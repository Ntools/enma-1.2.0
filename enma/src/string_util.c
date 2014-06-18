/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: string_util.c 1465 2011-12-21 11:58:27Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: string_util.c 1465 2011-12-21 11:58:27Z takahiko $");

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "string_util.h"


/**
 * Convert a string to a long integer (about the same strtol())
 *   differences:
 *     - does not allowed white space
 *     - only use decimal number
 *
 * @param string
 * @param errflag
 * @return
 */
long int
strtolstrict(const char *string, bool *errflag)
{
    if (0 == strlen(string) || isspace(*string)) {
        // string is empty or included leading spaces
        *errflag = true;
        return 0;
    }

    char *endptr;
    errno = 0;
    long int parsed_long = strtol(string, &endptr, 10);
    if ('\0' != *endptr) {
        *errflag = true;
        return 0;
    }
    if (EINVAL == errno || ERANGE == errno || (0 != errno && 0 == parsed_long)) {
        *errflag = true;
        return 0;
    }

    *errflag = false;
    return parsed_long;
}

/**
 * remove leading spaces
 *
 * @param string
 * @return
 */
char *
strlstrip(char *string)
{
    assert(NULL != string);

    char *start = string;
    // skip leading spaces
    for (; '\0' != *start && isspace((int) (*start)); ++start);
    memmove(string, start, strlen(start) + 1);

    return string;
}


/**
 * remove trailing spaces
 *
 * @param string
 * @return
 */
char *
strrstrip(char *string)
{
    assert(NULL != string);

    char *end = string + strlen(string) - 1;

    for (; string <= end && isspace((int) (*end)); --end);
    *(end + 1) = '\0';

    return string;
}


/**
 * remove leading and trailing spaces
 *
 * @param string
 * @return
 */
char *
strstrip(char *string)
{
    assert(NULL != string);

    return strlstrip(strrstrip(string));
}
