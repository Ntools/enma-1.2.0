/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfenum.c 1140 2009-08-29 15:41:08Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: sidfenum.c 1140 2009-08-29 15:41:08Z takahiko $");

#include <stdio.h>
#include <string.h>

#include "keywordmap.h"
#include "sidf.h"
#include "sidfenum.h"

static const KeywordMap sidf_score_tbl[] = {
    {"none", SIDF_SCORE_NONE},
    {"neutral", SIDF_SCORE_NEUTRAL},
    {"pass", SIDF_SCORE_PASS},
    {"policy", SIDF_SCORE_POLICY},
    {"hardfail", SIDF_SCORE_HARDFAIL},
    {"softfail", SIDF_SCORE_SOFTFAIL},
    {"temperror", SIDF_SCORE_TEMPERROR},
    {"permerror", SIDF_SCORE_PERMERROR},
    {"syserror", SIDF_SCORE_SYSERROR},  // logging use only, not as a final score
    {NULL, SIDF_SCORE_NULL},
};

////////////////////////////////////////////////////////////

SidfScore
SidfEnum_lookupScoreByKeyword(const char *keyword)
{
    return (SidfScore) KeywordMap_lookupByCaseString(sidf_score_tbl, keyword);
}   // end function: SidfEnum_lookupScoreByKeyword

SidfScore
SidfEnum_lookupScoreByKeywordSlice(const char *head, const char *tail)
{
    return (SidfScore) KeywordMap_lookupByCaseStringSlice(sidf_score_tbl, head, tail);
}   // end function: SidfEnum_lookupScoreByKeywordSlice

const char *
SidfEnum_lookupScoreByValue(SidfScore value)
{
    return KeywordMap_lookupByValue(sidf_score_tbl, value);
}   // end function: SidfEnum_lookupScoreByValue

////////////////////////////////////////////////////////////
