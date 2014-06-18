/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfenum.h 586 2009-01-24 15:19:26Z takahiko $
 */

#ifndef __SIDFENUM_H__
#define __SIDFENUM_H__

#include "sidf.h"

typedef enum SidfQualifier {
    SIDF_QUALIFIER_NULL = 0,
    SIDF_QUALIFIER_PLUS = SIDF_SCORE_PASS,
    SIDF_QUALIFIER_MINUS = SIDF_SCORE_HARDFAIL,
    SIDF_QUALIFIER_QUESTION = SIDF_SCORE_NEUTRAL,
    SIDF_QUALIFIER_TILDE = SIDF_SCORE_SOFTFAIL,
} SidfQualifier;

typedef enum SidfTermType {
    SIDF_TERM_MECH_NULL = 0,
    SIDF_TERM_MECH_ALL,
    SIDF_TERM_MECH_INCLUDE,
    SIDF_TERM_MECH_A,
    SIDF_TERM_MECH_MX,
    SIDF_TERM_MECH_PTR,
    SIDF_TERM_MECH_IP4,
    SIDF_TERM_MECH_IP6,
    SIDF_TERM_MECH_EXISTS,
    SIDF_TERM_MOD_REDIRECT,
    SIDF_TERM_MOD_EXPLANATION,
    SIDF_TERM_MOD_UNKNOWN,
} SidfTermType;

typedef enum SidfMechanismType {
    SIDF_MECHANISM_NULL = 0,
    SIDF_MECHANISM_ALL = SIDF_TERM_MECH_ALL,
    SIDF_MECHANISM_INCLUDE = SIDF_TERM_MECH_INCLUDE,
    SIDF_MECHANISM_A = SIDF_TERM_MECH_A,
    SIDF_MECHANISM_MX = SIDF_TERM_MECH_MX,
    SIDF_MECHANISM_PTR = SIDF_TERM_MECH_PTR,
    SIDF_MECHANISM_IP4 = SIDF_TERM_MECH_IP4,
    SIDF_MECHANISM_IP6 = SIDF_TERM_MECH_IP6,
    SIDF_MECHANISM_EXISTS = SIDF_TERM_MECH_EXISTS,
} SidfMechanism;

typedef enum SidfModifierType {
    SIDF_MODIFIER_NULL = 0,
    SIDF_MODIFIER_REDIRECT = SIDF_TERM_MOD_REDIRECT,
    SIDF_MODIFIER_EXPLANATION = SIDF_TERM_MOD_EXPLANATION,
    SIDF_MODIFIER_UNKNOWN = SIDF_TERM_MOD_UNKNOWN,
} SidfModifierType;

typedef enum SidfMacroLetter {
    SIDF_MACRO_NULL = 0,
    SIDF_MACRO_S_SENDER,
    SIDF_MACRO_L_SENDER_LOCALPART,
    SIDF_MACRO_O_SENDER_DOMAIN,
    SIDF_MACRO_D_DOMAIN,
    SIDF_MACRO_I_DOTTED_IPADDR,
    SIDF_MACRO_P_IPADDR_VALID_DOMAIN,
    SIDF_MACRO_V_REVADDR_SUFFIX,
    SIDF_MACRO_H_HELO_DOMAIN,
    SIDF_MACRO_C_TEXT_IPADDR,
    SIDF_MACRO_R_CHECKING_DOMAIN,
    SIDF_MACRO_T_TIMESTAMP,
} SidfMacroLetter;

typedef enum SidfTermParamType {
    SIDF_TERM_PARAM_NONE,
    SIDF_TERM_PARAM_DOMAINSPEC,
    SIDF_TERM_PARAM_IP4,
    SIDF_TERM_PARAM_IP6,
} SidfTermParamType;

#endif /* __SIDFENUM_H__ */
