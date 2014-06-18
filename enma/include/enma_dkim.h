/*
 * Copyright (c) 2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_dkim.h 1098 2009-08-03 02:20:19Z takahiko $
 */

#ifndef __ENMA_DKIM_H__
#define __ENMA_DKIM_H__

#include <stdbool.h>

#include "dkim.h"
#include "authresult.h"

extern bool EnmaDkim_evaluate(DkimVerifier *dkimverifier, AuthResult *authresult);
extern bool EnmaDkimAdsp_evaluate(DkimVerifier *dkimverifier, AuthResult *authresult);

#endif /* __ENMA_DKIM_H__ */
