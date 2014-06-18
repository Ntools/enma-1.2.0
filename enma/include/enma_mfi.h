/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_mfi.h 654 2009-02-28 20:46:58Z takahiko $
 */

#ifndef __ENMA_MFI_H__
#define __ENMA_MFI_H__

#include <stdbool.h>
#include <libmilter/mfapi.h>

extern bool EnmaMfi_init(char *socket, int timeout, int loglevel);
extern sfsistat mfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr);
extern sfsistat mfi_helo(SMFICTX *ctx, char *helohost);
extern sfsistat mfi_envfrom(SMFICTX *ctx, char **argv);
extern sfsistat mfi_envrcpt(SMFICTX *ctx, char **argv);
extern sfsistat mfi_header(SMFICTX *ctx, char *headerf, char *headerv);
extern sfsistat mfi_eoh(SMFICTX *ctx);
extern sfsistat mfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen);
extern sfsistat mfi_eom(SMFICTX *ctx);
extern sfsistat mfi_abort(SMFICTX *ctx);
extern sfsistat mfi_close(SMFICTX *ctx);

#endif
