/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: foldstring.h 1144 2009-08-29 18:07:12Z takahiko $
 */

#ifndef __FOLDSTRING_H__
#define __FOLDSTRING_H__

#include <sys/types.h>
#include <stdbool.h>

struct FoldString;
typedef struct FoldString FoldString;

extern FoldString *FoldString_new(size_t size);
extern void FoldString_free(FoldString *self);
extern void FoldString_reset(FoldString *self);
extern int FoldString_status(const FoldString *self);
extern void FoldString_setGrowth(FoldString *self, size_t growth);
extern int FoldString_folding(FoldString *self);
extern int FoldString_reserve(FoldString *self, size_t size);
extern int FoldString_precede(FoldString *self, size_t size);
extern int FoldString_appendChar(FoldString *self, bool permitPrefolding, char c);
extern int FoldString_appendBlock(FoldString *self, bool permitPrefolding, const char *s);
extern int FoldString_appendNonBlock(FoldString *self, bool permitPrefolding, const char *s);
extern int FoldString_appendFormatBlock(FoldString *self, bool permitPrefolding,
                                        const char *format, ...)
    __attribute__ ((format(printf, 3, 4)));
extern void FoldString_setLineLengthLimits(FoldString *self, size_t limits);
extern void FoldString_consumeLineSpace(FoldString *self, size_t size);
extern void FoldString_setFoldingCR(FoldString *self, bool cr);
extern const char *FoldString_getString(const FoldString *self);
extern size_t FoldString_getSize(const FoldString *self);

#endif /* __FOLDSTRING_H__ */
