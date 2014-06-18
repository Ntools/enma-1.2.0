/*
 * Copyright (c) 2006-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimtaglistobject.h 1368 2011-11-07 02:09:09Z takahiko $
 */

#ifndef __DKIM_TAGLISTOBJECT_H__
#define __DKIM_TAGLISTOBJECT_H__

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>   // as a substitute for stdint.h (Solaris 9 doesn't have)

#include "dkim.h"
#include "dkimpolicybase.h"

typedef struct DkimTagListObject DkimTagListObject;

typedef struct DkimTagParseContext {
    int tag_no;                 // The number of tag-value pair processing currently (0-oriented). -1 is used at applying default value.
    const char *tag_head;       // pointer to the head of the tag name
    const char *tag_tail;       // pointer to the tail of the tag name
    const char *value_head;     // pointer to the head of the tag value
    const char *value_tail;     // pointer to the tail of the tag value
} DkimTagParseContext;

typedef const struct DkimTagListObjectFieldMap {
    const char *tagname;
    DkimStatus (*tagparser) (DkimTagListObject *self, const DkimTagParseContext *context,
                             const char **nextp);
    bool required;
    const char *default_value;
    uint32_t parsed_mask;
} DkimTagListObjectFieldMap;

#define DkimTagListObject_MEMBER        \
    DkimTagListObjectFieldMap *ftbl;    \
    const DkimPolicyBase *policy;       \
    uint32_t parsed_flag

struct DkimTagListObject {
    DkimTagListObject_MEMBER;
};

extern DkimStatus DkimTagListObject_build(DkimTagListObject *self, const char *record_head,
                                          const char *record_tail, bool wsp_restriction);

#define DKIM_TAGLISTOBJECT_TAG_NO_AS_DEFAULT_VALUE -1

#endif /* __DKIM_TAGLISTOBJECT_H__ */
