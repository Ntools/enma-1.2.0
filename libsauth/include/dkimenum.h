/*
 * Copyright (c) 2006-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dkimenum.h 1225 2009-09-13 07:52:00Z takahiko $
 */

#ifndef __DKIM_ENUM_H__
#define __DKIM_ENUM_H__

typedef enum DkimC14nAlgorithm {
    DKIM_C14N_ALGORITHM_NULL = 0,
    DKIM_C14N_ALGORITHM_SIMPLE,
    DKIM_C14N_ALGORITHM_RELAXED,
    DKIM_C14N_ALGORITHM_NOWSP,  // obsolete
    DKIM_C14N_ALGORITHM_ANY = 0xffffffff,
} DkimC14nAlgorithm;

typedef enum DkimKeyType {
    DKIM_KEY_TYPE_NULL = 0,
    DKIM_KEY_TYPE_RSA,
    DKIM_KEY_TYPE_ANY = 0xffffffff,
} DkimKeyType;

typedef enum DkimHashAlgorithm {
    DKIM_HASH_ALGORITHM_NULL = 0x00,
    DKIM_HASH_ALGORITHM_SHA1 = 0x01,
    DKIM_HASH_ALGORITHM_SHA256 = 0x02,
    DKIM_HASH_ALGORITHM_ANY = 0xffffffff,
} DkimHashAlgorithm;

typedef enum DkimServiceType {
    DKIM_SERVICE_TYPE_NULL = 0x00,
    DKIM_SERVICE_TYPE_EMAIL = 0x01,
    DKIM_SERVICE_TYPE_ANY = 0xffffffff,
} DkimServiceType;

typedef enum DkimSelectorFlag {
    DKIM_SELECTOR_FLAG_NULL = 0x00,
    DKIM_SELECTOR_FLAG_TESTING = 0x01,
    DKIM_SELECTOR_FLAG_PROHIBIT_SUBDOMAIN = 0x02,
} DkimSelectorFlag;

typedef enum DkimQueryMethod {
    DKIM_QUERY_METHOD_NULL = 0,
    DKIM_QUERY_METHOD_DNS_TXT,
} DkimQueryMethod;

typedef enum DkimAdspPractice {
    DKIM_ADSP_PRACTICE_NULL = 0,
    DKIM_ADSP_PRACTICE_UNKNOWN,
    DKIM_ADSP_PRACTICE_ALL,
    DKIM_ADSP_PRACTICE_DISCARDABLE,
} DkimAdspPractice;

extern DkimC14nAlgorithm DkimEnum_lookupC14nAlgorithmByName(const char *keyword);
extern DkimC14nAlgorithm DkimEnum_lookupC14nAlgorithmByNameSlice(const char *head,
                                                                 const char *tail);
extern const char *DkimEnum_lookupC14nAlgorithmByValue(DkimC14nAlgorithm value);

extern DkimKeyType DkimEnum_lookupKeyTypeByName(const char *keyword);
extern DkimKeyType DkimEnum_lookupKeyTypeByNameSlice(const char *head, const char *tail);
extern const char *DkimEnum_lookupKeyTypeByValue(DkimKeyType value);

extern DkimHashAlgorithm DkimEnum_lookupHashAlgorithmByName(const char *keyword);
extern DkimHashAlgorithm DkimEnum_lookupHashAlgorithmByNameSlice(const char *head,
                                                                 const char *tail);
extern const char *DkimEnum_lookupHashAlgorithmByValue(DkimHashAlgorithm value);

extern DkimServiceType DkimEnum_lookupServiceTypeByName(const char *keyword);
extern DkimServiceType DkimEnum_lookupServiceTypeByNameSlice(const char *head, const char *tail);
extern const char *DkimEnum_lookupServiceTypeByValue(DkimServiceType value);

extern DkimSelectorFlag DkimEnum_lookupSelectorFlagByName(const char *keyword);
extern DkimSelectorFlag DkimEnum_lookupSelectorFlagByNameSlice(const char *head, const char *tail);
extern const char *DkimEnum_lookupSelectorFlagByValue(DkimSelectorFlag value);

extern DkimQueryMethod DkimEnum_lookupQueryMethodByName(const char *keyword);
extern DkimQueryMethod DkimEnum_lookupQueryMethodByNameSlice(const char *head, const char *tail);
extern const char *DkimEnum_lookupQueryMethodByValue(DkimQueryMethod value);

extern DkimAdspPractice DkimEnum_lookupPracticeByName(const char *keyword);
extern DkimAdspPractice DkimEnum_lookupPracticeByNameSlice(const char *head, const char *tail);
extern const char *DkimEnum_lookupPracticeByValue(DkimAdspPractice value);

#endif /* __DKIM_ENUM_H__ */
