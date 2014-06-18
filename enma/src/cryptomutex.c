/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: cryptomutex.c 642 2009-02-28 19:48:56Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: cryptomutex.c 642 2009-02-28 19:48:56Z takahiko $");

#include <stdio.h>
#include <pthread.h>
#include <openssl/crypto.h>

static pthread_mutex_t *lock_cs = NULL;

static void
pthreads_locking_callback(int mode, int type, const char *file, int line)
{
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}

static unsigned long
pthreads_thread_id(void)
{
    return (unsigned long) pthread_self();
}

void
Crypto_mutex_init(void)
{
    lock_cs = (pthread_mutex_t *) OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_set_id_callback((unsigned long (*)()) pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void
Crypto_mutex_cleanup(void)
{
    CRYPTO_set_locking_callback(NULL);
    for (int i = 0; i < CRYPTO_num_locks(); i++) {
        pthread_mutex_destroy(&(lock_cs[i]));
    }
    OPENSSL_free(lock_cs);
    lock_cs = NULL;
}
