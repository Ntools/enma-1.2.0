/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: daemonize.c 579 2009-01-12 16:19:17Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: daemonize.c 579 2009-01-12 16:19:17Z takahiko $");

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sysexits.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <syslog.h>

#define PID_BUF_LEN 128
#define SYSCONF_FALLBACK_PW_BUF_SIZE 1024
#define PATH_DEVNULL "/dev/null"


/**
 * Create pid file at daemon start-up
 *
 * @param pidfile
 * @param argc
 * @param argv
 * @return
 */
static bool
create_pidfile(const char *pidfile)
{
    assert(NULL != pidfile);

    // mode: 644
    int fd = open(pidfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (0 > fd) {
        syslog(LOG_ERR, "open failed: file=%s, error=%s", pidfile, strerror(errno));
        return false;
    }
    // get pid
    char pid_buf[PID_BUF_LEN];
    snprintf(pid_buf, PID_BUF_LEN, "%d\n", (int) getpid());

    // write pid
    ssize_t writtenlen = write(fd, pid_buf, strlen(pid_buf));
    if (strlen(pid_buf) > (unsigned int) writtenlen) {
        syslog(LOG_ERR, "write failed: file=%s, error=%s", pidfile, strerror(errno));
        goto error_close;
    }

    if (0 != close(fd)) {
        syslog(LOG_WARNING, "close failed: file=%s, error=%s", pidfile, strerror(errno));
    }
    return true;

  error_close:
    if (0 != close(fd)) {
        syslog(LOG_WARNING, "close failed: file=%s, error=%s", pidfile, strerror(errno));
    }
    return false;
}


/**
 * Delete pid file
 *
 * @param pidfile
 * @return
 */
static bool
remove_pidfile(const char *pidfile)
{
    assert(NULL != pidfile);

    struct stat st;
    if (0 == stat(pidfile, &st)) {
        if (-1 == unlink(pidfile)) {
            syslog(LOG_ERR, "unlink failed: file=%s, error=%s", pidfile, strerror(errno));
            return false;
        }
    }

    return true;
}


/**
 * Close tty
 *
 * @return
 */
static bool
close_tty(void)
{
    int fd_list[] = { STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO };

    int fd = open(PATH_DEVNULL, O_RDWR);
    if (0 > fd) {
        syslog(LOG_ERR, "open failed: file=%s, error=%s", PATH_DEVNULL, strerror(errno));
        return false;
    }

    for (int i = 0; i < (int) (sizeof(fd_list) / sizeof(fd_list[0])); ++i) {
        if (-1 == dup2(fd, fd_list[i])) {
            syslog(LOG_WARNING, "dup2 failed: fd=%d, error=%s", fd_list[i], strerror(errno));
        }
    }

    if (STDERR_FILENO < fd) {
        if (-1 == close(fd)) {
            syslog(LOG_WARNING, "close failed: file=%s, error=%s", PATH_DEVNULL, strerror(errno));
        }
    }

    return true;
}


/**
 * usernameで指定されたユーザが所属するグループに setgid し、そのユーザ名に setuidする
 *
 * @param username
 * @return
 */
static bool
set_uidgid(const char *username)
{
    assert(NULL != username);

    long pw_buf_len = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (-1 == pw_buf_len) {
        syslog(LOG_NOTICE, "sysconf(_SC_GETPW_R_SIZE_MAX) sames not to be implemented: error=%s",
               strerror(errno));
        // FreeBSD など sysconf(_SC_GETPW_R_SIZE_MAX) が正常に機能しないOSへの対応
        pw_buf_len = SYSCONF_FALLBACK_PW_BUF_SIZE;
    }
    char *pw_buf = (char *) malloc(pw_buf_len);
    if (NULL == pw_buf) {
        syslog(LOG_ERR, "memory allocation failed: error=%s", strerror(errno));
        return false;
    }
    // /etc/passwdファイルの存在チェック
    struct passwd pw, *pwp = NULL;
    int ret_val;
    errno = 0;
    while (0 != (ret_val = getpwnam_r(username, &pw, pw_buf, pw_buf_len, &pwp))) {
        // sysconf()の返す値が小さい場合がある
        if (ERANGE != errno) {
            syslog(LOG_ERR, "getpwnam_r failed: error=%s", strerror(errno));
            goto error_free;
        }
        pw_buf_len *= 2;
        char *new_pw_buf = (char *) realloc(pw_buf, pw_buf_len);
        if (NULL == new_pw_buf) {
            syslog(LOG_ERR, "memory allocation failed: error=%s", strerror(errno));
            goto error_free;
        }
        pw_buf = new_pw_buf;
    }

    if (-1 == setgid(pw.pw_gid)) {
        syslog(LOG_ERR, "setgid failed: username=%s, error=%s", username, strerror(errno));
        goto error_free;
    }

    if (-1 == setuid(pw.pw_uid)) {
        syslog(LOG_ERR, "setuid failed: username=%s, error=%s", username, strerror(errno));
        goto error_free;
    }

    free(pw_buf);
    return true;

  error_free:
    free(pw_buf);
    return false;
}


/**
 * Create daemon process
 *
 * @param chdirpath
 * @return
 */
static bool
daemon_start(const char *chdirpath)
{
    assert(NULL != chdirpath);

    // 親プロセスの終了
    pid_t pid;
    if (0 > (pid = fork())) {
        syslog(LOG_ERR, "fork failed: error=%s", strerror(errno));
        return false;
    } else if (0 != pid) {
        exit(EX_OK);
    }
    // セッションリーダ
    if (0 > setsid()) {
        syslog(LOG_ERR, "setsid failed: error=%s", strerror(errno));
        return false;
    }
    // セッションリーダのため、SIGHUP無視
    struct sigaction sigaction_ignore;
    memset(&sigaction_ignore, 0, sizeof(sigaction_ignore));
    sigaction_ignore.sa_handler = SIG_IGN;
    if (-1 == sigaction(SIGHUP, &sigaction_ignore, NULL)) {
        syslog(LOG_ERR, "sigaction failed: error=%s", strerror(errno));
        return false;
    }
    // セッションリーダ破棄のため、子プロセス生成
    if (0 > (pid = fork())) {
        syslog(LOG_ERR, "fork failed: error=%s", strerror(errno));
        return false;
    } else if (0 != pid) {
        exit(EX_OK);
    }
    // ルートディレクトリの変更
    if (0 > chdir(chdirpath)) {
        syslog(LOG_ERR, "chdir failed: rootdir=%s, error=%s", chdirpath, strerror(errno));
        return false;
    }

    return true;
}


/**
 * Initialize
 *
 * @param username  NULLの場合がある
 * @param chdirpath
 * @param pidfile
 * @param argc
 * @param argv
 * @return
 */
bool
daemonize_init(const char *username, const char *chdirpath, const char *pidfile)
{
    assert(NULL != chdirpath);
    assert(NULL != pidfile);

    // ユーザ名が指定され空欄でない場合、権限を変更
    if (NULL != username && !set_uidgid(username)) {
        syslog(LOG_ERR, "set_uidgid failed");
        return false;
    }
    // デーモン化
    if (!daemon_start(chdirpath)) {
        syslog(LOG_ERR, "daemon_start failed");
        return false;
    }
    // プロセスファイルを生成する
    if (!create_pidfile(pidfile)) {
        syslog(LOG_ERR, "create_pidfile failed");
        return false;
    }
    // 最後にttyを閉じる
    if (!close_tty()) {
        syslog(LOG_ERR, "close_tty failed");
        return false;
    }

    return true;
}


/**
 * Finalize
 *
 * @param pidfile
 * @return
 */
bool
daemonize_finally(const char *pidfile)
{
    assert(NULL != pidfile);

    if (!remove_pidfile(pidfile)) {
        syslog(LOG_ERR, "remove_pidfile failed");
        return false;
    }

    return true;
}
