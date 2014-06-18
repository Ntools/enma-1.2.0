/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_mfi.c 1193 2009-09-07 00:32:32Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma_mfi.c 1193 2009-09-07 00:32:32Z takahiko $");

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/err.h>
#include <libmilter/mfapi.h>

#include "ptrop.h"
#include "loghandler.h"
#include "bitmemcmp.h"
#include "dnsresolv.h"
#include "sidf.h"
#include "dkim.h"
#include "mailheaders.h"
#include "intarray.h"
#include "xskip.h"
#include "authresult.h"

#include "enma.h"
#include "enma_mfi.h"
#include "enma_config.h"
#include "enma_sidf.h"
#include "enma_dkim.h"
#include "enma_mfi_ctx.h"
#include "ipaddressrange.h"
#include "addr_util.h"

#define UNKNOWN_HOSTNAME "(unknown)"
#define UNKNOWN_QID "(unknown)"

struct smfiDesc mfi_desc = {
    ENMA_MILTER_NAME,   /* filter name */
    SMFI_VERSION,   /* version code -- do not change */
    SMFIF_ADDHDRS | SMFIF_CHGHDRS,  /* flags */
    mfi_connect,    /* connection info filter */
    mfi_helo,   /* SMTP HELO command filter */
    mfi_envfrom,    /* envelope sender filter */
    NULL,   /* envelope recipient filter */
    mfi_header, /* header filter */
    mfi_eoh,    /* end of header */
    mfi_body,   /* body block filter */
    mfi_eom,    /* end of message */
    mfi_abort,  /* message aborted */
    mfi_close,  /* connection cleanup */
#if defined(SM_LM_VRS_MAJOR) || (SMFI_VERSION > 2)
    NULL,   /* any unrecognized or unimplemented command filter */
#endif
#if defined(SM_LM_VRS_MAJOR) || (SMFI_VERSION > 3)
    NULL,   /* SMTP DATA command filter */
#endif
#if defined(SM_LM_VRS_MAJOR)
    NULL,   /* negotiation callback */
#endif
};


/**
 * libmilterの初期化
 *
 * @param socket	smfi_setconnの引数であるため、not const
 * @param timeout	smfi_settimeoutの引数であるため、not const
 * @param logleve	smfi_setdbgの引数であるため、not constl
 */
bool
EnmaMfi_init(char *socket, int timeout, int loglevel)
{
    assert(NULL != socket);
    assert(0 <= timeout);
    assert(0 <= loglevel);

    // libmilter のログレベル
    (void) smfi_setdbg(loglevel);

    // コネクションのタイムアウト
    (void) smfi_settimeout(timeout);

    // 待ち受けソケットの作成
    if (MI_FAILURE == smfi_setconn(socket)) {
        LogError("smfi_setconn failed");
        return false;
    }
    // コールバック関数の登録
    if (MI_FAILURE == smfi_register(mfi_desc)) {
        LogError("smfi_register failed");
        return false;
    }
    // smfi_setconn, smfi_register の後
    if (MI_FAILURE == smfi_opensocket(true)) {
        LogError("smfi_opensocket failed");
        return false;
    }

    return true;
}


/**
 * SPF の検証と Authentication-Results ヘッダの付加をおこなう.
 * @param session セッションコンテキスト
 * @return 正常終了の場合は true, エラーが発生した場合は false.
 */
static bool
EnmaMfi_sidf_eom(const EnmaMfiCtx *enma_mfi_ctx, const SidfRecordScope scope)
{
    switch (scope) {
    case SIDF_RECORD_SCOPE_SPF1:
        if (!EnmaSpf_evaluate
            (g_sidf_policy, enma_mfi_ctx->resolver, enma_mfi_ctx->authresult,
             enma_mfi_ctx->hostaddr, enma_mfi_ctx->ipaddr, enma_mfi_ctx->helohost,
             enma_mfi_ctx->raw_envfrom, enma_mfi_ctx->envfrom, g_enma_config->spf_explog)) {
            return false;
        }
        break;
    case SIDF_RECORD_SCOPE_SPF2_PRA:
        if (!EnmaSidf_evaluate
            (g_sidf_policy, enma_mfi_ctx->resolver, enma_mfi_ctx->authresult,
             enma_mfi_ctx->hostaddr, enma_mfi_ctx->ipaddr, enma_mfi_ctx->helohost,
             enma_mfi_ctx->headers, g_enma_config->sidf_explog)) {
            return false;
        }
        break;
    default:
        LogError("unknown SidfRecordScope: scope=0x%02x", scope);
        abort();
    }
    return true;
}


/**
 * SMFI_TEMPFAIL時の処理
 */
static sfsistat
EnmaMfi_tempfail(EnmaMfiCtx *enma_mfi_ctx)
{
    EnmaMfiCtx_reset(enma_mfi_ctx);
    ERR_remove_state(0);
    LogHandler_setPrefix(NULL);
    return SMFIS_TEMPFAIL;
}


/**
 * duplicate hostaddr
 *
 * @param hostaddr (maybe NULL)
 * @return
 */
static _SOCK_ADDR *
hostaddrdup(const _SOCK_ADDR *hostaddr)
{
    socklen_t address_len = 0;
    if (NULL != hostaddr) {
        switch (hostaddr->sa_family) {
        case AF_INET:
            address_len = sizeof(struct sockaddr_in);
            break;
        case AF_INET6:
            address_len = sizeof(struct sockaddr_in6);
            break;
        default:
            // Unknown protocol
            LogWarning("unknown protocol: sa_family=%d", hostaddr->sa_family);
            break;
        }
    }

    if (0 < address_len) {
        _SOCK_ADDR *psock = (_SOCK_ADDR *) malloc(address_len);
        if (NULL == psock) {
            return NULL;
        }
        memcpy(psock, hostaddr, address_len);
        return psock;
    } else {
        _SOCK_ADDR *psock = (_SOCK_ADDR *) loopbackAddrDup(AF_INET6);
        if (NULL == psock) {
            return NULL;
        }
        return psock;
    }
}


static char *
hostnamedup(const char *hostname)
{
    if (NULL == hostname) {
        LogWarning("failed to get hostname: set hostname=%s", UNKNOWN_HOSTNAME);
        return strdup(UNKNOWN_HOSTNAME);
    } else {
        return strdup(hostname);
    }
}


/**
 * duplicate ipaddr
 *
 * @param hostname
 * @param hostaddr
 * @return
 */
static char *
ipaddrdup(const char *hostname, const _SOCK_ADDR *hostaddr)
{
    assert(NULL != hostname);
    assert(NULL != hostaddr);

    char addr_buf[INET6_ADDRSTRLEN];

    switch (hostaddr->sa_family) {
    case AF_INET:;
        struct sockaddr_in *sin4 = (struct sockaddr_in *) hostaddr;
        if (NULL == inet_ntop(AF_INET, &(sin4->sin_addr), addr_buf, INET_ADDRSTRLEN)) {
            LogError("inet_ntop AF_INET4 failed: hostname=%s, error=%s", NNSTR(hostname),
                     strerror(errno));
            return NULL;
        }
        break;
    case AF_INET6:;
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) hostaddr;
        if (NULL == inet_ntop(AF_INET6, &(sin6->sin6_addr), addr_buf, INET6_ADDRSTRLEN)) {
            LogError("inet_ntop AF_INET6 failed: hostname=%s, error=%s", NNSTR(hostname),
                     strerror(errno));
            return NULL;
        }
        break;
    default:
        LogError("Unknown protocol: hostname=%s, sa_familyr=%d", NNSTR(hostname),
                 hostaddr->sa_family);
        errno = EAFNOSUPPORT;
        return NULL;
    }

    return strdup(addr_buf);
}


static char *
qiddup(const char *qid)
{
    if (NULL == qid) {
        LogWarning("failed to get qid: set qid=%s", UNKNOWN_QID);
        return strdup(UNKNOWN_QID);
    } else {
        return strdup(qid);
    }
}


static bool
EnmaMfi_set_qid(SMFICTX *ctx, EnmaMfiCtx *enma_mfi_ctx)
{
    assert(NULL != enma_mfi_ctx);

    enma_mfi_ctx->qid = qiddup(smfi_getsymval(ctx, "{i}"));
    if (NULL == enma_mfi_ctx->qid) {
        LogError("qiddup failed: error=%s", strerror(errno));
        return false;
    }
    // ログ出力用にqidを記憶
    if (!LogHandler_setPrefix(enma_mfi_ctx->qid)) {
        LogError("LogHandler_setPrefix failed: error=%s", strerror(errno));
        return false;
    }

    return true;
}

/**
 * 接続元が、設定されているIPアドレスレンジであるかの判定
 *
 * @param enma_mfi_ctx
 */
static bool
EnmaMfi_match_exclusion_address_ranges(EnmaMfiCtx *enma_mfi_ctx)
{
    char buf[INET6_ADDRSTRLEN];

    const struct sockaddr *sa = (struct sockaddr *) enma_mfi_ctx->hostaddr;
    if (!addrToIpStr(sa, buf)) {
        LogError("addrToIpStr failed: error=%s", strerror(errno));
    }
    LogDebug("connected ip address=%s", buf);

    if (IPAddressRangeList_matchToSocket(g_enma_config->common_exclusion_addresses, sa)) {
        LogInfo("excluded ip address=%s", buf);
        return true;
    }

    return false;
}

/**
 * Handler of each SMTP connection
 *
 * @param ctx
 * @param hostname (not NULL)
 * @param hostaddr (maybe NULL)
 */
sfsistat
mfi_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
    LogDebug("hostname=%s", NNSTR(hostname));

    EnmaMfiCtx *enma_mfi_ctx = EnmaMfiCtx_new();
    if (NULL == enma_mfi_ctx) {
        LogError("EnmaMfiCtx_new failed: hostname=%s, error=%s", NNSTR(hostname), strerror(errno));
        return SMFIS_TEMPFAIL;
    }
    // hostname
    enma_mfi_ctx->hostname = hostnamedup(hostname);
    if (NULL == enma_mfi_ctx->hostname) {
        LogError("hostnamedup failed: hostname=%s, error=%s", NNSTR(hostname), strerror(errno));
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // hostaddr
    enma_mfi_ctx->hostaddr = hostaddrdup(hostaddr);
    if (NULL == enma_mfi_ctx->hostaddr) {
        LogError("hostaddrdup failed: hostname=%s, error=%s", NNSTR(hostname), strerror(errno));
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // ipaddr
    enma_mfi_ctx->ipaddr = ipaddrdup(hostname, enma_mfi_ctx->hostaddr);
    if (NULL == enma_mfi_ctx->ipaddr) {
        LogError("ipaddrdup failed: hostname=%s, error=%s", NNSTR(hostname), strerror(errno));
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }

    if (MI_FAILURE == smfi_setpriv(ctx, enma_mfi_ctx)) {
        LogError("smfi_setpriv failed");
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }

    if (NULL != g_enma_config->common_exclusion_addresses
        && EnmaMfi_match_exclusion_address_ranges(enma_mfi_ctx)) {
        // 以降の処理をスキップ
        return SMFIS_ACCEPT;
    }

    return SMFIS_CONTINUE;
}


/**
 * Handle the HELO/EHLO command
 *
 * @param ctx
 * @param helohost (not NULL)
 */
sfsistat
mfi_helo(SMFICTX *ctx, char *helohost)
{
    LogDebug("helohost=%s", NNSTR(helohost));

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL == enma_mfi_ctx) {
        LogError("smfi_getpriv failed: helohost=%s", NNSTR(helohost));
        return SMFIS_TEMPFAIL;
    }

    if (NULL != helohost) {
        // 複数回受け付けるので、以前の情報を破棄
        PTRINIT(enma_mfi_ctx->helohost);
        enma_mfi_ctx->helohost = strdup(helohost);
        if (NULL == enma_mfi_ctx->helohost) {
            LogError("helohost get failed: helohost=%s, error=%s", NNSTR(helohost),
                     strerror(errno));
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }
    }

    return SMFIS_CONTINUE;
}


/**
 * envfrom時に呼ばれるコールバック関数
 *
 * @param ctx
 * @param argv MAIL FROMコマンドの引数 (not NULL)
 */
sfsistat
mfi_envfrom(SMFICTX *ctx, char **argv)
{
    const char *envfrom = argv[0];
    LogDebug("envfrom=%s", NNSTR(envfrom));

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL == enma_mfi_ctx) {
        LogError("smfi_getpriv failed: envfrom=%s", NNSTR(envfrom));
        return SMFIS_TEMPFAIL;
    }
    // 2回目以降のトランザクションの場合に備えて以前の情報を解放
    EnmaMfiCtx_reset(enma_mfi_ctx);

    // sendmail qid
    if (!g_enma_config->milter_postfix) {
        if (!EnmaMfi_set_qid(ctx, enma_mfi_ctx)) {
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }
    }
    // envfrom を記憶
    enma_mfi_ctx->raw_envfrom = strdup(envfrom);
    if (NULL == enma_mfi_ctx->raw_envfrom) {
        LogError("strdup failed: error=%s", strerror(errno));
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    char *mailaddr_tail = STRTAIL(enma_mfi_ctx->raw_envfrom);
    const char *nextp, *errptr;
    enma_mfi_ctx->envfrom =
        InetMailbox_buildSendmailReversePath(enma_mfi_ctx->raw_envfrom, mailaddr_tail, &nextp,
                                             &errptr);
    if (NULL != enma_mfi_ctx->envfrom) {
        XSkip_fws(nextp, mailaddr_tail, &nextp);
        if (nextp < mailaddr_tail) {
            LogNotice("envfrom=%s", enma_mfi_ctx->raw_envfrom);
            InetMailbox_free(enma_mfi_ctx->envfrom);
            enma_mfi_ctx->envfrom = NULL;
        }
    } else {
        // parse失敗
        if (NULL == errptr) {
            LogError("InetMailbox_buildSendmailReversePath: error=%s", strerror(errno));
            return EnmaMfi_tempfail(enma_mfi_ctx);
        } else {
            LogNotice("parse failed: envfrom=%s", enma_mfi_ctx->raw_envfrom);
        }
    }

    return SMFIS_CONTINUE;
}


/**
 * Handle a message header
 *
 * @param ctx
 * @param headerf (not NULL)
 * @param headerv (not NULL)
 */
sfsistat
mfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
    LogDebug("headerf=%s, headerv=%s", NNSTR(headerf), NNSTR(headerv));

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL == enma_mfi_ctx) {
        LogError("smfis_getpriv failed: headerf=%s, headerv=%s", NNSTR(headerf), NNSTR(headerv));
        return SMFIS_TEMPFAIL;
    }
    // AUTHRESULTSHDR の削除するべきヘッダの番号を保存する
    if (0 == strcasecmp(AUTHRESULTSHDR, headerf)) {
        ++(enma_mfi_ctx->authhdr_count);
        if (AuthResult_compareAuthservId(headerv, g_enma_config->authresult_identifier)) {
            // Authentication-Results ヘッダについているホスト名がこれから付けるホスト名と同一
            // 削除対象ヘッダとして覚えておく
            if (IntArray_append(enma_mfi_ctx->delauthhdr, enma_mfi_ctx->authhdr_count) < 0) {
                LogError("IntArray_append failed: error=%s", strerror(errno));
                return EnmaMfi_tempfail(enma_mfi_ctx);
            }
            LogDebug("fraud AuthResultHeader: [No.%d] %s", enma_mfi_ctx->authhdr_count, headerv);
        }
    }
    // SIDF/DKIM が有効の場合ヘッダを格納する
    if (g_enma_config->sidf_auth || g_enma_config->dkim_auth) {
        int pos = MailHeaders_append(enma_mfi_ctx->headers, headerf, headerv);
        if (pos < 0) {
            LogError("MailHeaders_append failed: headerf=%s, headerv=%s", NNSTR(headerf),
                     NNSTR(headerv));
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }
    }

    return SMFIS_CONTINUE;
}


sfsistat
mfi_eoh(SMFICTX *ctx)
{
    LogDebug("eoh");

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL == enma_mfi_ctx) {
        LogError("smfi_getpriv failed");
        return SMFIS_TEMPFAIL;
    }

    if (g_enma_config->dkim_auth) {
        // DkimVerifier オブジェクトの初期化
        enma_mfi_ctx->dkimverifier = DkimVerifier_new(g_dkim_vpolicy, enma_mfi_ctx->resolver);
        if (NULL == enma_mfi_ctx->dkimverifier) {
            LogError("DkimVerifier_new failed: err=%s", strerror(errno));
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }   // end if
        DkimStatus eoh_stat = DkimVerifier_setup(enma_mfi_ctx->dkimverifier, enma_mfi_ctx->headers);
        if (DSTAT_INFO_NO_SIGNHEADER == eoh_stat) {
            // DKIM 署名ヘッダが1つもついていなかった場合
            LogDebug("[DKIM-skip] No DKIM-Signature header found and verification is skipped.");
        } else if (DSTAT_ISCRITERR(eoh_stat)) {
            // エラーが発生した場合
            LogError("DkimVerifier_startBody failed: err=%s", DKIM_strerror(eoh_stat));
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }   // end if
    }

    return SMFIS_CONTINUE;
}


sfsistat
mfi_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
    LogDebug("body");

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL == enma_mfi_ctx) {
        LogError("smfi_getpriv failed");
        return SMFIS_TEMPFAIL;
    }

    if (g_enma_config->dkim_auth) {
        DkimStatus body_stat = DkimVerifier_updateBody(enma_mfi_ctx->dkimverifier, bodyp, bodylen);
        if (DSTAT_ISCRITERR(body_stat)) {
            // エラーが発生した場合
            LogError("DkimVerifier_updateBody failed: err=%s", DKIM_strerror(body_stat));
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }   // end if
    }   // end if

    return SMFIS_CONTINUE;
}


/**
 * eom時に呼ばれるコールバック関数
 *
 * @param ctx
 */
sfsistat
mfi_eom(SMFICTX *ctx)
{
    LogDebug("eom");

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL == enma_mfi_ctx) {
        LogError("smfi_getpriv failed");
        return SMFIS_TEMPFAIL;
    }
    // postfix qid(for protocol version 2)
    if (g_enma_config->milter_postfix && NULL == enma_mfi_ctx->qid) {
        if (!EnmaMfi_set_qid(ctx, enma_mfi_ctx)) {
            return EnmaMfi_tempfail(enma_mfi_ctx);
        }
    }
    // Authentication-result ヘッダの削除
    size_t authhdr_num = IntArray_getCount(enma_mfi_ctx->delauthhdr);
    for (size_t n = 0; n < authhdr_num; ++n) {
        int change_stat =
            smfi_chgheader(ctx, AUTHRESULTSHDR, IntArray_get(enma_mfi_ctx->delauthhdr, n), NULL);
        if (MI_FAILURE == change_stat) {
            LogWarning("smfi_chgheader failed: [No.%d] %s",
                       IntArray_get(enma_mfi_ctx->delauthhdr, n), AUTHRESULTSHDR);
        }
    }

    // Authentication-Results ヘッダの準備
    bool appended_stat =
        AuthResult_appendAuthServId(enma_mfi_ctx->authresult, g_enma_config->authresult_identifier);
    if (!appended_stat) {
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // SPF
    if (g_enma_config->spf_auth && !EnmaMfi_sidf_eom(enma_mfi_ctx, SIDF_RECORD_SCOPE_SPF1)) {
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // SIDF
    if (g_enma_config->sidf_auth && !EnmaMfi_sidf_eom(enma_mfi_ctx, SIDF_RECORD_SCOPE_SPF2_PRA)) {
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // DKIM
    if (g_enma_config->dkim_auth
        && !EnmaDkim_evaluate(enma_mfi_ctx->dkimverifier, enma_mfi_ctx->authresult)) {
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // DKIM ADSP
    if (g_enma_config->dkim_auth && g_enma_config->dkimadsp_auth
        && !EnmaDkimAdsp_evaluate(enma_mfi_ctx->dkimverifier, enma_mfi_ctx->authresult)) {
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }
    // Authentication-Results ヘッダをメッセージの先頭に挿入
    if (0 != AuthResult_status(enma_mfi_ctx->authresult)) {
        LogError("AuthResult_status failed");
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }

    const char *authheader_body = AuthResult_getFieldBody(enma_mfi_ctx->authresult);
    if (MI_FAILURE == smfi_insheader(ctx, 0, (char *) AUTHRESULTSHDR, (char *) authheader_body)) {
        LogError("smfi_insheader failed: %s", authheader_body);
        return EnmaMfi_tempfail(enma_mfi_ctx);
    }

    EnmaMfiCtx_reset(enma_mfi_ctx);
    ERR_remove_state(0);
    (void) LogHandler_setPrefix(NULL);

    return SMFIS_CONTINUE;
}


/**
 * Handler the current message's begin aborted
 *
 * @param ctx
 * @return
 */
sfsistat
mfi_abort(SMFICTX *ctx)
{
    LogDebug("abort");

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL != enma_mfi_ctx) {
        EnmaMfiCtx_reset(enma_mfi_ctx);
    }
    ERR_remove_state(0);
    LogHandler_setPrefix(NULL);

    return SMFIS_CONTINUE;
}


/**
 * The current connection is being closed
 *
 * @param ctx
 * @return
 */
sfsistat
mfi_close(SMFICTX *ctx)
{
    LogDebug("close");

    EnmaMfiCtx *enma_mfi_ctx = smfi_getpriv(ctx);
    if (NULL != enma_mfi_ctx) {
        EnmaMfiCtx_free(enma_mfi_ctx);
        if (MI_FAILURE == smfi_setpriv(ctx, NULL)) {
            LogError("smfi_setpriv failed");
        }
    }
    LogHandler_setPrefix(NULL);

    return SMFIS_CONTINUE;
}
