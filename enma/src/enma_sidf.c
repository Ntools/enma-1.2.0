/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: enma_sidf.c 1460 2011-12-21 11:47:15Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: enma_sidf.c 1460 2011-12-21 11:47:15Z takahiko $");

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "loghandler.h"
#include "authresult.h"
#include "mailheaders.h"
#include "dnsresolv.h"
#include "sidf.h"

#include "enma_sidf.h"


/**
 * 必要なパラメーターが揃わず SPF 評価をスキップした場合は "permerror"
 *
 * [RFC5451] 2.4.2.
 * permerror:  The message could not be verified due to some error that
 *    is unrecoverable, such as a required header field being absent or
 *    a syntax error in a retrieved DNS TXT record.  A later attempt is
 *    unlikely to produce a final result.
 */
static void
EnmaSidfBase_appendPermError(AuthResult *authresult, const char *method)
{
    assert(NULL != authresult);
    assert(NULL != method);

    const char *resultexp = SidfEnum_lookupScoreByValue(SIDF_SCORE_PERMERROR);
    (void) AuthResult_appendMethodSpec(authresult, method, resultexp);

    // 必要なパラメータが揃わず評価をスキップした
    LogInfo("[%s-auth] score=%s", method, resultexp);
}


/**
 * select PRA Header
 *
 * @param headers
 * @param pra_header
 * @param pra_mailbox
 * @return
 */
static bool
EnmaSidf_setPRAHeader(const SidfPolicy *policy, const MailHeaders *headers, const char **pra_header,
                      InetMailbox **pra_mailbox)
{
    int pra_index;
    if (!SidfPra_extract(policy, headers, &pra_index, pra_mailbox)) {
        return false;
    }

    if (NULL == *pra_mailbox) {
        LogEvent("SIDF-skip", "PRA header extraction failed");
        return true;
    }

    MailHeaders_get(headers, pra_index, pra_header, NULL);
    LogDebug("SIDF-PRA-Header: field=%s, mailbox=%s@%s", *pra_header,
             InetMailbox_getLocalPart(*pra_mailbox), InetMailbox_getDomain(*pra_mailbox));

    return true;
}


/**
 * preparation of SPF authentication
 *
 * @param request
 * @param hostaddr
 * @param helohost
 * @param envfrom
 * @return
 */
static bool
EnmaSpf_prepare(SidfRequest *request, const struct sockaddr *hostaddr, const char *helohost,
                const InetMailbox *envfrom)
{
    assert(NULL != request);
    assert(NULL != hostaddr);
    assert(NULL != helohost);

    if (!SidfRequest_setIpAddr(request, hostaddr->sa_family, hostaddr)) {
        LogError("SidfRequest_setIpAddr failed, invalid address family: sa_family=0x%x",
                 hostaddr->sa_family);
        return false;
    }

    if (!SidfRequest_setHeloDomain(request, helohost)) {
        LogError("SidfRequest_setHeloDomain failed: helo=%s", helohost);
        return false;
    }

    if (NULL != envfrom && !InetMailbox_isNullAddr(envfrom)) {
        if (!SidfRequest_setSender(request, envfrom)) {
            LogNoResource();
            return false;
        }
        LogDebug("SPF-EnvFrom-Domain=%s", InetMailbox_getDomain(envfrom));
    }

    return true;
}


/**
 * preparation of SIDF authentication
 *
 * @param request
 * @param hostaddr
 * @param helohost
 * @param pra_mailbox
 * @return
 */
static bool
EnmaSidf_prepare(SidfRequest *request, const struct sockaddr *hostaddr, const char *helohost,
                 const InetMailbox *pra_mailbox)
{
    assert(NULL != request);
    assert(NULL != hostaddr);
    assert(NULL != helohost);
    assert(NULL != pra_mailbox);

    if (!SidfRequest_setIpAddr(request, hostaddr->sa_family, hostaddr)) {
        LogError("SidfRequest_setIpAddr failed, invalid address family: sa_family=0x%x",
                 hostaddr->sa_family);
        return false;
    }

    if (!SidfRequest_setHeloDomain(request, helohost)) {
        LogError("SidfRequest_setHeloDomain failed: helo=%s", helohost);
        return false;
    }

    if (!SidfRequest_setSender(request, pra_mailbox)) {
        LogNoResource();
        return false;
    }

    return true;
}


/**
 * SPF append score
 *
 * @param request
 * @param authresult
 * @param ipaddr
 * @param helohost
 * @param raw_envfrom
 * @param envfrom
 * @param explog
 * @return
 */
static bool
EnmaSpf_appendScore(SidfRequest *request, AuthResult *authresult, const char *ipaddr,
                    const char *helohost, const char *raw_envfrom, const InetMailbox *envfrom,
                    bool explog)
{
    assert(NULL != request);
    assert(NULL != authresult);
    assert(NULL != ipaddr);
    assert(NULL != helohost);
    assert(NULL != raw_envfrom);

    SidfScore score = SidfRequest_eval(request, SIDF_RECORD_SCOPE_SPF1);
    if (SIDF_SCORE_SYSERROR == score || SIDF_SCORE_NULL == score) {
        LogWarning("SidfRequest_eval failed: score=0x%x", score);
        return false;
    }
    // 評価結果に応じたアクションの実行
    const char *resultexp = SidfEnum_lookupScoreByValue(score);
    assert(NULL != resultexp);

    // Authentication-Results ヘッダの生成
    (void) AuthResult_appendMethodSpec(authresult, AUTHRES_METHOD_SPF, resultexp);
    if (SidfRequest_isSenderContext(request)) {
        (void) AuthResult_appendPropSpecWithAddrSpec(authresult, AUTHRES_PTYPE_SMTP,
                                                     AUTHRES_PROPERTY_MAILFROM, envfrom);
    } else {
        (void) AuthResult_appendPropSpecWithToken(authresult, AUTHRES_PTYPE_SMTP,
                                                  AUTHRES_PROPERTY_HELO, helohost);
    }

    // SPF 検証結果をログに残す
    LogEvent("SPF-auth", "ipaddr=%s, eval=smtp.%s, helo=%s, envfrom=%s, score=%s",
             ipaddr,
             SidfRequest_isSenderContext(request) ? AUTHRES_PROPERTY_MAILFROM :
             AUTHRES_PROPERTY_HELO, helohost, raw_envfrom, resultexp);

    // 設定により explanation をログに残す
    if (explog && NULL != SidfRequest_getExplanation(request)) {
        LogEvent("SPF-explanation", "%s", SidfRequest_getExplanation(request));
    }

    return true;
}


/**
 * SIDF append score
 *
 * @param request
 * @param authresult
 * @param ipaddr
 * @param pra_header
 * @param pra_mailbox
 * @param explog
 * @return
 */
static bool
EnmaSidf_appendScore(SidfRequest *request, AuthResult *authresult, const char *ipaddr,
                     const char *pra_header, const InetMailbox *pra_mailbox, bool explog)
{
    assert(NULL != request);
    assert(NULL != authresult);
    assert(NULL != ipaddr);
    assert(NULL != pra_header);
    assert(NULL != pra_mailbox);

    SidfScore score = SidfRequest_eval(request, SIDF_RECORD_SCOPE_SPF2_PRA);
    if (SIDF_SCORE_SYSERROR == score || SIDF_SCORE_NULL == score) {
        LogWarning("SidfRequest_eval failed: score=0x%x", score);
        return false;
    }
    // 評価結果に応じたアクションの実行
    const char *resultexp = SidfEnum_lookupScoreByValue(score);
    assert(NULL != resultexp);

    // Authentication-Results ヘッダの生成
    (void) AuthResult_appendMethodSpec(authresult, AUTHRES_METHOD_SENDERID, resultexp);
    (void) AuthResult_appendPropSpecWithAddrSpec(authresult, AUTHRES_PTYPE_HEADER,
                                                 pra_header, pra_mailbox);

    // SIDF 検証結果をログに残す
    LogEvent("SIDF-auth", "ipaddr=%s, header.%s=%s@%s, score=%s",
             ipaddr, pra_header,
             InetMailbox_getLocalPart(pra_mailbox), InetMailbox_getDomain(pra_mailbox), resultexp);

    // 設定により explanation をログに残す
    if (explog && NULL != SidfRequest_getExplanation(request)) {
        LogEvent("SIDF-explanation", "%s", SidfRequest_getExplanation(request));
    }

    return true;
}


/**
 * SPF evalute
 *
 * @param policy
 * @param resolver
 * @param authresult
 * @param hostaddr
 * @param ipaddr
 * @param helohost
 * @param raw_envfrom
 * @param envfrom
 * @param explog
 * @return
 */
bool
EnmaSpf_evaluate(SidfPolicy *policy, DnsResolver *resolver, AuthResult *authresult,
                 const struct sockaddr *hostaddr, const char *ipaddr, const char *helohost,
                 const char *raw_envfrom, const InetMailbox *envfrom, bool explog)
{
    assert(NULL != policy);
    assert(NULL != resolver);
    assert(NULL != authresult);
    assert(NULL != hostaddr);
    assert(NULL != ipaddr);
    assert(NULL != raw_envfrom);

    // %{h} マクロの展開に使われる可能性があるので, HELO の値は必ずセットする.
    // Sender がセットされていれば HELO で SPF/SIDF の評価がおこなわれることはない.
    if (NULL == helohost) {
        LogEvent("SPF-skip", "HELO not set, SPF-authentication skipped: ipaddr=%s", ipaddr);
        EnmaSidfBase_appendPermError(authresult, AUTHRES_METHOD_SPF);
        return true;
    }

    SidfRequest *request = SidfRequest_new(policy, resolver);
    if (NULL == request) {
        LogNoResource();
        return false;
    }

    if (!EnmaSpf_prepare(request, hostaddr, helohost, envfrom)) {
        goto cleanup;
    }
    // evaluation
    if (!EnmaSpf_appendScore(request, authresult, ipaddr, helohost, raw_envfrom, envfrom, explog)) {
        goto cleanup;
    }

    SidfRequest_free(request);
    return true;

  cleanup:
    SidfRequest_free(request);
    return false;
}


/**
 * SIDF evalute
 *
 * @param policy
 * @param resolver
 * @param authresult
 * @param hostaddr
 * @param ipaddr
 * @param helohost
 * @param headers
 * @param explog
 * @return
 */
bool
EnmaSidf_evaluate(SidfPolicy *policy, DnsResolver *resolver, AuthResult *authresult,
                  const struct sockaddr *hostaddr, const char *ipaddr, const char *helohost,
                  const MailHeaders *headers, bool explog)
{
    assert(NULL != policy);
    assert(NULL != resolver);
    assert(NULL != authresult);
    assert(NULL != hostaddr);
    assert(NULL != ipaddr);
    assert(NULL != headers);

    // %{h} マクロの展開に使われる可能性があるので, HELO の値は必ずセットする.
    // Sender がセットされていれば HELO で SPF/SIDF の評価がおこなわれることはない.
    if (NULL == helohost) {
        LogEvent("SIDF-skip", "HELO not set, SIDF-authentication skipped: ipaddr=%s", ipaddr);
        EnmaSidfBase_appendPermError(authresult, AUTHRES_METHOD_SENDERID);
        return true;
    }
    // lookup PRA header
    const char *pra_header = NULL;
    InetMailbox *pra_mailbox = NULL;
    if (!EnmaSidf_setPRAHeader(policy, headers, &pra_header, &pra_mailbox)) {
        return false;
    }
    if (NULL == pra_mailbox) {
        EnmaSidfBase_appendPermError(authresult, AUTHRES_METHOD_SENDERID);
        return true;
    }

    SidfRequest *request = SidfRequest_new(policy, resolver);
    if (NULL == request) {
        LogNoResource();
        return false;
    }
    // prepare
    if (!EnmaSidf_prepare(request, hostaddr, helohost, pra_mailbox)) {
        goto cleanup;
    }
    // evaluation
    if (!EnmaSidf_appendScore(request, authresult, ipaddr, pra_header, pra_mailbox, explog)) {
        goto cleanup;
    }

    SidfRequest_free(request);
    InetMailbox_free(pra_mailbox);
    return true;

  cleanup:
    SidfRequest_free(request);
    InetMailbox_free(pra_mailbox);
    return false;
}
