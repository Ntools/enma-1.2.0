/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: sidfpolicy.h 1349 2011-08-15 02:23:13Z takahiko $
 */

#ifndef __SIDFPOLICY_H__
#define __SIDFPOLICY_H__

#include <stdbool.h>
#include "sidf.h"

struct SidfPolicy {
    // whether to lookup SPF RR (type 99)
    bool lookup_spf_rr;
    // whether to lookup explanation
    bool lookup_exp;
    // domain name of host performing the check (to expand "r" macro)
    char *checking_domain;
    // マクロ展開の際, 展開過程を中断する長さの閾値
    unsigned int macro_expansion_limit;
    // SPFレコード中のどのメカニズムにもマッチしなかった場合, Neutral を返す前にこのレコードの評価を挟む
    // 評価されるタイミングは redirect modifier が存在しなかった場合
    char *local_policy;
    // local_policy によって "Fail" になった場合に使用する explanation を設定する. マクロ使用可.
    char *local_policy_explanation;
    // the maximum limit of mechanisms which involves DNS lookups per an evaluation.
    // RFC4408 defines this as 10. DO NOT TOUCH NORMALLY.
    unsigned int max_dns_mech;
    // check_host() 関数の <domain> 引数に含まれる label の最大長, RFC4408 defines this as 63.
    unsigned int max_label_len;
    // mx メカニズム評価中に1回のMXレコードのルックアップに対するレスポンスとして受け取るRRの最大数
    // RFC4408 defines this as 10. DO NOT TOUCH NORMALLY.
    unsigned int max_mxrr_per_mxmech;
    // ptr メカニズム評価中に1回のPTRレコードのルックアップに対するレスポンスとして受け取るRRの最大数
    // RFC4408 defines this as 10. DO NOT TOUCH NORMALLY.
    unsigned int max_ptrrr_per_ptrmech;
    // "all" メカニズムにどんな qualifier が付いていようとスコアを上書きする.
    // SIDF_SCORE_NULL の場合は通常動作 (レコードに書かれている qualifier を使用)
    SidfScore overwrite_all_directive_score;
    // action on encountering "+all" directives
    SidfCustomAction action_on_plus_all_directive;
    // action on encountering malicious "ip4-cidr-length"
    SidfCustomAction action_on_malicious_ip4_cidr_length;
    // action on encountering malicious "ip6-cidr-length"
    SidfCustomAction action_on_malicious_ip6_cidr_length;
    // threshold of handling "ip4-cidr-length" as malicious
    unsigned char malicious_ip4_cidr_length;
    // threshold of handling "ip6-cidr-length" as malicious
    unsigned char malicious_ip6_cidr_length;
    // logging function
    void (*logger)(int priority, const char *message, ...);
};

#endif /* __SIDFPOLICY_H__ */
