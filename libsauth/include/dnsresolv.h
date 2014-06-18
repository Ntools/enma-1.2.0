/*
 * Copyright (c) 2008-2011 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: dnsresolv.h 1365 2011-10-16 08:08:36Z takahiko $
 */

#ifndef __DNSRESOLV_H__
#define __DNSRESOLV_H__

#include <inttypes.h>   // as a substitute for stdint.h (Solaris 9 doesn't have)
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct DnsResolver DnsResolver;

enum dns_stat_t {
    DNS_STAT_NOERROR = 0,
    DNS_STAT_FORMERR = 1,
    DNS_STAT_SERVFAIL = 2,
    DNS_STAT_NXDOMAIN = 3,
    DNS_STAT_NOTIMPL = 4,
    DNS_STAT_REFUSED = 5,
    DNS_STAT_YXDOMAIN = 6,
    DNS_STAT_YXRRSET = 7,
    DNS_STAT_NXRRSET = 8,
    DNS_STAT_NOTAUTH = 9,
    DNS_STAT_NOTZONE = 10,
    DNS_STAT_RESERVED11 = 11,
    DNS_STAT_RESERVED12 = 12,
    DNS_STAT_RESERVED13 = 13,
    DNS_STAT_RESERVED14 = 14,
    DNS_STAT_RESERVED15 = 15,
    DNS_STAT_SYSTEM = 0x100,
    DNS_STAT_NODATA,
    DNS_STAT_NOMEMORY,
    DNS_STAT_RESOLVER,
    DNS_STAT_RESOLVER_INTERNAL,
    DNS_STAT_BADREQUEST,
};
typedef enum dns_stat_t dns_stat_t;

typedef struct DnsAResponse DnsAResponse;
typedef struct DnsAaaaResponse DnsAaaaResponse;
typedef struct DnsMxResponse DnsMxResponse;
typedef struct DnsTxtResponse DnsTxtResponse;
typedef struct DnsTxtResponse DnsSpfResponse;
typedef struct DnsPtrResponse DnsPtrResponse;

extern DnsResolver *DnsResolver_new(void);
extern void DnsResolver_free(DnsResolver *self);

extern size_t DnsAResponse_size(const DnsAResponse *self);
extern const struct in_addr *DnsAResponse_addr(const DnsAResponse *self, size_t index);
extern void DnsAResponse_free(DnsAResponse *self);

extern size_t DnsAaaaResponse_size(const DnsAaaaResponse *self);
extern const struct in6_addr *DnsAaaaResponse_addr(const DnsAaaaResponse *self, size_t index);
extern void DnsAaaaResponse_free(DnsAaaaResponse *self);

extern size_t DnsMxResponse_size(const DnsMxResponse *self);
extern uint16_t DnsMxResponse_preference(const DnsMxResponse *self, size_t index);
extern const char *DnsMxResponse_domain(const DnsMxResponse *self, size_t index);
extern void DnsMxResponse_free(DnsMxResponse *self);

extern size_t DnsTxtResponse_size(const DnsTxtResponse *self);
extern const char *DnsTxtResponse_data(const DnsTxtResponse *self, size_t index);
extern void DnsTxtResponse_free(DnsTxtResponse *self);

extern size_t DnsSpfResponse_size(const DnsSpfResponse *self);
extern const char *DnsSpfResponse_data(const DnsSpfResponse *self, size_t index);
extern void DnsSpfResponse_free(DnsSpfResponse *self);

extern size_t DnsPtrResponse_size(const DnsPtrResponse *self);
extern const char *DnsPtrResponse_domain(const DnsPtrResponse *self, size_t index);
extern void DnsPtrResponse_free(DnsPtrResponse *self);

extern dns_stat_t DnsResolver_lookupA(DnsResolver *self, const char *domain, DnsAResponse **resp);
extern dns_stat_t DnsResolver_lookupAaaa(DnsResolver *self, const char *domain,
                                         DnsAaaaResponse **resp);
extern dns_stat_t DnsResolver_lookupMx(DnsResolver *self, const char *domain, DnsMxResponse **resp);
extern dns_stat_t DnsResolver_lookupTxt(DnsResolver *self, const char *domain,
                                        DnsTxtResponse **resp);
extern dns_stat_t DnsResolver_lookupSpf(DnsResolver *self, const char *domain,
                                        DnsSpfResponse **resp);
extern dns_stat_t DnsResolver_lookupPtr(DnsResolver *self, sa_family_t af, const void *addr,
                                        DnsPtrResponse **resp);

extern const char *DnsResolver_getErrorString(const DnsResolver *self);

#ifndef _PATH_RESCONF
#define _PATH_RESCONF  "/etc/resolv.conf"
#endif

#ifdef __cplusplus
}
#endif

#endif /* __DNSRESOLV_H__ */
