/*
 * Copyright (c) 2008-2010 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: config_loader.c 1366 2011-10-16 08:13:40Z takahiko $
 */

#include "rcsid.h"
RCSID("$Id: config_loader.c 1366 2011-10-16 08:13:40Z takahiko $");

#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stddef.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ptrop.h"
#include "strarray.h"

#include "ipaddressrange.h"
#include "consolehandler.h"
#include "string_util.h"
#include "syslogtable.h"
#include "config_loader.h"

/**
 * 渡された文字列情報を、文字列のまま設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setString(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    char **config_char_p = (char **) config_storage;

    *config_char_p = strdup(config_value);
    if (NULL == *config_char_p) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return false;
    }
    return true;
}

/**
 * Convert from string to bool
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setBoolean(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    const char true_list[][10] = { "yes", "true", "on", "1" };
    const char false_list[][10] = { "no", "false", "off", "0" };

    int *config_bool_p = (int *) config_storage;

    // true?
    for (int i = 0; i < (int) (sizeof(true_list) / sizeof(true_list[0])); ++i) {
        if (0 == strcasecmp(config_value, true_list[i])) {
            *config_bool_p = true;
            return true;
        }
    }
    // false?
    for (int i = 0; i < (int) (sizeof(false_list) / sizeof(false_list[0])); ++i) {
        if (0 == strcasecmp(config_value, false_list[i])) {
            *config_bool_p = false;
            return true;
        }
    }

    return false;
}

/**
 * 渡された文字列情報を、int に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setInteger(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    int *config_int_p = (int *) config_storage;

    bool errflag;
    long int parsed_long = strtolstrict(config_value, &errflag);
    if (errflag) {
        return false;
    }
    *config_int_p = (int) parsed_long;
    return true;
}

/**
 * 渡された文字列情報を、long int に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setLong(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    long int *config_long_p = (long int *) config_storage;

    bool errflag;
    long int parsed_long = strtolstrict(config_value, &errflag);
    if (errflag) {
        return false;
    }
    *config_long_p = parsed_long;
    return true;
}

/**
 * 渡された文字列情報を、syslogのfacilityを示すint型に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setSyslogFacility(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    int *config_int_p = (int *) config_storage;

    if (-1 == (*config_int_p = lookup_facility_const(config_value))) {
        return false;
    }

    return true;
}

/**
 * 渡された文字列情報を、syslogのpriorityを示すint型に変換し設定の保存領域に記憶
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setSyslogPriority(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    int *config_int_p = (int *) config_storage;

    if (-1 == (*config_int_p = lookup_priority_const(config_value))) {
        return false;
    }

    return true;
}

/**
 * 渡された文字列情報を、IPAddressRange に格納
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setIPAddress(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    IPAddressRange **config_ip_address_p = (IPAddressRange **) config_storage;

    *config_ip_address_p = IPAddressRange_new();
    if (NULL == *config_ip_address_p) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return false;
    }

    if (!IPAddressRange_set(*config_ip_address_p, config_value)) {
        ConsoleError("failed to parse address: address=%s", config_value);
        goto error;
    }

    return true;

  error:
    if (NULL != *config_ip_address_p) {
        IPAddressRange_free(*config_ip_address_p);
        *config_ip_address_p = NULL;
    }
    return false;
}

/**
 * 渡された文字列情報を、IPAddressRangeList に格納
 *
 * @param config_storage
 * @param config_value
 * @return
 */
static bool
ConfigLoader_setIPAddressList(void *config_storage, const char *config_value)
{
    assert(NULL != config_storage);
    assert(NULL != config_value);

    IPAddressRangeList **config_ip_address_list_p = (IPAddressRangeList **) config_storage;

    /* 渡されたIPアドレス情報を、特定の文字で分割 */
    StrArray *addr_array = StrArray_split(config_value, ", ", true);
    if (addr_array == NULL) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return false;
    }

    /* IPアドレスのリストを作成 */
    int range_list_len = (int) StrArray_getCount(addr_array);
    *config_ip_address_list_p = IPAddressRangeList_new(range_list_len);
    if (NULL == *config_ip_address_list_p) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        goto error;
    }

    const char *addr;
    for (int i = 0; i < range_list_len; ++i) {
        addr = StrArray_get(addr_array, i);
        if (!IPAddressRangeList_set(*config_ip_address_list_p, (size_t) i, addr)) {
            ConsoleError("failed to parse address: address=%s", addr);
            goto error;
        }
    }
    StrArray_free(addr_array);

    return true;

  error:
    if (NULL != *config_ip_address_list_p) {
        IPAddressRangeList_free(*config_ip_address_list_p);
        *config_ip_address_list_p = NULL;
    }
    if (NULL != addr_array) {
        StrArray_free(addr_array);
    }
    return false;
}

/**
 * 既に設定情報が保持されているかを判定する
 *
 * @param config_storage
 * @param config_type
 * @return
 */
static bool
ConfigLoader_isSet(void *config_storage, const ConfigType config_type)
{
    assert(NULL != config_storage);

    switch (config_type) {
    case CONFIGTYPE_STRING:
    case CONFIGTYPE_IP_ADDRESS:
    case CONFIGTYPE_IP_ADDRESS_LIST:;
        void **config_ptr = (void **) config_storage;
        if (NULL == *config_ptr) {
            return false;
        }
        break;
    case CONFIGTYPE_BOOLEAN:
    case CONFIGTYPE_INTEGER:
    case CONFIGTYPE_LONG:
    case CONFIGTYPE_SYSLOG_PRIORITY:
    case CONFIGTYPE_SYSLOG_FACILITY:;
        int *config_int_p = (int *) config_storage;
        if (-1 == *config_int_p) {
            return false;
        }
        break;
    default:
        ConsoleError("unknown config type: type=%d", config_type);
        abort();
    }

    return true;
}

/**
 * 各設定情報の型に合わせて設定情報を記憶
 *
 * @param config_entry
 * @param config_struct
 * @param config_value	NULLの場合もある
 * @return
 */
static bool
ConfigLoader_setValue(const ConfigEntry *config_entry,
                      void *config_struct, const char *config_value)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    void *config_storage = STRUCT_MEMBER_P(config_struct, config_entry->struct_offset);

    // 既に保存されていたら上書きしない
    if (ConfigLoader_isSet(config_storage, config_entry->config_type)) {
        return true;
    }

    switch (config_entry->config_type) {
    case CONFIGTYPE_STRING:
        if (NULL != config_value && !ConfigLoader_setString(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_BOOLEAN:
        if (!ConfigLoader_setBoolean(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_INTEGER:
        if (!ConfigLoader_setInteger(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_LONG:
        if (!ConfigLoader_setLong(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_SYSLOG_FACILITY:
        if (!ConfigLoader_setSyslogFacility(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_SYSLOG_PRIORITY:
        if (!ConfigLoader_setSyslogPriority(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_IP_ADDRESS:
        if (!ConfigLoader_setIPAddress(config_storage, config_value)) {
            return false;
        }
        break;
    case CONFIGTYPE_IP_ADDRESS_LIST:
        if (!ConfigLoader_setIPAddressList(config_storage, config_value)) {
            return false;
        }
        break;
    default:
        ConsoleError("unknown config type: type=%d", config_entry->config_type);
        abort();
    }
    return true;
}

/**
 * 指定された設定項目に対応するエントリを返す
 *
 * @param config_entry
 * @param entry_name
 * @return
 */
static const ConfigEntry *
ConfigLoader_lookupEntry(const ConfigEntry *config_entry, const char *entry_name)
{
    assert(NULL != config_entry);
    assert(NULL != entry_name);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        if (0 == strncmp(p->config_name, entry_name, strlen(p->config_name))) {
            return p;
        }
    }
    return NULL;
}

/**
 * 指定されたファイルから設定情報を読み込み、記憶する
 *
 * @param config_entry
 * @param filename
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setConfigValue(const ConfigEntry *config_entry,
                            const char *filename, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != filename);
    assert(NULL != config_struct);

    FILE *fp = fopen(filename, "r");
    if (NULL == fp) {
        ConsoleError("fopen failed: file=%s, error=%s", filename, strerror(errno));
        return false;
    }

    char line[CONFIG_LINE_MAX_LEN];
    char *line_orig;
    int current_line_no = 0;
    char *config_key, *config_value;
    while (NULL != fgets(line, CONFIG_LINE_MAX_LEN, fp)) {
        line_orig = line;
        ++current_line_no;
        (void) strstrip(line);

        // コメント、空行は無視
        if (line[0] == '#' || line[0] == '\0') {
            continue;
        }

        config_key = strtok_r(line, ":", &config_value);
        if (NULL == config_key || NULL == config_value) {
            ConsoleNotice("config parse failed: file=%s:%d, line=%s", filename, current_line_no,
                          line_orig);
            goto error_finally;
        }
        (void) strstrip(config_key);
        (void) strstrip(config_value);

        const ConfigEntry *entry = ConfigLoader_lookupEntry(config_entry,
                                                            config_key);
        if (NULL == entry) {
            ConsoleNotice("config parse failed: file=%s:%d, key=%s, value=%s", filename,
                          current_line_no, config_key, config_value);
            goto error_finally;
        }
        if (!ConfigLoader_setValue(entry, config_struct, config_value)) {
            ConsoleNotice("config parse failed: file=%s:%d, key=%s, value=%s", filename,
                          current_line_no, config_key, config_value);
            goto error_finally;
        }
    }

    if (0 != ferror(fp)) {
        ConsoleError("fgets failed: file=%s", filename);
        goto error_finally;
    }

    if (0 != fclose(fp)) {
        // エラー出力のみ
        ConsoleError("fclose failed: file=%s, error=%s", filename, strerror(errno));
    }

    return true;

  error_finally:
    if (0 != fclose(fp)) {
        // エラー出力のみ
        ConsoleError("fclose failed: file=%s, error=%s", filename, strerror(errno));
    }
    return false;
}

/**
 * デフォルトの設定情報を設定の保存領域に記憶
 *
 * @param config_entry
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setDefaultValue(const ConfigEntry *config_entry, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        if (!ConfigLoader_setValue(p, config_struct, p->default_value)) {
            // デフォルトの設定値の記憶失敗
            ConsoleNotice("config parse failed: key=%s, value=%s", p->config_name,
                          p->default_value);
            return false;
        }
    }
    return true;
}

/**
 * オプションとして渡された引数の設定情報を保存領域に記憶
 *
 * @param config_entry
 * @param config_key
 * @param config_value
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setOptionValue(const ConfigEntry *config_entry,
                            const char *config_key, const char *config_value, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_key);
    assert(NULL != config_value);
    assert(NULL != config_struct);

    const ConfigEntry *entry = ConfigLoader_lookupEntry(config_entry,
                                                        config_key);
    if (NULL == entry) {
        ConsoleNotice("config parse failed: key=%s, value=%s", config_key, config_value);
        return false;
    }
    if (!ConfigLoader_setValue(entry, config_struct, config_value)) {
        // 設定値の記憶失敗
        ConsoleNotice("config parse failed: key=%s, value=%s", config_key, config_value);
        return false;
    }

    return true;
}

/**
 * -oオプションで渡された'='付きの設定情報を保存領域に記憶
 *
 * @param config_entry
 * @param optarg
 * @param config_struct
 * @return
 */
bool
ConfigLoader_setEqualStringOptionValue(const ConfigEntry *config_entry,
                                       const char *optarg, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != optarg);
    assert(NULL != config_struct);

    // key=value を分割
    char *pair = strdup(optarg);
    if (NULL == pair) {
        ConsoleError("memory allocation failed: error=%s", strerror(errno));
        return false;
    }
    char *config_key = pair;
    char *config_value = strchr(pair, '=');
    if (NULL != config_value) {
        *config_value++ = '\0';
        // 空白ならエラー
        if (config_value[0] == '\0') {
            goto error_finally;
        }
    } else {
        goto error_finally;
    }

    // key と value を保存
    if (!ConfigLoader_setOptionValue(config_entry, config_key, config_value, config_struct)) {
        goto error_finally;
    }

    PTRINIT(pair);
    return true;

  error_finally:
    PTRINIT(pair);
    return false;
}

/**
 * initialize the ConfigLoader
 *
 * @param config_entry
 * @param config_struct
 * @return
 */
void
ConfigLoader_init(const ConfigEntry *config_entry, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        switch (p->config_type) {
        case CONFIGTYPE_STRING:;
            char **config_char_p = (char **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            *config_char_p = NULL;
            break;
        case CONFIGTYPE_BOOLEAN:
        case CONFIGTYPE_INTEGER:
        case CONFIGTYPE_LONG:
        case CONFIGTYPE_SYSLOG_FACILITY:
        case CONFIGTYPE_SYSLOG_PRIORITY:;
            int *config_int_p = (int *) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            *config_int_p = -1;
            break;
        case CONFIGTYPE_IP_ADDRESS:;
            IPAddressRange **config_ip_address_p =
                (IPAddressRange **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            *config_ip_address_p = NULL;
            break;
        case CONFIGTYPE_IP_ADDRESS_LIST:;
            IPAddressRangeList **config_ip_address_list_p =
                (IPAddressRangeList **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            *config_ip_address_list_p = NULL;
            break;
        default:
            ConsoleError("unknown config type: type=%d", p->config_type);
            abort();
        }
    }
}

/**
 * free the ConfigEntry
 *
 * @param config_entry
 * @param config_struct
 * @return
 */
void
ConfigLoader_free(const ConfigEntry *config_entry, void *config_struct)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);

    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        switch (p->config_type) {
        case CONFIGTYPE_STRING:;
            char **config_char_p = (char **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            PTRINIT(*config_char_p);
            break;
        case CONFIGTYPE_BOOLEAN:
        case CONFIGTYPE_INTEGER:
        case CONFIGTYPE_LONG:
        case CONFIGTYPE_SYSLOG_FACILITY:
        case CONFIGTYPE_SYSLOG_PRIORITY:
            break;
        case CONFIGTYPE_IP_ADDRESS:;
            IPAddressRange **config_ipaddress_p =
                (IPAddressRange **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            if (NULL != *config_ipaddress_p) {
                IPAddressRange_free(*config_ipaddress_p);
                *config_ipaddress_p = NULL;
            }
            break;
        case CONFIGTYPE_IP_ADDRESS_LIST:;
            IPAddressRangeList **config_ipaddress_list_p =
                (IPAddressRangeList **) STRUCT_MEMBER_P(config_struct, p->struct_offset);
            if (NULL != *config_ipaddress_list_p) {
                IPAddressRangeList_free(*config_ipaddress_list_p);
                *config_ipaddress_list_p = NULL;
            }
            break;
        default:
            ConsoleError("unknown config type: type=%d", p->config_type);
            abort();
        }
    }
}

/**
 * dump configuration entries
 *
 * @param config_entry
 * @param config_struct
 * @param out
 */
void
ConfigLoader_dump(const ConfigEntry *config_entry, const void *config_struct, FILE *out)
{
    assert(NULL != config_entry);
    assert(NULL != config_struct);
    assert(NULL != out);

    fprintf(out, "configure list:\n");
    for (const ConfigEntry *p = config_entry; NULL != p->config_name; ++p) {
        fprintf(out, "  %s: ", p->config_name);
        void *value = STRUCT_MEMBER_P(config_struct, p->struct_offset);

        int retval;
        switch (p->config_type) {
        case CONFIGTYPE_STRING:
            fprintf(out, "%s", NNSTR(*(char **) value));
            break;
        case CONFIGTYPE_BOOLEAN:
            fprintf(out, "%s", *(int *) value ? "true" : "false");
            break;
        case CONFIGTYPE_INTEGER:
            fprintf(out, "%d", *(int *) value);
            break;
        case CONFIGTYPE_LONG:
            fprintf(out, "%ld", *(long *) value);
            break;
        case CONFIGTYPE_SYSLOG_FACILITY:
            fprintf(out, "%s", lookup_facility_name(*(int *) value));
            break;
        case CONFIGTYPE_SYSLOG_PRIORITY:
            fprintf(out, "%s", lookup_priority_name(*(int *) value));
            break;
        case CONFIGTYPE_IP_ADDRESS:;
            IPAddressRange **addr_range_p = (IPAddressRange **) value;
            char addrbuf[INET6_ADDRSTRLEN + sizeof("/128")];
            retval = IPAddressRange_toString(*addr_range_p, addrbuf, sizeof(addrbuf));
            if (retval < 0) {
                ConsoleError("IPAddressRange_toString failed: error=%s", strerror(retval));
                abort();
            }
            fprintf(out, "[%s]", addrbuf);
            break;
        case CONFIGTYPE_IP_ADDRESS_LIST:;
            IPAddressRangeList **addr_range_list_p = (IPAddressRangeList **) value;
            char rangebuf[INET6_ADDRSTRLEN + sizeof("/128")];
            for (int i = 0; i < (int) IPAddressRangeList_getCount(*addr_range_list_p); ++i) {
                const IPAddressRange *addr_range = IPAddressRangeList_get(*addr_range_list_p, i);
                retval = IPAddressRange_toString(addr_range, rangebuf, sizeof(rangebuf));
                if (retval < 0) {
                    ConsoleError("IPAddressRange_toString failed: error=%s", strerror(retval));
                    abort();
                }
                fprintf(out, "[%s]", rangebuf);
            }
            break;
        default:
            ConsoleError("unknown config type: type=%d", p->config_type);
            abort();
        }
        fprintf(out, "\n");
    }
    fflush(out);
}
