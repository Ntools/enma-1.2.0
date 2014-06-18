/*
 * Copyright (c) 2008-2009 Internet Initiative Japan Inc. All rights reserved.
 *
 * The terms and conditions of the accompanying program
 * shall be provided separately by Internet Initiative Japan Inc.
 * Any use, reproduction or distribution of the program are permitted
 * provided that you agree to be bound to such terms and conditions.
 *
 * $Id: config_loader.h 1462 2011-12-21 11:55:05Z takahiko $
 */

#ifndef __CONFIG_LOADER_H__
#define __CONFIG_LOADER_H__

#include <stdbool.h>
#include <netinet/in.h>
#include <arpa/inet.h>

typedef enum {
    CONFIGTYPE_STRING,
    CONFIGTYPE_BOOLEAN,
    CONFIGTYPE_INTEGER,
    CONFIGTYPE_LONG,
    CONFIGTYPE_SYSLOG_PRIORITY,
    CONFIGTYPE_SYSLOG_FACILITY,
    CONFIGTYPE_IP_ADDRESS,
    CONFIGTYPE_IP_ADDRESS_LIST,
} ConfigType;

typedef struct ConfigEntry {
    const char *config_name;    // name of configuration entry
    const ConfigType config_type;   // type of the entry
    const char *default_value;  // default value of the entry
    const int struct_offset;    // offset of the entry
    const char *description;    // description of the entry
} ConfigEntry;

#define CONFIG_LINE_MAX_LEN 512 // maximum line length of configuration file

extern bool ConfigLoader_setConfigValue(const ConfigEntry *config_entry, const char *filename,
                                        void *config_struct);
extern bool ConfigLoader_setDefaultValue(const ConfigEntry *config_entry, void *config_struct);
extern bool ConfigLoader_setOptionValue(const ConfigEntry *config_entry, const char *config_key,
                                        const char *config_value, void *config_struct);
extern bool ConfigLoader_setEqualStringOptionValue(const ConfigEntry *config_entry,
                                                   const char *optarg, void *config_struct);
extern void ConfigLoader_init(const ConfigEntry *config_entry, void *config_struct);
extern void ConfigLoader_free(const ConfigEntry *config_entry, void *config_struct);
extern void ConfigLoader_dump(const ConfigEntry *config_entry, const void *config_struct,
                              FILE *out);

#endif /* __CONFIG_LOADER_H__ */
