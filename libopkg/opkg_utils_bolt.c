/* vi: set expandtab sw=4 sts=4: */
/* opkg_utils_bolt.c - the opkg package management system

   Copyright (C) 2020 Tobias Koch <tobias.koch@gmail.com>

   SPDX-License-Identifier: GPL-2.0-or-later

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
*/

#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libgen.h>
#include <string.h>
#include <ctype.h>

#include "sprintf_alloc.h"
#include "opkg_conf.h"
#include "xfuncs.h"

static char *_target_name = NULL;

char *get_bbox_target_name()
{
    if (_target_name)
        return _target_name;

    char *etc_target = NULL;

    sprintf_alloc(&etc_target, "%s/etc/target",
        opkg_config->offline_root ? opkg_config->offline_root : "");

    struct stat sb;

    if (stat(etc_target, &sb) == -1)
        goto cleanup;

    if (opkg_config->offline_root) {
        char *tmp = xstrdup(opkg_config->offline_root);
        _target_name = xstrdup(basename(tmp));
        free(tmp);
    } else {
        size_t size = 0;
        char *line = NULL;

        FILE *fp = fopen(etc_target, "r");
        if (!fp)
            goto cleanup;

        while (getline(&line, &size, fp) != -1) {
            char *s = line;
            char *d = line;

            do {
                while (isspace(*d))
                    ++d;
            } while ((*s++ = *d++));

            s = line;
            d = strstr(line, "=");

            if (!d)
                continue;
            *d++ = '\0';

            if (!strcmp(s, "TARGET_ID")) {
                _target_name = xstrdup(d);
                break;
            }
        }

        free(line);
        fclose(fp);
    }

cleanup:
    free(etc_target);
    return _target_name;
}
