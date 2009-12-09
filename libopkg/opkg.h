/* opkg.h - the opkg  package management system

   Thomas Wood <thomas@openedhand.com>

   Copyright (C) 2008 OpenMoko Inc

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
*/

#ifndef OPKG_H
#define OPKG_H

#include "pkg.h"
#include "opkg_message.h"

//typedef struct _opkg_package_t opkg_package_t;
typedef struct _opkg_progress_data_t opkg_progress_data_t;

typedef void (*opkg_progress_callback_t) (const opkg_progress_data_t *progress, void *user_data);
typedef void (*opkg_package_callback_t) (pkg_t *pkg, void *user_data);

enum _opkg_action_t
{
  OPKG_INSTALL,
  OPKG_REMOVE,
  OPKG_DOWNLOAD
};

enum _opkg_error_code_t
{
  OPKG_NO_ERROR,
  OPKG_UNKNOWN_ERROR,
  OPKG_DOWNLOAD_FAILED,
  OPKG_DEPENDENCIES_FAILED,
  OPKG_PACKAGE_ALREADY_INSTALLED,
  OPKG_PACKAGE_NOT_AVAILABLE,
  OPKG_PACKAGE_NOT_FOUND,
  OPKG_PACKAGE_NOT_INSTALLED,
  OPKG_GPG_ERROR,
  OPKG_MD5_ERROR,
  OPKG_SHA256_ERROR
};

struct _opkg_package_t
{
  char *name;
  char *version;
  char *architecture;
  char *repository;
  char *description;
  char *tags;
  int size;
  int installed;
};

struct _opkg_progress_data_t
{
  int percentage;
  int action;
  pkg_t *pkg;
};

int opkg_new (void);
void opkg_free (void);
int opkg_re_read_config_files (void);
void opkg_get_option (char *option, void **value);
void opkg_set_option (char *option, void *value);

int opkg_install_package (const char *package_name, opkg_progress_callback_t callback, void *user_data);
int opkg_remove_package (const char *package_name, opkg_progress_callback_t callback, void *user_data);
int opkg_upgrade_package (const char *package_name, opkg_progress_callback_t callback, void *user_data);
int opkg_upgrade_all (opkg_progress_callback_t callback, void *user_data);
int opkg_update_package_lists (opkg_progress_callback_t callback, void *user_data);

int opkg_list_packages (opkg_package_callback_t callback, void *user_data);
int opkg_list_upgradable_packages (opkg_package_callback_t callback, void *user_data);
pkg_t* opkg_find_package (const char *name, const char *version, const char *architecture, const char *repository);

int opkg_repository_accessibility_check(void);

#endif /* OPKG_H */
