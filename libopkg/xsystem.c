/* vi: set expandtab sw=4 sts=4: */
/* xsystem.c - system(3) with error messages

   Carl D. Worth

   Copyright (C) 2001 University of Southern California

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

#include "config.h"

#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>

#include "opkg_message.h"
#include "opkg_conf.h"
#include "sprintf_alloc.h"
#include "xsystem.h"

static int unshare_and_map_user_helper();

/* Like system(3), but with error messages printed if the fork fails
   or if the child process dies due to an uncaught signal. Also, the
   return value is a bit simpler:

   -1 if there was any problem
   Otherwise, the 8-bit return value of the program ala WEXITSTATUS
   as defined in <sys/wait.h>.
*/
int xsystem(const char *argv[])
{
    int status;
    pid_t pid;
    int r;

    pid = vfork();

    switch (pid) {
    case -1:
        opkg_perror(ERROR, "%s: vfork", argv[0]);
        return -1;
    case 0:
        /* child */
        execvp(argv[0], (char *const *)argv);
        _exit(-1);
    default:
        /* parent */
        break;
    }

    r = waitpid(pid, &status, 0);
    if (r == -1) {
        opkg_perror(ERROR, "%s: waitpid", argv[0]);
        return -1;
    }

    if (WIFSIGNALED(status)) {
        opkg_msg(ERROR, "%s: Child killed by signal %d.\n", argv[0],
                 WTERMSIG(status));
        return -1;
    }

    if (!WIFEXITED(status)) {
        /* shouldn't happen */
        opkg_msg(ERROR,
                 "%s: Your system is broken: got status %d " "from waitpid.\n",
                 argv[0], status);
        return -1;
    }

    return WEXITSTATUS(status);
}

/* Like xsystem above, but additionally chroots into an offline root.

   Returns -1 if there was any problem.

   Otherwise, the 8-bit return value of the program ala WEXITSTATUS
   as defined in <sys/wait.h>.
*/
int xsystem_offline_root(const char *argv[])
{
    int status;
    pid_t pid;
    int r;

    pid = vfork();

    switch (pid) {
    case -1:
        opkg_perror(ERROR, "%s: vfork", argv[0]);
        return -1;
    case 0:
        /* child */
        if (opkg_config->offline_root) {
            if (geteuid() != 0) {
                if (unshare_and_map_user_helper() != 0) {
                    _exit(-1);
                }
            }

            if (chroot(opkg_config->offline_root) != 0) {
                opkg_msg(ERROR, "Failed to chroot to offline root.");
                _exit(-1);
            }
        }
        execvp(argv[0], (char *const *)argv);
        _exit(-1);
    default:
        /* parent */
        break;
    }

    r = waitpid(pid, &status, 0);
    if (r == -1) {
        opkg_perror(ERROR, "%s: waitpid", argv[0]);
        return -1;
    }

    if (WIFSIGNALED(status)) {
        opkg_msg(ERROR, "%s: Child killed by signal %d.\n", argv[0],
                 WTERMSIG(status));
        return -1;
    }

    if (!WIFEXITED(status)) {
        /* shouldn't happen */
        opkg_msg(ERROR,
                 "%s: Your system is broken: got status %d " "from waitpid.\n",
                 argv[0], status);
        return -1;
    }

    return WEXITSTATUS(status);
}

static int unshare_and_map_user_helper() {
    int fd, ret = -1;

    char *mapfile = NULL;
    char *content = NULL;

    pid_t pid = getpid();
    uid_t uid = geteuid();
    gid_t gid = getegid();

    /* Call `unshare` */

    if (unshare(CLONE_NEWUSER) != 0) {
        opkg_msg(ERROR, "Failed to unshare the user namespace.");
        return -1;
    }

    /* Write uid_map */

    sprintf_alloc(&mapfile, "/proc/%ld/uid_map", (long) pid);
    ret = fd = open(mapfile, O_RDWR);

    if (ret == -1) {
        opkg_msg(ERROR, "Failed to open '%s'.", mapfile);
        goto error;
    }

    sprintf_alloc(&content, "0 %lu 1", (unsigned long) uid);
    ret = write(fd, content, strlen(content));
    close(fd);
    free(content);
    content = NULL;

    if(ret == -1) {
        opkg_msg(ERROR, "Failed to write mapping to '%s'.", mapfile);
        goto error;
    }

    free(mapfile);
    mapfile = NULL;

    /* Write "deny" to /proc/<pid>/setgroups */

    sprintf_alloc(&mapfile, "/proc/%ld/setgroups", (long) pid);
    ret = fd = open(mapfile, O_RDWR);

    if (ret == -1) {
        opkg_msg(ERROR, "Failed to open '%s'.", mapfile);
        goto error;
    }

    ret = write(fd, "deny", strlen("deny"));
    close(fd);

    if (ret == -1) {
        opkg_msg(ERROR, "Failed to disable setgroup.");
        goto error;
    }

    free(mapfile);
    mapfile = NULL;

    /* Write gid_map */

    sprintf_alloc(&mapfile, "/proc/%ld/gid_map", (long) pid);
    ret = fd = open(mapfile, O_RDWR);

    if (ret == -1) {
        opkg_msg(ERROR, "Failed to open '%s'.", mapfile);
        goto error;
    }

    sprintf_alloc(&content, "0 %lu 1\n", (unsigned long) gid);
    ret = write(fd, content, strlen(content));
    close(fd);
    free(content);
    content = NULL;

    if(ret == -1) {
        opkg_msg(ERROR, "Failed to write mapping to '%s'.", mapfile);
        goto error;
    }

    free(mapfile);
    mapfile = NULL;

    ret = 0;

error:
    free(mapfile);
    free(content);

    return ret;
}
