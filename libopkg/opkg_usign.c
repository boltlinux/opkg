/* vi: set expandtab sw=4 sts=4: */
/* opkg_usign.c - the opkg package management system

    Copyright (C) 2019 Tobias Koch

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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "opkg_conf.h"
#include "opkg_message.h"
#include "opkg_usign.h"

int opkg_verify_usign_signature(const char *file, const char *sigfile)
{
    int status = -1;
    int pid;

    pid = fork();

    if(pid < 0) {
        opkg_perror(ERROR, "Failed to fork usign process");
        return -1;
    }

    if(!pid) {
        char *usign = NULL;
        struct stat st;

        char *usign_progs[] = {"/tools/bin/usign", "/usr/bin/usign", NULL};

        for (int i = 0; (usign = usign_progs[i]) != NULL; i++) {
            if (lstat(usign, &st) == 0) {
                break;
            } else {
                usign = NULL;
            }
        }

        if (usign) {
            execl(usign, "usign", "-q", "-V", "-P", "/etc/opkg/usign/trustdb",
                    "-m", file, "-x", sigfile, NULL);
        } else {
            opkg_perror(ERROR, "Could not find usign executable");
        }

        exit(255);
    }

    waitpid(pid, &status, 0);
    if(!WIFEXITED(status) || WEXITSTATUS(status))
        return -1;

    return 0;
}
