/* pkg_extract.c - the opkg package management system

   Carl D. Worth

   Copyright (C) 2001 University of Southern California

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2, or (at
   your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.
*/

#include <archive.h>
#include <archive_entry.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>

#include "opkg_message.h"
#include "file_util.h"
#include "pkg_extract.h"
#include "sprintf_alloc.h"
#include "xfuncs.h"

struct inner_data {
	/* Pointer to the original archive file we're extracting from. */
	struct archive *	outer;

	/* Buffer for extracted data. */
	void *			buffer;
};

static ssize_t
inner_read(struct archive *a, void *client_data, const void **buff)
{
	struct inner_data * data = (struct inner_data *)client_data;

	*buff = data->buffer;
	return archive_read_data(data->outer, data->buffer, EXTRACT_BUFFER_LEN);
}

static int
inner_close(struct archive *inner, void *client_data)
{
	struct inner_data * data = (struct inner_data *)client_data;

	archive_read_free(data->outer);
	free(data->buffer);
	free(data);

	return ARCHIVE_OK;
}

static int
copy_to_stream(struct archive * a, FILE * stream)
{
	void * buffer;
	size_t sz_in, sz_out;

	buffer = xmalloc(EXTRACT_BUFFER_LEN);

	while (1) {
		/* Read data into buffer. */
		sz_in = archive_read_data(a, buffer, EXTRACT_BUFFER_LEN);
		if (sz_in == ARCHIVE_FATAL || sz_in == ARCHIVE_WARN) {
			opkg_msg(ERROR, "Failed to read data from archive: %s\n", archive_error_string(a));
			free(buffer);
			return -1;
		}
		else if (sz_in == ARCHIVE_RETRY)
			continue;
		else if (sz_in == 0) {
			/* We've reached the end of the file. */
			free(buffer);
			return 0;
		}

		/* Now write data to the output stream. */
		sz_out = fwrite(buffer, 1, sz_in, stream);
		if (sz_out < sz_in) {
			/* An error occurred during writing. */
			opkg_msg(ERROR, "Failed to write data to stream: %s\n", strerror(errno));
			free(buffer);
			return -1;
		}
	}
}

/* Extact a single file from an open archive, writing data to an open stream.
 * Returns 0 on success or <0 on error.
 */
static int
extract_file_to_stream(struct archive * a, const char * name, FILE * stream)
{
	struct archive_entry * entry;
	const char * path;

	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		path = archive_entry_pathname(entry);
		if (strcmp(path, name) == 0)
			/* We found the requested file. */
			return copy_to_stream(a, stream);
		else
			archive_read_data_skip(a);
	}

	/* If we get here, we didn't find the listed file. */
	opkg_msg(ERROR, "Could not find the file '%s' in archive.\n", name);
	return -1;
}

/* Extact the paths of files contained in an open archive, writing data to an
 * open stream.  Returns 0 on success or <0 on error.
 */
static int
extract_paths_to_stream(struct archive * a, FILE * stream)
{
	struct archive_entry * entry;
	int r;
	const char * path;

	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		path = archive_entry_pathname(entry);
		r = fprintf(stream, "%s\n", path);
		if (r <= 0)
			/* Read failed */
			return -1;

		archive_read_data_skip(a);
	}

	return 0;
}

static char * join_paths(const char * left, const char * right)
{
	char * path;

	/* Skip leading '/' or './' in right-hand path if present. */
	while (right[0] == '.' && right[1] == '/')
		right += 2;
	while (right[0] == '/')
		right++;

	/* Don't create '.' directory. */
	if (right[0] == '.' && right[1] == '\0')
		return NULL;

	if  (!left)
		return xstrdup(right);

	sprintf_alloc(&path, "%s%s", left, right);
	return path;
}

/* Transform path components of the given entry.
 *
 * Returns 0 on success, 1 where the file does not need to be extracted and <0
 * on error.
 */
static int
transform_path(struct archive_entry * entry, const char * dest)
{
	char * path;
	const char * filename;

	/* Before we write the file, we need to transform the path.
	 *
	 * Join dest and filename without intervening '/' as left may end with a
	 * prefix to be applied to the names of extracted files.
	 */
	filename = archive_entry_pathname(entry);

	path = join_paths(dest, filename);
	archive_entry_set_pathname(entry, path);
	opkg_msg(DEBUG, "Extracting '%s'.\n", path);
	free(path);

	/* Next transform hardlink and symlink destinations. */
	filename = archive_entry_hardlink(entry);
	if (filename) {
		/* Apply the same transform to the hardlink path as was applied
		 * to the filename path.
		 */
		path = join_paths(dest, filename);
		archive_entry_set_hardlink(entry, path);
		opkg_msg(DEBUG, "... hardlink to '%s'.\n", path);
		free(path);
	}

	filename = archive_entry_symlink(entry);
	if (filename) {
		opkg_msg(DEBUG, "... symlink to '%s'.\n", filename);
	}

	opkg_msg(DEBUG, ".\n");
	return 0;
}

/* Extract all files in an archive to the filesystem under the path given by
 * dest. Returns 0 on success or <0 on error.
 */
static int
extract_all(struct archive * a, const char * dest, int flags)
{
	struct archive * disk;
	struct archive_entry * entry;
	int r;

	disk = archive_write_disk_new();
	archive_write_disk_set_options(disk, flags);
	archive_write_disk_set_standard_lookup(disk);

	while (1) {
		r = archive_read_next_header(a, &entry);
		if (r == ARCHIVE_EOF)
			break;
		if (r != ARCHIVE_OK) {
			opkg_msg(ERROR, "Failed to read header from archive: %s\n", archive_error_string(a));
			goto err_cleanup;
		}

		r = transform_path(entry, dest);
		if (r == 1)
			continue;
		if (r < 0) {
			opkg_msg(ERROR, "Failed to transform path.\n");
			goto err_cleanup;
		}

		r = archive_read_extract2(a, entry, disk);
		if (r != ARCHIVE_OK) {
			opkg_msg(ERROR, "Failed to extract file '%s' to disk.\n", archive_entry_pathname(entry));
			opkg_msg(ERROR, "Archive error: %s\n", archive_error_string(a));
			opkg_msg(ERROR, "Disk error: %s\n", archive_error_string(disk));
			goto err_cleanup;
		}
	}

	r = ARCHIVE_OK;
err_cleanup:
	archive_write_free(disk);
	return (r == ARCHIVE_OK) ? 0 : -1;
}

/* Prepare to extract 'control.tar.gz' or 'data.tar.gz' from the outer package
 * archive, returning a `struct archive *` for the enclosed file. On error,
 * return NULL.
 */
static struct archive *
extract_outer(pkg_t * pkg, const char * arname)
{
	int r;
	struct archive * inner;
	struct archive * outer;
	struct archive_entry * entry;
	struct inner_data * data;
	const char * path;

	data = (struct inner_data *)xmalloc(sizeof(struct inner_data));
	data->buffer = xmalloc(EXTRACT_BUFFER_LEN);

	outer = archive_read_new();
	/* Outer package is in 'ar' format, uncompressed. */
	archive_read_support_format_ar(outer);

	inner = archive_read_new();
	/* Inner package is in 'tar' format, gzip compressed. */
	archive_read_support_filter_gzip(inner);
	archive_read_support_format_tar(inner);

	r = archive_read_open_filename(outer, pkg->local_filename, EXTRACT_BUFFER_LEN);
	if (r != ARCHIVE_OK) {
		opkg_msg(ERROR, "Failed to open package '%s': %s\n", pkg->local_filename, archive_error_string(outer));
		goto err_cleanup;
	}

	while (archive_read_next_header(outer, &entry) == ARCHIVE_OK) {
		path = archive_entry_pathname(entry);
		if (strcmp(path, arname) == 0) {
			/* We found the requested file. */
			data->outer = outer;
			r = archive_read_open(inner, data, NULL, inner_read, inner_close);
			if (r != ARCHIVE_OK) {
				opkg_msg(ERROR, "Failed to open inner archive: %s\n", archive_error_string(inner));
				goto err_cleanup;
			}

			return inner;
		}
	}

err_cleanup:
	opkg_msg(ERROR, "Could not find the inner archive '%s' in package '%s'\n", arname, pkg->local_filename);
	if (data) {
		if (data->buffer)
			free(data->buffer);
		free(data);
	}

	if (outer)
		archive_read_free(outer);

	return NULL;
}

int
pkg_extract_control_file_to_stream(pkg_t *pkg, FILE *stream)
{
	int err = 0;
	struct archive * a = extract_outer(pkg, "control.tar.gz");
	if (!a) {
		opkg_msg(ERROR,
			 "Failed to extract control.tar.gz from package '%s'.\n",
			 pkg->local_filename);
		return -1;
	}

	err = extract_file_to_stream(a, "control", stream);
	archive_read_free(a);
	if (err < 0)
		opkg_msg(ERROR,
			 "Failed to extract control file from package '%s'.\n",
			 pkg->local_filename);

	return err;
}

int
pkg_extract_control_files_to_dir_with_prefix(pkg_t *pkg, const char *dir,
		const char *prefix)
{
	int err;
	int flags;
	char *dir_with_prefix;

	sprintf_alloc(&dir_with_prefix, "%s/%s", dir, prefix);

	struct archive * a = extract_outer(pkg, "control.tar.gz");
	if (!a) {
		free(dir_with_prefix);
		opkg_msg(ERROR,
			 "Failed to extract control.tar.gz from package '%s'.\n",
			 pkg->local_filename);
		return -1;
	}

	flags = ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_PERM |
		ARCHIVE_EXTRACT_TIME;
	err = extract_all(a, dir_with_prefix, flags);
	archive_read_free(a);
	free(dir_with_prefix);
	if (err < 0)
		opkg_msg(ERROR,
			 "Failed to extract all control files from package '%s'.\n",
			 pkg->local_filename);

	return err;
}

int
pkg_extract_control_files_to_dir(pkg_t *pkg, const char *dir)
{
	return pkg_extract_control_files_to_dir_with_prefix(pkg, dir, "");
}


int
pkg_extract_data_files_to_dir(pkg_t *pkg, const char *dir)
{
	int err;
	int flags;

	struct archive * a = extract_outer(pkg, "data.tar.gz");
	if (!a) {
		opkg_msg(ERROR,
			 "Failed to extract data.tar.gz from package '%s'.\n",
			 pkg->local_filename);
		return -1;
	}

	/** Flags:
	 *
	 * TODO: Do we want to support ACLs, extended flags and extended
	 * attributes? (ARCHIVE_EXTRACT_ACL, ARCHIVE_EXTRACT_FFLAGS,
	 * ARCHIVE_EXTRACT_XATTR).
	 */
	flags = ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_PERM |
		ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_UNLINK;
	err = extract_all(a, dir, flags);
	archive_read_free(a);
	if (err < 0)
		opkg_msg(ERROR,
			 "Failed to extract data files from package '%s'.\n",
			 pkg->local_filename);

	return err;
}

int
pkg_extract_data_file_names_to_stream(pkg_t *pkg, FILE *stream)
{
	int err;

	struct archive * a = extract_outer(pkg, "data.tar.gz");
	if (!a) {
		opkg_msg(ERROR,
			 "Failed to extract data.tar.gz from package '%s'.\n",
			 pkg->local_filename);
		return -1;
	}

	err = extract_paths_to_stream(a, stream);
	archive_read_free(a);
	if (err < 0)
		opkg_msg(ERROR,
			 "Failed to extract data file names from package '%s'.\n",
			 pkg->local_filename);

	return err;
}
