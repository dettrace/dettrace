/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

/** @file
 *
 * This "filesystem" provides only a single file. The mountpoint
 * needs to be a file rather than a directory. All writes to the
 * file will be discarded, and reading the file always returns
 * \0.
 *
 * Compile with:
 *
 *     gcc -Wall null.c `pkg-config fuse3 --cflags --libs` -o null
 *
 * ## Source code ##
 * \include passthrough_fh.c
 */


#define FUSE_USE_VERSION 31

#include <fuse.h>
//#include <fuse_lowlevel.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

static char FILE_CONTENTS[12];
static int FILE_LENGTH = 12; // include NUL

static int irw_getattr(const char *path, struct stat *stbuf) {
  if (strcmp(path, "/") != 0) {
    return -ENOENT;
  }
  
  stbuf->st_mode = S_IFREG | 0644;
  stbuf->st_nlink = 1;
  stbuf->st_uid = getuid();
  stbuf->st_gid = getgid();
  stbuf->st_size = FILE_LENGTH;
  stbuf->st_blocks = 1;
  stbuf->st_atime = stbuf->st_mtime = stbuf->st_ctime = time(NULL);
  
  return 0;
}

static int irw_truncate(const char *path, off_t size) {
  if (strcmp(path, "/") != 0) {
    return -ENOENT;
  }
  return 0;
}

static int irw_open(const char *path, struct fuse_file_info *fi)
{
	(void) fi;

	if(strcmp(path, "/") != 0)
		return -ENOENT;

        const char* hw = "hello world";
        strcpy(FILE_CONTENTS, hw);

	return 0;
}

static int irw_read(const char *path, char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
  printf("[fuse] read size:%lu offset:%lu\n", size, offset);

	if (strcmp(path, "/") != 0) {
          return -ENOENT;
        }

	if (offset >= FILE_LENGTH) {
          return 0;
        }

        // we only read 1 byte at a time
	buf[0] = FILE_CONTENTS[offset];
	return 1;
}

static int irw_write(const char *path, const char *buf, size_t size,
		      off_t offset, struct fuse_file_info *fi)
{
	(void) buf;
	(void) offset;
	(void) fi;

        printf("[fuse] write size:%lu offset:%lu\n", size, offset);

	if (strcmp(path, "/") != 0) {
          return -ENOENT;
        }

	if (offset >= FILE_LENGTH) {
          return 0;
        }

        // we only write 1 byte at a time
	FILE_CONTENTS[offset] = buf[0];
printf("[fuse] completed write of size:%lu offset:%lu\n", size, offset);
	return 1;
}

static struct fuse_operations irw_oper = {
	.getattr	= irw_getattr,
	.truncate	= irw_truncate,
	.open		= irw_open,
	.read		= irw_read,
	.write		= irw_write,
};

int main(int argc, char *argv[]) {
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        char* mountpoint;
        int multithreaded, foreground;
	struct stat stbuf;

	if (fuse_parse_cmdline(&args, &mountpoint, &multithreaded, &foreground) != 0)
		return 1;

	if (NULL == mountpoint) {
		fprintf(stderr, "missing mountpoint parameter\n");
		return 1;
	}

	if (stat(mountpoint, &stbuf) == -1) {
		fprintf(stderr ,"failed to access mountpoint %s: %s\n",
			mountpoint, strerror(errno));
		return 1;
	}
	if (!S_ISREG(stbuf.st_mode)) {
		fprintf(stderr, "mountpoint is not a regular file\n");
		return 1;
	}

	return fuse_main(argc, argv, &irw_oper, NULL);
}
