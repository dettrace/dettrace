#include <errno.h>
#include <stdlib.h>
# include <unistd.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>

/* Arrange to define PATH_MAX, like "pathmax.h" does. */
#include <unistd.h>
#include <limits.h>
#include <sys/param.h>
#if !defined PATH_MAX && defined MAXPATHLEN
# define PATH_MAX MAXPATHLEN
#endif

#ifndef AT_FDCWD
# define AT_FDCWD 0
#endif
#ifdef ENAMETOOLONG
# define is_ENAMETOOLONG(x) ((x) == ENAMETOOLONG)
#else
# define is_ENAMETOOLONG(x) 0
#endif

/* Use the getcwd function, not any macro.  */
#undef getcwd

/* Don't get link errors because mkdir is redefined to rpl_mkdir.  */
#undef mkdir

#ifndef S_IRWXU
# define S_IRWXU 0700
#endif

/* The length of this name must be 8.  */
#define DIR_NAME "confdir3"
#define DIR_NAME_LEN 8
#define DIR_NAME_SIZE (DIR_NAME_LEN + 1)

/* The length of "../".  */
#define DOTDOTSLASH_LEN 3

/* Leftover bytes in the buffer, to work around library or OS bugs.  */
#define BUF_SLOP 20

int
main ()
{
  char buf[PATH_MAX * (DIR_NAME_SIZE / DOTDOTSLASH_LEN + 1)
           + DIR_NAME_SIZE + BUF_SLOP];
  char *cwd = getcwd (buf, PATH_MAX);
  size_t initial_cwd_len;
  size_t cwd_len;
  int fail = 0;
  size_t n_chdirs = 0;

  if (cwd == NULL)
    exit (10);

  if (access(DIR_NAME, R_OK | W_OK | X_OK) == 0) {
    fprintf(stderr, "%s already existed\n", DIR_NAME);
    exit(1);
  }

  cwd_len = initial_cwd_len = strlen (cwd);

  while (1)
    {
      size_t dotdot_max = PATH_MAX * (DIR_NAME_SIZE / DOTDOTSLASH_LEN);
      char *c = NULL;

      cwd_len += DIR_NAME_SIZE;
      /* If mkdir or chdir fails, it could be that this system cannot create
         any file with an absolute name longer than PATH_MAX, such as cygwin.
         If so, leave fail as 0, because the current working directory can't
         be too long for getcwd if it can't even be created.  For other
         errors, be pessimistic and consider that as a failure, too.  */
      if (mkdir (DIR_NAME, S_IRWXU) < 0 || chdir (DIR_NAME) < 0)
        {
          if (! (errno == ERANGE || is_ENAMETOOLONG (errno)))
            fail = 20;
          break;
        }

      if (PATH_MAX <= cwd_len && cwd_len < PATH_MAX + DIR_NAME_SIZE)
        {
          struct stat sb;

          c = getcwd (buf, PATH_MAX);
          if (!c && errno == ENOENT)
            {
              fail = 11;
              break;
            }
          if (c)
            {
              fail = 31;
              break;
            }
          if (! (errno == ERANGE || is_ENAMETOOLONG (errno)))
            {
              fail = 21;
              break;
            }

          /* Our replacement needs to be able to stat() long ../../paths,
             so generate a path larger than PATH_MAX to check,
             avoiding the replacement if we can't stat().  */
          c = getcwd (buf, cwd_len + 1);
          if (c && !AT_FDCWD && stat (c, &sb) != 0 && is_ENAMETOOLONG (errno))
            {
              fail = 32;
              break;
            }
        }

      if (dotdot_max <= cwd_len - initial_cwd_len)
        {
          if (dotdot_max + DIR_NAME_SIZE < cwd_len - initial_cwd_len)
            break;
          c = getcwd (buf, cwd_len + 1);
          if (!c)
            {
              if (! (errno == ERANGE || errno == ENOENT
                     || is_ENAMETOOLONG (errno)))
                {
                  fail = 22;
                  break;
                }
              if (AT_FDCWD || errno == ERANGE || errno == ENOENT)
                {
                  fail = 12;
                  break;
                }
            }
        }

      if (c && strlen (c) != cwd_len)
        {
          fail = 23;
          break;
        }
      ++n_chdirs;
    }

  /* Leaving behind such a deep directory is not polite.
     So clean up here, right away, even though the driving
     shell script would also clean up.  */
  {
    size_t i;

    /* Try rmdir first, in case the chdir failed.  */
    rmdir (DIR_NAME);
    for (i = 0; i <= n_chdirs; i++)
      {
        if (chdir ("..") < 0)
          break;
        if (rmdir (DIR_NAME) != 0)
          break;
      }
  }

  printf("success\n");

  exit (fail);
}

