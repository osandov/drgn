/* Retrieve ELF / DWARF / source files from the debuginfod.
   Copyright (C) 2019-2020 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */


/* cargo-cult from libdwfl linux-kernel-modules.c */
/* In case we have a bad fts we include this before config.h because it
   can't handle _FILE_OFFSET_BITS.
   Everything we need here is fine if its declarations just come first.
   Also, include sys/types.h before fts. On some systems fts.h is not self
   contained. */
#ifdef BAD_FTS
  #include <sys/types.h>
  #include <fts.h>
#endif

#include "config.h"
#include "debuginfod.h"
#include "system.h"
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <regex.h>
#include <string.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <time.h>
#include <utime.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <curl/curl.h>

/* If fts.h is included before config.h, its indirect inclusions may not
   give us the right LFS aliases of these functions, so map them manually.  */
#ifdef BAD_FTS
  #ifdef _FILE_OFFSET_BITS
    #define open open64
    #define fopen fopen64
  #endif
#else
  #include <sys/types.h>
  #include <fts.h>
#endif

struct debuginfod_client
{
  /* Progress/interrupt callback function. */
  debuginfod_progressfn_t progressfn;

  /* Stores user data. */
  void* user_data;

  /* Stores current/last url, if any. */
  char* url;

  /* Accumulates outgoing http header names/values. */
  int user_agent_set_p; /* affects add_default_headers */
  struct curl_slist *headers;

  /* Flags the default_progressfn having printed something that
     debuginfod_end needs to terminate. */
  int default_progressfn_printed_p;

  /* Can contain all other context, like cache_path, server_urls,
     timeout or other info gotten from environment variables, the
     handle data, etc. So those don't have to be reparsed and
     recreated on each request.  */
};

/* The cache_clean_interval_s file within the debuginfod cache specifies
   how frequently the cache should be cleaned. The file's st_mtime represents
   the time of last cleaning.  */
static const char *cache_clean_interval_filename = "cache_clean_interval_s";
static const time_t cache_clean_default_interval_s = 86400; /* 1 day */

/* The cache_max_unused_age_s file within the debuginfod cache specifies the
   the maximum time since last access that a file will remain in the cache.  */
static const char *cache_max_unused_age_filename = "max_unused_age_s";
static const time_t cache_default_max_unused_age_s = 604800; /* 1 week */

/* Location of the cache of files downloaded from debuginfods.
   The default parent directory is $HOME, or '/' if $HOME doesn't exist.  */
static const char *cache_default_name = ".debuginfod_client_cache";
static const char *cache_xdg_name = "debuginfod_client";
static const char *cache_path_envvar = DEBUGINFOD_CACHE_PATH_ENV_VAR;

/* URLs of debuginfods, separated by url_delim. */
static const char *server_urls_envvar = DEBUGINFOD_URLS_ENV_VAR;
static const char *url_delim =  " ";
static const char url_delim_char = ' ';

/* Timeout for debuginfods, in seconds (to get at least 100K). */
static const char *server_timeout_envvar = DEBUGINFOD_TIMEOUT_ENV_VAR;
static const long default_timeout = 90;


/* Data associated with a particular CURL easy handle. Passed to
   the write callback.  */
struct handle_data
{
  /* Cache file to be written to in case query is successful.  */
  int fd;

  /* URL queried by this handle.  */
  char url[PATH_MAX];

  /* This handle.  */
  CURL *handle;

  /* The client object whom we're serving. */
  debuginfod_client *client;

  /* Pointer to handle that should write to fd. Initially points to NULL,
     then points to the first handle that begins writing the target file
     to the cache. Used to ensure that a file is not downloaded from
     multiple servers unnecessarily.  */
  CURL **target_handle;
};

static size_t
debuginfod_write_callback (char *ptr, size_t size, size_t nmemb, void *data)
{
  ssize_t count = size * nmemb;

  struct handle_data *d = (struct handle_data*)data;

  /* Indicate to other handles that they can abort their transfer.  */
  if (*d->target_handle == NULL)
    {
      *d->target_handle = d->handle;
      /* update the client object */
      const char *url = NULL;
      (void) curl_easy_getinfo (d->handle, CURLINFO_EFFECTIVE_URL, &url);
      if (url)
        {
          free (d->client->url);
          d->client->url = strdup(url); /* ok if fails */
        }
    }

  /* If this handle isn't the target handle, abort transfer.  */
  if (*d->target_handle != d->handle)
    return -1;

  return (size_t) write(d->fd, (void*)ptr, count);
}

/* Create the cache and interval file if they do not already exist.
   Return 0 if cache and config file are initialized, otherwise return
   the appropriate error code.  */
static int
debuginfod_init_cache (char *cache_path, char *interval_path, char *maxage_path)
{
  struct stat st;

  /* If the cache and config file already exist then we are done.  */
  if (stat(cache_path, &st) == 0 && stat(interval_path, &st) == 0)
    return 0;

  /* Create the cache and config files as necessary.  */
  if (stat(cache_path, &st) != 0 && mkdir(cache_path, 0777) < 0)
    return -errno;

  int fd = -1;

  /* init cleaning interval config file.  */
  fd = open(interval_path, O_CREAT | O_RDWR, 0666);
  if (fd < 0)
    return -errno;

  if (dprintf(fd, "%ld", cache_clean_default_interval_s) < 0)
    return -errno;

  /* init max age config file.  */
  if (stat(maxage_path, &st) != 0
      && (fd = open(maxage_path, O_CREAT | O_RDWR, 0666)) < 0)
    return -errno;

  if (dprintf(fd, "%ld", cache_default_max_unused_age_s) < 0)
    return -errno;

  return 0;
}


/* Delete any files that have been unmodied for a period
   longer than $DEBUGINFOD_CACHE_CLEAN_INTERVAL_S.  */
static int
debuginfod_clean_cache(debuginfod_client *c,
		       char *cache_path, char *interval_path,
		       char *max_unused_path)
{
  struct stat st;
  FILE *interval_file;
  FILE *max_unused_file;

  if (stat(interval_path, &st) == -1)
    {
      /* Create new interval file.  */
      interval_file = fopen(interval_path, "w");

      if (interval_file == NULL)
        return -errno;

      int rc = fprintf(interval_file, "%ld", cache_clean_default_interval_s);
      fclose(interval_file);

      if (rc < 0)
        return -errno;
    }

  /* Check timestamp of interval file to see whether cleaning is necessary.  */
  time_t clean_interval;
  interval_file = fopen(interval_path, "r");
  if (fscanf(interval_file, "%ld", &clean_interval) != 1)
    clean_interval = cache_clean_default_interval_s;
  fclose(interval_file);

  if (time(NULL) - st.st_mtime < clean_interval)
    /* Interval has not passed, skip cleaning.  */
    return 0;

  /* Read max unused age value from config file.  */
  time_t max_unused_age;
  max_unused_file = fopen(max_unused_path, "r");
  if (max_unused_file)
    {
      if (fscanf(max_unused_file, "%ld", &max_unused_age) != 1)
        max_unused_age = cache_default_max_unused_age_s;
      fclose(max_unused_file);
    }
  else
    max_unused_age = cache_default_max_unused_age_s;

  char * const dirs[] = { cache_path, NULL, };

  FTS *fts = fts_open(dirs, 0, NULL);
  if (fts == NULL)
    return -errno;

  regex_t re;
  const char * pattern = ".*/[a-f0-9]+/(debuginfo|executable|source.*)$";
  if (regcomp (&re, pattern, REG_EXTENDED | REG_NOSUB) != 0)
    return -ENOMEM;

  FTSENT *f;
  long files = 0;
  while ((f = fts_read(fts)) != NULL)
    {
      /* ignore any files that do not match the pattern.  */
      if (regexec (&re, f->fts_path, 0, NULL, 0) != 0)
        continue;

      files++;
      if (c->progressfn) /* inform/check progress callback */
        if ((c->progressfn) (c, files, 0))
          break;

      switch (f->fts_info)
        {
        case FTS_F:
          /* delete file if max_unused_age has been met or exceeded.  */
          /* XXX consider extra effort to clean up old tmp files */
          if (time(NULL) - f->fts_statp->st_atime >= max_unused_age)
            unlink (f->fts_path);
          break;

        case FTS_DP:
          /* Remove if empty. */
          (void) rmdir (f->fts_path);
          break;

        default:
          ;
        }
    }
  fts_close (fts);
  regfree (&re);

  /* Update timestamp representing when the cache was last cleaned.  */
  utime (interval_path, NULL);
  return 0;
}


#define MAX_BUILD_ID_BYTES 64


static void
add_default_headers(debuginfod_client *client)
{
  if (client->user_agent_set_p)
    return;

  /* Compute a User-Agent: string to send.  The more accurately this
     describes this host, the likelier that the debuginfod servers
     might be able to locate debuginfo for us. */

  char* utspart = NULL;
  struct utsname uts;
  int rc = 0;
  rc = uname (&uts);
  if (rc == 0)
    rc = asprintf(& utspart, "%s/%s", uts.sysname, uts.machine);
  if (rc < 0)
    utspart = NULL;

  FILE *f = fopen ("/etc/os-release", "r");
  if (f == NULL)
    f = fopen ("/usr/lib/os-release", "r");
  char *id = NULL;
  char *version = NULL;
  if (f != NULL)
    {
      while (id == NULL || version == NULL)
        {
          char buf[128];
          char *s = &buf[0];
          if (fgets (s, sizeof(buf), f) == NULL)
            break;

          int len = strlen (s);
          if (len < 3)
            continue;
          if (s[len - 1] == '\n')
            {
              s[len - 1] = '\0';
              len--;
            }

          char *v = strchr (s, '=');
          if (v == NULL || strlen (v) < 2)
            continue;

          /* Split var and value. */
          *v = '\0';
          v++;

          /* Remove optional quotes around value string. */
          if (*v == '"' || *v == '\'')
            {
              v++;
              s[len - 1] = '\0';
            }
          if (strcmp (s, "ID") == 0)
            id = strdup (v);
          if (strcmp (s, "VERSION_ID") == 0)
            version = strdup (v);
        }
      fclose (f);
    }

  char *ua = NULL;
  rc = asprintf(& ua, "User-Agent: %s/%s,%s,%s/%s",
                PACKAGE_NAME, PACKAGE_VERSION,
                utspart ?: "",
                id ?: "",
                version ?: "");
  if (rc < 0)
    ua = NULL;

  if (ua)
    (void) debuginfod_add_http_header (client, ua);

  free (ua);
  free (id);
  free (version);
  free (utspart);
}


#define xalloc_str(p, fmt, args...)        \
  do                                       \
    {                                      \
      if (asprintf (&p, fmt, args) < 0)    \
        {                                  \
          p = NULL;                        \
          rc = -ENOMEM;                    \
          goto out;                        \
        }                                  \
    } while (0)


/* Offer a basic form of progress tracing */
static int
default_progressfn (debuginfod_client *c, long a, long b)
{
  const char* url = debuginfod_get_url (c);
  int len = 0;

  /* We prefer to print the host part of the URL to keep the
     message short. */
  if (url != NULL)
    {
      const char* buildid = strstr(url, "buildid/");
      if (buildid != NULL)
        len = (buildid - url);
      else
        len = strlen(url);
    }

  if (b == 0 || url==NULL) /* early stage */
    dprintf(STDERR_FILENO,
            "\rDownloading %c", "-/|\\"[a % 4]);
  else if (b < 0) /* download in progress but unknown total length */
    dprintf(STDERR_FILENO,
            "\rDownloading from %.*s %ld",
            len, url, a);
  else /* download in progress, and known total length */
    dprintf(STDERR_FILENO,
            "\rDownloading from %.*s %ld/%ld",
            len, url, a, b);
  c->default_progressfn_printed_p = 1;

  return 0;
}


/* Query each of the server URLs found in $DEBUGINFOD_URLS for the file
   with the specified build-id, type (debuginfo, executable or source)
   and filename. filename may be NULL. If found, return a file
   descriptor for the target, otherwise return an error code.
*/
static int
debuginfod_query_server (debuginfod_client *c,
			 const unsigned char *build_id,
                         int build_id_len,
                         const char *type,
                         const char *filename,
                         char **path)
{
  char *server_urls;
  char *urls_envvar;
  char *cache_path = NULL;
  char *maxage_path = NULL;
  char *interval_path = NULL;
  char *target_cache_dir = NULL;
  char *target_cache_path = NULL;
  char *target_cache_tmppath = NULL;
  char suffix[PATH_MAX];
  char build_id_bytes[MAX_BUILD_ID_BYTES * 2 + 1];
  int rc;

  /* Clear the obsolete URL from a previous _find operation. */
  free (c->url);
  c->url = NULL;

  add_default_headers(c);

  /* Is there any server we can query?  If not, don't do any work,
     just return with ENOSYS.  Don't even access the cache.  */
  urls_envvar = getenv(server_urls_envvar);
  if (urls_envvar == NULL || urls_envvar[0] == '\0')
    {
      rc = -ENOSYS;
      goto out;
    }

  /* Copy lowercase hex representation of build_id into buf.  */
  if ((build_id_len >= MAX_BUILD_ID_BYTES) ||
      (build_id_len == 0 &&
       sizeof(build_id_bytes) > MAX_BUILD_ID_BYTES*2 + 1))
    return -EINVAL;
  if (build_id_len == 0) /* expect clean hexadecimal */
    strcpy (build_id_bytes, (const char *) build_id);
  else
    for (int i = 0; i < build_id_len; i++)
      sprintf(build_id_bytes + (i * 2), "%02x", build_id[i]);

  if (filename != NULL)
    {
      if (filename[0] != '/') // must start with /
        return -EINVAL;

      /* copy the filename to suffix, s,/,#,g */
      unsigned q = 0;
      for (unsigned fi=0; q < PATH_MAX-1; fi++)
        switch (filename[fi])
          {
          case '\0':
            suffix[q] = '\0';
            q = PATH_MAX-1; /* escape for loop too */
            break;
          case '/': /* escape / to prevent dir escape */
            suffix[q++]='#';
            suffix[q++]='#';
            break;
          case '#': /* escape # to prevent /# vs #/ collisions */
            suffix[q++]='#';
            suffix[q++]='_';
            break;
          default:
            suffix[q++]=filename[fi];
          }
      suffix[q] = '\0';
      /* If the DWARF filenames are super long, this could exceed
         PATH_MAX and truncate/collide.  Oh well, that'll teach
         them! */
    }
  else
    suffix[0] = '\0';

  /* set paths needed to perform the query

     example format
     cache_path:        $HOME/.cache
     target_cache_dir:  $HOME/.cache/0123abcd
     target_cache_path: $HOME/.cache/0123abcd/debuginfo
     target_cache_path: $HOME/.cache/0123abcd/source#PATH#TO#SOURCE ?

     $XDG_CACHE_HOME takes priority over $HOME/.cache.
     $DEBUGINFOD_CACHE_PATH takes priority over $HOME/.cache and $XDG_CACHE_HOME.
  */

  /* Determine location of the cache. The path specified by the debuginfod
     cache environment variable takes priority.  */
  char *cache_var = getenv(cache_path_envvar);
  if (cache_var != NULL && strlen (cache_var) > 0)
    xalloc_str (cache_path, "%s", cache_var);
  else
    {
      /* If a cache already exists in $HOME ('/' if $HOME isn't set), then use
         that. Otherwise use the XDG cache directory naming format.  */
      xalloc_str (cache_path, "%s/%s", getenv ("HOME") ?: "/", cache_default_name);

      struct stat st;
      if (stat (cache_path, &st) < 0)
        {
          char cachedir[PATH_MAX];
          char *xdg = getenv ("XDG_CACHE_HOME");

          if (xdg != NULL && strlen (xdg) > 0)
            snprintf (cachedir, PATH_MAX, "%s", xdg);
          else
            snprintf (cachedir, PATH_MAX, "%s/.cache", getenv ("HOME") ?: "/");

          /* Create XDG cache directory if it doesn't exist.  */
          if (stat (cachedir, &st) == 0)
            {
              if (! S_ISDIR (st.st_mode))
                {
                  rc = -EEXIST;
                  goto out;
                }
            }
          else
            {
              rc = mkdir (cachedir, 0700);

              /* Also check for EEXIST and S_ISDIR in case another client just
                 happened to create the cache.  */
              if (rc < 0
                  && (errno != EEXIST
                      || stat (cachedir, &st) != 0
                      || ! S_ISDIR (st.st_mode)))
                {
                  rc = -errno;
                  goto out;
                }
            }

          free (cache_path);
          xalloc_str (cache_path, "%s/%s", cachedir, cache_xdg_name);
        }
    }

  xalloc_str (target_cache_dir, "%s/%s", cache_path, build_id_bytes);
  xalloc_str (target_cache_path, "%s/%s%s", target_cache_dir, type, suffix);
  xalloc_str (target_cache_tmppath, "%s.XXXXXX", target_cache_path);

  /* XXX combine these */
  xalloc_str (interval_path, "%s/%s", cache_path, cache_clean_interval_filename);
  xalloc_str (maxage_path, "%s/%s", cache_path, cache_max_unused_age_filename);
  rc = debuginfod_init_cache(cache_path, interval_path, maxage_path);
  if (rc != 0)
    goto out;
  rc = debuginfod_clean_cache(c, cache_path, interval_path, maxage_path);
  if (rc != 0)
    goto out;

  /* If the target is already in the cache then we are done.  */
  int fd = open (target_cache_path, O_RDONLY);
  if (fd >= 0)
    {
      /* Success!!!! */
      if (path != NULL)
        *path = strdup(target_cache_path);
      rc = fd;
      goto out;
    }

  long timeout = default_timeout;
  const char* timeout_envvar = getenv(server_timeout_envvar);
  if (timeout_envvar != NULL)
    timeout = atoi (timeout_envvar);

  /* make a copy of the envvar so it can be safely modified.  */
  server_urls = strdup(urls_envvar);
  if (server_urls == NULL)
    {
      rc = -ENOMEM;
      goto out;
    }
  /* thereafter, goto out0 on error*/

  /* create target directory in cache if not found.  */
  struct stat st;
  if (stat(target_cache_dir, &st) == -1 && mkdir(target_cache_dir, 0700) < 0)
    {
      rc = -errno;
      goto out0;
    }

  /* NB: write to a temporary file first, to avoid race condition of
     multiple clients checking the cache, while a partially-written or empty
     file is in there, being written from libcurl. */
  fd = mkstemp (target_cache_tmppath);
  if (fd < 0)
    {
      rc = -errno;
      goto out0;
    }

  /* Count number of URLs.  */
  int num_urls = 0;
  for (int i = 0; server_urls[i] != '\0'; i++)
    if (server_urls[i] != url_delim_char
        && (i == 0 || server_urls[i - 1] == url_delim_char))
      num_urls++;

  /* Tracks which handle should write to fd. Set to the first
     handle that is ready to write the target file to the cache.  */
  CURL *target_handle = NULL;
  struct handle_data *data = malloc(sizeof(struct handle_data) * num_urls);

  /* Initalize handle_data with default values. */
  for (int i = 0; i < num_urls; i++)
    {
      data[i].handle = NULL;
      data[i].fd = -1;
    }

  CURLM *curlm = curl_multi_init();
  if (curlm == NULL)
    {
      rc = -ENETUNREACH;
      goto out0;
    }
  /* thereafter, goto out1 on error.  */

  char *strtok_saveptr;
  char *server_url = strtok_r(server_urls, url_delim, &strtok_saveptr);

  /* Initialize each handle.  */
  for (int i = 0; i < num_urls && server_url != NULL; i++)
    {
      data[i].fd = fd;
      data[i].target_handle = &target_handle;
      data[i].handle = curl_easy_init();
      data[i].client = c;

      if (data[i].handle == NULL)
        {
          rc = -ENETUNREACH;
          goto out1;
        }

      /* Build handle url. Tolerate both  http://foo:999  and
         http://foo:999/  forms */
      char *slashbuildid;
      if (strlen(server_url) > 1 && server_url[strlen(server_url)-1] == '/')
        slashbuildid = "buildid";
      else
        slashbuildid = "/buildid";

      if (filename) /* must start with / */
        snprintf(data[i].url, PATH_MAX, "%s%s/%s/%s%s", server_url,
                 slashbuildid, build_id_bytes, type, filename);
      else
        snprintf(data[i].url, PATH_MAX, "%s%s/%s/%s", server_url,
                 slashbuildid, build_id_bytes, type);

      curl_easy_setopt(data[i].handle, CURLOPT_URL, data[i].url);
      curl_easy_setopt(data[i].handle,
                       CURLOPT_WRITEFUNCTION,
                       debuginfod_write_callback);
      curl_easy_setopt(data[i].handle, CURLOPT_WRITEDATA, (void*)&data[i]);
      if (timeout > 0)
	{
	  /* Make sure there is at least some progress,
	     try to get at least 100K per timeout seconds.  */
	  curl_easy_setopt (data[i].handle, CURLOPT_LOW_SPEED_TIME,
			    timeout);
	  curl_easy_setopt (data[i].handle, CURLOPT_LOW_SPEED_LIMIT,
			    100 * 1024L);
	}
      curl_easy_setopt(data[i].handle, CURLOPT_FILETIME, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_FOLLOWLOCATION, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_FAILONERROR, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_NOSIGNAL, (long) 1);
#if LIBCURL_VERSION_NUM >= 0x072a00 /* 7.42.0 */
      curl_easy_setopt(data[i].handle, CURLOPT_PATH_AS_IS, (long) 1);
#else
      /* On old curl; no big deal, canonicalization here is almost the
         same, except perhaps for ? # type decorations at the tail. */
#endif
      curl_easy_setopt(data[i].handle, CURLOPT_AUTOREFERER, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_ACCEPT_ENCODING, "");
      curl_easy_setopt(data[i].handle, CURLOPT_HTTPHEADER, c->headers);

      curl_multi_add_handle(curlm, data[i].handle);
      server_url = strtok_r(NULL, url_delim, &strtok_saveptr);
    }

  /* Query servers in parallel.  */
  int still_running;
  long loops = 0;
  do
    {
      /* Wait 1 second, the minimum DEBUGINFOD_TIMEOUT.  */
      curl_multi_wait(curlm, NULL, 0, 1000, NULL);

      /* If the target file has been found, abort the other queries.  */
      if (target_handle != NULL)
        for (int i = 0; i < num_urls; i++)
          if (data[i].handle != target_handle)
            curl_multi_remove_handle(curlm, data[i].handle);

      CURLMcode curlm_res = curl_multi_perform(curlm, &still_running);
      if (curlm_res != CURLM_OK)
        {
          switch (curlm_res)
            {
            case CURLM_CALL_MULTI_PERFORM: continue;
            case CURLM_OUT_OF_MEMORY: rc = -ENOMEM; break;
            default: rc = -ENETUNREACH; break;
            }
          goto out1;
        }

      if (c->progressfn) /* inform/check progress callback */
        {
          loops ++;
          long pa = loops; /* default params for progress callback */
          long pb = 0; /* transfer_timeout tempting, but loops != elapsed-time */
          if (target_handle) /* we've committed to a server; report its download progress */
            {
              CURLcode curl_res;
#ifdef CURLINFO_SIZE_DOWNLOAD_T
              curl_off_t dl;
              curl_res = curl_easy_getinfo(target_handle,
                                           CURLINFO_SIZE_DOWNLOAD_T,
                                           &dl);
              if (curl_res == 0 && dl >= 0)
                pa = (dl > LONG_MAX ? LONG_MAX : (long)dl);
#else
              double dl;
              curl_res = curl_easy_getinfo(target_handle,
                                           CURLINFO_SIZE_DOWNLOAD,
                                           &dl);
              if (curl_res == 0)
                pa = (dl > LONG_MAX ? LONG_MAX : (long)dl);
#endif

              /* NB: If going through deflate-compressing proxies, this
                 number is likely to be unavailable, so -1 may show. */
#ifdef CURLINFO_CURLINFO_CONTENT_LENGTH_DOWNLOAD_T
              curl_off_t cl;
              curl_res = curl_easy_getinfo(target_handle,
                                           CURLINFO_CONTENT_LENGTH_DOWNLOAD_T,
                                           &cl);
              if (curl_res == 0 && cl >= 0)
                pb = (cl > LONG_MAX ? LONG_MAX : (long)cl);
#else
              double cl;
              curl_res = curl_easy_getinfo(target_handle,
                                           CURLINFO_CONTENT_LENGTH_DOWNLOAD,
                                           &cl);
              if (curl_res == 0)
                pb = (cl > LONG_MAX ? LONG_MAX : (long)cl);
#endif
            }

          if ((*c->progressfn) (c, pa, pb))
            break;
        }
    } while (still_running);

  /* Check whether a query was successful. If so, assign its handle
     to verified_handle.  */
  int num_msg;
  rc = -ENOENT;
  CURL *verified_handle = NULL;
  do
    {
      CURLMsg *msg;

      msg = curl_multi_info_read(curlm, &num_msg);
      if (msg != NULL && msg->msg == CURLMSG_DONE)
        {
          if (msg->data.result != CURLE_OK)
            {
              /* Unsucessful query, determine error code.  */
              switch (msg->data.result)
                {
                case CURLE_COULDNT_RESOLVE_HOST: rc = -EHOSTUNREACH; break; // no NXDOMAIN
                case CURLE_URL_MALFORMAT: rc = -EINVAL; break;
                case CURLE_COULDNT_CONNECT: rc = -ECONNREFUSED; break;
                case CURLE_REMOTE_ACCESS_DENIED: rc = -EACCES; break;
                case CURLE_WRITE_ERROR: rc = -EIO; break;
                case CURLE_OUT_OF_MEMORY: rc = -ENOMEM; break;
                case CURLE_TOO_MANY_REDIRECTS: rc = -EMLINK; break;
                case CURLE_SEND_ERROR: rc = -ECONNRESET; break;
                case CURLE_RECV_ERROR: rc = -ECONNRESET; break;
                case CURLE_OPERATION_TIMEDOUT: rc = -ETIME; break;
                default: rc = -ENOENT; break;
                }
            }
          else
            {
              /* Query completed without an error. Confirm that the
                 response code is 200 when using HTTP/HTTPS and 0 when
                 using file:// and set verified_handle.  */

              if (msg->easy_handle != NULL)
                {
                  char *effective_url = NULL;
                  long resp_code = 500;
                  CURLcode ok1 = curl_easy_getinfo (target_handle,
						    CURLINFO_EFFECTIVE_URL,
						    &effective_url);
                  CURLcode ok2 = curl_easy_getinfo (target_handle,
						    CURLINFO_RESPONSE_CODE,
						    &resp_code);
                  if(ok1 == CURLE_OK && ok2 == CURLE_OK && effective_url)
                    {
                      if (strncmp (effective_url, "http", 4) == 0)
                        if (resp_code == 200)
                          {
                            verified_handle = msg->easy_handle;
                            break;
                          }
                      if (strncmp (effective_url, "file", 4) == 0)
                        if (resp_code == 0)
                          {
                            verified_handle = msg->easy_handle;
                            break;
                          }
                    }
                }
            }
        }
    } while (num_msg > 0);

  if (verified_handle == NULL)
    goto out1;

  /* we've got one!!!! */
  time_t mtime;
  CURLcode curl_res = curl_easy_getinfo(verified_handle, CURLINFO_FILETIME, (void*) &mtime);
  if (curl_res != CURLE_OK)
    mtime = time(NULL); /* fall back to current time */

  struct timeval tvs[2];
  tvs[0].tv_sec = tvs[1].tv_sec = mtime;
  tvs[0].tv_usec = tvs[1].tv_usec = 0;
  (void) futimes (fd, tvs);  /* best effort */

  /* rename tmp->real */
  rc = rename (target_cache_tmppath, target_cache_path);
  if (rc < 0)
    {
      rc = -errno;
      goto out1;
      /* Perhaps we need not give up right away; could retry or something ... */
    }

  /* Success!!!! */
  for (int i = 0; i < num_urls; i++)
    curl_easy_cleanup(data[i].handle);

  curl_multi_cleanup (curlm);
  free (data);
  free (server_urls);

  /* don't close fd - we're returning it */
  /* don't unlink the tmppath; it's already been renamed. */
  if (path != NULL)
   *path = strdup(target_cache_path);

  rc = fd;
  goto out;

/* error exits */
 out1:
  for (int i = 0; i < num_urls; i++)
    curl_easy_cleanup(data[i].handle);

  curl_multi_cleanup(curlm);
  unlink (target_cache_tmppath);
  close (fd); /* before the rmdir, otherwise it'll fail */
  (void) rmdir (target_cache_dir); /* nop if not empty */
  free(data);

 out0:
  free (server_urls);

/* general purpose exit */
 out:
  /* Conclude the last \r status line */
  /* Another possibility is to use the ANSI CSI n K EL "Erase in Line"
     code.  That way, the previously printed messages would be erased,
     and without a newline. */
  if (c->default_progressfn_printed_p)
    dprintf(STDERR_FILENO, "\n");

  free (cache_path);
  free (maxage_path);
  free (interval_path);
  free (target_cache_dir);
  free (target_cache_path);
  free (target_cache_tmppath);
  return rc;
}



/* See debuginfod.h  */
debuginfod_client  *
debuginfod_begin (void)
{
  debuginfod_client *client;
  size_t size = sizeof (struct debuginfod_client);
  client = (debuginfod_client *) calloc (1, size);
  if (client != NULL)
    {
      if (getenv(DEBUGINFOD_PROGRESS_ENV_VAR))
	client->progressfn = default_progressfn;
    }
  return client;
}

void
debuginfod_set_user_data(debuginfod_client *client,
                         void *data)
{
  client->user_data = data;
}

void *
debuginfod_get_user_data(debuginfod_client *client)
{
  return client->user_data;
}

const char *
debuginfod_get_url(debuginfod_client *client)
{
  return client->url;
}

void
debuginfod_end (debuginfod_client *client)
{
  if (client == NULL)
    return;

  curl_slist_free_all (client->headers);
  free (client->url);
  free (client);
}

int
debuginfod_find_debuginfo (debuginfod_client *client,
			   const unsigned char *build_id, int build_id_len,
                           char **path)
{
  return debuginfod_query_server(client, build_id, build_id_len,
                                 "debuginfo", NULL, path);
}


/* See debuginfod.h  */
int
debuginfod_find_executable(debuginfod_client *client,
			   const unsigned char *build_id, int build_id_len,
                           char **path)
{
  return debuginfod_query_server(client, build_id, build_id_len,
                                 "executable", NULL, path);
}

/* See debuginfod.h  */
int debuginfod_find_source(debuginfod_client *client,
			   const unsigned char *build_id, int build_id_len,
                           const char *filename, char **path)
{
  return debuginfod_query_server(client, build_id, build_id_len,
                                 "source", filename, path);
}


/* Add an outgoing HTTP header.  */
int debuginfod_add_http_header (debuginfod_client *client, const char* header)
{
  /* Sanity check header value is of the form Header: Value.
     It should contain exactly one colon that isn't the first or
     last character.  */
  char *colon = strchr (header, ':');
  if (colon == NULL
      || colon == header
      || *(colon + 1) == '\0'
      || strchr (colon + 1, ':') != NULL)
    return -EINVAL;

  struct curl_slist *temp = curl_slist_append (client->headers, header);
  if (temp == NULL)
    return -ENOMEM;

  /* Track if User-Agent: is being set.  If so, signal not to add the
     default one. */
  if (strncmp (header, "User-Agent:", 11) == 0)
    client->user_agent_set_p = 1;

  client->headers = temp;
  return 0;
}


void
debuginfod_set_progressfn(debuginfod_client *client,
			  debuginfod_progressfn_t fn)
{
  client->progressfn = fn;
}


/* NB: these are thread-unsafe. */
__attribute__((constructor)) attribute_hidden void libdebuginfod_ctor(void)
{
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

/* NB: this is very thread-unsafe: it breaks other threads that are still in libcurl */
__attribute__((destructor)) attribute_hidden void libdebuginfod_dtor(void)
{
  /* ... so don't do this: */
  /* curl_global_cleanup(); */
}
