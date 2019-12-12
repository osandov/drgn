/* Retrieve ELF / DWARF / source files from the debuginfod.
   Copyright (C) 2019 Red Hat, Inc.
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
#include <assert.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <string.h>
#include <stdbool.h>
#include <linux/limits.h>
#include <time.h>
#include <utime.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
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
static const char *cache_path_envvar = DEBUGINFOD_CACHE_PATH_ENV_VAR;

/* URLs of debuginfods, separated by url_delim.
   This env var must be set for debuginfod-client to run.  */
static const char *server_urls_envvar = DEBUGINFOD_URLS_ENV_VAR;
static const char *url_delim =  " ";
static const char url_delim_char = ' ';

/* Timeout for debuginfods, in seconds.
   This env var must be set for debuginfod-client to run.  */
static const char *server_timeout_envvar = DEBUGINFOD_TIMEOUT_ENV_VAR;
static int server_timeout = 5;

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
    *d->target_handle = d->handle;

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

  FTSENT *f;
  long files = 0;
  while ((f = fts_read(fts)) != NULL)
    {
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
  fts_close(fts);

  /* Update timestamp representing when the cache was last cleaned.  */
  utime (interval_path, NULL);
  return 0;
}


#define MAX_BUILD_ID_BYTES 64


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
  char *urls_envvar;
  char *server_urls;
  char cache_path[PATH_MAX];
  char maxage_path[PATH_MAX*3]; /* These *3 multipliers are to shut up gcc -Wformat-truncation */
  char interval_path[PATH_MAX*4];
  char target_cache_dir[PATH_MAX*2];
  char target_cache_path[PATH_MAX*4];
  char target_cache_tmppath[PATH_MAX*5];
  char suffix[PATH_MAX*2];
  char build_id_bytes[MAX_BUILD_ID_BYTES * 2 + 1];
  int rc;

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
     cache_path:        $HOME/.debuginfod_cache
     target_cache_dir:  $HOME/.debuginfod_cache/0123abcd
     target_cache_path: $HOME/.debuginfod_cache/0123abcd/debuginfo
     target_cache_path: $HOME/.debuginfod_cache/0123abcd/source#PATH#TO#SOURCE ?
  */

  if (getenv(cache_path_envvar))
    strcpy(cache_path, getenv(cache_path_envvar));
  else
    {
      if (getenv("HOME"))
        sprintf(cache_path, "%s/%s", getenv("HOME"), cache_default_name);
      else
        sprintf(cache_path, "/%s", cache_default_name);
    }

  /* avoid using snprintf here due to compiler warning.  */
  snprintf(target_cache_dir, sizeof(target_cache_dir), "%s/%s", cache_path, build_id_bytes);
  snprintf(target_cache_path, sizeof(target_cache_path), "%s/%s%s", target_cache_dir, type, suffix);
  snprintf(target_cache_tmppath, sizeof(target_cache_tmppath), "%s.XXXXXX", target_cache_path);

  /* XXX combine these */
  snprintf(interval_path, sizeof(interval_path), "%s/%s", cache_path, cache_clean_interval_filename);
  snprintf(maxage_path, sizeof(maxage_path), "%s/%s", cache_path, cache_max_unused_age_filename);
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
      return fd;
    }

  if (getenv(server_timeout_envvar))
    server_timeout = atoi (getenv(server_timeout_envvar));

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
      curl_easy_setopt(data[i].handle, CURLOPT_TIMEOUT, (long) server_timeout);
      curl_easy_setopt(data[i].handle, CURLOPT_FILETIME, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_FOLLOWLOCATION, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_FAILONERROR, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_NOSIGNAL, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_AUTOREFERER, (long) 1);
      curl_easy_setopt(data[i].handle, CURLOPT_ACCEPT_ENCODING, "");
      curl_easy_setopt(data[i].handle, CURLOPT_USERAGENT, (void*) PACKAGE_STRING);

      curl_multi_add_handle(curlm, data[i].handle);
      server_url = strtok_r(NULL, url_delim, &strtok_saveptr);
    }

  /* Query servers in parallel.  */
  int still_running;
  long loops = 0;
  do
    {
      if (c->progressfn) /* inform/check progress callback */
        {
          loops ++;
          long pa = loops; /* default params for progress callback */
          long pb = 0;
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
                 response code is 200 and set verified_handle.  */
              long resp_code = 500;
              CURLcode curl_res;

              curl_res = curl_easy_getinfo(target_handle,
                                           CURLINFO_RESPONSE_CODE,
                                           &resp_code);

              if (curl_res == CURLE_OK
                  && resp_code == 200
                  && msg->easy_handle != NULL)
                {
                  verified_handle = msg->easy_handle;
                  break;
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

  return fd;

/* error exits */
 out1:
  for (int i = 0; i < num_urls; i++)
    curl_easy_cleanup(data[i].handle);

  curl_multi_cleanup(curlm);
  unlink (target_cache_tmppath);
  (void) rmdir (target_cache_dir); /* nop if not empty */
  free(data);
  close (fd);

 out0:
  free (server_urls);

 out:
  return rc;
}

/* See debuginfod.h  */
debuginfod_client  *
debuginfod_begin (void)
{
  debuginfod_client *client;
  size_t size = sizeof (struct debuginfod_client);
  client = (debuginfod_client *) malloc (size);
  if (client != NULL)
    client->progressfn = NULL;
  return client;
}

void
debuginfod_end (debuginfod_client *client)
{
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
