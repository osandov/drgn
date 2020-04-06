/* Debuginfo-over-http server.
   Copyright (C) 2019-2020 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */


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

#ifdef HAVE_CONFIG_H
  #include "config.h"
#endif

extern "C" {
#include "printversion.h"
}

#include "debuginfod.h"
#include <dwarf.h>

#include <argp.h>
#ifdef __GNUC__
#undef __attribute__ /* glibc bug - rhbz 1763325 */
#endif

#include <unistd.h>
#include <stdlib.h>
#include <error.h>
// #include <libintl.h> // not until it supports C++ << better
#include <locale.h>
#include <pthread.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>


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

#include <cstring>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <iostream>
#include <iomanip>
#include <ostream>
#include <sstream>
#include <mutex>
#include <deque>
#include <condition_variable>
#include <thread>
// #include <regex> // on rhel7 gcc 4.8, not competent
#include <regex.h>
// #include <algorithm>
using namespace std;

#include <gelf.h>
#include <libdwelf.h>

#include <microhttpd.h>
#include <curl/curl.h>
#include <archive.h>
#include <archive_entry.h>
#include <sqlite3.h>

#ifdef __linux__
#include <sys/syscall.h>
#endif

#ifdef __linux__
#define tid() syscall(SYS_gettid)
#else
#define tid() pthread_self()
#endif


inline bool
string_endswith(const string& haystack, const string& needle)
{
  return (haystack.size() >= needle.size() &&
	  equal(haystack.end()-needle.size(), haystack.end(),
                needle.begin()));
}


// Roll this identifier for every sqlite schema incompatiblity.
#define BUILDIDS "buildids9"

#if SQLITE_VERSION_NUMBER >= 3008000
#define WITHOUT_ROWID "without rowid"
#else
#define WITHOUT_ROWID ""
#endif

static const char DEBUGINFOD_SQLITE_DDL[] =
  "pragma foreign_keys = on;\n"
  "pragma synchronous = 0;\n" // disable fsync()s - this cache is disposable across a machine crash
  "pragma journal_mode = wal;\n" // https://sqlite.org/wal.html
  "pragma wal_checkpoint = truncate;\n" // clean out any preexisting wal file
  "pragma journal_size_limit = 0;\n" // limit steady state file (between grooming, which also =truncate's)
  "pragma auto_vacuum = incremental;\n" // https://sqlite.org/pragma.html
  "pragma busy_timeout = 1000;\n" // https://sqlite.org/pragma.html
  // NB: all these are overridable with -D option

  // Normalization table for interning file names
  "create table if not exists " BUILDIDS "_files (\n"
  "        id integer primary key not null,\n"
  "        name text unique not null\n"
  "        );\n"
  // Normalization table for interning buildids
  "create table if not exists " BUILDIDS "_buildids (\n"
  "        id integer primary key not null,\n"
  "        hex text unique not null);\n"
  // Track the completion of scanning of a given file & sourcetype at given time
  "create table if not exists " BUILDIDS "_file_mtime_scanned (\n"
  "        mtime integer not null,\n"
  "        file integer not null,\n"
  "        size integer not null,\n" // in bytes
  "        sourcetype text(1) not null\n"
  "            check (sourcetype IN ('F', 'R')),\n"
  "        foreign key (file) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        primary key (file, mtime, sourcetype)\n"
  "        ) " WITHOUT_ROWID ";\n"
  "create table if not exists " BUILDIDS "_f_de (\n"
  "        buildid integer not null,\n"
  "        debuginfo_p integer not null,\n"
  "        executable_p integer not null,\n"
  "        file integer not null,\n"
  "        mtime integer not null,\n"
  "        foreign key (file) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (buildid) references " BUILDIDS "_buildids(id) on update cascade on delete cascade,\n"
  "        primary key (buildid, file, mtime)\n"
  "        ) " WITHOUT_ROWID ";\n"
  "create table if not exists " BUILDIDS "_f_s (\n"
  "        buildid integer not null,\n"
  "        artifactsrc integer not null,\n"
  "        file integer not null,\n" // NB: not necessarily entered into _mtime_scanned
  "        mtime integer not null,\n"
  "        foreign key (file) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (artifactsrc) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (buildid) references " BUILDIDS "_buildids(id) on update cascade on delete cascade,\n"
  "        primary key (buildid, artifactsrc, file, mtime)\n"
  "        ) " WITHOUT_ROWID ";\n"
  "create table if not exists " BUILDIDS "_r_de (\n"
  "        buildid integer not null,\n"
  "        debuginfo_p integer not null,\n"
  "        executable_p integer not null,\n"
  "        file integer not null,\n"
  "        mtime integer not null,\n"
  "        content integer not null,\n"
  "        foreign key (file) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (content) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (buildid) references " BUILDIDS "_buildids(id) on update cascade on delete cascade,\n"
  "        primary key (buildid, debuginfo_p, executable_p, file, content, mtime)\n"
  "        ) " WITHOUT_ROWID ";\n"
  "create table if not exists " BUILDIDS "_r_sref (\n" // outgoing dwarf sourcefile references from rpm
  "        buildid integer not null,\n"
  "        artifactsrc integer not null,\n"
  "        foreign key (artifactsrc) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (buildid) references " BUILDIDS "_buildids(id) on update cascade on delete cascade,\n"
  "        primary key (buildid, artifactsrc)\n"
  "        ) " WITHOUT_ROWID ";\n"
  "create table if not exists " BUILDIDS "_r_sdef (\n" // rpm contents that may satisfy sref
  "        file integer not null,\n"
  "        mtime integer not null,\n"
  "        content integer not null,\n"
  "        foreign key (file) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        foreign key (content) references " BUILDIDS "_files(id) on update cascade on delete cascade,\n"
  "        primary key (content, file, mtime)\n"
  "        ) " WITHOUT_ROWID ";\n"
  // create views to glue together some of the above tables, for webapi D queries
  "create view if not exists " BUILDIDS "_query_d as \n"
  "select\n"
  "        b.hex as buildid, n.mtime, 'F' as sourcetype, f0.name as source0, n.mtime as mtime, null as source1\n"
  "        from " BUILDIDS "_buildids b, " BUILDIDS "_files f0, " BUILDIDS "_f_de n\n"
  "        where b.id = n.buildid and f0.id = n.file and n.debuginfo_p = 1\n"
  "union all select\n"
  "        b.hex as buildid, n.mtime, 'R' as sourcetype, f0.name as source0, n.mtime as mtime, f1.name as source1\n"
  "        from " BUILDIDS "_buildids b, " BUILDIDS "_files f0, " BUILDIDS "_files f1, " BUILDIDS "_r_de n\n"
  "        where b.id = n.buildid and f0.id = n.file and f1.id = n.content and n.debuginfo_p = 1\n"
  ";"
  // ... and for E queries
  "create view if not exists " BUILDIDS "_query_e as \n"
  "select\n"
  "        b.hex as buildid, n.mtime, 'F' as sourcetype, f0.name as source0, n.mtime as mtime, null as source1\n"
  "        from " BUILDIDS "_buildids b, " BUILDIDS "_files f0, " BUILDIDS "_f_de n\n"
  "        where b.id = n.buildid and f0.id = n.file and n.executable_p = 1\n"
  "union all select\n"
  "        b.hex as buildid, n.mtime, 'R' as sourcetype, f0.name as source0, n.mtime as mtime, f1.name as source1\n"
  "        from " BUILDIDS "_buildids b, " BUILDIDS "_files f0, " BUILDIDS "_files f1, " BUILDIDS "_r_de n\n"
  "        where b.id = n.buildid and f0.id = n.file and f1.id = n.content and n.executable_p = 1\n"
  ";"
  // ... and for S queries
  "create view if not exists " BUILDIDS "_query_s as \n"
  "select\n"
  "        b.hex as buildid, fs.name as artifactsrc, 'F' as sourcetype, f0.name as source0, n.mtime as mtime, null as source1, null as source0ref\n"
  "        from " BUILDIDS "_buildids b, " BUILDIDS "_files f0, " BUILDIDS "_files fs, " BUILDIDS "_f_s n\n"
  "        where b.id = n.buildid and f0.id = n.file and fs.id = n.artifactsrc\n"
  "union all select\n"
  "        b.hex as buildid, f1.name as artifactsrc, 'R' as sourcetype, f0.name as source0, sd.mtime as mtime, f1.name as source1, fsref.name as source0ref\n"
  "        from " BUILDIDS "_buildids b, " BUILDIDS "_files f0, " BUILDIDS "_files f1, " BUILDIDS "_files fsref, "
  "        " BUILDIDS "_r_sdef sd, " BUILDIDS "_r_sref sr, " BUILDIDS "_r_de sde\n"
  "        where b.id = sr.buildid and f0.id = sd.file and fsref.id = sde.file and f1.id = sd.content\n"
  "        and sr.artifactsrc = sd.content and sde.buildid = sr.buildid\n"
  ";"
  // and for startup overview counts
  "drop view if exists " BUILDIDS "_stats;\n"
  "create view if not exists " BUILDIDS "_stats as\n"
  "          select 'file d/e' as label,count(*) as quantity from " BUILDIDS "_f_de\n"
  "union all select 'file s',count(*) from " BUILDIDS "_f_s\n"
  "union all select 'archive d/e',count(*) from " BUILDIDS "_r_de\n"
  "union all select 'archive sref',count(*) from " BUILDIDS "_r_sref\n"
  "union all select 'archive sdef',count(*) from " BUILDIDS "_r_sdef\n"
  "union all select 'buildids',count(*) from " BUILDIDS "_buildids\n"
  "union all select 'filenames',count(*) from " BUILDIDS "_files\n"
  "union all select 'files scanned (#)',count(*) from " BUILDIDS "_file_mtime_scanned\n"
  "union all select 'files scanned (mb)',coalesce(sum(size)/1024/1024,0) from " BUILDIDS "_file_mtime_scanned\n"
#if SQLITE_VERSION_NUMBER >= 3016000
  "union all select 'index db size (mb)',page_count*page_size/1024/1024 as size FROM pragma_page_count(), pragma_page_size()\n"
#endif
  ";\n"

// schema change history & garbage collection
//
// XXX: we could have migration queries here to bring prior-schema
// data over instead of just dropping it.
//
// buildids9: widen the mtime_scanned table
  "" // <<< we are here
// buildids8: slim the sref table
  "drop table if exists buildids8_f_de;\n"
  "drop table if exists buildids8_f_s;\n"
  "drop table if exists buildids8_r_de;\n"
  "drop table if exists buildids8_r_sref;\n"
  "drop table if exists buildids8_r_sdef;\n"
  "drop table if exists buildids8_file_mtime_scanned;\n"
  "drop table if exists buildids8_files;\n"
  "drop table if exists buildids8_buildids;\n"
// buildids7: separate _norm table into dense subtype tables
  "drop table if exists buildids7_f_de;\n"
  "drop table if exists buildids7_f_s;\n"
  "drop table if exists buildids7_r_de;\n"
  "drop table if exists buildids7_r_sref;\n"
  "drop table if exists buildids7_r_sdef;\n"
  "drop table if exists buildids7_file_mtime_scanned;\n"
  "drop table if exists buildids7_files;\n"
  "drop table if exists buildids7_buildids;\n"
// buildids6: drop bolo/rfolo again, represent sources / rpmcontents in main table
  "drop table if exists buildids6_norm;\n"
  "drop table if exists buildids6_files;\n"
  "drop table if exists buildids6_buildids;\n"
  "drop view if exists buildids6;\n"
// buildids5: redefine srcfile1 column to be '.'-less (for rpms)
  "drop table if exists buildids5_norm;\n"
  "drop table if exists buildids5_files;\n"
  "drop table if exists buildids5_buildids;\n"
  "drop table if exists buildids5_bolo;\n"
  "drop table if exists buildids5_rfolo;\n"
  "drop view if exists buildids5;\n"
// buildids4: introduce rpmfile RFOLO
  "drop table if exists buildids4_norm;\n"
  "drop table if exists buildids4_files;\n"
  "drop table if exists buildids4_buildids;\n"
  "drop table if exists buildids4_bolo;\n"
  "drop table if exists buildids4_rfolo;\n"
  "drop view if exists buildids4;\n"
// buildids3*: split out srcfile BOLO
  "drop table if exists buildids3_norm;\n"
  "drop table if exists buildids3_files;\n"
  "drop table if exists buildids3_buildids;\n"
  "drop table if exists buildids3_bolo;\n"
  "drop view if exists buildids3;\n"
// buildids2: normalized buildid and filenames into interning tables;
  "drop table if exists buildids2_norm;\n"
  "drop table if exists buildids2_files;\n"
  "drop table if exists buildids2_buildids;\n"
  "drop view if exists buildids2;\n"
  // buildids1: made buildid and artifacttype NULLable, to represent cached-negative
//           lookups from sources, e.g. files or rpms that contain no buildid-indexable content
  "drop table if exists buildids1;\n"
// buildids: original
  "drop table if exists buildids;\n"
  ;

static const char DEBUGINFOD_SQLITE_CLEANUP_DDL[] =
  "pragma wal_checkpoint = truncate;\n" // clean out any preexisting wal file
  ;




/* Name and version of program.  */
/* ARGP_PROGRAM_VERSION_HOOK_DEF = print_version; */ // not this simple for C++

/* Bug report address.  */
ARGP_PROGRAM_BUG_ADDRESS_DEF = PACKAGE_BUGREPORT;

/* Definitions of arguments for argp functions.  */
static const struct argp_option options[] =
  {
   { NULL, 0, NULL, 0, "Scanners:", 1 },
   { "scan-file-dir", 'F', NULL, 0, "Enable ELF/DWARF file scanning.", 0 },
   { "scan-rpm-dir", 'R', NULL, 0, "Enable RPM scanning.", 0 },
   { "scan-deb-dir", 'U', NULL, 0, "Enable DEB scanning.", 0 },
   { "scan-archive", 'Z', "EXT=CMD", 0, "Enable arbitrary archive scanning.", 0 },
   // "source-oci-imageregistry"  ...

   { NULL, 0, NULL, 0, "Options:", 2 },
   { "logical", 'L', NULL, 0, "Follow symlinks, default=ignore.", 0 },
   { "rescan-time", 't', "SECONDS", 0, "Number of seconds to wait between rescans, 0=disable.", 0 },
   { "groom-time", 'g', "SECONDS", 0, "Number of seconds to wait between database grooming, 0=disable.", 0 },
   { "maxigroom", 'G', NULL, 0, "Run a complete database groom/shrink pass at startup.", 0 },
   { "concurrency", 'c', "NUM", 0, "Limit scanning thread concurrency to NUM.", 0 },
   { "include", 'I', "REGEX", 0, "Include files matching REGEX, default=all.", 0 },
   { "exclude", 'X', "REGEX", 0, "Exclude files matching REGEX, default=none.", 0 },
   { "port", 'p', "NUM", 0, "HTTP port to listen on, default 8002.", 0 },
   { "database", 'd', "FILE", 0, "Path to sqlite database.", 0 },
   { "ddl", 'D', "SQL", 0, "Apply extra sqlite ddl/pragma to connection.", 0 },
   { "verbose", 'v', NULL, 0, "Increase verbosity.", 0 },
#define ARGP_KEY_FDCACHE_FDS 0x1001
   { "fdcache-fds", ARGP_KEY_FDCACHE_FDS, "NUM", 0, "Maximum number of archive files to keep in fdcache.", 0 },
#define ARGP_KEY_FDCACHE_MBS 0x1002
   { "fdcache-mbs", ARGP_KEY_FDCACHE_MBS, "MB", 0, "Maximum total size of archive file fdcache.", 0 },
#define ARGP_KEY_FDCACHE_PREFETCH 0x1003
   { "fdcache-prefetch", ARGP_KEY_FDCACHE_PREFETCH, "NUM", 0, "Number of archive files to prefetch into fdcache.", 0 },
   { NULL, 0, NULL, 0, NULL, 0 }
  };

/* Short description of program.  */
static const char doc[] = "Serve debuginfo-related content across HTTP from files under PATHs.";

/* Strings for arguments in help texts.  */
static const char args_doc[] = "[PATH ...]";

/* Prototype for option handler.  */
static error_t parse_opt (int key, char *arg, struct argp_state *state);

/* Data structure to communicate with argp functions.  */
static struct argp argp =
  {
   options, parse_opt, args_doc, doc, NULL, NULL, NULL
  };


static string db_path;
static sqlite3 *db; // single connection, serialized across all our threads!
static unsigned verbose;
static volatile sig_atomic_t interrupted = 0;
static volatile sig_atomic_t sigusr1 = 0;
static volatile sig_atomic_t sigusr2 = 0;
static unsigned http_port = 8002;
static unsigned rescan_s = 300;
static unsigned groom_s = 86400;
static bool maxigroom = false;
static unsigned concurrency = std::thread::hardware_concurrency() ?: 1;
static set<string> source_paths;
static bool scan_files = false;
static map<string,string> scan_archives;
static vector<string> extra_ddl;
static regex_t file_include_regex;
static regex_t file_exclude_regex;
static bool traverse_logical;
static long fdcache_fds;
static long fdcache_mbs;
static long fdcache_prefetch;
static string tmpdir;

static void set_metric(const string& key, int64_t value);
// static void inc_metric(const string& key);
static void set_metric(const string& metric,
                       const string& lname, const string& lvalue,
                       int64_t value);
static void inc_metric(const string& metric,
                       const string& lname, const string& lvalue);
static void add_metric(const string& metric,
                       const string& lname, const string& lvalue,
                       int64_t value);
// static void add_metric(const string& metric, int64_t value);

/* Handle program arguments.  */
static error_t
parse_opt (int key, char *arg,
	   struct argp_state *state __attribute__ ((unused)))
{
  int rc;
  switch (key)
    {
    case 'v': verbose ++; break;
    case 'd': db_path = string(arg); break;
    case 'p': http_port = (unsigned) atoi(arg);
      if (http_port == 0 || http_port > 65535)
        argp_failure(state, 1, EINVAL, "port number");
      break;
    case 'F': scan_files = true; break;
    case 'R':
      scan_archives[".rpm"]="cat"; // libarchive groks rpm natively
      break;
    case 'U':
      if (access("/usr/bin/dpkg-deb", X_OK) == 0)
        {
          scan_archives[".deb"]="dpkg-deb --fsys-tarfile";
          scan_archives[".ddeb"]="dpkg-deb --fsys-tarfile";
        }
      else
        {
          scan_archives[".deb"]="(bsdtar -O -x -f - data.tar.xz)<";
          scan_archives[".ddeb"]="(bsdtar -O -x -f - data.tar.xz)<";
        }
      // .udeb too?
      break;
    case 'Z':
      {
        char* extension = strchr(arg, '=');
        if (arg[0] == '\0')
          argp_failure(state, 1, EINVAL, "missing EXT");
        else if (extension)
          scan_archives[string(arg, (extension-arg))]=string(extension+1);
        else
          scan_archives[string(arg)]=string("cat");
      }
      break;
    case 'L':
      traverse_logical = true;
      break;
    case 'D': extra_ddl.push_back(string(arg)); break;
    case 't':
      rescan_s = (unsigned) atoi(arg);
      break;
    case 'g':
      groom_s = (unsigned) atoi(arg);
      break;
    case 'G':
      maxigroom = true;
      break;
    case 'c':
      concurrency = (unsigned) atoi(arg);
      if (concurrency < 1) concurrency = 1;
      break;
    case 'I':
      // NB: no problem with unconditional free here - an earlier failed regcomp would exit program
      regfree (&file_include_regex);
      rc = regcomp (&file_include_regex, arg, REG_EXTENDED|REG_NOSUB);
      if (rc != 0)
        argp_failure(state, 1, EINVAL, "regular expession");
      break;
    case 'X':
      regfree (&file_exclude_regex);
      rc = regcomp (&file_exclude_regex, arg, REG_EXTENDED|REG_NOSUB);
      if (rc != 0)
        argp_failure(state, 1, EINVAL, "regular expession");
      break;
    case ARGP_KEY_FDCACHE_FDS:
      fdcache_fds = atol (arg);
      break;
    case ARGP_KEY_FDCACHE_MBS:
      fdcache_mbs = atol (arg);
      break;
    case ARGP_KEY_FDCACHE_PREFETCH:
      fdcache_prefetch = atol (arg);
      break;
    case ARGP_KEY_ARG:
      source_paths.insert(string(arg));
      break;
      // case 'h': argp_state_help (state, stderr, ARGP_HELP_LONG|ARGP_HELP_EXIT_OK);
    default: return ARGP_ERR_UNKNOWN;
    }

  return 0;
}


////////////////////////////////////////////////////////////////////////


// represent errors that may get reported to an ostream and/or a libmicrohttpd connection

struct reportable_exception
{
  int code;
  string message;

  reportable_exception(int c, const string& m): code(c), message(m) {}
  reportable_exception(const string& m): code(503), message(m) {}
  reportable_exception(): code(503), message() {}

  void report(ostream& o) const; // defined under obatched() class below

  int mhd_send_response(MHD_Connection* c) const {
    MHD_Response* r = MHD_create_response_from_buffer (message.size(),
                                                       (void*) message.c_str(),
                                                       MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header (r, "Content-Type", "text/plain");
    int rc = MHD_queue_response (c, code, r);
    MHD_destroy_response (r);
    return rc;
  }
};


struct sqlite_exception: public reportable_exception
{
  sqlite_exception(int rc, const string& msg):
    reportable_exception(string("sqlite3 error: ") + msg + ": " + string(sqlite3_errstr(rc) ?: "?")) {}
};

struct libc_exception: public reportable_exception
{
  libc_exception(int rc, const string& msg):
    reportable_exception(string("libc error: ") + msg + ": " + string(strerror(rc) ?: "?")) {}
};


struct archive_exception: public reportable_exception
{
  archive_exception(const string& msg):
    reportable_exception(string("libarchive error: ") + msg) {}
  archive_exception(struct archive* a, const string& msg):
    reportable_exception(string("libarchive error: ") + msg + ": " + string(archive_error_string(a) ?: "?")) {}
};


struct elfutils_exception: public reportable_exception
{
  elfutils_exception(int rc, const string& msg):
    reportable_exception(string("elfutils error: ") + msg + ": " + string(elf_errmsg(rc) ?: "?")) {}
};


////////////////////////////////////////////////////////////////////////

template <typename Payload>
class workq
{
  set<Payload> q; // eliminate duplicates
  mutex mtx;
  condition_variable cv;
  bool dead;
  unsigned idlers;

public:
  workq() { dead = false; idlers = 0; }
  ~workq() {}

  void push_back(const Payload& p)
  {
    unique_lock<mutex> lock(mtx);
    q.insert (p);
    set_metric("thread_work_pending","role","scan", q.size());
    cv.notify_all();
  }

  // kill this workqueue, wake up all idlers / scanners
  void nuke() {
    unique_lock<mutex> lock(mtx);
    // optional: q.clear();
    dead = true;
    cv.notify_all();
  }

  // block this scanner thread until there is work to do and no active
  bool wait_front (Payload& p)
  {
    unique_lock<mutex> lock(mtx);
    while (!dead && (q.size() == 0 || idlers > 0))
      cv.wait(lock);
    if (dead)
      return false;
    else
      {
        p = * q.begin();
        q.erase (q.begin());
        set_metric("thread_work_pending","role","scan", q.size());
        if (q.size() == 0)
          cv.notify_all(); // maybe wake up waiting idlers
        return true;
      }
  }

  // block this idler thread until there is no work to do
  void wait_idle ()
  {
    unique_lock<mutex> lock(mtx);
    cv.notify_all(); // maybe wake up waiting scanners
    while (!dead && (q.size() != 0))
      cv.wait(lock);
    idlers ++;
  }

  void done_idle ()
  {
    unique_lock<mutex> lock(mtx);
    idlers --;
    cv.notify_all(); // maybe wake up waiting scanners, but probably not (shutting down)
  }
};

typedef struct stat stat_t;
typedef pair<string,stat_t> scan_payload;
inline bool operator< (const scan_payload& a, const scan_payload& b)
{
  return a.first < b.first; // don't bother compare the stat fields
}
static workq<scan_payload> scanq; // just a single one
// producer & idler: thread_main_fts_source_paths()
// consumer: thread_main_scanner()
// idler: thread_main_groom()



////////////////////////////////////////////////////////////////////////


// Print a standard timestamp.
static ostream&
timestamp (ostream &o)
{
  char datebuf[80];
  char *now2 = NULL;
  time_t now_t = time(NULL);
  struct tm *now = gmtime (&now_t);
  if (now)
    {
      (void) strftime (datebuf, sizeof (datebuf), "%c", now);
      now2 = datebuf;
    }

  return o << "[" << (now2 ? now2 : "") << "] "
           << "(" << getpid () << "/" << tid() << "): ";
}


// A little class that impersonates an ostream to the extent that it can
// take << streaming operations.  It batches up the bits into an internal
// stringstream until it is destroyed; then flushes to the original ostream.
// It adds a timestamp
class obatched
{
private:
  ostream& o;
  stringstream stro;
  static mutex lock;
public:
  obatched(ostream& oo, bool timestamp_p = true): o(oo)
  {
    if (timestamp_p)
      timestamp(stro);
  }
  ~obatched()
  {
    unique_lock<mutex> do_not_cross_the_streams(obatched::lock);
    o << stro.str();
    o.flush();
  }
  operator ostream& () { return stro; }
  template <typename T> ostream& operator << (const T& t) { stro << t; return stro; }
};
mutex obatched::lock; // just the one, since cout/cerr iostreams are not thread-safe


void reportable_exception::report(ostream& o) const {
  obatched(o) << message << endl;
}


////////////////////////////////////////////////////////////////////////


// RAII style sqlite prepared-statement holder that matches { } block lifetime

struct sqlite_ps
{
private:
  sqlite3* db;
  const string nickname;
  const string sql;
  sqlite3_stmt *pp;

  sqlite_ps(const sqlite_ps&); // make uncopyable
  sqlite_ps& operator=(const sqlite_ps &); // make unassignable

public:
  sqlite_ps (sqlite3* d, const string& n, const string& s): db(d), nickname(n), sql(s) {
    if (verbose > 4)
      obatched(clog) << nickname << " prep " << sql << endl;
    int rc = sqlite3_prepare_v2 (db, sql.c_str(), -1 /* to \0 */, & this->pp, NULL);
    if (rc != SQLITE_OK)
      throw sqlite_exception(rc, "prepare " + sql);
  }

  sqlite_ps& reset()
  {
    sqlite3_reset(this->pp);
    return *this;
  }

  sqlite_ps& bind(int parameter, const string& str)
  {
    if (verbose > 4)
      obatched(clog) << nickname << " bind " << parameter << "=" << str << endl;
    int rc = sqlite3_bind_text (this->pp, parameter, str.c_str(), -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK)
      throw sqlite_exception(rc, "sqlite3 bind");
    return *this;
  }

  sqlite_ps& bind(int parameter, int64_t value)
  {
    if (verbose > 4)
      obatched(clog) << nickname << " bind " << parameter << "=" << value << endl;
    int rc = sqlite3_bind_int64 (this->pp, parameter, value);
    if (rc != SQLITE_OK)
      throw sqlite_exception(rc, "sqlite3 bind");
    return *this;
  }

  sqlite_ps& bind(int parameter)
  {
    if (verbose > 4)
      obatched(clog) << nickname << " bind " << parameter << "=" << "NULL" << endl;
    int rc = sqlite3_bind_null (this->pp, parameter);
    if (rc != SQLITE_OK)
      throw sqlite_exception(rc, "sqlite3 bind");
    return *this;
  }


  void step_ok_done() {
    int rc = sqlite3_step (this->pp);
    if (verbose > 4)
      obatched(clog) << nickname << " step-ok-done(" << sqlite3_errstr(rc) << ") " << sql << endl;
    if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW)
      throw sqlite_exception(rc, "sqlite3 step");
    (void) sqlite3_reset (this->pp);
  }


  int step() {
    int rc = sqlite3_step (this->pp);
    if (verbose > 4)
      obatched(clog) << nickname << " step(" << sqlite3_errstr(rc) << ") " << sql << endl;
    return rc;
  }



  ~sqlite_ps () { sqlite3_finalize (this->pp); }
  operator sqlite3_stmt* () { return this->pp; }
};


////////////////////////////////////////////////////////////////////////

// RAII style templated autocloser

template <class Payload, class Ignore>
struct defer_dtor
{
public:
  typedef Ignore (*dtor_fn) (Payload);

private:
  Payload p;
  dtor_fn fn;

public:
  defer_dtor(Payload _p, dtor_fn _fn): p(_p), fn(_fn) {}
  ~defer_dtor() { (void) (*fn)(p); }

private:
  defer_dtor(const defer_dtor<Payload,Ignore>&); // make uncopyable
  defer_dtor& operator=(const defer_dtor<Payload,Ignore> &); // make unassignable
};



////////////////////////////////////////////////////////////////////////


static string
header_censor(const string& str)
{
  string y;
  for (auto&& x : str)
    {
      if (isalnum(x) || x == '/' || x == '.' || x == ',' || x == '_' || x == ':')
        y += x;
    }
  return y;
}


static string
conninfo (struct MHD_Connection * conn)
{
  char hostname[256]; // RFC1035
  char servname[256];
  int sts = -1;

  if (conn == 0)
    return "internal";

  /* Look up client address data. */
  const union MHD_ConnectionInfo *u = MHD_get_connection_info (conn,
                                                               MHD_CONNECTION_INFO_CLIENT_ADDRESS);
  struct sockaddr *so = u ? u->client_addr : 0;

  if (so && so->sa_family == AF_INET) {
    sts = getnameinfo (so, sizeof (struct sockaddr_in), hostname, sizeof (hostname), servname,
                       sizeof (servname), NI_NUMERICHOST | NI_NUMERICSERV);
  } else if (so && so->sa_family == AF_INET6) {
    sts = getnameinfo (so, sizeof (struct sockaddr_in6), hostname, sizeof (hostname),
                       servname, sizeof (servname), NI_NUMERICHOST | NI_NUMERICSERV);
  }
  if (sts != 0) {
    hostname[0] = servname[0] = '\0';
  }

  // extract headers relevant to administration
  const char* user_agent = MHD_lookup_connection_value (conn, MHD_HEADER_KIND, "User-Agent") ?: "";
  const char* x_forwarded_for = MHD_lookup_connection_value (conn, MHD_HEADER_KIND, "X-Forwarded-For") ?: "";
  // NB: these are untrustworthy, beware if machine-processing log files

  return string(hostname) + string(":") + string(servname) +
    string(" UA:") + header_censor(string(user_agent)) +
    string(" XFF:") + header_censor(string(x_forwarded_for));
}



////////////////////////////////////////////////////////////////////////


static void
add_mhd_last_modified (struct MHD_Response *resp, time_t mtime)
{
  struct tm *now = gmtime (&mtime);
  if (now != NULL)
    {
      char datebuf[80];
      size_t rc = strftime (datebuf, sizeof (datebuf), "%a, %d %b %Y %T GMT", now);
      if (rc > 0 && rc < sizeof (datebuf))
        (void) MHD_add_response_header (resp, "Last-Modified", datebuf);
    }

  (void) MHD_add_response_header (resp, "Cache-Control", "public");
}



static struct MHD_Response*
handle_buildid_f_match (int64_t b_mtime,
                        const string& b_source0,
                        int *result_fd)
{
  int fd = open(b_source0.c_str(), O_RDONLY);
  if (fd < 0)
    {
      if (verbose)
        obatched(clog) << "cannot open " << b_source0 << endl;
      // if still missing, a periodic groom pass will delete this buildid record
      return 0;
    }

  // NB: use manual close(2) in error case instead of defer_dtor, because
  // in the normal case, we want to hand the fd over to libmicrohttpd for
  // file transfer.

  struct stat s;
  int rc = fstat(fd, &s);
  if (rc < 0)
    {
      if (verbose)
        clog << "cannot fstat " << b_source0 << endl;
      close(fd);
      return 0;
    }

  if ((int64_t) s.st_mtime != b_mtime)
    {
      if (verbose)
        obatched(clog) << "mtime mismatch for " << b_source0 << endl;
      close(fd);
      return 0;
    }

  inc_metric ("http_responses_total","result","file");
  struct MHD_Response* r = MHD_create_response_from_fd ((uint64_t) s.st_size, fd);
  if (r == 0)
    {
      if (verbose)
        obatched(clog) << "cannot create fd-response for " << b_source0 << endl;
      close(fd);
    }
  else
    {
      MHD_add_response_header (r, "Content-Type", "application/octet-stream");
      add_mhd_last_modified (r, s.st_mtime);
      if (verbose > 1)
        obatched(clog) << "serving file " << b_source0 << endl;
      /* libmicrohttpd will close it. */
      if (result_fd)
        *result_fd = fd;
    }

  return r;
}


// quote all questionable characters of str for safe passage through a sh -c expansion.
static string
shell_escape(const string& str)
{
  string y;
  for (auto&& x : str)
    {
      if (! isalnum(x) && x != '/')
        y += "\\";
      y += x;
    }
  return y;
}


// PR25548: Perform POSIX / RFC3986 style path canonicalization on the input string.
//
// Namely:
//    //         ->   /
//    /foo/../   ->   /
//    /./        ->   /
//
// This mapping is done on dwarf-side source path names, which may
// include these constructs, so we can deal with debuginfod clients
// that accidentally canonicalize the paths.
//
// realpath(3) is close but not quite right, because it also resolves
// symbolic links.  Symlinks at the debuginfod server have nothing to
// do with the build-time symlinks, thus they must not be considered.
//
// see also curl Curl_dedotdotify() aka RFC3986, which we mostly follow here
// see also libc __realpath()
// see also llvm llvm::sys::path::remove_dots()
static string
canon_pathname (const string& input)
{
  string i = input; // 5.2.4 (1)
  string o;

  while (i.size() != 0)
    {
      // 5.2.4 (2) A
      if (i.substr(0,3) == "../")
        i = i.substr(3);
      else if(i.substr(0,2) == "./")
        i = i.substr(2);

      // 5.2.4 (2) B
      else if (i.substr(0,3) == "/./")
        i = i.substr(2);
      else if (i == "/.")
        i = ""; // no need to handle "/." complete-path-segment case; we're dealing with file names

      // 5.2.4 (2) C
      else if (i.substr(0,4) == "/../") {
        i = i.substr(3);
        string::size_type sl = o.rfind("/");
        if (sl != string::npos)
          o = o.substr(0, sl);
        else
          o = "";
      } else if (i == "/..")
        i = ""; // no need to handle "/.." complete-path-segment case; we're dealing with file names

      // 5.2.4 (2) D
      // no need to handle these cases; we're dealing with file names
      else if (i == ".")
        i = "";
      else if (i == "..")
        i = "";

      // POSIX special: map // to /
      else if (i.substr(0,2) == "//")
        i = i.substr(1);

      // 5.2.4 (2) E
      else {
        string::size_type next_slash = i.find("/", (i[0]=='/' ? 1 : 0)); // skip first slash
        o += i.substr(0, next_slash);
        if (next_slash == string::npos)
          i = "";
        else
          i = i.substr(next_slash);
      }
    }

  return o;
}



// A map-like class that owns a cache of file descriptors (indexed by
// file / content names).
//
// If only it could use fd's instead of file names ... but we can't
// dup(2) to create independent descriptors for the same unlinked
// files, so would have to use some goofy linux /proc/self/fd/%d
// hack such as the following

#if 0
int superdup(int fd)
{
#ifdef __linux__
  char *fdpath = NULL;
  int rc = asprintf(& fdpath, "/proc/self/fd/%d", fd);
  int newfd;
  if (rc >= 0)
    newfd = open(fdpath, O_RDONLY);
  else
    newfd = -1;
  free (fdpath);
  return newfd;
#else
  return -1;
#endif
}
#endif

class libarchive_fdcache
{
private:
  mutex fdcache_lock;

  struct fdcache_entry
  {
    string archive;
    string entry;
    string fd;
    double fd_size_mb; // slightly rounded up megabytes
  };
  deque<fdcache_entry> lru; // @head: most recently used
  long max_fds;
  long max_mbs;

public:
  void intern(const string& a, const string& b, string fd, off_t sz, bool front_p)
  {
    {
      unique_lock<mutex> lock(fdcache_lock);
      for (auto i = lru.begin(); i < lru.end(); i++) // nuke preexisting copy
        {
          if (i->archive == a && i->entry == b)
            {
              unlink (i->fd.c_str());
              lru.erase(i);
              break; // must not continue iterating
            }
        }
      double mb = (sz+65535)/1048576.0; // round up to 64K block
      fdcache_entry n = { a, b, fd, mb };
      if (front_p)
        lru.push_front(n);
      else
        lru.push_back(n);
    if (verbose > 3)
      obatched(clog) << "fdcache interned a=" << a << " b=" << b
                     << " fd=" << fd << " mb=" << mb << " front=" << front_p << endl;
    }

    // NB: we age the cache at lookup time too
    if (front_p)
      this->limit(max_fds, max_mbs); // age cache if required
  }

  int lookup(const string& a, const string& b)
  {
    int fd = -1;
    {
      unique_lock<mutex> lock(fdcache_lock);
      for (auto i = lru.begin(); i < lru.end(); i++)
        {
          if (i->archive == a && i->entry == b)
            { // found it; move it to head of lru
              fdcache_entry n = *i;
              lru.erase(i); // invalidates i, so no more iteration!
              lru.push_front(n);

              fd = open(n.fd.c_str(), O_RDONLY); // NB: no problem if dup() fails; looks like cache miss
              break;
            }
        }
    }

    if (fd >= 0)
      this->limit(max_fds, max_mbs); // age cache if required

    return fd;
  }

  int probe(const string& a, const string& b) // just a cache residency check - don't modify LRU state, don't open
  {
    unique_lock<mutex> lock(fdcache_lock);
    for (auto i = lru.begin(); i < lru.end(); i++)
      {
        if (i->archive == a && i->entry == b)
          return true;
      }
    return false;
  }

  void clear(const string& a, const string& b)
  {
    unique_lock<mutex> lock(fdcache_lock);
    for (auto i = lru.begin(); i < lru.end(); i++)
      {
        if (i->archive == a && i->entry == b)
          { // found it; move it to head of lru
            fdcache_entry n = *i;
            lru.erase(i); // invalidates i, so no more iteration!
            unlink (n.fd.c_str());
            return;
          }
      }
  }

  void limit(long maxfds, long maxmbs)
  {
    if (verbose > 3 && (this->max_fds != maxfds || this->max_mbs != maxmbs))
      obatched(clog) << "fdcache limited to maxfds=" << maxfds << " maxmbs=" << maxmbs << endl;

    unique_lock<mutex> lock(fdcache_lock);
    this->max_fds = maxfds;
    this->max_mbs = maxmbs;

    long total_fd = 0;
    double total_mb = 0.0;
    for (auto i = lru.begin(); i < lru.end(); i++)
      {
        // accumulate totals from most recently used one going backward
        total_fd ++;
        total_mb += i->fd_size_mb;
        if (total_fd > max_fds || total_mb > max_mbs)
          {
            // found the cut here point!

            for (auto j = i; j < lru.end(); j++) // close all the fds from here on in
              {
                if (verbose > 3)
                  obatched(clog) << "fdcache evicted a=" << j->archive << " b=" << j->entry
                                 << " fd=" << j->fd << " mb=" << j->fd_size_mb << endl;
                unlink (j->fd.c_str());
              }

            lru.erase(i, lru.end()); // erase the nodes generally
            break;
          }

      }
  }

  ~libarchive_fdcache()
  {
    limit(0, 0);
  }
};
static libarchive_fdcache fdcache;


// For security/portability reasons, many distro-package archives have
// a "./" in front of path names; others have nothing, others have
// "/".  Canonicalize them all to a single leading "/", with the
// assumption that this matches the dwarf-derived file names too.
string canonicalized_archive_entry_pathname(struct archive_entry *e)
{
  string fn = archive_entry_pathname(e);
  if (fn.size() == 0)
    return fn;
  if (fn[0] == '/')
    return fn;
  if (fn[0] == '.')
    return fn.substr(1);
  else
    return string("/")+fn;
}



static struct MHD_Response*
handle_buildid_r_match (int64_t b_mtime,
                        const string& b_source0,
                        const string& b_source1,
                        int *result_fd)
{
  struct stat fs;
  int rc = stat (b_source0.c_str(), &fs);
  if (rc != 0)
    throw libc_exception (errno, string("stat ") + b_source0);

  if ((int64_t) fs.st_mtime != b_mtime)
    {
      if (verbose)
        obatched(clog) << "mtime mismatch for " << b_source0 << endl;
      return 0;
    }

  // check for a match in the fdcache first
  int fd = fdcache.lookup(b_source0, b_source1);
  while (fd >= 0) // got one!; NB: this is really an if() with a possible branch out to the end
    {
      rc = fstat(fd, &fs);
      if (rc < 0) // disappeared?
        {
          if (verbose)
            obatched(clog) << "cannot fstat fdcache " << b_source0 << endl;
          close(fd);
          fdcache.clear(b_source0, b_source1);
          break; // branch out of if "loop", to try new libarchive fetch attempt
        }

      struct MHD_Response* r = MHD_create_response_from_fd (fs.st_size, fd);
      if (r == 0)
        {
          if (verbose)
            obatched(clog) << "cannot create fd-response for " << b_source0 << endl;
          close(fd);
          break; // branch out of if "loop", to try new libarchive fetch attempt
        }

      inc_metric ("http_responses_total","result","archive fdcache");

      MHD_add_response_header (r, "Content-Type", "application/octet-stream");
      add_mhd_last_modified (r, fs.st_mtime);
      if (verbose > 1)
        obatched(clog) << "serving fdcache archive " << b_source0 << " file " << b_source1 << endl;
      /* libmicrohttpd will close it. */
      if (result_fd)
        *result_fd = fd;
      return r;
      // NB: see, we never go around the 'loop' more than once
    }

  // no match ... grumble, must process the archive
  string archive_decoder = "/dev/null";
  string archive_extension = "";
  for (auto&& arch : scan_archives)
    if (string_endswith(b_source0, arch.first))
      {
        archive_extension = arch.first;
        archive_decoder = arch.second;
      }
  FILE* fp;
  defer_dtor<FILE*,int>::dtor_fn dfn;
  if (archive_decoder != "cat")
    {
      string popen_cmd = archive_decoder + " " + shell_escape(b_source0);
      fp = popen (popen_cmd.c_str(), "r"); // "e" O_CLOEXEC?
      dfn = pclose;
      if (fp == NULL)
        throw libc_exception (errno, string("popen ") + popen_cmd);
    }
  else
    {
      fp = fopen (b_source0.c_str(), "r");
      dfn = fclose;
      if (fp == NULL)
        throw libc_exception (errno, string("fopen ") + b_source0);
    }
  defer_dtor<FILE*,int> fp_closer (fp, dfn);

  struct archive *a;
  a = archive_read_new();
  if (a == NULL)
    throw archive_exception("cannot create archive reader");
  defer_dtor<struct archive*,int> archive_closer (a, archive_read_free);

  rc = archive_read_support_format_all(a);
  if (rc != ARCHIVE_OK)
    throw archive_exception(a, "cannot select all format");
  rc = archive_read_support_filter_all(a);
  if (rc != ARCHIVE_OK)
    throw archive_exception(a, "cannot select all filters");

  rc = archive_read_open_FILE (a, fp);
  if (rc != ARCHIVE_OK)
    throw archive_exception(a, "cannot open archive from pipe");

  // archive traversal is in three stages, no, four stages:
  // 1) skip entries whose names do not match the requested one
  // 2) extract the matching entry name (set r = result)
  // 3) extract some number of prefetched entries (just into fdcache)
  // 4) abort any further processing
  struct MHD_Response* r = 0;                 // will set in stage 2
  unsigned prefetch_count = fdcache_prefetch; // will decrement in stage 3

  while(r == 0 || prefetch_count > 0) // stage 1, 2, or 3
    {
      if (interrupted)
        break;

      struct archive_entry *e;
      rc = archive_read_next_header (a, &e);
      if (rc != ARCHIVE_OK)
        break;

      if (! S_ISREG(archive_entry_mode (e))) // skip non-files completely
        continue;

      string fn = canonicalized_archive_entry_pathname (e);
      if ((r == 0) && (fn != b_source1)) // stage 1
        continue;

      if (fdcache.probe (b_source0, fn)) // skip if already interned
        continue;

      // extract this file to a temporary file
      char* tmppath = NULL;
      rc = asprintf (&tmppath, "%s/debuginfod.XXXXXX", tmpdir.c_str());
      if (rc < 0)
        throw libc_exception (ENOMEM, "cannot allocate tmppath");
      defer_dtor<void*,void> tmmpath_freer (tmppath, free);
      fd = mkstemp (tmppath);
      if (fd < 0)
        throw libc_exception (errno, "cannot create temporary file");
      // NB: don't unlink (tmppath), as fdcache will take charge of it.

      rc = archive_read_data_into_fd (a, fd);
      if (rc != ARCHIVE_OK) // e.g. ENOSPC!
        {
          close (fd);
          unlink (tmppath);
          throw archive_exception(a, "cannot extract file");
        }

      // Set the mtime so the fdcache file mtimes, even prefetched ones,
      // propagate to future webapi clients.
      struct timeval tvs[2];
      tvs[0].tv_sec = tvs[1].tv_sec = archive_entry_mtime(e);
      tvs[0].tv_usec = tvs[1].tv_usec = 0;
      (void) futimes (fd, tvs);  /* best effort */

      if (r != 0) // stage 3
        {
          // NB: now we know we have a complete reusable file; make fdcache
          // responsible for unlinking it later.
          fdcache.intern(b_source0, fn,
                         tmppath, archive_entry_size(e),
                         false); // prefetched ones go to back of lru
          prefetch_count --;
          close (fd); // we're not saving this fd to make a mhd-response from!
          continue;
        }

      // NB: now we know we have a complete reusable file; make fdcache
      // responsible for unlinking it later.
      fdcache.intern(b_source0, b_source1,
                     tmppath, archive_entry_size(e),
                     true); // requested ones go to the front of lru

      inc_metric ("http_responses_total","result",archive_extension + " archive");
      r = MHD_create_response_from_fd (archive_entry_size(e), fd);
      if (r == 0)
        {
          if (verbose)
            obatched(clog) << "cannot create fd-response for " << b_source0 << endl;
          close(fd);
          break; // assume no chance of better luck around another iteration; no other copies of same file
        }
      else
        {
          MHD_add_response_header (r, "Content-Type", "application/octet-stream");
          add_mhd_last_modified (r, archive_entry_mtime(e));
          if (verbose > 1)
            obatched(clog) << "serving archive " << b_source0 << " file " << b_source1 << endl;
          /* libmicrohttpd will close it. */
          if (result_fd)
            *result_fd = fd;
          continue;
        }
    }

  // XXX: rpm/file not found: delete this R entry?
  return r;
}


static struct MHD_Response*
handle_buildid_match (int64_t b_mtime,
                      const string& b_stype,
                      const string& b_source0,
                      const string& b_source1,
                      int *result_fd)
{
  if (b_stype == "F")
    return handle_buildid_f_match(b_mtime, b_source0, result_fd);
  else if (b_stype == "R")
    return handle_buildid_r_match(b_mtime, b_source0, b_source1, result_fd);
  else
    return 0;
}


static int
debuginfod_find_progress (debuginfod_client *, long a, long b)
{
  if (verbose > 4)
    obatched(clog) << "federated debuginfod progress=" << a << "/" << b << endl;

  return interrupted;
}


static struct MHD_Response*
handle_buildid (MHD_Connection* conn,
                const string& buildid /* unsafe */,
                const string& artifacttype /* unsafe */,
                const string& suffix /* unsafe */,
                int *result_fd)
{
  // validate artifacttype
  string atype_code;
  if (artifacttype == "debuginfo") atype_code = "D";
  else if (artifacttype == "executable") atype_code = "E";
  else if (artifacttype == "source") atype_code = "S";
  else throw reportable_exception("invalid artifacttype");

  if (atype_code == "S" && suffix == "")
     throw reportable_exception("invalid source suffix");

  // validate buildid
  if ((buildid.size() < 2) || // not empty
      (buildid.size() % 2) || // even number
      (buildid.find_first_not_of("0123456789abcdef") != string::npos)) // pure tasty lowercase hex
    throw reportable_exception("invalid buildid");

  if (verbose > 1)
    obatched(clog) << "searching for buildid=" << buildid << " artifacttype=" << artifacttype
         << " suffix=" << suffix << endl;

  sqlite_ps *pp = 0;

  if (atype_code == "D")
    {
      pp = new sqlite_ps (db, "mhd-query-d",
                          "select mtime, sourcetype, source0, source1 from " BUILDIDS "_query_d where buildid = ? "
                          "order by mtime desc");
      pp->reset();
      pp->bind(1, buildid);
    }
  else if (atype_code == "E")
    {
      pp = new sqlite_ps (db, "mhd-query-e",
                          "select mtime, sourcetype, source0, source1 from " BUILDIDS "_query_e where buildid = ? "
                          "order by mtime desc");
      pp->reset();
      pp->bind(1, buildid);
    }
  else if (atype_code == "S")
    {
      // PR25548
      // Incoming source queries may come in with either dwarf-level OR canonicalized paths.
      // We let the query pass with either one.

      pp = new sqlite_ps (db, "mhd-query-s",
                          "select mtime, sourcetype, source0, source1 from " BUILDIDS "_query_s where buildid = ? and artifactsrc in (?,?) "
                          "order by sharedprefix(source0,source0ref) desc, mtime desc");
      pp->reset();
      pp->bind(1, buildid);
      pp->bind(2, suffix);
      pp->bind(3, canon_pathname(suffix));
    }
  unique_ptr<sqlite_ps> ps_closer(pp); // release pp if exception or return

  // consume all the rows
  while (1)
    {
      int rc = pp->step();
      if (rc == SQLITE_DONE) break;
      if (rc != SQLITE_ROW)
        throw sqlite_exception(rc, "step");

      int64_t b_mtime = sqlite3_column_int64 (*pp, 0);
      string b_stype = string((const char*) sqlite3_column_text (*pp, 1) ?: ""); /* by DDL may not be NULL */
      string b_source0 = string((const char*) sqlite3_column_text (*pp, 2) ?: ""); /* may be NULL */
      string b_source1 = string((const char*) sqlite3_column_text (*pp, 3) ?: ""); /* may be NULL */

      if (verbose > 1)
        obatched(clog) << "found mtime=" << b_mtime << " stype=" << b_stype
             << " source0=" << b_source0 << " source1=" << b_source1 << endl;

      // Try accessing the located match.
      // XXX: in case of multiple matches, attempt them in parallel?
      auto r = handle_buildid_match (b_mtime, b_stype, b_source0, b_source1, result_fd);
      if (r)
        return r;
    }

  // We couldn't find it in the database.  Last ditch effort
  // is to defer to other debuginfo servers.

  int fd = -1;
  debuginfod_client *client = debuginfod_begin ();
  if (client != NULL)
    {
      debuginfod_set_progressfn (client, & debuginfod_find_progress);

      if (conn)
        {
          // Transcribe incoming User-Agent:
          string ua = MHD_lookup_connection_value (conn, MHD_HEADER_KIND, "User-Agent") ?: "";
          string ua_complete = string("User-Agent: ") + ua;
          debuginfod_add_http_header (client, ua_complete.c_str());

          // Compute larger XFF:, for avoiding info loss during
          // federation, and for future cyclicity detection.
          string xff = MHD_lookup_connection_value (conn, MHD_HEADER_KIND, "X-Forwarded-For") ?: "";
          if (xff != "")
            xff += string(", "); // comma separated list

          // Compute the client's numeric IP address only - so can't merge with conninfo()
          const union MHD_ConnectionInfo *u = MHD_get_connection_info (conn,
                                                                       MHD_CONNECTION_INFO_CLIENT_ADDRESS);
          struct sockaddr *so = u ? u->client_addr : 0;
          char hostname[256] = ""; // RFC1035
          if (so && so->sa_family == AF_INET)
            (void) getnameinfo (so, sizeof (struct sockaddr_in), hostname, sizeof (hostname), NULL, 0,
                                NI_NUMERICHOST);
          else if (so && so->sa_family == AF_INET6)
            (void) getnameinfo (so, sizeof (struct sockaddr_in6), hostname, sizeof (hostname), NULL, 0,
                                NI_NUMERICHOST);

          string xff_complete = string("X-Forwarded-For: ")+xff+string(hostname);
          debuginfod_add_http_header (client, xff_complete.c_str());
        }

      if (artifacttype == "debuginfo")
	fd = debuginfod_find_debuginfo (client,
					(const unsigned char*) buildid.c_str(),
					0, NULL);
      else if (artifacttype == "executable")
	fd = debuginfod_find_executable (client,
					 (const unsigned char*) buildid.c_str(),
					 0, NULL);
      else if (artifacttype == "source")
	fd = debuginfod_find_source (client,
				     (const unsigned char*) buildid.c_str(),
				     0, suffix.c_str(), NULL);
    }
  else
    fd = -errno; /* Set by debuginfod_begin.  */
  debuginfod_end (client);

  if (fd >= 0)
    {
      inc_metric ("http_responses_total","result","upstream");
      struct stat s;
      int rc = fstat (fd, &s);
      if (rc == 0)
        {
          auto r = MHD_create_response_from_fd ((uint64_t) s.st_size, fd);
          if (r)
            {
              MHD_add_response_header (r, "Content-Type", "application/octet-stream");
              add_mhd_last_modified (r, s.st_mtime);
              if (verbose > 1)
                obatched(clog) << "serving file from upstream debuginfod/cache" << endl;
              if (result_fd)
                *result_fd = fd;
              return r; // NB: don't close fd; libmicrohttpd will
            }
        }
      close (fd);
    }
  else
    switch(fd)
      {
      case -ENOSYS:
        break;
      case -ENOENT:
        break;
      default: // some more tricky error
        throw libc_exception(-fd, "upstream debuginfod query failed");
      }

  throw reportable_exception(MHD_HTTP_NOT_FOUND, "not found");
}


////////////////////////////////////////////////////////////////////////

static map<string,int64_t> metrics; // arbitrary data for /metrics query
// NB: store int64_t since all our metrics are integers; prometheus accepts double
static mutex metrics_lock;

// utility function for assembling prometheus-compatible
// name="escaped-value" strings
// https://prometheus.io/docs/instrumenting/exposition_formats/
static string
metric_label(const string& name, const string& value)
{
  string x = name + "=\"";
  for (auto&& c : value)
    switch(c)
      {
      case '\\': x += "\\\\"; break;
      case '\"': x += "\\\""; break;
      case '\n': x += "\\n"; break;
      default: x += c; break;
      }
  x += "\"";
  return x;
}


// add prometheus-format metric name + label tuple (if any) + value

static void
set_metric(const string& metric, int64_t value)
{
  unique_lock<mutex> lock(metrics_lock);
  metrics[metric] = value;
}
#if 0 /* unused */
static void
inc_metric(const string& metric)
{
  unique_lock<mutex> lock(metrics_lock);
  metrics[metric] ++;
}
#endif
static void
set_metric(const string& metric,
           const string& lname, const string& lvalue,
           int64_t value)
{
  string key = (metric + "{" + metric_label(lname, lvalue) + "}");
  unique_lock<mutex> lock(metrics_lock);
  metrics[key] = value;
}

static void
inc_metric(const string& metric,
           const string& lname, const string& lvalue)
{
  string key = (metric + "{" + metric_label(lname, lvalue) + "}");
  unique_lock<mutex> lock(metrics_lock);
  metrics[key] ++;
}
static void
add_metric(const string& metric,
           const string& lname, const string& lvalue,
           int64_t value)
{
  string key = (metric + "{" + metric_label(lname, lvalue) + "}");
  unique_lock<mutex> lock(metrics_lock);
  metrics[key] += value;
}
#if 0
static void
add_metric(const string& metric,
           int64_t value)
{
  unique_lock<mutex> lock(metrics_lock);
  metrics[metric] += value;
}
#endif


// and more for higher arity labels if needed


static struct MHD_Response*
handle_metrics (off_t* size)
{
  stringstream o;
  {
    unique_lock<mutex> lock(metrics_lock);
    for (auto&& i : metrics)
      o << i.first << " " << i.second << endl;
  }
  const string& os = o.str();
  MHD_Response* r = MHD_create_response_from_buffer (os.size(),
                                                     (void*) os.c_str(),
                                                     MHD_RESPMEM_MUST_COPY);
  *size = os.size();
  MHD_add_response_header (r, "Content-Type", "text/plain");
  return r;
}


////////////////////////////////////////////////////////////////////////


/* libmicrohttpd callback */
static int
handler_cb (void * /*cls*/,
            struct MHD_Connection *connection,
            const char *url,
            const char *method,
            const char * /*version*/,
            const char * /*upload_data*/,
            size_t * /*upload_data_size*/,
            void ** /*con_cls*/)
{
  struct MHD_Response *r = NULL;
  string url_copy = url;

  int rc = MHD_NO; // mhd
  int http_code = 500;
  off_t http_size = -1;
  struct timeval tv_start, tv_end;
  gettimeofday (&tv_start, NULL);

  try
    {
      if (string(method) != "GET")
        throw reportable_exception(400, "we support GET only");

      /* Start decoding the URL. */
      size_t slash1 = url_copy.find('/', 1);
      string url1 = url_copy.substr(0, slash1); // ok even if slash1 not found

      if (slash1 != string::npos && url1 == "/buildid")
        {
          size_t slash2 = url_copy.find('/', slash1+1);
          if (slash2 == string::npos)
            throw reportable_exception("/buildid/ webapi error, need buildid");

          string buildid = url_copy.substr(slash1+1, slash2-slash1-1);

          size_t slash3 = url_copy.find('/', slash2+1);
          string artifacttype, suffix;
          if (slash3 == string::npos)
            {
              artifacttype = url_copy.substr(slash2+1);
              suffix = "";
            }
          else
            {
              artifacttype = url_copy.substr(slash2+1, slash3-slash2-1);
              suffix = url_copy.substr(slash3); // include the slash in the suffix
            }

          inc_metric("http_requests_total", "type", artifacttype);
          // get the resulting fd so we can report its size
          int fd;
          r = handle_buildid(connection, buildid, artifacttype, suffix, &fd);
          if (r)
            {
              struct stat fs;
              if (fstat(fd, &fs) == 0)
                http_size = fs.st_size;
              // libmicrohttpd will close (fd);
            }
        }
      else if (url1 == "/metrics")
        {
          inc_metric("http_requests_total", "type", "metrics");
          r = handle_metrics(& http_size);
        }
      else
        throw reportable_exception("webapi error, unrecognized /operation");

      if (r == 0)
        throw reportable_exception("internal error, missing response");

      rc = MHD_queue_response (connection, MHD_HTTP_OK, r);
      http_code = MHD_HTTP_OK;
      MHD_destroy_response (r);
    }
  catch (const reportable_exception& e)
    {
      inc_metric("http_responses_total","result","error");
      e.report(clog);
      http_code = e.code;
      http_size = e.message.size();
      rc = e.mhd_send_response (connection);
    }

  gettimeofday (&tv_end, NULL);
  double deltas = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec)*0.000001;
  obatched(clog) << conninfo(connection)
                 << ' ' << method << ' ' << url
                 << ' ' << http_code << ' ' << http_size
                 << ' ' << (int)(deltas*1000) << "ms"
                 << endl;

  // related prometheus metrics
  string http_code_str = to_string(http_code);
  if (http_size >= 0)
    add_metric("http_responses_transfer_bytes_sum","code",http_code_str,
               http_size);
  inc_metric("http_responses_transfer_bytes_count","code",http_code_str);

  add_metric("http_responses_duration_milliseconds_sum","code",http_code_str,
             deltas*1000); // prometheus prefers _seconds and floating point
  inc_metric("http_responses_duration_milliseconds_count","code",http_code_str);

  return rc;
}


////////////////////////////////////////////////////////////////////////
// borrowed originally from src/nm.c get_local_names()

static void
dwarf_extract_source_paths (Elf *elf, set<string>& debug_sourcefiles)
  noexcept // no exceptions - so we can simplify the altdbg resource release at end
{
  Dwarf* dbg = dwarf_begin_elf (elf, DWARF_C_READ, NULL);
  if (dbg == NULL)
    return;

  Dwarf* altdbg = NULL;
  int    altdbg_fd = -1;

  // DWZ handling: if we have an unsatisfied debug-alt-link, add an
  // empty string into the outgoing sourcefiles set, so the caller
  // should know that our data is incomplete.
  const char *alt_name_p;
  const void *alt_build_id; // elfutils-owned memory
  ssize_t sz = dwelf_dwarf_gnu_debugaltlink (dbg, &alt_name_p, &alt_build_id);
  if (sz > 0) // got one!
    {
      string buildid;
      unsigned char* build_id_bytes = (unsigned char*) alt_build_id;
      for (ssize_t idx=0; idx<sz; idx++)
        {
          buildid += "0123456789abcdef"[build_id_bytes[idx] >> 4];
          buildid += "0123456789abcdef"[build_id_bytes[idx] & 0xf];
        }

      if (verbose > 3)
        obatched(clog) << "Need altdebug buildid=" << buildid << endl;

      // but is it unsatisfied the normal elfutils ways?
      Dwarf* alt = dwarf_getalt (dbg);
      if (alt == NULL)
        {
          // Yup, unsatisfied the normal way.  Maybe we can satisfy it
          // from our own debuginfod database.
          int alt_fd;
          struct MHD_Response *r = 0;
          try
            {
              r = handle_buildid (0, buildid, "debuginfo", "", &alt_fd);
            }
          catch (const reportable_exception& e)
            {
              // swallow exceptions
            }

          // NB: this is not actually recursive!  This invokes the web-query
          // path, which cannot get back into the scan code paths.
          if (r)
            {
              // Found it!
              altdbg_fd = dup(alt_fd); // ok if this fails, downstream failures ok
              alt = altdbg = dwarf_begin (altdbg_fd, DWARF_C_READ);
              // NB: must close this dwarf and this fd at the bottom of the function!
              MHD_destroy_response (r); // will close alt_fd
              if (alt)
                dwarf_setalt (dbg, alt);
            }
        }
      else
        {
          // NB: dwarf_setalt(alt) inappropriate - already done!
          // NB: altdbg will stay 0 so nothing tries to redundantly dealloc.
        }

      if (alt)
        {
          if (verbose > 3)
            obatched(clog) << "Resolved altdebug buildid=" << buildid << endl;
        }
      else // (alt == NULL) - signal possible presence of poor debuginfo
        {
          debug_sourcefiles.insert("");
          if (verbose > 3)
            obatched(clog) << "Unresolved altdebug buildid=" << buildid << endl;
        }
    }

  Dwarf_Off offset = 0;
  Dwarf_Off old_offset;
  size_t hsize;

  while (dwarf_nextcu (dbg, old_offset = offset, &offset, &hsize, NULL, NULL, NULL) == 0)
    {
      Dwarf_Die cudie_mem;
      Dwarf_Die *cudie = dwarf_offdie (dbg, old_offset + hsize, &cudie_mem);

      if (cudie == NULL)
        continue;
      if (dwarf_tag (cudie) != DW_TAG_compile_unit)
        continue;

      const char *cuname = dwarf_diename(cudie) ?: "unknown";

      Dwarf_Files *files;
      size_t nfiles;
      if (dwarf_getsrcfiles (cudie, &files, &nfiles) != 0)
        continue;

      // extract DW_AT_comp_dir to resolve relative file names
      const char *comp_dir = "";
      const char *const *dirs;
      size_t ndirs;
      if (dwarf_getsrcdirs (files, &dirs, &ndirs) == 0 &&
          dirs[0] != NULL)
        comp_dir = dirs[0];
      if (comp_dir == NULL)
        comp_dir = "";

      if (verbose > 3)
        obatched(clog) << "searching for sources for cu=" << cuname << " comp_dir=" << comp_dir
                       << " #files=" << nfiles << " #dirs=" << ndirs << endl;

      if (comp_dir[0] == '\0' && cuname[0] != '/')
        {
          // This is a common symptom for dwz-compressed debug files,
          // where the altdebug file cannot be resolved.
          if (verbose > 3)
            obatched(clog) << "skipping cu=" << cuname << " due to empty comp_dir" << endl;
          continue;
        }

      for (size_t f = 1; f < nfiles; f++)
        {
          const char *hat = dwarf_filesrc (files, f, NULL, NULL);
          if (hat == NULL)
            continue;

          if (string(hat) == "<built-in>") // gcc intrinsics, don't bother record
            continue;

          string waldo;
          if (hat[0] == '/') // absolute
            waldo = (string (hat));
          else if (comp_dir[0] != '\0') // comp_dir relative
            waldo = (string (comp_dir) + string("/") + string (hat));
          else
           {
             if (verbose > 3)
               obatched(clog) << "skipping hat=" << hat << " due to empty comp_dir" << endl;
             continue;
           }

          // NB: this is the 'waldo' that a dbginfo client will have
          // to supply for us to give them the file The comp_dir
          // prefixing is a definite complication.  Otherwise we'd
          // have to return a setof comp_dirs (one per CU!) with
          // corresponding filesrc[] names, instead of one absolute
          // resoved set.  Maybe we'll have to do that anyway.  XXX

          if (verbose > 4)
            obatched(clog) << waldo
                           << (debug_sourcefiles.find(waldo)==debug_sourcefiles.end() ? " new" : " dup") <<  endl;

          debug_sourcefiles.insert (waldo);
        }
    }

  dwarf_end(dbg);
  if (altdbg)
    dwarf_end(altdbg);
  if (altdbg_fd >= 0)
    close(altdbg_fd);
}



static void
elf_classify (int fd, bool &executable_p, bool &debuginfo_p, string &buildid, set<string>& debug_sourcefiles)
{
  Elf *elf = elf_begin (fd, ELF_C_READ_MMAP_PRIVATE, NULL);
  if (elf == NULL)
    return;

  try // catch our types of errors and clean up the Elf* object
    {
      if (elf_kind (elf) != ELF_K_ELF)
        {
          elf_end (elf);
          return;
        }

      GElf_Ehdr ehdr_storage;
      GElf_Ehdr *ehdr = gelf_getehdr (elf, &ehdr_storage);
      if (ehdr == NULL)
        {
          elf_end (elf);
          return;
        }
      auto elf_type = ehdr->e_type;

      const void *build_id; // elfutils-owned memory
      ssize_t sz = dwelf_elf_gnu_build_id (elf, & build_id);
      if (sz <= 0)
        {
          // It's not a diagnostic-worthy error for an elf file to lack build-id.
          // It might just be very old.
          elf_end (elf);
          return;
        }

      // build_id is a raw byte array; convert to hexadecimal *lowercase*
      unsigned char* build_id_bytes = (unsigned char*) build_id;
      for (ssize_t idx=0; idx<sz; idx++)
        {
          buildid += "0123456789abcdef"[build_id_bytes[idx] >> 4];
          buildid += "0123456789abcdef"[build_id_bytes[idx] & 0xf];
        }

      // now decide whether it's an executable - namely, any allocatable section has
      // PROGBITS;
      if (elf_type == ET_EXEC || elf_type == ET_DYN)
        {
          size_t shnum;
          int rc = elf_getshdrnum (elf, &shnum);
          if (rc < 0)
            throw elfutils_exception(rc, "getshdrnum");

          executable_p = false;
          for (size_t sc = 0; sc < shnum; sc++)
            {
              Elf_Scn *scn = elf_getscn (elf, sc);
              if (scn == NULL)
                continue;

              GElf_Shdr shdr_mem;
              GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_mem);
              if (shdr == NULL)
                continue;

              // allocated (loadable / vm-addr-assigned) section with available content?
              if ((shdr->sh_type == SHT_PROGBITS) && (shdr->sh_flags & SHF_ALLOC))
                {
                  if (verbose > 4)
                    obatched(clog) << "executable due to SHF_ALLOC SHT_PROGBITS sc=" << sc << endl;
                  executable_p = true;
                  break; // no need to keep looking for others
                }
            } // iterate over sections
        } // executable_p classification

      // now decide whether it's a debuginfo - namely, if it has any .debug* or .zdebug* sections
      // logic mostly stolen from fweimer@redhat.com's elfclassify drafts
      size_t shstrndx;
      int rc = elf_getshdrstrndx (elf, &shstrndx);
      if (rc < 0)
        throw elfutils_exception(rc, "getshdrstrndx");

      Elf_Scn *scn = NULL;
      while (true)
        {
          scn = elf_nextscn (elf, scn);
          if (scn == NULL)
            break;
          GElf_Shdr shdr_storage;
          GElf_Shdr *shdr = gelf_getshdr (scn, &shdr_storage);
          if (shdr == NULL)
            break;
          const char *section_name = elf_strptr (elf, shstrndx, shdr->sh_name);
          if (section_name == NULL)
            break;
          if (strncmp(section_name, ".debug_line", 11) == 0 ||
              strncmp(section_name, ".zdebug_line", 12) == 0)
            {
              debuginfo_p = true;
              dwarf_extract_source_paths (elf, debug_sourcefiles);
              break; // expecting only one .*debug_line, so no need to look for others
            }
          else if (strncmp(section_name, ".debug_", 7) == 0 ||
                   strncmp(section_name, ".zdebug_", 8) == 0)
            {
              debuginfo_p = true;
              // NB: don't break; need to parse .debug_line for sources
            }
        }
    }
  catch (const reportable_exception& e)
    {
      e.report(clog);
    }
  elf_end (elf);
}


static void
scan_source_file (const string& rps, const stat_t& st,
                  sqlite_ps& ps_upsert_buildids,
                  sqlite_ps& ps_upsert_files,
                  sqlite_ps& ps_upsert_de,
                  sqlite_ps& ps_upsert_s,
                  sqlite_ps& ps_query,
                  sqlite_ps& ps_scan_done,
                  unsigned& fts_cached,
                  unsigned& fts_executable,
                  unsigned& fts_debuginfo,
                  unsigned& fts_sourcefiles)
{
  /* See if we know of it already. */
  int rc = ps_query
    .reset()
    .bind(1, rps)
    .bind(2, st.st_mtime)
    .step();
  ps_query.reset();
  if (rc == SQLITE_ROW) // i.e., a result, as opposed to DONE (no results)
    // no need to recheck a file/version we already know
    // specifically, no need to elf-begin a file we already determined is non-elf
    // (so is stored with buildid=NULL)
    {
      fts_cached++;
      return;
    }

  bool executable_p = false, debuginfo_p = false; // E and/or D
  string buildid;
  set<string> sourcefiles;

  int fd = open (rps.c_str(), O_RDONLY);
  try
    {
      if (fd >= 0)
        elf_classify (fd, executable_p, debuginfo_p, buildid, sourcefiles);
      else
        throw libc_exception(errno, string("open ") + rps);
      inc_metric ("scanned_total","source","file");
    }
  // NB: we catch exceptions here too, so that we can
  // cache the corrupt-elf case (!executable_p &&
  // !debuginfo_p) just below, just as if we had an
  // EPERM error from open(2).
  catch (const reportable_exception& e)
    {
      e.report(clog);
    }

  if (fd >= 0)
    close (fd);

  // register this file name in the interning table
  ps_upsert_files
    .reset()
    .bind(1, rps)
    .step_ok_done();

  if (buildid == "")
    {
      // no point storing an elf file without buildid
      executable_p = false;
      debuginfo_p = false;
    }
  else
    {
      // register this build-id in the interning table
      ps_upsert_buildids
        .reset()
        .bind(1, buildid)
        .step_ok_done();
    }

  if (executable_p)
    fts_executable ++;
  if (debuginfo_p)
    fts_debuginfo ++;
  if (executable_p || debuginfo_p)
    {
      ps_upsert_de
        .reset()
        .bind(1, buildid)
        .bind(2, debuginfo_p ? 1 : 0)
        .bind(3, executable_p ? 1 : 0)
        .bind(4, rps)
        .bind(5, st.st_mtime)
        .step_ok_done();
    }
  if (executable_p)
    inc_metric("found_executable_total","source","files");
  if (debuginfo_p)
    inc_metric("found_debuginfo_total","source","files");

  if (sourcefiles.size() && buildid != "")
    {
      fts_sourcefiles += sourcefiles.size();

      for (auto&& dwarfsrc : sourcefiles)
        {
          char *srp = realpath(dwarfsrc.c_str(), NULL);
          if (srp == NULL) // also if DWZ unresolved dwarfsrc=""
            continue; // unresolvable files are not a serious problem
          // throw libc_exception(errno, "fts/file realpath " + srcpath);
          string srps = string(srp);
          free (srp);

          struct stat sfs;
          rc = stat(srps.c_str(), &sfs);
          if (rc != 0)
            continue;

          if (verbose > 2)
            obatched(clog) << "recorded buildid=" << buildid << " file=" << srps
                           << " mtime=" << sfs.st_mtime
                           << " as source " << dwarfsrc << endl;

          ps_upsert_files
            .reset()
            .bind(1, srps)
            .step_ok_done();

          // register the dwarfsrc name in the interning table too
          ps_upsert_files
            .reset()
            .bind(1, dwarfsrc)
            .step_ok_done();

          ps_upsert_s
            .reset()
            .bind(1, buildid)
            .bind(2, dwarfsrc)
            .bind(3, srps)
            .bind(4, sfs.st_mtime)
            .step_ok_done();

          // PR25548: also store canonicalized source path
          string dwarfsrc_canon = canon_pathname (dwarfsrc);
          if (dwarfsrc_canon != dwarfsrc)
            {
              if (verbose > 3)
                obatched(clog) << "canonicalized src=" << dwarfsrc << " alias=" << dwarfsrc_canon << endl;

              ps_upsert_files
                .reset()
                .bind(1, dwarfsrc_canon)
                .step_ok_done();

              ps_upsert_s
                .reset()
                .bind(1, buildid)
                .bind(2, dwarfsrc_canon)
                .bind(3, srps)
                .bind(4, sfs.st_mtime)
                .step_ok_done();
            }

          inc_metric("found_sourcerefs_total","source","files");
        }
    }

  ps_scan_done
    .reset()
    .bind(1, rps)
    .bind(2, st.st_mtime)
    .bind(3, st.st_size)
    .step_ok_done();

  if (verbose > 2)
    obatched(clog) << "recorded buildid=" << buildid << " file=" << rps
                   << " mtime=" << st.st_mtime << " atype="
                   << (executable_p ? "E" : "")
                   << (debuginfo_p ? "D" : "") << endl;
}





// Analyze given archive file of given age; record buildids / exec/debuginfo-ness of its
// constituent files with given upsert statements.
static void
archive_classify (const string& rps, string& archive_extension,
                  sqlite_ps& ps_upsert_buildids, sqlite_ps& ps_upsert_files,
                  sqlite_ps& ps_upsert_de, sqlite_ps& ps_upsert_sref, sqlite_ps& ps_upsert_sdef,
                  time_t mtime,
                  unsigned& fts_executable, unsigned& fts_debuginfo, unsigned& fts_sref, unsigned& fts_sdef,
                  bool& fts_sref_complete_p)
{
  string archive_decoder = "/dev/null";
  for (auto&& arch : scan_archives)
    if (string_endswith(rps, arch.first))
      {
        archive_extension = arch.first;
        archive_decoder = arch.second;
      }

  FILE* fp;
  defer_dtor<FILE*,int>::dtor_fn dfn;
  if (archive_decoder != "cat")
    {
      string popen_cmd = archive_decoder + " " + shell_escape(rps);
      fp = popen (popen_cmd.c_str(), "r"); // "e" O_CLOEXEC?
      dfn = pclose;
      if (fp == NULL)
        throw libc_exception (errno, string("popen ") + popen_cmd);
    }
  else
    {
      fp = fopen (rps.c_str(), "r");
      dfn = fclose;
      if (fp == NULL)
        throw libc_exception (errno, string("fopen ") + rps);
    }
  defer_dtor<FILE*,int> fp_closer (fp, dfn);

  struct archive *a;
  a = archive_read_new();
  if (a == NULL)
    throw archive_exception("cannot create archive reader");
  defer_dtor<struct archive*,int> archive_closer (a, archive_read_free);

  int rc = archive_read_support_format_all(a);
  if (rc != ARCHIVE_OK)
    throw archive_exception(a, "cannot select all formats");
  rc = archive_read_support_filter_all(a);
  if (rc != ARCHIVE_OK)
    throw archive_exception(a, "cannot select all filters");

  rc = archive_read_open_FILE (a, fp);
  if (rc != ARCHIVE_OK)
    throw archive_exception(a, "cannot open archive from pipe");

  if (verbose > 3)
    obatched(clog) << "libarchive scanning " << rps << endl;

  while(1) // parse cpio archive entries
    {
      try
        {
          struct archive_entry *e;
          rc = archive_read_next_header (a, &e);
          if (rc != ARCHIVE_OK)
            break;

          if (! S_ISREG(archive_entry_mode (e))) // skip non-files completely
            continue;

          string fn = canonicalized_archive_entry_pathname (e);

          if (verbose > 3)
            obatched(clog) << "libarchive checking " << fn << endl;

          // extract this file to a temporary file
          char* tmppath = NULL;
          rc = asprintf (&tmppath, "%s/debuginfod.XXXXXX", tmpdir.c_str());
          if (rc < 0)
            throw libc_exception (ENOMEM, "cannot allocate tmppath");
          defer_dtor<void*,void> tmmpath_freer (tmppath, free);
          int fd = mkstemp (tmppath);
          if (fd < 0)
            throw libc_exception (errno, "cannot create temporary file");
          unlink (tmppath); // unlink now so OS will release the file as soon as we close the fd
          defer_dtor<int,int> minifd_closer (fd, close);

          rc = archive_read_data_into_fd (a, fd);
          if (rc != ARCHIVE_OK)
            throw archive_exception(a, "cannot extract file");

          // finally ... time to run elf_classify on this bad boy and update the database
          bool executable_p = false, debuginfo_p = false;
          string buildid;
          set<string> sourcefiles;
          elf_classify (fd, executable_p, debuginfo_p, buildid, sourcefiles);
          // NB: might throw

          if (buildid != "") // intern buildid
            {
              ps_upsert_buildids
                .reset()
                .bind(1, buildid)
                .step_ok_done();
            }

          ps_upsert_files // register this rpm constituent file name in interning table
            .reset()
            .bind(1, fn)
            .step_ok_done();

          if (sourcefiles.size() > 0) // sref records needed
            {
              // NB: we intern each source file once.  Once raw, as it
              // appears in the DWARF file list coming back from
              // elf_classify() - because it'll end up in the
              // _norm.artifactsrc column.  We don't also put another
              // version with a '.' at the front, even though that's
              // how rpm/cpio packs names, because we hide that from
              // the database for storage efficiency.

              for (auto&& s : sourcefiles)
                {
                  if (s == "")
                    {
                      fts_sref_complete_p = false;
                      continue;
                    }

                  ps_upsert_files
                    .reset()
                    .bind(1, s)
                    .step_ok_done();

                  ps_upsert_sref
                    .reset()
                    .bind(1, buildid)
                    .bind(2, s)
                    .step_ok_done();

                  // PR25548: also store canonicalized source path
                  const string& dwarfsrc = s;
                  string dwarfsrc_canon = canon_pathname (dwarfsrc);
                  if (dwarfsrc_canon != dwarfsrc)
                    {
                      if (verbose > 3)
                        obatched(clog) << "canonicalized src=" << dwarfsrc << " alias=" << dwarfsrc_canon << endl;

                      ps_upsert_files
                        .reset()
                        .bind(1, dwarfsrc_canon)
                        .step_ok_done();

                      ps_upsert_sref
                        .reset()
                        .bind(1, buildid)
                        .bind(2, dwarfsrc_canon)
                        .step_ok_done();
                    }

                  fts_sref ++;
                }
            }

          if (executable_p)
            fts_executable ++;
          if (debuginfo_p)
            fts_debuginfo ++;

          if (executable_p || debuginfo_p)
            {
              ps_upsert_de
                .reset()
                .bind(1, buildid)
                .bind(2, debuginfo_p ? 1 : 0)
                .bind(3, executable_p ? 1 : 0)
                .bind(4, rps)
                .bind(5, mtime)
                .bind(6, fn)
                .step_ok_done();
            }
          else // potential source - sdef record
            {
              fts_sdef ++;
              ps_upsert_sdef
                .reset()
                .bind(1, rps)
                .bind(2, mtime)
                .bind(3, fn)
                .step_ok_done();
            }

          if ((verbose > 2) && (executable_p || debuginfo_p))
            obatched(clog) << "recorded buildid=" << buildid << " rpm=" << rps << " file=" << fn
                           << " mtime=" << mtime << " atype="
                           << (executable_p ? "E" : "")
                           << (debuginfo_p ? "D" : "")
                           << " sourcefiles=" << sourcefiles.size() << endl;

        }
      catch (const reportable_exception& e)
        {
          e.report(clog);
        }
    }
}



// scan for archive files such as .rpm
static void
scan_archive_file (const string& rps, const stat_t& st,
                   sqlite_ps& ps_upsert_buildids,
                   sqlite_ps& ps_upsert_files,
                   sqlite_ps& ps_upsert_de,
                   sqlite_ps& ps_upsert_sref,
                   sqlite_ps& ps_upsert_sdef,
                   sqlite_ps& ps_query,
                   sqlite_ps& ps_scan_done,
                   unsigned& fts_cached,
                   unsigned& fts_executable,
                   unsigned& fts_debuginfo,
                   unsigned& fts_sref,
                   unsigned& fts_sdef)
{
  /* See if we know of it already. */
  int rc = ps_query
    .reset()
    .bind(1, rps)
    .bind(2, st.st_mtime)
    .step();
  ps_query.reset();
  if (rc == SQLITE_ROW) // i.e., a result, as opposed to DONE (no results)
    // no need to recheck a file/version we already know
    // specifically, no need to parse this archive again, since we already have
    // it as a D or E or S record,
    // (so is stored with buildid=NULL)
    {
      fts_cached ++;
      return;
    }

  // intern the archive file name
  ps_upsert_files
    .reset()
    .bind(1, rps)
    .step_ok_done();

  // extract the archive contents
  unsigned my_fts_executable = 0, my_fts_debuginfo = 0, my_fts_sref = 0, my_fts_sdef = 0;
  bool my_fts_sref_complete_p = true;
  try
    {
      string archive_extension;
      archive_classify (rps, archive_extension,
                        ps_upsert_buildids, ps_upsert_files,
                        ps_upsert_de, ps_upsert_sref, ps_upsert_sdef, // dalt
                        st.st_mtime,
                        my_fts_executable, my_fts_debuginfo, my_fts_sref, my_fts_sdef,
                        my_fts_sref_complete_p);
      inc_metric ("scanned_total","source",archive_extension + " archive");
      add_metric("found_debuginfo_total","source",archive_extension + " archive",
                 my_fts_debuginfo);
      add_metric("found_executable_total","source",archive_extension + " archive",
                 my_fts_executable);
      add_metric("found_sourcerefs_total","source",archive_extension + " archive",
                 my_fts_sref);
    }
  catch (const reportable_exception& e)
    {
      e.report(clog);
    }

  if (verbose > 2)
    obatched(clog) << "scanned archive=" << rps
                   << " mtime=" << st.st_mtime
                   << " executables=" << my_fts_executable
                   << " debuginfos=" << my_fts_debuginfo
                   << " srefs=" << my_fts_sref
                   << " sdefs=" << my_fts_sdef
                   << endl;

  fts_executable += my_fts_executable;
  fts_debuginfo += my_fts_debuginfo;
  fts_sref += my_fts_sref;
  fts_sdef += my_fts_sdef;

  if (my_fts_sref_complete_p) // leave incomplete?
    ps_scan_done
      .reset()
      .bind(1, rps)
      .bind(2, st.st_mtime)
      .bind(3, st.st_size)
      .step_ok_done();
}



////////////////////////////////////////////////////////////////////////



// The thread that consumes file names off of the scanq.  We hold
// the persistent sqlite_ps's at this level and delegate file/archive
// scanning to other functions.
static void*
thread_main_scanner (void* arg)
{
  (void) arg;

  // all the prepared statements fit to use, the _f_ set:
  sqlite_ps ps_f_upsert_buildids (db, "file-buildids-intern", "insert or ignore into " BUILDIDS "_buildids VALUES (NULL, ?);");
  sqlite_ps ps_f_upsert_files (db, "file-files-intern", "insert or ignore into " BUILDIDS "_files VALUES (NULL, ?);");
  sqlite_ps ps_f_upsert_de (db, "file-de-upsert",
                          "insert or ignore into " BUILDIDS "_f_de "
                          "(buildid, debuginfo_p, executable_p, file, mtime) "
                          "values ((select id from " BUILDIDS "_buildids where hex = ?),"
                          "        ?,?,"
                          "        (select id from " BUILDIDS "_files where name = ?), ?);");
  sqlite_ps ps_f_upsert_s (db, "file-s-upsert",
                         "insert or ignore into " BUILDIDS "_f_s "
                         "(buildid, artifactsrc, file, mtime) "
                         "values ((select id from " BUILDIDS "_buildids where hex = ?),"
                         "        (select id from " BUILDIDS "_files where name = ?),"
                         "        (select id from " BUILDIDS "_files where name = ?),"
                         "        ?);");
  sqlite_ps ps_f_query (db, "file-negativehit-find",
                        "select 1 from " BUILDIDS "_file_mtime_scanned where sourcetype = 'F' "
                        "and file = (select id from " BUILDIDS "_files where name = ?) and mtime = ?;");
  sqlite_ps ps_f_scan_done (db, "file-scanned",
                          "insert or ignore into " BUILDIDS "_file_mtime_scanned (sourcetype, file, mtime, size)"
                          "values ('F', (select id from " BUILDIDS "_files where name = ?), ?, ?);");

  // and now for the _r_ set
  sqlite_ps ps_r_upsert_buildids (db, "rpm-buildid-intern", "insert or ignore into " BUILDIDS "_buildids VALUES (NULL, ?);");
  sqlite_ps ps_r_upsert_files (db, "rpm-file-intern", "insert or ignore into " BUILDIDS "_files VALUES (NULL, ?);");
  sqlite_ps ps_r_upsert_de (db, "rpm-de-insert",
                          "insert or ignore into " BUILDIDS "_r_de (buildid, debuginfo_p, executable_p, file, mtime, content) values ("
                          "(select id from " BUILDIDS "_buildids where hex = ?), ?, ?, "
                          "(select id from " BUILDIDS "_files where name = ?), ?, "
                          "(select id from " BUILDIDS "_files where name = ?));");
  sqlite_ps ps_r_upsert_sref (db, "rpm-sref-insert",
                            "insert or ignore into " BUILDIDS "_r_sref (buildid, artifactsrc) values ("
                            "(select id from " BUILDIDS "_buildids where hex = ?), "
                            "(select id from " BUILDIDS "_files where name = ?));");
  sqlite_ps ps_r_upsert_sdef (db, "rpm-sdef-insert",
                            "insert or ignore into " BUILDIDS "_r_sdef (file, mtime, content) values ("
                            "(select id from " BUILDIDS "_files where name = ?), ?,"
                            "(select id from " BUILDIDS "_files where name = ?));");
  sqlite_ps ps_r_query (db, "rpm-negativehit-query",
                      "select 1 from " BUILDIDS "_file_mtime_scanned where "
                      "sourcetype = 'R' and file = (select id from " BUILDIDS "_files where name = ?) and mtime = ?;");
  sqlite_ps ps_r_scan_done (db, "rpm-scanned",
                          "insert or ignore into " BUILDIDS "_file_mtime_scanned (sourcetype, file, mtime, size)"
                          "values ('R', (select id from " BUILDIDS "_files where name = ?), ?, ?);");


  unsigned fts_cached = 0, fts_executable = 0, fts_debuginfo = 0, fts_sourcefiles = 0;
  unsigned fts_sref = 0, fts_sdef = 0;

  add_metric("thread_count", "role", "scan", 1);
  add_metric("thread_busy", "role", "scan", 1);
  while (! interrupted)
    {
      scan_payload p;

      add_metric("thread_busy", "role", "scan", -1);
      bool gotone = scanq.wait_front(p);
      add_metric("thread_busy", "role", "scan", 1);
      if (! gotone) continue; // or break

      try
        {
          bool scan_archive = false;
          for (auto&& arch : scan_archives)
            if (string_endswith(p.first, arch.first))
              scan_archive = true;

          if (scan_archive)
            scan_archive_file (p.first, p.second,
                               ps_r_upsert_buildids,
                               ps_r_upsert_files,
                               ps_r_upsert_de,
                               ps_r_upsert_sref,
                               ps_r_upsert_sdef,
                               ps_r_query,
                               ps_r_scan_done,
                               fts_cached,
                               fts_executable,
                               fts_debuginfo,
                               fts_sref,
                               fts_sdef);

          if (scan_files) // NB: maybe "else if" ?
            scan_source_file (p.first, p.second,
                              ps_f_upsert_buildids,
                              ps_f_upsert_files,
                              ps_f_upsert_de,
                              ps_f_upsert_s,
                              ps_f_query,
                              ps_f_scan_done,
                              fts_cached, fts_executable, fts_debuginfo, fts_sourcefiles);
        }
      catch (const reportable_exception& e)
        {
          e.report(cerr);
        }

      inc_metric("thread_work_total", "role","scan");
    }

  add_metric("thread_busy", "role", "scan", -1);
  return 0;
}



// The thread that traverses all the source_paths and enqueues all the
// matching files into the file/archive scan queue.
static void
scan_source_paths()
{
  // NB: fedora 31 glibc/fts(3) crashes inside fts_read() on empty
  // path list.
  if (source_paths.empty())
    return;

  // Turn the source_paths into an fts(3)-compatible char**.  Since
  // source_paths[] does not change after argv processing, the
  // c_str()'s are safe to keep around awile.
  vector<const char *> sps;
  for (auto&& sp: source_paths)
    sps.push_back(sp.c_str());
  sps.push_back(NULL);

  FTS *fts = fts_open ((char * const *)sps.data(),
                      (traverse_logical ? FTS_LOGICAL : FTS_PHYSICAL|FTS_XDEV)
                      | FTS_NOCHDIR /* multithreaded */,
                      NULL);
  if (fts == NULL)
    throw libc_exception(errno, "cannot fts_open");
  defer_dtor<FTS*,int> fts_cleanup (fts, fts_close);

  struct timeval tv_start, tv_end;
  gettimeofday (&tv_start, NULL);
  unsigned fts_scanned = 0, fts_regex = 0;

  FTSENT *f;
  while ((f = fts_read (fts)) != NULL)
  {
    if (interrupted) break;

    fts_scanned ++;

    if (verbose > 2)
      obatched(clog) << "fts traversing " << f->fts_path << endl;

    /* Found a file.  Convert it to an absolute path, so
       the buildid database does not have relative path
       names that are unresolvable from a subsequent run
       in a different cwd. */
    char *rp = realpath(f->fts_path, NULL);
    if (rp == NULL)
      continue; // ignore dangling symlink or such
    string rps = string(rp);
    free (rp);

    bool ri = !regexec (&file_include_regex, rps.c_str(), 0, 0, 0);
    bool rx = !regexec (&file_exclude_regex, rps.c_str(), 0, 0, 0);
    if (!ri || rx)
      {
        if (verbose > 3)
          obatched(clog) << "fts skipped by regex " << (!ri ? "I" : "") << (rx ? "X" : "") << endl;
        fts_regex ++;
        continue;
      }

    switch (f->fts_info)
      {
      case FTS_F:
        scanq.push_back (make_pair(rps, *f->fts_statp));
        break;

      case FTS_ERR:
      case FTS_NS:
        // report on some types of errors because they may reflect fixable misconfiguration
        {
          auto x = libc_exception(f->fts_errno, string("fts traversal ") + string(f->fts_path));
          x.report(cerr);
        }
        break;

      default:
        ;
        /* ignore */
      }
  }
  gettimeofday (&tv_end, NULL);
  double deltas = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec)*0.000001;

  obatched(clog) << "fts traversed source paths in " << deltas << "s, scanned=" << fts_scanned
                 << ", regex-skipped=" << fts_regex << endl;
}


static void*
thread_main_fts_source_paths (void* arg)
{
  (void) arg; // ignore; we operate on global data

  sig_atomic_t forced_rescan_count = 0;
  set_metric("thread_tid", "role","traverse", tid());
  add_metric("thread_count", "role", "traverse", 1);

  time_t last_rescan = 0;

  while (! interrupted)
    {
      sleep (1);
      scanq.wait_idle(); // don't start a new traversal while scanners haven't finished the job
      scanq.done_idle(); // release the hounds
      if (interrupted) break;

      time_t now = time(NULL);
      bool rescan_now = false;
      if (last_rescan == 0) // at least one initial rescan is documented even for -t0
        rescan_now = true;
      if (rescan_s > 0 && (long)now > (long)(last_rescan + rescan_s))
        rescan_now = true;
      if (sigusr1 != forced_rescan_count)
        {
          forced_rescan_count = sigusr1;
          rescan_now = true;
        }
      if (rescan_now)
        try
          {
            set_metric("thread_busy", "role","traverse", 1);
            scan_source_paths();
            last_rescan = time(NULL); // NB: now was before scanning
            inc_metric("thread_work_total", "role","traverse");
            set_metric("thread_busy", "role","traverse", 0);
          }
        catch (const reportable_exception& e)
          {
            e.report(cerr);
          }
    }

  return 0;
}



////////////////////////////////////////////////////////////////////////

static void
database_stats_report()
{
  sqlite_ps ps_query (db, "database-overview",
                      "select label,quantity from " BUILDIDS "_stats");

  obatched(clog) << "database record counts:" << endl;
  while (1)
    {
      int rc = sqlite3_step (ps_query);
      if (rc == SQLITE_DONE) break;
      if (rc != SQLITE_ROW)
        throw sqlite_exception(rc, "step");

      obatched(clog)
        << right << setw(20) << ((const char*) sqlite3_column_text(ps_query, 0) ?: (const char*) "NULL")
        << " "
        << (sqlite3_column_text(ps_query, 1) ?: (const unsigned char*) "NULL")
        << endl;

      set_metric("groom", "statistic",
                 ((const char*) sqlite3_column_text(ps_query, 0) ?: (const char*) "NULL"),
                 (sqlite3_column_double(ps_query, 1)));
    }
}


// Do a round of database grooming that might take many minutes to run.
void groom()
{
  obatched(clog) << "grooming database" << endl;

  struct timeval tv_start, tv_end;
  gettimeofday (&tv_start, NULL);

  // scan for files that have disappeared
  sqlite_ps files (db, "check old files", "select s.mtime, s.file, f.name from "
                       BUILDIDS "_file_mtime_scanned s, " BUILDIDS "_files f "
                       "where f.id = s.file");
  sqlite_ps files_del_f_de (db, "nuke f_de", "delete from " BUILDIDS "_f_de where file = ? and mtime = ?");
  sqlite_ps files_del_r_de (db, "nuke r_de", "delete from " BUILDIDS "_r_de where file = ? and mtime = ?");
  sqlite_ps files_del_scan (db, "nuke f_m_s", "delete from " BUILDIDS "_file_mtime_scanned "
                            "where file = ? and mtime = ?");
  files.reset();
  while(1)
    {
      int rc = files.step();
      if (rc != SQLITE_ROW)
        break;

      int64_t mtime = sqlite3_column_int64 (files, 0);
      int64_t fileid = sqlite3_column_int64 (files, 1);
      const char* filename = ((const char*) sqlite3_column_text (files, 2) ?: "");
      struct stat s;
      rc = stat(filename, &s);
      if (rc < 0 || (mtime != (int64_t) s.st_mtime))
        {
          if (verbose > 2)
            obatched(clog) << "groom: forgetting file=" << filename << " mtime=" << mtime << endl;
          files_del_f_de.reset().bind(1,fileid).bind(2,mtime).step_ok_done();
          files_del_r_de.reset().bind(1,fileid).bind(2,mtime).step_ok_done();
          files_del_scan.reset().bind(1,fileid).bind(2,mtime).step_ok_done();
        }
    }
  files.reset();

  // delete buildids with no references in _r_de or _f_de tables;
  // cascades to _r_sref & _f_s records
  sqlite_ps buildids_del (db, "nuke orphan buildids",
                          "delete from " BUILDIDS "_buildids "
                          "where not exists (select 1 from " BUILDIDS "_f_de d where " BUILDIDS "_buildids.id = d.buildid) "
                          "and not exists (select 1 from " BUILDIDS "_r_de d where " BUILDIDS "_buildids.id = d.buildid)");
  buildids_del.reset().step_ok_done();

  // NB: "vacuum" is too heavy for even daily runs: it rewrites the entire db, so is done as maxigroom -G
  sqlite_ps g1 (db, "incremental vacuum", "pragma incremental_vacuum");
  g1.reset().step_ok_done();
  sqlite_ps g2 (db, "optimize", "pragma optimize");
  g2.reset().step_ok_done();
  sqlite_ps g3 (db, "wal checkpoint", "pragma wal_checkpoint=truncate");
  g3.reset().step_ok_done();

  database_stats_report();

  sqlite3_db_release_memory(db); // shrink the process if possible

  fdcache.limit(0,0); // release the fdcache contents
  fdcache.limit(fdcache_fds,fdcache_mbs); // restore status quo parameters

  gettimeofday (&tv_end, NULL);
  double deltas = (tv_end.tv_sec - tv_start.tv_sec) + (tv_end.tv_usec - tv_start.tv_usec)*0.000001;

  obatched(clog) << "groomed database in " << deltas << "s" << endl;
}


static void*
thread_main_groom (void* /*arg*/)
{
  sig_atomic_t forced_groom_count = 0;
  set_metric("thread_tid", "role", "groom", tid());
  add_metric("thread_count", "role", "groom", 1);

  time_t last_groom = 0;

  while (1)
    {
      sleep (1);
      scanq.wait_idle(); // PR25394: block scanners during grooming!
      if (interrupted) break;

      time_t now = time(NULL);
      bool groom_now = false;
      if (last_groom == 0) // at least one initial groom is documented even for -g0
        groom_now = true;
      if (groom_s > 0 && (long)now > (long)(last_groom + groom_s))
        groom_now = true;
      if (sigusr2 != forced_groom_count)
        {
          forced_groom_count = sigusr2;
          groom_now = true;
        }
      if (groom_now)
        try
          {
            set_metric("thread_busy", "role", "groom", 1);
            groom ();
            last_groom = time(NULL); // NB: now was before grooming
            inc_metric("thread_work_total", "role", "groom");
            set_metric("thread_busy", "role", "groom", 0);
          }
        catch (const sqlite_exception& e)
          {
            obatched(cerr) << e.message << endl;
          }

      scanq.done_idle();
    }

  return 0;
}


////////////////////////////////////////////////////////////////////////


static void
signal_handler (int /* sig */)
{
  interrupted ++;

  if (db)
    sqlite3_interrupt (db);

  // NB: don't do anything else in here
}

static void
sigusr1_handler (int /* sig */)
{
   sigusr1 ++;
  // NB: don't do anything else in here
}

static void
sigusr2_handler (int /* sig */)
{
   sigusr2 ++;
  // NB: don't do anything else in here
}





// A user-defined sqlite function, to score the sharedness of the
// prefix of two strings.  This is used to compare candidate debuginfo
// / source-rpm names, so that the closest match
// (directory-topology-wise closest) is found.  This is important in
// case the same sref (source file name) is in many -debuginfo or
// -debugsource RPMs, such as when multiple versions/releases of the
// same package are in the database.

static void sqlite3_sharedprefix_fn (sqlite3_context* c, int argc, sqlite3_value** argv)
{
  if (argc != 2)
    sqlite3_result_error(c, "expect 2 string arguments", -1);
  else if ((sqlite3_value_type(argv[0]) != SQLITE_TEXT) ||
           (sqlite3_value_type(argv[1]) != SQLITE_TEXT))
    sqlite3_result_null(c);
  else
    {
      const unsigned char* a = sqlite3_value_text (argv[0]);
      const unsigned char* b = sqlite3_value_text (argv[1]);
      int i = 0;
      while (*a++ == *b++)
        i++;
      sqlite3_result_int (c, i);
    }
}


int
main (int argc, char *argv[])
{
  (void) setlocale (LC_ALL, "");
  (void) bindtextdomain (PACKAGE_TARNAME, LOCALEDIR);
  (void) textdomain (PACKAGE_TARNAME);

  /* Tell the library which version we are expecting.  */
  elf_version (EV_CURRENT);

  tmpdir = string(getenv("TMPDIR") ?: "/tmp");

  /* Set computed default values. */
  db_path = string(getenv("HOME") ?: "/") + string("/.debuginfod.sqlite"); /* XDG? */
  int rc = regcomp (& file_include_regex, ".*", REG_EXTENDED|REG_NOSUB); // match everything
  if (rc != 0)
    error (EXIT_FAILURE, 0, "regcomp failure: %d", rc);
  rc = regcomp (& file_exclude_regex, "^$", REG_EXTENDED|REG_NOSUB); // match nothing
  if (rc != 0)
    error (EXIT_FAILURE, 0, "regcomp failure: %d", rc);

  // default parameters for fdcache are computed from system stats
  struct statfs sfs;
  rc = statfs(tmpdir.c_str(), &sfs);
  if (rc < 0)
    fdcache_mbs = 1024; // 1 gigabyte
  else
    fdcache_mbs = sfs.f_bavail * sfs.f_bsize / 1024 / 1024 / 4; // 25% of free space
  fdcache_prefetch = 64; // guesstimate storage is this much less costly than re-decompression
  fdcache_fds = (concurrency + fdcache_prefetch) * 2;

  /* Parse and process arguments.  */
  int remaining;
  argp_program_version_hook = print_version; // this works
  (void) argp_parse (&argp, argc, argv, ARGP_IN_ORDER, &remaining, NULL);
  if (remaining != argc)
      error (EXIT_FAILURE, 0,
             "unexpected argument: %s", argv[remaining]);

  if (scan_archives.size()==0 && !scan_files && source_paths.size()>0)
    obatched(clog) << "warning: without -F -R -U -Z, ignoring PATHs" << endl;

  fdcache.limit(fdcache_fds, fdcache_mbs);

  (void) signal (SIGPIPE, SIG_IGN); // microhttpd can generate it incidentally, ignore
  (void) signal (SIGINT, signal_handler); // ^C
  (void) signal (SIGHUP, signal_handler); // EOF
  (void) signal (SIGTERM, signal_handler); // systemd
  (void) signal (SIGUSR1, sigusr1_handler); // end-user
  (void) signal (SIGUSR2, sigusr2_handler); // end-user

  /* Get database ready. */
  rc = sqlite3_open_v2 (db_path.c_str(), &db, (SQLITE_OPEN_READWRITE
                                               |SQLITE_OPEN_CREATE
                                               |SQLITE_OPEN_FULLMUTEX), /* thread-safe */
                        NULL);
  if (rc == SQLITE_CORRUPT)
    {
      (void) unlink (db_path.c_str());
      error (EXIT_FAILURE, 0,
             "cannot open %s, deleted database: %s", db_path.c_str(), sqlite3_errmsg(db));
    }
  else if (rc)
    {
      error (EXIT_FAILURE, 0,
             "cannot open %s, consider deleting database: %s", db_path.c_str(), sqlite3_errmsg(db));
    }

  obatched(clog) << "opened database " << db_path << endl;
  obatched(clog) << "sqlite version " << sqlite3_version << endl;

  // add special string-prefix-similarity function used in rpm sref/sdef resolution
  rc = sqlite3_create_function(db, "sharedprefix", 2, SQLITE_UTF8, NULL,
                               & sqlite3_sharedprefix_fn, NULL, NULL);
  if (rc != SQLITE_OK)
    error (EXIT_FAILURE, 0,
           "cannot create sharedprefix( function: %s", sqlite3_errmsg(db));

  if (verbose > 3)
    obatched(clog) << "ddl: " << DEBUGINFOD_SQLITE_DDL << endl;
  rc = sqlite3_exec (db, DEBUGINFOD_SQLITE_DDL, NULL, NULL, NULL);
  if (rc != SQLITE_OK)
    {
      error (EXIT_FAILURE, 0,
             "cannot run database schema ddl: %s", sqlite3_errmsg(db));
    }

  // Start httpd server threads.  Separate pool for IPv4 and IPv6, in
  // case the host only has one protocol stack.
  MHD_Daemon *d4 = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION
#if MHD_VERSION >= 0x00095300
                                     | MHD_USE_INTERNAL_POLLING_THREAD
#else
                                     | MHD_USE_SELECT_INTERNALLY
#endif
                                     | MHD_USE_DEBUG, /* report errors to stderr */
                                     http_port,
                                     NULL, NULL, /* default accept policy */
                                     handler_cb, NULL, /* handler callback */
                                     MHD_OPTION_END);
  MHD_Daemon *d6 = MHD_start_daemon (MHD_USE_THREAD_PER_CONNECTION
#if MHD_VERSION >= 0x00095300
                                     | MHD_USE_INTERNAL_POLLING_THREAD
#else
                                     | MHD_USE_SELECT_INTERNALLY
#endif
                                     | MHD_USE_IPv6
                                     | MHD_USE_DEBUG, /* report errors to stderr */
                                     http_port,
                                     NULL, NULL, /* default accept policy */
                                     handler_cb, NULL, /* handler callback */
                                     MHD_OPTION_END);

  if (d4 == NULL && d6 == NULL) // neither ipv4 nor ipv6? boo
    {
      sqlite3 *database = db;
      db = 0; // for signal_handler not to freak
      sqlite3_close (database);
      error (EXIT_FAILURE, 0, "cannot start http server at port %d", http_port);
    }

  obatched(clog) << "started http server on "
                 << (d4 != NULL ? "IPv4 " : "")
                 << (d6 != NULL ? "IPv6 " : "")
                 << "port=" << http_port << endl;

  // add maxigroom sql if -G given
  if (maxigroom)
    {
      obatched(clog) << "maxigrooming database, please wait." << endl;
      extra_ddl.push_back("create index if not exists " BUILDIDS "_r_sref_arc on " BUILDIDS "_r_sref(artifactsrc);");
      extra_ddl.push_back("delete from " BUILDIDS "_r_sdef where not exists (select 1 from " BUILDIDS "_r_sref b where " BUILDIDS "_r_sdef.content = b.artifactsrc);");
      extra_ddl.push_back("drop index if exists " BUILDIDS "_r_sref_arc;");

      // NB: we don't maxigroom the _files interning table.  It'd require a temp index on all the
      // tables that have file foreign-keys, which is a lot.

      // NB: with =delete, may take up 3x disk space total during vacuum process
      //     vs.  =off (only 2x but may corrupt database if program dies mid-vacuum)
      //     vs.  =wal (>3x observed, but safe)
      extra_ddl.push_back("pragma journal_mode=delete;");
      extra_ddl.push_back("vacuum;");
      extra_ddl.push_back("pragma journal_mode=wal;");
    }

  // run extra -D sql if given
  for (auto&& i: extra_ddl)
    {
      if (verbose > 1)
        obatched(clog) << "extra ddl:\n" << i << endl;
      rc = sqlite3_exec (db, i.c_str(), NULL, NULL, NULL);
      if (rc != SQLITE_OK && rc != SQLITE_DONE && rc != SQLITE_ROW)
        error (0, 0,
               "warning: cannot run database extra ddl %s: %s", i.c_str(), sqlite3_errmsg(db));
    }

  if (maxigroom)
    obatched(clog) << "maxigroomed database" << endl;

  obatched(clog) << "search concurrency " << concurrency << endl;
  obatched(clog) << "rescan time " << rescan_s << endl;
  obatched(clog) << "fdcache fds " << fdcache_fds << endl;
  obatched(clog) << "fdcache mbs " << fdcache_mbs << endl;
  obatched(clog) << "fdcache prefetch " << fdcache_prefetch << endl;
  obatched(clog) << "fdcache tmpdir " << tmpdir << endl;
  obatched(clog) << "groom time " << groom_s << endl;
  if (scan_archives.size()>0)
    {
      obatched ob(clog);
      auto& o = ob << "scanning archive types ";
      for (auto&& arch : scan_archives)
	o << arch.first << "(" << arch.second << ") ";
      o << endl;
    }
  const char* du = getenv(DEBUGINFOD_URLS_ENV_VAR);
  if (du && du[0] != '\0') // set to non-empty string?
    obatched(clog) << "upstream debuginfod servers: " << du << endl;

  vector<pthread_t> all_threads;

  pthread_t pt;
  rc = pthread_create (& pt, NULL, thread_main_groom, NULL);
  if (rc < 0)
    error (0, 0, "warning: cannot spawn thread (%d) to groom database\n", rc);
  else
    all_threads.push_back(pt);

  if (scan_files || scan_archives.size() > 0)
    {
      pthread_create (& pt, NULL, thread_main_fts_source_paths, NULL);
      if (rc < 0)
        error (0, 0, "warning: cannot spawn thread (%d) to traverse source paths\n", rc);
      all_threads.push_back(pt);
      for (unsigned i=0; i<concurrency; i++)
        {
          pthread_create (& pt, NULL, thread_main_scanner, NULL);
          if (rc < 0)
            error (0, 0, "warning: cannot spawn thread (%d) to scan source files / archives\n", rc);
          all_threads.push_back(pt);
        }
    }

  /* Trivial main loop! */
  set_metric("ready", 1);
  while (! interrupted)
    pause ();
  scanq.nuke(); // wake up any remaining scanq-related threads, let them die
  set_metric("ready", 0);

  if (verbose)
    obatched(clog) << "stopping" << endl;

  /* Join all our threads. */
  for (auto&& it : all_threads)
    pthread_join (it, NULL);

  /* Stop all the web service threads. */
  if (d4) MHD_stop_daemon (d4);
  if (d6) MHD_stop_daemon (d6);

  /* With all threads known dead, we can clean up the global resources. */
  rc = sqlite3_exec (db, DEBUGINFOD_SQLITE_CLEANUP_DDL, NULL, NULL, NULL);
  if (rc != SQLITE_OK)
    {
      error (0, 0,
             "warning: cannot run database cleanup ddl: %s", sqlite3_errmsg(db));
    }

  // NB: no problem with unconditional free here - an earlier failed regcomp would exit program
  (void) regfree (& file_include_regex);
  (void) regfree (& file_exclude_regex);

  sqlite3 *database = db;
  db = 0; // for signal_handler not to freak
  (void) sqlite3_close (database);

  return 0;
}
