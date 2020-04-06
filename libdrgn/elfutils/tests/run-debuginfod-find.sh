#!/bin/bash
#
# Copyright (C) 2019-2020 Red Hat, Inc.
# This file is part of elfutils.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# elfutils is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

. $srcdir/test-subr.sh  # includes set -e

type curl 2>/dev/null || (echo "need curl"; exit 77)
type rpm2cpio 2>/dev/null || (echo "need rpm2cpio"; exit 77)
type bzcat 2>/dev/null || (echo "need bzcat"; exit 77)
bsdtar --version | grep -q zstd && zstd=true || zstd=false
echo "zstd=$zstd bsdtar=`bsdtar --version`"

# for test case debugging, uncomment:
#set -x
#VERBOSE=-vvvv

DB=${PWD}/.debuginfod_tmp.sqlite
tempfiles $DB
export DEBUGINFOD_CACHE_PATH=${PWD}/.client_cache

PID1=0
PID2=0
PID3=0

cleanup()
{
  if [ $PID1 -ne 0 ]; then kill $PID1; wait $PID1; fi
  if [ $PID2 -ne 0 ]; then kill $PID2; wait $PID2; fi
  if [ $PID3 -ne 0 ]; then kill $PID3; wait $PID3; fi

  rm -rf F R D L Z ${PWD}/foobar ${PWD}/mocktree ${PWD}/.client_cache* ${PWD}/tmp*
  exit_cleanup
}

# clean up trash if we were aborted early
trap cleanup 0 1 2 3 5 9 15

# find an unused port number
while true; do
    PORT1=`expr '(' $RANDOM % 1000 ')' + 9000`
    ss -atn | fgrep ":$PORT1" || break
done    

# We want to run debuginfod in the background.  We also want to start
# it with the same check/installcheck-sensitive LD_LIBRARY_PATH stuff
# that the testrun alias sets.  But: we if we just use
#    testrun .../debuginfod
# it runs in a subshell, with different pid, so not helpful.
#
# So we gather the LD_LIBRARY_PATH with this cunning trick:
ldpath=`testrun sh -c 'echo $LD_LIBRARY_PATH'`

mkdir F R L D Z
# not tempfiles F R L D Z - they are directories which we clean up manually
ln -s ${abs_builddir}/dwfllines L/foo   # any program not used elsewhere in this test

wait_ready()
{
  port=$1;
  what=$2;
  value=$3;
  timeout=20;

  echo "Wait $timeout seconds on $port for metric $what to change to $value"
  while [ $timeout -gt 0 ]; do
    mvalue="$(curl -s http://127.0.0.1:$port/metrics \
              | grep "$what" | awk '{print $NF}')"
    if [ -z "$mvalue" ]; then mvalue=0; fi
      echo "metric $what: $mvalue"
      if [ "$mvalue" -eq "$value" ]; then
        break;
    fi
    sleep 0.5;
    ((timeout--));
  done;

  if [ $timeout -eq 0 ]; then
      echo "metric $what never changed to $value on port $port"
      curl -s http://127.0.0.1:$port/metrics
    exit 1;
  fi
}

env LD_LIBRARY_PATH=$ldpath DEBUGINFOD_URLS= ${abs_builddir}/../debuginfod/debuginfod $VERBOSE -F -R -d $DB -p $PORT1 -t0 -g0 --fdcache-fds 1 --fdcache-mbs 2 -Z .tar.xz -Z .tar.bz2=bzcat -v R F Z L > vlog4 2>&1 &
PID1=$!
tempfiles vlog4
# Server must become ready
wait_ready $PORT1 'ready' 1
export DEBUGINFOD_URLS=http://127.0.0.1:$PORT1/   # or without trailing /

# Be patient when run on a busy machine things might take a bit.
export DEBUGINFOD_TIMEOUT=10

# We use -t0 and -g0 here to turn off time-based scanning & grooming.
# For testing purposes, we just sic SIGUSR1 / SIGUSR2 at the process.

########################################################################

# Compile a simple program, strip its debuginfo and save the build-id.
# Also move the debuginfo into another directory so that elfutils
# cannot find it without debuginfod.
echo "int main() { return 0; }" > ${PWD}/prog.c
tempfiles prog.c
# Create a subdirectory to confound source path names
mkdir foobar
gcc -Wl,--build-id -g -o prog ${PWD}/foobar///./../prog.c
testrun ${abs_top_builddir}/src/strip -g -f prog.debug ${PWD}/prog
BUILDID=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
          -a prog | grep 'Build ID' | cut -d ' ' -f 7`

wait_ready $PORT1 'thread_work_total{role="traverse"}' 1
mv prog F
mv prog.debug F
kill -USR1 $PID1
# Wait till both files are in the index.
wait_ready $PORT1 'thread_work_total{role="traverse"}' 2
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0

########################################################################

# Test whether elfutils, via the debuginfod client library dlopen hooks,
# is able to fetch debuginfo from the local debuginfod.
testrun ${abs_builddir}/debuginfod_build_id_find -e F/prog 1

########################################################################

# Test whether debuginfod-find is able to fetch those files.
rm -rf $DEBUGINFOD_CACHE_PATH # clean it from previous tests
filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID`
cmp $filename F/prog.debug

filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find executable F/prog`
cmp $filename F/prog

# raw source filename
filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find source $BUILDID ${PWD}/foobar///./../prog.c`
cmp $filename  ${PWD}/prog.c

# and also the canonicalized one
filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find source $BUILDID ${PWD}/prog.c`
cmp $filename  ${PWD}/prog.c


########################################################################

# Test whether the cache default locations are correct

mkdir tmphome

# $HOME/.cache should be created.
testrun env HOME=$PWD/tmphome XDG_CACHE_HOME= DEBUGINFOD_CACHE_PATH= ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
if [ ! -f $PWD/tmphome/.cache/debuginfod_client/$BUILDID/debuginfo ]; then
  echo "could not find cache in $PWD/tmphome/.cache"
  exit 1
fi

# $HOME/.cache should be found.
testrun env HOME=$PWD/tmphome XDG_CACHE_HOME= DEBUGINFOD_CACHE_PATH= ${abs_top_builddir}/debuginfod/debuginfod-find executable $BUILDID
if [ ! -f $PWD/tmphome/.cache/debuginfod_client/$BUILDID/executable ]; then
  echo "could not find cache in $PWD/tmphome/.cache"
  exit 1
fi

# $XDG_CACHE_HOME should take priority over $HOME.cache.
testrun env HOME=$PWD/tmphome XDG_CACHE_HOME=$PWD/tmpxdg DEBUGINFOD_CACHE_PATH= ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
if [ ! -f $PWD/tmpxdg/debuginfod_client/$BUILDID/debuginfo ]; then
  echo "could not find cache in $PWD/tmpxdg/"
  exit 1
fi

# A cache at the old default location ($HOME/.debuginfod_client_cache) should take
# priority over $HOME/.cache, $XDG_CACHE_HOME.
cp -r $DEBUGINFOD_CACHE_PATH tmphome/.debuginfod_client_cache

# Add a file that doesn't exist in $HOME/.cache, $XDG_CACHE_HOME.
mkdir tmphome/.debuginfod_client_cache/deadbeef
echo ELF... > tmphome/.debuginfod_client_cache/deadbeef/debuginfo
filename=`testrun env HOME=$PWD/tmphome XDG_CACHE_HOME=$PWD/tmpxdg DEBUGINFOD_CACHE_PATH= ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo deadbeef`
cmp $filename tmphome/.debuginfod_client_cache/deadbeef/debuginfo

# $DEBUGINFO_CACHE_PATH should take priority over all else.
testrun env HOME=$PWD/tmphome XDG_CACHE_HOME=$PWD/tmpxdg DEBUGINFOD_CACHE_PATH=$PWD/tmpcache ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID
if [ ! -f $PWD/tmpcache/$BUILDID/debuginfo ]; then
  echo "could not find cache in $PWD/tmpcache/"
  exit 1
fi

########################################################################

# Add artifacts to the search paths and test whether debuginfod finds them while already running.

# Build another, non-stripped binary
echo "int main() { return 0; }" > ${PWD}/prog2.c
tempfiles prog2.c
gcc -Wl,--build-id -g -o prog2 ${PWD}/prog2.c
BUILDID2=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
          -a prog2 | grep 'Build ID' | cut -d ' ' -f 7`

mv prog2 F
kill -USR1 $PID1
# Now there should be 3 files in the index
wait_ready $PORT1 'thread_work_total{role="traverse"}' 3
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0

# Rerun same tests for the prog2 binary
filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find -v debuginfo $BUILDID2 2>vlog`
cmp $filename F/prog2
cat vlog
grep -q Progress vlog
grep -q Downloaded.from vlog
tempfiles vlog
filename=`testrun env DEBUGINFOD_PROGRESS=1 ${abs_top_builddir}/debuginfod/debuginfod-find executable $BUILDID2 2>vlog2`
cmp $filename F/prog2
cat vlog2
grep -q 'Downloading.*http' vlog2
tempfiles vlog2
filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find source $BUILDID2 ${PWD}/prog2.c`
cmp $filename ${PWD}/prog2.c

cp -rvp ${abs_srcdir}/debuginfod-rpms R
if [ "$zstd" = "false" ]; then  # nuke the zstd fedora 31 ones
    rm -vrf R/debuginfod-rpms/fedora31
fi

cp -rvp ${abs_srcdir}/debuginfod-tars Z
kill -USR1 $PID1
# All rpms need to be in the index
rpms=$(find R -name \*rpm | wc -l)
wait_ready $PORT1 'scanned_total{source=".rpm archive"}' $rpms
txz=$(find Z -name \*tar.xz | wc -l)
wait_ready $PORT1 'scanned_total{source=".tar.xz archive"}' $txz
tb2=$(find Z -name \*tar.bz2 | wc -l)
wait_ready $PORT1 'scanned_total{source=".tar.bz2 archive"}' $tb2

kill -USR1 $PID1  # two hits of SIGUSR1 may be needed to resolve .debug->dwz->srefs
# Expect all source files found in the rpms (they are all called hello.c :)
# We will need to extract all rpms (in their own directory) and could all
# sources referenced in the .debug files.
mkdir extracted
cd extracted
subdir=0;
newrpms=$(find ../R -name \*\.rpm)
for i in $newrpms; do
    subdir=$[$subdir+1];
    mkdir $subdir;
    cd $subdir;
    ls -lah ../$i
    rpm2cpio ../$i | cpio -ivd;
    cd ..;
done
sourcefiles=$(find -name \*\\.debug \
	      | env LD_LIBRARY_PATH=$ldpath xargs \
		${abs_top_builddir}/src/readelf --debug-dump=decodedline \
	      | grep mtime: | wc --lines)
cd ..
rm -rf extracted

wait_ready $PORT1 'found_sourcerefs_total{source=".rpm archive"}' $sourcefiles

# Run a bank of queries against the debuginfod-rpms / debuginfod-debs test cases

archive_test() {
    __BUILDID=$1
    __SOURCEPATH=$2
    __SOURCESHA1=$3
    
    filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find executable $__BUILDID`
    buildid=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
             -a $filename | grep 'Build ID' | cut -d ' ' -f 7`
    test $__BUILDID = $buildid
    # check that timestamps are plausible - older than the near-present (tmpdir mtime)
    test $filename -ot `pwd`

    # run again to assure that fdcache is being enjoyed
    filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find executable $__BUILDID`
    buildid=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
             -a $filename | grep 'Build ID' | cut -d ' ' -f 7`
    test $__BUILDID = $buildid
    test $filename -ot `pwd`

    filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $__BUILDID`
    buildid=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
             -a $filename | grep 'Build ID' | cut -d ' ' -f 7`
    test $__BUILDID = $buildid
    test $filename -ot `pwd`

    if test "x$__SOURCEPATH" != "x"; then
        filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find source $__BUILDID $__SOURCEPATH`
        hash=`cat $filename | sha1sum | awk '{print $1}'`
        test $__SOURCESHA1 = $hash
        test $filename -ot `pwd`
    fi
}


# common source file sha1
SHA=f4a1a8062be998ae93b8f1cd744a398c6de6dbb1
# fedora31
if [ $zstd = true ]; then
    # fedora31 uses zstd compression on rpms, older rpm2cpio/libarchive can't handle it
    # and we're not using the fancy -Z '.rpm=(rpm2cpio|zstdcat)<' workaround in this testsuite
    archive_test 420e9e3308971f4b817cc5bf83928b41a6909d88 /usr/src/debug/hello3-1.0-2.x86_64/foobar////./../hello.c $SHA
    archive_test 87c08d12c78174f1082b7c888b3238219b0eb265 /usr/src/debug/hello3-1.0-2.x86_64///foobar/./..//hello.c $SHA
fi
# fedora30
archive_test c36708a78618d597dee15d0dc989f093ca5f9120 /usr/src/debug/hello2-1.0-2.x86_64/hello.c $SHA
archive_test 41a236eb667c362a1c4196018cc4581e09722b1b /usr/src/debug/hello2-1.0-2.x86_64/hello.c $SHA
# rhel7
archive_test bc1febfd03ca05e030f0d205f7659db29f8a4b30 /usr/src/debug/hello-1.0/hello.c $SHA
archive_test f0aa15b8aba4f3c28cac3c2a73801fefa644a9f2 /usr/src/debug/hello-1.0/hello.c $SHA
# rhel6
archive_test bbbf92ebee5228310e398609c23c2d7d53f6e2f9 /usr/src/debug/hello-1.0/hello.c $SHA
archive_test d44d42cbd7d915bc938c81333a21e355a6022fb7 /usr/src/debug/hello-1.0/hello.c $SHA
# arch
archive_test cee13b2ea505a7f37bd20d271c6bc7e5f8d2dfcb /usr/src/debug/hello.c 7a1334e086b97e5f124003a6cfb3ed792d10cdf4

RPM_BUILDID=d44d42cbd7d915bc938c81333a21e355a6022fb7 # in rhel6/ subdir, for a later test


########################################################################

# Drop some of the artifacts, run a groom cycle; confirm that
# debuginfod has forgotten them, but remembers others

rm -r R/debuginfod-rpms/rhel6/*
kill -USR2 $PID1  # groom cycle
# Expect 3 rpms to be deleted by the groom
# 1 groom already took place at/soon-after startup, so -USR2 makes 2
wait_ready $PORT1 'thread_work_total{role="groom"}' 2
wait_ready $PORT1 'groom{statistic="file d/e"}' 3

rm -rf $DEBUGINFOD_CACHE_PATH # clean it from previous tests

testrun ${abs_top_builddir}/debuginfod/debuginfod-find executable $RPM_BUILDID && false || true

testrun ${abs_top_builddir}/debuginfod/debuginfod-find executable $BUILDID2

########################################################################

# Federation mode

# find another unused port
while true; do
    PORT2=`expr '(' $RANDOM % 1000 ')' + 9000`
    ss -atn | fgrep ":$PORT2" || break
done

export DEBUGINFOD_CACHE_PATH=${PWD}/.client_cache2
mkdir -p $DEBUGINFOD_CACHE_PATH
# NB: inherits the DEBUGINFOD_URLS to the first server
# NB: run in -L symlink-following mode for the L subdir
env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../debuginfod/debuginfod $VERBOSE -F -U -d ${DB}_2 -p $PORT2 -L L D > vlog3 2>&1 &
PID2=$!
tempfiles vlog3
tempfiles ${DB}_2
wait_ready $PORT2 'ready' 1
wait_ready $PORT2 'thread_work_total{role="traverse"}' 1
wait_ready $PORT2 'thread_work_pending{role="scan"}' 0
wait_ready $PORT2 'thread_busy{role="scan"}' 0

# have clients contact the new server
export DEBUGINFOD_URLS=http://127.0.0.1:$PORT2

if type bsdtar 2>/dev/null; then
    # copy in the deb files
    cp -rvp ${abs_srcdir}/debuginfod-debs/*deb D
    kill -USR1 $PID2
    # All debs need to be in the index
    debs=$(find D -name \*.deb | wc -l)
    wait_ready $PORT2 'scanned_total{source=".deb archive"}' `expr $debs`
    ddebs=$(find D -name \*.ddeb | wc -l)
    wait_ready $PORT2 'scanned_total{source=".ddeb archive"}' `expr $ddebs`

    # ubuntu
    archive_test f17a29b5a25bd4960531d82aa6b07c8abe84fa66 "" ""
fi

rm -rf $DEBUGINFOD_CACHE_PATH
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID

# send a request to stress XFF and User-Agent federation relay;
# we'll grep for the two patterns in vlog4
curl -s -H 'User-Agent: TESTCURL' -H 'X-Forwarded-For: TESTXFF' $DEBUGINFOD_URLS/buildid/deaddeadbeef00000000/debuginfo -o /dev/null || true

grep UA:TESTCURL vlog4
grep XFF:TESTXFF vlog4


# confirm that first server can't resolve symlinked info in L/ but second can
BUILDID=`env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../src/readelf \
         -a L/foo | grep 'Build ID' | cut -d ' ' -f 7`
file L/foo
file -L L/foo
export DEBUGINFOD_URLS=http://127.0.0.1:$PORT1
rm -rf $DEBUGINFOD_CACHE_PATH
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID && false || true
export DEBUGINFOD_URLS=http://127.0.0.1:$PORT2
testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID


# test parallel queries in client
export DEBUGINFOD_CACHE_PATH=${PWD}/.client_cache3
mkdir -p $DEBUGINFOD_CACHE_PATH
export DEBUGINFOD_URLS="BAD http://127.0.0.1:$PORT1 127.0.0.1:$PORT1 http://127.0.0.1:$PORT2 DNE"

testrun ${abs_builddir}/debuginfod_build_id_find -e F/prog2 1

########################################################################

# Fetch some metrics
curl -s http://127.0.0.1:$PORT1/badapi
curl -s http://127.0.0.1:$PORT1/metrics
curl -s http://127.0.0.1:$PORT2/metrics
curl -s http://127.0.0.1:$PORT1/metrics | grep -q 'http_responses_total.*result.*error'
curl -s http://127.0.0.1:$PORT1/metrics | grep -q 'http_responses_total.*result.*fdcache'
curl -s http://127.0.0.1:$PORT2/metrics | grep -q 'http_responses_total.*result.*upstream'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_duration_milliseconds_count'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_duration_milliseconds_sum'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_transfer_bytes_count'
curl -s http://127.0.0.1:$PORT1/metrics | grep 'http_responses_transfer_bytes_sum'

# And generate a few errors into the second debuginfod's logs, for analysis just below
curl -s http://127.0.0.1:$PORT2/badapi > /dev/null || true
curl -s http://127.0.0.1:$PORT2/buildid/deadbeef/debuginfo > /dev/null || true


########################################################################

# Run the tests again without the servers running. The target file should
# be found in the cache.

kill -INT $PID1 $PID2
wait $PID1 $PID2
PID1=0
PID2=0
tempfiles .debuginfod_*

testrun ${abs_builddir}/debuginfod_build_id_find -e F/prog2 1

# check out the debuginfod logs for the new style status lines
# cat vlog3
grep -q 'UA:.*XFF:.*GET /buildid/.* 200 ' vlog3
grep -q 'UA:.*XFF:.*GET /metrics 200 ' vlog3
grep -q 'UA:.*XFF:.*GET /badapi 503 ' vlog3
grep -q 'UA:.*XFF:.*GET /buildid/deadbeef.* 404 ' vlog3

########################################################################

# Add some files to the cache that do not fit its naming format.
# They should survive cache cleaning.
mkdir $DEBUGINFOD_CACHE_PATH/malformed
touch $DEBUGINFOD_CACHE_PATH/malformed0
touch $DEBUGINFOD_CACHE_PATH/malformed/malformed1

# Trigger a cache clean and run the tests again. The clients should be unable to
# find the target.
echo 0 > $DEBUGINFOD_CACHE_PATH/cache_clean_interval_s
echo 0 > $DEBUGINFOD_CACHE_PATH/max_unused_age_s

testrun ${abs_builddir}/debuginfod_build_id_find -e F/prog 1

testrun ${abs_top_builddir}/debuginfod/debuginfod-find debuginfo $BUILDID2 && false || true

if [ ! -f $DEBUGINFOD_CACHE_PATH/malformed0 ] \
    || [ ! -f $DEBUGINFOD_CACHE_PATH/malformed/malformed1 ]; then
  echo "unrelated files did not survive cache cleaning"
  exit 1
fi

# Test debuginfod without a path list; reuse $PORT1
env LD_LIBRARY_PATH=$ldpath ${abs_builddir}/../debuginfod/debuginfod $VERBOSE -F -U -d :memory: -p $PORT1 -L -F &
PID3=$!
wait_ready $PORT1 'thread_work_total{role="traverse"}' 1
wait_ready $PORT1 'thread_work_pending{role="scan"}' 0
wait_ready $PORT1 'thread_busy{role="scan"}' 0
kill -int $PID3
wait $PID3
PID3=0

########################################################################
# Test fetching a file using file:// . No debuginfod server needs to be run for
# this test.
local_dir=${PWD}/mocktree/buildid/aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd/source/my/path
mkdir -p ${local_dir}
echo "int main() { return 0; }" > ${local_dir}/main.c

# first test that is doesn't work, when no DEBUGINFOD_URLS is set
DEBUGINFOD_URLS=""
testrun ${abs_top_builddir}/debuginfod/debuginfod-find source aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd /my/path/main.c && false || true

# Now test is with proper DEBUGINFOD_URLS
DEBUGINFOD_URLS="file://${PWD}/mocktree/"
filename=`testrun ${abs_top_builddir}/debuginfod/debuginfod-find source aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd /my/path/main.c`
cmp $filename ${local_dir}/main.c

exit 0
