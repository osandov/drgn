#!/bin/bash

: ${PYTHON:=python3}
cscope_args=(-bq -i-)

python_include="$("$PYTHON" -c 'import sysconfig; print(sysconfig.get_path("include"))' 2>/dev/null)"
if [[ -n $python_include ]] ; then
	cscope_args+=("-I$python_include")
fi
python_platinclude="$("$PYTHON" -c 'import sysconfig; print(sysconfig.get_path("platinclude"))' 2>/dev/null)"
if [[ -n $python_platinclude && $python_platinclude != $python_include ]] ; then
	cscope_args+=("-I$python_platinclude")
fi

find libdrgn -name '*.[ch]' -o -name '*.[ch].in' | cscope "${cscope_args[@]}"
