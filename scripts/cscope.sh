#!/bin/sh

find libdrgn -name '*.[ch]' -o -name '*.[ch].in' | cscope -bq -i-
