Build Wheels
============

This directory contains scripts for creating manylinux wheels. The following are
required:

* docker
* curl
* bash

To build wheels:

    cd wheels  # your working directory MUST be wheels
    ./build_drgn.sh "36 37 38"

The above builds wheels for Python 3.6, 3.7, and 3.8. The quotes are required.
Resulting wheels will be placed in the current directory.

If your user account is not authorized to use Docker commands, but you have
sudo, you can use `DOCKER="sudo docker" ./build_drgn.sh ...` instead.
