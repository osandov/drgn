drgn VM Testing
===============

drgn is tested on multiple Linux kernel versions using QEMU. The tests are run
using an Arch Linux-based root filesystem image and a minimal kernel.

``scripts/vmtest/run.sh`` downloads the required testing files, sets up the
disk image for the virtual machine, and runs drgn tests in the virtual machine.

``scripts/vmtest/mkrootfs.sh`` builds the root filesystem image. It must be run
from an Arch Linux machine (or an Arch Linux chroot). The image contains the
dependencies for drgn and a BusyBox init setup. The setup allows ``run.sh`` to
simply copy in the source code and drop in a couple of init scripts to
automatically run tests on boot.

The root filesystem images and kernel builds are hosted on `Dropbox
<https://www.dropbox.com/sh/2mcf2xvg319qdaw/AAChpI5DJZX2VwlCgPFDdaZHa?dl=0>`_.
``scripts/vmtest/manage.py`` builds kernels and uploads files to this shared
folder using the Dropbox API. It also updates the ``INDEX`` file in that shared
folder, which is required because the files under a shared folder have
randomly-generated links.

``scripts/generate_travis_yml.py`` generates ``.travis.yml`` to test all
supported kernel versions (currently the mainline, stable, and longterm
releases from kernel.org).
