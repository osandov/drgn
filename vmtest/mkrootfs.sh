#!/bin/bash

# This script was inspired by https://github.com/pierres/genbootstrap, which is
# used to generate the official Arch Linux bootstrap images.

set -euo pipefail

usage () {
	USAGE_STRING="usage: $0 [NAME]
       $0 -h

Build an Arch Linux root filesystem image for testing drgn in a virtual
machine.

The image is generated as a zstd-compressed tarball.

This must be run as root, as most of the installation is done in a chroot.

Arguments:
  NAME   name of generated image file (default:
         drgn-vmtest-rootfs-\$DATE.tar.zst)

Options:
  -h     display this help message and exit"

	case "$1" in
		out)
			echo "$USAGE_STRING"
			exit 0
			;;
		err)
			echo "$USAGE_STRING" >&2
			exit 1
			;;
	esac
}

while getopts "h" OPT; do
	case "$OPT" in
		h)
			usage out
			;;
		*)
			usage err
			;;
	esac
done
if [[ $OPTIND -eq $# ]]; then
	NAME="${!OPTIND}"
elif [[ $OPTIND -gt $# ]]; then
	NAME="drgn-vmtest-rootfs-$(date +%Y.%m.%d).tar.zst"
else
	usage err
fi

pacman_conf=
root=
trap 'rm -rf "$pacman_conf" "$root"' EXIT
pacman_conf="$(mktemp -p "$PWD")"
cat > "$pacman_conf" << "EOF"
[options]
Architecture = auto
CheckSpace
SigLevel = Required DatabaseOptional
[core]
Include = /etc/pacman.d/mirrorlist
[extra]
Include = /etc/pacman.d/mirrorlist
[community]
Include = /etc/pacman.d/mirrorlist
EOF
root="$(mktemp -d -p "$PWD")"

packages=(
	busybox
	# Required by some of the packages below.
	gettext
	# drgn dependencies.
	autoconf
	automake
	bison
	bzip2
	flex
	gawk
	gcc
	libtool
	make
	pkgconf
	python
	python-setuptools
	xz
	zlib
)

pacstrap -C "$pacman_conf" -cGM "$root" "${packages[@]}"

# Remove unnecessary files from the chroot.

# We don't need the pacman databases anymore.
rm -rf "$root/var/lib/pacman/sync/"
# We don't need D, Fortran, or Go.
rm -f "$root/usr/lib/libgdruntime."* \
	"$root/usr/lib/libgphobos."* \
	"$root/usr/lib/libgfortran."* \
	"$root/usr/lib/libgo."*
# We don't need the Python test package.
rm -rf "$root/usr/lib/python"*/test
# We don't need any documentation.
rm -rf "$root/usr/share/doc" \
	"$root/usr/share/help" \
	"$root/usr/share/man" \
	"$root/usr/share/texinfo"
# We don't need locale data.
find "$root/usr/share/i18n/locales" "$root/usr/share/locale" \
	-mindepth 1 -maxdepth 1 -not -name POSIX -exec rm -rf {} +

chroot "$root" /bin/busybox --install

cat > "$root/etc/fstab" << "EOF"
dev /dev devtmpfs rw,nosuid 0 0
proc /proc proc rw,nosuid,nodev,noexec 0 0
sys /sys sysfs rw,nosuid,nodev,noexec 0 0
EOF
chmod 644 "$root/etc/fstab"

cat > "$root/etc/inittab" << "EOF"
::sysinit:/etc/init.d/rcS
::ctrlaltdel:/sbin/reboot
::shutdown:/sbin/swapoff -a
::shutdown:/bin/umount -a -r
::restart:/sbin/init
EOF
chmod 644 "$root/etc/inittab"

mkdir -m 755 "$root/etc/init.d" "$root/etc/rcS.d"
cat > "$root/etc/init.d/rcS" << "EOF"
#!/bin/sh

/bin/mount -a

for path in /etc/rcS.d/S*; do
	[ -x "$path" ] && "$path"
done
EOF
chmod 755 "$root/etc/init.d/rcS"

chmod 755 "$root"
tar -C "$root" -c . | zstd -T0 -19 -o "$NAME"
chmod 644 "$NAME"
