#!/bin/bash

set -uo pipefail
trap 'exit 2' ERR

usage () {
	USAGE_STRING="usage: $0 [-k KERNELRELEASE] [[-r ROOTFSVERSION] [-fo]|-I] [-Si] [-d DIR] IMG
       $0 [-k KERNELRELEASE] -l
       $0 -h

Run drgn tests in a virtual machine.

This exits with status 0 on success, 1 if the virtual machine ran successfully
but tests failed, and 2 if we encountered a fatal error.

This script uses sudo to mount and modify the disk image.

Arguments:
  IMG                 path of virtual machine disk image to create

Versions:
  -k KERNELRELEASE    kernel release to test. This is a glob pattern; the
		      newest (sorted by version number) release that matches
		      the pattern is used (default: newest available release)
  -r ROOTFSVERSION    version of root filesystem to use (default: newest
                      available version)

Setup:
  -f                  overwrite IMG if it already exists
  -o                  one-shot mode. By default, this script saves a clean copy
		      of the downloaded root filesystem image and vmlinux and
		      makes a copy (reflinked, when possible) for executing the
		      virtual machine. This allows subsequent runs to skip
		      downloading these files. If this option is given, the
		      root filesystem image and vmlinux are always
		      re-downloaded and are not saved. This option implies -f
  -I                  skip creating the disk image; use the existing one at
                      IMG. This option cannot be combined with -r, -f, or -o
  -S                  skip copying the source files and init scripts

Miscellaneous:
  -i                  interactive mode. Boot the virtual machine into an
		      interactive shell instead of automatically running tests
  -d DIR              working directory to use for downloading and caching
                      files (default: current working directory)
  -l                  list available kernel releases instead of running tests.
		      The list may be filtered with -k
  -h                  display this help message and exit"

	case "$1" in
		out)
			echo "$USAGE_STRING"
			exit 0
			;;
		err)
			echo "$USAGE_STRING" >&2
			exit 2
			;;
	esac
}

KERNELRELEASE='*'
unset ROOTFSVERSION
unset IMG
FORCE=0
ONESHOT=0
SKIPIMG=0
SKIPSOURCE=0
APPEND=""
DIR="$PWD"
LIST=0
while getopts "k:r:foISid:lh" OPT; do
	case "$OPT" in
		k)
			KERNELRELEASE="$OPTARG"
			;;
		r)
			ROOTFSVERSION="$OPTARG"
			;;
		f)
			FORCE=1
			;;
		o)
			ONESHOT=1
			FORCE=1
			;;
		I)
			SKIPIMG=1
			;;
		S)
			SKIPSOURCE=1
			;;
		i)
			APPEND=" single"
			;;
		d)
			DIR="$OPTARG"
			;;
		l)
			LIST=1
			;;
		h)
			usage out
			;;
		*)
			usage err
			;;
	esac
done
if [[ $SKIPIMG -ne 0 && ( -v ROOTFSVERSION || $FORCE -ne 0 ) ]]; then
	usage err
fi
if (( LIST )); then
	if [[ $OPTIND -le $# || -v ROOTFSVERSION || $FORCE -ne 0 ||
	      $SKIPIMG -ne 0 || $SKIPSOURCE -ne 0 || -n $APPEND ]]; then
		usage err
	fi
else
	if [[ $OPTIND -ne $# ]]; then
		usage err
	fi
	IMG="${!OPTIND}"
fi

unset URLS
cache_urls() {
	if ! declare -p URLS &> /dev/null; then
		# This URL contains a mapping from file names to URLs where
		# those files can be downloaded.
		local INDEX='https://www.dropbox.com/sh/2mcf2xvg319qdaw/AACB_NCTIcbJ-Dx_Cw3JEYFHa/INDEX?dl=1'
		declare -gA URLS
		while IFS=$'\t' read -r name url; do
			URLS["$name"]="$url"
		done < <(curl -LfsS "$INDEX")
	fi
}

matching_kernel_releases() {
	local pattern="$1"
	{
	for file in "${!URLS[@]}"; do
		if [[ $file =~ ^bzImage-(.*)$ ]]; then
			release="${BASH_REMATCH[1]}"
			case "$release" in
				$pattern)
					# sort -V handles rc versions properly
					# if we use "~" instead of "-".
					echo "${release//-rc/~rc}"
					;;
			esac
		fi
	done
	} | sort -rV | sed 's/~rc/-rc/g'
}

newest_rootfs_version() {
	{
	for file in "${!URLS[@]}"; do
		if [[ $file =~ ^drgn-vmtest-rootfs-(.*)\.tar\.zst$ ]]; then
			echo "${BASH_REMATCH[1]}"
		fi
	done
	} | sort -rV | head -1
}

download() {
	local file="$1"
	cache_urls
	if [[ ! -v URLS[$file] ]]; then
		echo "$file not found" >&2
		return 1
	fi
	echo "Downloading $file..." >&2
	curl -Lf "${URLS[$file]}" "${@:2}"
}

set_nocow() {
	touch "$@"
	chattr +C "$@" >/dev/null 2>&1 || true
}

cp_img() {
	set_nocow "$2"
	cp --reflink=auto "$1" "$2"
}

create_rootfs_img() {
	local path="$1"
	set_nocow "$path"
	truncate -s 2G "$path"
	mkfs.ext4 -q "$path"
}

download_rootfs() {
	local rootfsversion="$1"
	local dir="$2"
	download "drgn-vmtest-rootfs-$rootfsversion.tar.zst" |
		zstd -d | sudo tar -C "$dir" -x
}

if (( LIST )); then
	cache_urls
	matching_kernel_releases "$KERNELRELEASE"
	exit 0
fi

if [[ $FORCE -eq 0 && $SKIPIMG -eq 0 && -e $IMG ]]; then
	echo "$IMG already exists; use -f to overwrite it or -I to reuse it" >&2
	exit 1
fi

# Only go to the network if it's actually a glob pattern.
if [[ ! $KERNELRELEASE =~ ^([^\\*?[]|\\[*?[])*\\?$ ]]; then
	# We need to cache the list of URLs outside of the command
	# substitution, which happens in a subshell.
	cache_urls
	KERNELRELEASE="$(matching_kernel_releases "$KERNELRELEASE" | head -1)"
	if [[ -z $KERNELRELEASE ]]; then
		echo "No matching kernel release found" >&2
		exit 1
	fi
fi
if [[ $SKIPIMG -eq 0 && ! -v ROOTFSVERSION ]]; then
	cache_urls
	ROOTFSVERSION="$(newest_rootfs_version)"
fi

echo "Kernel release: $KERNELRELEASE" >&2
if (( SKIPIMG )); then
	echo "Not extracting root filesystem" >&2
else
	echo "Root filesystem version: $ROOTFSVERSION" >&2
fi
echo "Disk image: $IMG" >&2

tmp=
mkdir -p "$DIR"
mnt="$(mktemp -d -p "$DIR" mnt.XXXXXXXXXX)"

cleanup() {
	if [[ -n $tmp ]]; then
		rm -f "$tmp" || true
	fi
	if mountpoint -q "$mnt"; then
		sudo umount "$mnt" || true
	fi
	if [[ -d "$mnt" ]]; then
		rmdir "$mnt" || true
	fi
}
trap cleanup EXIT

bzImage="$DIR/bzImage-$KERNELRELEASE"
if [[ ! -e $bzImage ]]; then
	tmp="$(mktemp "$bzImage.XXX.part")"
	download "bzImage-$KERNELRELEASE" -o "$tmp"
	mv "$tmp" "$bzImage"
	tmp=
fi

# Mount and set up the rootfs image.
if (( ONESHOT )); then
	rm -f "$IMG"
	create_rootfs_img "$IMG"
	sudo mount -o loop "$IMG" "$mnt"
	download_rootfs "$ROOTFSVERSION" "$mnt"
else
	if (( ! SKIPIMG )); then
		rootfs_img="$DIR/drgn-vmtest-rootfs-$ROOTFSVERSION.img"

		if [[ ! -e $rootfs_img ]]; then
			tmp="$(mktemp "$rootfs_img.XXX.part")"
			set_nocow "$tmp"
			truncate -s 2G "$tmp"
			mkfs.ext4 -q "$tmp"
			sudo mount -o loop "$tmp" "$mnt"

			download_rootfs "$ROOTFSVERSION" "$mnt"

			sudo umount "$mnt"
			mv "$tmp" "$rootfs_img"
			tmp=
		fi

		rm -f "$IMG"
		cp_img "$rootfs_img" "$IMG"
	fi
	sudo mount -o loop "$IMG" "$mnt"
fi

# Install vmlinux.
vmlinux="$mnt/boot/vmlinux-$KERNELRELEASE"
if [[ ! -e $vmlinux ]]; then
	if (( ! ONESHOT )); then
		downloaded_vmlinux="$DIR/vmlinux-$KERNELRELEASE"
		if [[ ! -e $downloaded_vmlinux ]]; then
			tmp="$(mktemp "$downloaded_vmlinux.XXX.part")"
			download "vmlinux-$KERNELRELEASE.zst" | zstd -dfo "$tmp"
			mv "$tmp" "$downloaded_vmlinux"
			tmp=
		fi
	fi
	tmp="$(sudo mktemp -p "$mnt/boot" "vmlinux-$KERNELRELEASE.XXX.part")"
	if (( ONESHOT )); then
		# We could use "sudo zstd -o", but let's not run zstd as root
		# with input from the internet.
		download "vmlinux-$KERNELRELEASE.zst" |
			zstd -d | sudo tee "$tmp" > /dev/null
	else
		echo "Copying vmlinux..." >&2
		sudo cp "$downloaded_vmlinux" "$tmp"
	fi
	sudo mv "$tmp" "$vmlinux"
	tmp=
	sudo chmod 644 "$vmlinux"
fi

if (( SKIPSOURCE )); then
	echo "Not copying source files..." >&2
else
	echo "Copying source files..." >&2

	# Copy the source files in.
	sudo mkdir -p -m 0755 "$mnt/drgn"
	{
	if [[ -e .git ]]; then
		git ls-files -z
	else
		tr '\n' '\0' < drgn.egg-info/SOURCES.txt
	fi
	} | sudo xargs -0 cp --parents --preserve=mode,timestamps -t "$mnt/drgn"

	# Create the init scripts.
	sudo tee "$mnt/etc/rcS.d/S50-run-tests" > /dev/null << "EOF"
#!/bin/sh

# Force the Linux helper tests to run and fail if they would be skipped
# otherwise.
export DRGN_RUN_LINUX_HELPER_TESTS=1
cd /drgn && python3 --version && python3 setup.py build -j "$(nproc)" test
echo $? > /exitstatus
chmod 644 /exitstatus
EOF
	sudo chmod 755 "$mnt/etc/rcS.d/S50-run-tests"

	sudo tee "$mnt/etc/rcS.d/S99-poweroff" > /dev/null << "EOF"
#!/bin/sh

poweroff
EOF
	sudo chmod 755 "$mnt/etc/rcS.d/S99-poweroff"
fi

sudo umount "$mnt"

echo "Starting virtual machine..." >&2
qemu-system-x86_64 -nodefaults -display none -serial mon:stdio \
	-cpu kvm64 -enable-kvm -smp "$(nproc)" -m 2G \
	-drive file="$IMG",format=raw,index=1,media=disk,if=virtio,cache=none \
	-kernel "$bzImage" -append "root=/dev/vda rw console=ttyS0,115200$APPEND"

sudo mount -o loop "$IMG" "$mnt"
if exitstatus="$(cat "$mnt/exitstatus" 2>/dev/null)"; then
	printf '\nTests exit status: %s\n' "$exitstatus" >&2
else
	printf '\nCould not read tests exit status\n' >&2
	exitstatus=1
fi
sudo umount "$mnt"
exit "$exitstatus"
