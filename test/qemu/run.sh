#!/bin/sh
# Run reptyr's test suite inside a full-system QEMU VM for a foreign
# architecture.
#
# qemu-user can't emulate ptrace, so we boot a real Debian kernel under
# qemu-system. The guest root filesystem is a Debian tree (created with
# `mmdebstrap --variant=extract`, so no foreign binaries are executed
# on the host) packed into an initramfs together with this source tree.
# The guest's init builds reptyr natively and runs `make test`.
#
# Usage: test/qemu/run.sh <armhf|ppc64el|riscv64|loong64>
#
# Needs to run as root on a Debian-ish host with mmdebstrap, cpio, git
# and the relevant qemu-system-* package (plus qemu-efi-loongarch64 for
# loong64); see .github/workflows/ci.yml. Set QEMU_WORKDIR to reuse the
# guest root filesystem between runs.
set -eu

arch=${1:?usage: $0 <debian-arch>}
suite=trixie
mirror=http://deb.debian.org/debian
mem=2G
timeout=${QEMU_TIMEOUT:-1800}

case "$arch" in
    armhf)
        kernel_pkg=linux-image-armmp-lpae
        qemu="qemu-system-arm -machine virt -cpu cortex-a15"
        console=ttyAMA0
        ;;
    ppc64el)
        kernel_pkg=linux-image-powerpc64le
        qemu="qemu-system-ppc64 -machine pseries -cpu POWER9"
        console=hvc0
        ;;
    riscv64)
        kernel_pkg=linux-image-riscv64
        qemu="qemu-system-riscv64 -machine virt -bios default"
        console=ttyS0
        ;;
    loong64)
        # loong64 is a release architecture starting with forky.
        suite=forky
        kernel_pkg=linux-image-loong64
        qemu="qemu-system-loongarch64 -machine virt -cpu la464 -bios /usr/share/qemu-efi-loongarch64/QEMU_EFI.fd"
        console=ttyS0
        ;;
    *)
        echo "unsupported architecture: $arch" >&2
        exit 1
        ;;
esac

src=$(cd "$(dirname "$0")/../.." && pwd)
work=${QEMU_WORKDIR:-$(mktemp -d)}
root=$work/root
mkdir -p "$work"

if [ ! -d "$root" ]; then
    mmdebstrap --variant=extract --architectures="$arch" \
        --include="$kernel_pkg,busybox,coreutils,dash,make,gcc,libc6-dev,python3,python3-pexpect,python3-prctl" \
        "$suite" "$root.tmp" "$mirror"
    mv "$root.tmp" "$root"
fi

# The extract variant runs no maintainer scripts, so fill in the few
# things they (or base-files) would normally set up.
for d in bin sbin lib lib32 lib64; do
    if [ -d "$root/usr/$d" ] && [ ! -e "$root/$d" ]; then
        ln -s "usr/$d" "$root/$d"
    fi
done
ln -sf dash "$root/usr/bin/sh"
mkdir -p "$root/proc" "$root/sys" "$root/dev" "$root/tmp" "$root/root"

# Newer Debian kernels only ship the image under /usr/lib/modules and
# leave /boot to maintainer scripts, which the extract variant skips.
kernel=$(ls "$root"/boot/vmlinu[xz]-* "$root"/usr/lib/modules/*/vmlinu[xz] 2>/dev/null | head -n1)

rm -rf "$root/src"
mkdir "$root/src"
(cd "$src" && git -c safe.directory="$src" ls-files -z) > "$work/files"
(cd "$src" && cpio --null -pdm --quiet "$root/src") < "$work/files"
cp "$src/test/qemu/init" "$root/init"

# Leave the kernel image and modules out of the initramfs.
(cd "$root" && find . \
    -path ./boot -prune -o \
    -path ./usr/lib/modules -prune -o \
    -path ./usr/share/doc -prune -o \
    -path ./usr/share/locale -prune -o \
    -path ./usr/share/man -prune -o \
    -print | cpio -o -H newc --quiet) > "$work/initrd.cpio"

log=$work/console.log
# shellcheck disable=SC2086
timeout "$timeout" $qemu -m "$mem" -smp 2 -nographic -vga none -no-reboot -nic none \
    -kernel "$kernel" -initrd "$work/initrd.cpio" \
    -append "console=$console rdinit=/init panic=-1" \
    </dev/null 2>&1 | tee "$log"

if grep -aq 'reptyr-qemu-result: 0' "$log"; then
    echo "$arch: tests passed"
else
    echo "$arch: tests FAILED" >&2
    exit 1
fi
