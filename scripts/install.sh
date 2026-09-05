#!/bin/sh
set -e

ARCH="${1:?usage: install.sh <arch> <version> <kernel_version>}"
VERSION="${2:?usage: install.sh <arch> <version> <kernel_version>}"
KERNEL_VERSION="${3:?usage: install.sh <arch> <version> <kernel_version>}"

PORT=2222

IMAGE="images/debian-${VERSION}-${ARCH}-hdd.qcow2"
CDIMAGE="images/debian-${VERSION}-${ARCH}-NETINST-1.iso"

QEMU_PREFIX="${QEMU_PREFIX:-/usr}"
QEMU_RAM=512
QEMU_CPU=4
QEMU_DISK_SIZE=4G
QEMU_SHARE="share/"

SYSTEM_ARGS="-accel tcg,thread=multi -smp cpus=${QEMU_CPU} -m ${QEMU_RAM}"
QEMU_COMMON_ARGS="${SYSTEM_ARGS} -serial mon:stdio -net nic"

if [ -f "${IMAGE}" ]; then
	echo "Image already exists at ${IMAGE}, nothing to install."
	exit 0
fi

export PATH="${QEMU_PREFIX}/bin:$PATH"
qemu-system-${ARCH} --version

qemu-img create -f qcow2 -o size=${QEMU_DISK_SIZE} "${IMAGE}"

qemu-system-${ARCH} -L "${QEMU_PREFIX}/share/qemu" \
	${QEMU_COMMON_ARGS} \
	-boot d \
	-drive file="${IMAGE}" \
	-drive file="${CDIMAGE}",if=ide,media=cdrom \
	# -drive file=fat:rw:${QEMU_SHARE} \
	-net user,hostfwd=tcp::${PORT}-:22 \
