#!/bin/sh
set -e

ARCH="${1:?usage: run.sh <arch> <version> <kernel_version>}"
VERSION="${2:?usage: run.sh <arch> <version> <kernel_version>}"
KERNEL_VERSION="${3:?usage: run.sh <arch> <version> <kernel_version>}"

PORT=2222

IMAGE="images/debian-${VERSION}-${ARCH}-hdd.qcow2"

QEMU_PREFIX="${QEMU_PREFIX:-/usr}"
QEMU_RAM=512
QEMU_CPU=4
QEMU_SHARE="share/"

SYSTEM_ARGS="-accel tcg,thread=multi -smp cpus=${QEMU_CPU} -m ${QEMU_RAM}"
QEMU_COMMON_ARGS="${SYSTEM_ARGS} -serial file:vm-console.log -net nic"

if [ ! -f "${IMAGE}" ]; then
	echo "No image found at ${IMAGE} -- run install.sh first." >&2
	exit 1
fi

export PATH="${QEMU_PREFIX}/bin:$PATH"

qemu-system-${ARCH} -L "${QEMU_PREFIX}/share/qemu" \
	${QEMU_COMMON_ARGS} \
	-drive file="${IMAGE}" \
	-drive file=fat:rw:${QEMU_SHARE} \
	-net user,hostfwd=tcp::${PORT}-:22 \
    -display none
	-daemonize