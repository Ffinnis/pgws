#!/bin/sh
# Owns only a newly allocated file-backed pool in this disposable lab VM.
set -eu
if [ "$(id -u)" != 0 ]; then echo 'run as root in the dedicated lab VM' >&2; exit 1; fi
test_binary=$1
lab_dir=$(mktemp -d /tmp/pgws-zfs.XXXXXXXX)
pool_name=pgws_lab_$(basename "$lab_dir" | tr -cd 'A-Za-z0-9')
created=0
cleanup() {
  if [ "$created" = 1 ]; then zpool destroy "$pool_name"; fi
  rm -rf "$lab_dir"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
truncate -s 4G "$lab_dir/vdev"
zpool create -m none -o cachefile=none -O canmount=off -O compression=lz4 -O atime=off "$pool_name" "$lab_dir/vdev"
created=1
zfs create -o mountpoint=none -o canmount=off -o org.pgws:managed=on "$pool_name/pgws"
export PGWS_ZFS_ROOT="$pool_name/pgws"
export PGWS_ZFS_MOUNTS="$lab_dir/mounts"
zfs version
uname -r
"$test_binary" -test.v -test.run "${PGWS_ZFS_TEST_PATTERN:-TestLive}" -test.timeout 18m
