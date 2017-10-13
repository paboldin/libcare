#!/bin/sh

exec 1>&2

ln -fs /data /kcdata

ls -lR /data

yum install -y rpm-build

LIBCARE_DIR="/data"
KPATCH_PATH="/data"
export LIBCARE_DIR KPATCH_PATH
/kcdata/scripts/pkgbuild $@ /kcdata/package
