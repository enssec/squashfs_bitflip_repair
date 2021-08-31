#!/usr/bin/env bash

#
# (c) 2020-2022 Hadrien Barral
# (c) 2020-2022 Georges-Axel Jaloyan
# SPDX-License-Identifier: CC0-1.0
#
# A small script to check python and shell scripts
#

set -euo pipefail

(cd repairchunk && make)
(cd sasquatch && make -j8)

call_unsquashfs() {
    # Note: for now, this must be called from all.sh directory ('store' is hard-coded!)
    ./sasquatch/sasquatch -no-progress "$1"
}

rm -rf out

if [ ! -d "store" ]; then
    mkdir store
    # First pass to create '.in' files
    call_unsquashfs squashfs.dump
    rm -rf out
fi

if [ -d "squashfs-root" ]; then
    rm -rf squashfs-root
fi


# Generate in files from the 2 bitflip repair file
(cd utils && ./2repairs_mutate.py)

# Repair 1 bitflip in those files
./repairchunk/repairchunk store/ 1 ""

#generate the masks files
(cd utils && ./mask.py)

# generate links to every mask0
while read -r line; do
	if [[ $line == \#* ]]
	then
		continue
	fi
	ln -f "store/$line.mask0" "store/$line.out"
done < utils/multi_targets.txt
call_unsquashfs squashfs.dump
mv -f squashfs-root/ out0/

# generate links to every mask1
while read -r line; do
        if [[ $line == \#* ]]
        then
                continue
        fi
        ln -f "store/$line.mask1" "store/$line.out"
done < utils/multi_targets.txt
call_unsquashfs squashfs.dump
mv -f squashfs-root/ out1/

while read -r line; do
        if [[ $line == \#* ]]
        then
                continue
        fi
        rm "store/$line.out"
done < utils/multi_targets.txt

diff -qr out0 out1 | tee diff0vs1
