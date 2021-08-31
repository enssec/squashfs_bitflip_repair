#!/usr/bin/env python3

#
# (c) 2019-2022 Georges-Axel Jaloyan
# SPDX-License-Identifier: Apache-2.0
#

import os

bsize = 128 * 1024
store = "../store"


def popcount(b1):
    cnt = 0
    for i in range(0, bsize):
        if b1[i]:
            cnt += bin(b1[i]).count("1")
    return cnt


def popcount_bytes(b1):
    cnt = 0
    for i in range(0, bsize):
        if b1[i]:
            cnt += 1
    return cnt


def xoreq(b1, b2):
    for i in range(0, bsize):
        b1[i] ^= b2[i]
    return b1


def oreq(b1, b2):
    for i in range(0, bsize):
        b1[i] |= b2[i]
    return b1


def andeq(b1, b2):
    for i in range(0, bsize):
        b1[i] &= b2[i]
    return b1


def noteq(b1):
    for i in range(0, bsize):
        b1[i] = ~b1[i] & (2**8 - 1)
    return b1


def gen_mask(filename):
    mask = bytearray(bsize)  # 128KiB
    data = None
    data0 = None
    for file in os.listdir(store):
        if not file.startswith(filename):
            continue
        if file.endswith(".in"):
            continue
        elif file.endswith(".size"):
            continue
        elif file.endswith(".1fail"):
            continue
        elif file.endswith(".mask0"):
            continue
        elif file.endswith(".mask1"):
            continue
        with open(f"{store}/{file}", "rb") as infile:
            data = bytearray(infile.read())
            print(f"{store}/{file}" + " {0}".format(len(data)))
            if len(data) != bsize:
                continue
            if data0 is None:
                data0 = data.copy()
                continue

            oreq(mask, xoreq(data, data0))

    if data0 is None:
        data0 = bytearray(bsize)
        noteq(mask)

    print(f"{store}/{filename}" + " popcount {0}".format(popcount(mask)))
    print(f"{store}/{filename}" + " popcount_bytes {0}".format(popcount_bytes(mask)))

    with open(f"{store}/{filename}.mask0", "wb") as f0:
        f0.write(oreq(mask.copy(), data0))

    with open(f"{store}/{filename}.mask1", "wb") as f1:
        f1.write(andeq(noteq(mask.copy()), data0))


with open("multi_targets.txt", "r") as mtar:
    for filename in mtar.read().splitlines():
        if filename.startswith("#"):
            continue
        gen_mask(filename)
