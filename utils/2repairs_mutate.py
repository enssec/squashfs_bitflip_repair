#!/usr/bin/env python3

#
# (c) 2019-2022 Georges-Axel Jaloyan
# SPDX-License-Identifier: Apache-2.0
#

import sys

store = "../store"
if len(sys.argv) >= 2:
    store = sys.argv[1]

with open("2repairs.txt", "r") as f_repairs:
    for line in f_repairs.readlines():
        fname, position, _, _ = line.split(":")
        with open(f"{store}/{fname}.in", "rb") as infile:
            data = bytearray(infile.read())
            i, j = map(int, position.split("_"))
            data[i] ^= 1 << j
            with open(f"{store}/{fname}.{position}.in", "wb") as outfile:
                outfile.write(data)
