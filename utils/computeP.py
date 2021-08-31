#!/usr/bin/env python3

#
# (c) 2019-2022 Georges-Axel Jaloyan
# SPDX-License-Identifier: Apache-2.0
#

import math
import os

precision = 10.0 ** (-12)
good_count = 0
total_count = 0
monoms = list()
store = "../store/"

for file in os.listdir(store):
    if "_" in file:
        continue
    if file.endswith(".in"):
        pass
    elif file.endswith(".good"):
        good_count += 1
        pass
    else:
        continue
    total_count += 1
    print(file)
    monoms.append(os.stat(store + file).st_size * 8)


# solve equation X^Monom_i = good_count
l = 0.0
h = 1.0
while (h - l) > precision:
    m = (h - l) / 2 + l
    tot = 0.0
    for k in monoms:
        tot += m**k
    if tot < good_count:
        l = m
    else:
        h = m
p = 1 - l
print("A bitflip occurs every " + str(int((1 / p) / 8)) + " bytes (p = " + str(p) + ")")

# compute the expectations for 1, 2... bitflips
for k in range(0, 6):
    sm = 0.0
    for n in monoms:
        sm += math.comb(n, k) * (p**k) * ((1 - p) ** (n - k))
    print(str(k) + " bitflips: %.2f" % sm)


from decimal import *

import IPython

getcontext().prec = 3000
variance = Decimal(0)
for n in monoms:
    variance += (Decimal(1 - p) ** n) * (1 - (Decimal(1 - p) ** n))
    print("Adding : " + str(n) + " " + str(variance))
print("Variance: " + str(variance))
