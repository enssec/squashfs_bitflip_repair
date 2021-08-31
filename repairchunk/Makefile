#
# (c) 2019-2022 Hadrien Barral
# SPDX-License-Identifier: Apache-2.0
#

all: repairchunk

repairchunk: repairchunk.cpp
	g++ -std=gnu++2a -fconcepts -O3 -march=native -Wall -Wextra -Wshadow $< -lz -ldeflate -lpthread -o $@

clean:
	rm -f repairchunk
