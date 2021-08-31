/*#
 *# (c) 2019-2022 Hadrien Barral
 *# SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <ostream>
#include <string>
#include <unistd.h>

#include <libdeflate.h>
#include <zlib.h>
#if ZLIB_VERNUM < 0x12b0
# error "zlib version is too old. Use at least 1.2.11."
#endif

#include "ThreadPool.h"

/* ===========================================================================
 * Helpers
 */

/* Simple helper for debug logs */
__attribute__((format(printf, 1, 2)))
static inline
int noprintf(const char *format, ...)
{
	(void) format;
	return 0;
}

/* ===========================================================================
 * File handling
 */

[[gnu::warn_unused_result]] static
int write_file(std::string filename, const void *buf, size_t bufsize)
{
	std::string filename_tmp = filename + ".tmp";
	FILE *f = fopen(filename_tmp.c_str(), "wb");
	if(f == NULL) {
		printf("%s: fopen failed for file '%s'\n", __func__, filename.c_str());
		return -1;
	}

	fwrite(buf, bufsize, 1, f);
	fclose(f);

	/* Atomic move to the final destination, so we can ^C this program anytime */
	std::filesystem::rename(filename_tmp, filename);
	return 0;
}

[[gnu::warn_unused_result]] static
int write_out_file(std::string store_path, std::string hash, const void *buf, size_t bufsize)
{
	std::string filename = store_path + "/" + hash + ".out";
	return write_file(filename, buf, bufsize);
}

[[gnu::warn_unused_result]] static
int read_in_file(std::string store_path, std::string hash, void *buf, size_t buf_size, size_t *out_read_size)
{
	std::string fn = store_path + "/" + hash + ".in";
	FILE *fp = fopen(fn.c_str(), "rb");
	if(fp == NULL) {
		perror("fopen");
		return -1;
	}

	size_t read_size = fread(buf, 1, buf_size, fp);
	if(read_size == 0) {
		perror("fread fail (A)");
		return -1;
	}
	if(feof(fp) == 0) {
		perror("fread fail (B)");
		return -1;
	}

	fclose(fp);

	*out_read_size = read_size;
	return 0;
}

/* ===========================================================================
 * Decompression handling
 */


class Decompr
{
private:
	struct libdeflate_decompressor *libdeflate_decompressor;
public:
	enum lib_mode {
		ZLIB, /* Uses zlib. Slower than libdeflate. */
		LIBDEFLATE, /* Uses libdeflate. In this mode, `decompr_uncompress` will not set `source_used` */
	};

	Decompr()
	{
		libdeflate_decompressor = libdeflate_alloc_decompressor();
		if (libdeflate_decompressor == NULL) {
			throw "Could not allocate libdeflate_decompressor";
		}
	}

	~Decompr()
	{
		libdeflate_free_decompressor(libdeflate_decompressor);
	}

	/* Decompresses a https://tools.ietf.org/html/rfc1950 stream */
	[[gnu::warn_unused_result]]
	int uncompress(enum lib_mode mode, void *dest, size_t dest_size, const void *source, size_t source_size,
	               size_t *out_dest_written, size_t *out_source_used, int *out_lib_error) const
	{
		int ret;
		int lib_error;
		size_t dest_written;
		size_t source_used;

		if (mode == Decompr::ZLIB) {
			uLongf destLen = dest_size;
			uLong sourceLen = source_size;
			int lib_ret = uncompress2((Bytef *) dest, &destLen, (const Bytef *) source, &sourceLen);
			dest_written = destLen;
			source_used = sourceLen;
			lib_error = lib_ret;
			ret = (lib_ret == Z_OK) ? 0 : -1;
		} else if (mode == Decompr::LIBDEFLATE) {
			if (out_source_used != NULL) {
				std::cout << "`Decompr::LIBDEFLATE` is incompatible with a nonnull `out_source_used`" << std::endl;
				exit(1);
			}

			enum libdeflate_result lib_ret;
			size_t actual_out_nbytes_ret;
			lib_ret = libdeflate_zlib_decompress(libdeflate_decompressor, source, source_size, dest, dest_size, &actual_out_nbytes_ret);
			dest_written = actual_out_nbytes_ret;
			lib_error = lib_ret;
			ret = (lib_ret == 0) ? 0 : -1;
		} else {
			std::cout << "Unexpected mode in " << __func__ << std::endl;
			exit(1);
		}

		if (out_dest_written != NULL) {
			*out_dest_written = dest_written;
		}
		if (out_source_used != NULL) {
			*out_source_used = source_used;
		}
		if (out_lib_error != NULL) {
			*out_lib_error = lib_error;
		}

		return ret;
	}
};

/* ===========================================================================
 * Algorithm core: bit-flip repair
 */

typedef std::vector<std::pair<size_t, size_t>> bf_vector_t;

[[gnu::warn_unused_result]] static
int try_fix_1bitflip(uint8_t *inbuf, size_t inbuf_size, bf_vector_t &out_bf_vector,
                     size_t mini_i, size_t mini_j,
                     const Decompr &decompressor, const std::string &debug_id)
{
	int ret;
	uint8_t outbuf[0x20000]; /* Max uncompressed chunk size in our squashfs image */

	/*
	 * First, let us find out how much of the input is actually used during decompression.
	 * There is no need to try to perform bit-flips in the unused range.
	 */
	size_t orig_source_used;
	ret = decompressor.uncompress(Decompr::ZLIB, outbuf, sizeof(outbuf), inbuf, inbuf_size,
	                              NULL, &orig_source_used, NULL);
	if(ret == 0) {
		printf("Unexpected: original is OK.\n");
		return -10;
	}

	int nb_successes = 0;

	/*
	 * Iterate on the input and try all possible bit-flips
	 */
	for(size_t i=mini_i; i<orig_source_used; i++) {
		for(size_t j=0; j<8; j++) {
			if ((i == mini_i) && (j < mini_j)) {
				continue;
			}
			inbuf[i] ^= (UINT8_C(1) << j); /* Perform bit-flip */

			size_t outbuf_written;
			int lib_error;
			ret = decompressor.uncompress(Decompr::LIBDEFLATE, outbuf, sizeof(outbuf), inbuf, inbuf_size,
			                              &outbuf_written, NULL, &lib_error);
			if(ret == 0) { [[unlikely]]
				nb_successes++;
				out_bf_vector.push_back(std::make_pair(i, j));
				printf("[%s] Success: i:0x%04zx j:%zd (bytes:%#zx)\n", debug_id.c_str(), i, j, outbuf_written);
			} else {
				noprintf("[%s] Noluck: i:%5zu j:%zu in_size:%5zu out_written:%#zx lib_error:%d\n",
				         debug_id.c_str(), i, j, inbuf_size, outbuf_written, lib_error);
			}

			inbuf[i] ^= (UINT8_C(1) << j); /* Revert bit-flip added at the beginning of the loop */
		}
	}

	return 0;
}

/* ===========================================================================
 * Wrapper for the 'slow' repair when we assume at most two bit-flips
 */

[[gnu::warn_unused_result]] static
int write_2_bitflips_status_file(std::string store_path, std::string hash, size_t first_i, size_t first_j, std::string message)
{
	std::string store_path_2b = store_path + "/" + hash + "_2b";
	std::string filename = store_path_2b + "/" + std::to_string(first_i) + "_" + std::to_string(first_j) + ".status";
	message += "\n";
	return write_file(filename, message.c_str(), strlen(message.c_str()));
}

[[gnu::warn_unused_result]] static
int process_chunk_max_2_bitflip(std::string store_path, std::string hash, size_t first_i, size_t first_j)
{
	auto t_start = std::chrono::high_resolution_clock::now();

	std::string first_i_str = std::to_string(first_i);
	first_i_str = std::string(std::max((size_t) 0, ((size_t)6) - first_i_str.size()), ' ') + first_i_str;
	std::string debug_id = "2b " + hash + " " + first_i_str + "," + std::to_string(first_j);

	uint8_t inbuf[0x20000];
	size_t inbuf_size = 0;
	int ret = read_in_file(store_path, hash, inbuf, sizeof(inbuf), &inbuf_size);
	if(ret != 0) {
		return ret;
	}

	/* Apply first bitflip */
	inbuf[first_i] ^= (UINT8_C(1) << first_j);

	/* Init decompression lib */
	Decompr decompressor;

	bf_vector_t good_bitflips;
	size_t mini_i = first_i; /* Do not bitflip before the first bitflip */
	size_t mini_j = first_j + 1;
	if (mini_j == 8) {
		mini_i++;
		mini_j = 0;
	}
	ret = try_fix_1bitflip(inbuf, inbuf_size, good_bitflips, mini_i, mini_j, decompressor, debug_id);
	if(ret != 0) {
		return ret;
	}

	size_t nb_successes = good_bitflips.size();

	ret = write_2_bitflips_status_file(store_path, hash, first_i, first_j, std::to_string(nb_successes));
	if (ret != 0) {
		return ret;
	}

	auto t_end = std::chrono::high_resolution_clock::now();
	unsigned t_elapsed = (unsigned) std::chrono::duration<float>(t_end-t_start).count();
	unsigned elapsed_m = t_elapsed / 60;
	unsigned elapsed_s = t_elapsed % 60;
	printf("[%s] Found %zu possibles fixes in %um%02us\n",
	       debug_id.c_str(), nb_successes, elapsed_m, elapsed_s);

	return 0;
}

[[gnu::warn_unused_result]] static
int schedule_max_2_bitflips(std::string store_path, std::string hash,
                            size_t bitflip_1_min_idx, size_t bitflip_1_max_idx,
                            ThreadPool &pool, auto &future_results)
{
	std::string debug_id = "2b " + hash;

	std::string store_path_2b = store_path + "/" + hash + "_2b";
	std::filesystem::create_directory(store_path_2b); /* Make sure the directory exists */

	uint8_t inbuf[0x20000];
	size_t inbuf_size = 0;
	int ret = read_in_file(store_path, hash, inbuf, sizeof(inbuf), &inbuf_size);
	if(ret != 0) {
		return ret;
	}

	/* Init decompression lib */
	Decompr decompressor;
	uint8_t outbuf[0x20000];

	/*
	 * First, let us find out how much of the input is actually used during decompression.
	 * There is no need to try to perform bit-flips in the unused range.
	 */
	size_t orig_source_used;
	ret = decompressor.uncompress(Decompr::ZLIB, outbuf, sizeof(outbuf), inbuf, inbuf_size,
	                              NULL, &orig_source_used, NULL);
	if(ret == 0) {
		printf("[%s] Unexpected: original is OK.\n", debug_id.c_str());
		return -1;
	}

	if (bitflip_1_max_idx > orig_source_used) {
		bitflip_1_max_idx = orig_source_used;
	}

	/* Iterate on the first possible bitflip */
	for (size_t idx=bitflip_1_min_idx; idx<bitflip_1_max_idx; idx++) {
		for (size_t bit = 0; bit<8; bit++) {
			std::string idx_status_file = store_path_2b + "/" + std::to_string(idx) + "_" \
			                              + std::to_string(bit) + ".status";
			if (access(idx_status_file.c_str(), F_OK) == 0) {
				noprintf("[%s] idx %zu previously repaired\n", debug_id.c_str(), idx);
				continue; /* Chunk was already processed for this index */
			}

			future_results.emplace_back(
				pool.enqueue([store_path, hash, idx, bit] {
					return process_chunk_max_2_bitflip(store_path, hash, idx, bit);
				})
			);
		}
	}

	return 0;
}

/* ===========================================================================
 * Wrapper for the 'quick' repair when we assume at most one bit-flip
 */

[[gnu::warn_unused_result]] static
int write_1_bitflip_fail_file(std::string store_path, std::string hash, std::string message)
{
	std::string filename = store_path + "/" + hash + ".1fail";
	message += "\n";
	return write_file(filename, message.c_str(), strlen(message.c_str()));
}

[[gnu::warn_unused_result]] static
int process_chunk_max_1_bitflip(std::string store_path, std::string hash)
{
	std::string debug_id = "1b " + hash;

	uint8_t inbuf[0x20000];
	size_t inbuf_size = 0;
	int ret = read_in_file(store_path, hash, inbuf, sizeof(inbuf), &inbuf_size);
	if(ret != 0) {
		return ret;
	}

	printf("[%s] Start trying to repair chunk of size %#zx\n", debug_id.c_str(), inbuf_size);

	/* Init compression lib */
	Decompr decompressor;

	uint8_t outbuf[0x20000];

	ret = decompressor.uncompress(Decompr::LIBDEFLATE, outbuf, sizeof(outbuf), inbuf, inbuf_size, NULL, NULL, NULL);
	if(ret == 0) {
		printf("[%s] Success: original is OK.\n", debug_id.c_str());
		return ret;
	}

	bf_vector_t good_bitflips;
	ret = try_fix_1bitflip(inbuf, inbuf_size, good_bitflips, 0, 0, decompressor, debug_id);
	if(ret != 0) {
		return ret;
	}

	size_t nb_successes = good_bitflips.size();

	if(nb_successes == 0) {
		printf("[%s] Could not repair chunk: no valid bit-flip\n", debug_id.c_str());
		ret = write_1_bitflip_fail_file(store_path, hash, "0");
	} else if(nb_successes == 1) {
		/* Apply the only good known bit-flip */
		inbuf[good_bitflips[0].first] ^= 1U << good_bitflips[0].second;
		size_t outbuf_written;
		ret = decompressor.uncompress(Decompr::LIBDEFLATE, outbuf, sizeof(outbuf), inbuf, inbuf_size,
		                              &outbuf_written, NULL, NULL);
		if(ret != 0) {
			printf("Error: was not able to generate 'out' data from valid bit-flip\n");
			return ret;
		}
		ret = write_out_file(store_path, hash, outbuf, outbuf_written);
		printf("[%s] OK: repaired chunk\n", debug_id.c_str());
	} else if(nb_successes > 1) {
        printf("[%s] Multiple possible repairs (%zu)\n", debug_id.c_str(), nb_successes);
		ret = write_1_bitflip_fail_file(store_path, hash, std::to_string(nb_successes));
        for (size_t sc = 0; sc < nb_successes; sc++)
        {
            inbuf[good_bitflips[sc].first] ^= 1U << good_bitflips[sc].second;
            size_t outbuf_written;
            ret = decompressor.uncompress(Decompr::LIBDEFLATE, outbuf,
                                          sizeof(outbuf), inbuf, inbuf_size,
                                          &outbuf_written, NULL, NULL);
            if(ret != 0) {
                printf("Error: was not able to generate 'tgt' data from valid bit-flip\n");
                return ret;
            }
            std::string filename = store_path + "/" + hash + ".tgt."
                + std::to_string(sc);
            ret = write_file(filename, outbuf, outbuf_written);
            printf("[%s] Dumped target candidate %zu\n", debug_id.c_str(), sc);
            //revert the bitflip
            inbuf[good_bitflips[sc].first] ^= 1U << good_bitflips[sc].second;
        }
	}

	return ret;
}

/* ===========================================================================
 * main
 */

[[gnu::warn_unused_result]] static
int process_store(std::string store_path, std::string target_hash, size_t repair_depth,
                  size_t first_mini_i, size_t first_maxi_i, unsigned int threads_number)
{
	/* Allocate a thread pool */
	ThreadPool pool(threads_number);
	std::vector<std::future<int>> results;

	/* Iterate on the 'store' schedule jobs for all needed chunks */
	for (const auto& dir_entry : std::filesystem::directory_iterator(store_path)) {
		if (!dir_entry.is_regular_file()) {
			continue;
		}
		if (dir_entry.path().extension() != ".in") {
			continue;
		}

		std::string hash = dir_entry.path().stem().string();
		if ((target_hash != "") && (target_hash != hash)) {
			continue; /* User does not want to attempt repair on this chunk */
		}

		std::filesystem::path out_path = dir_entry.path();
		out_path.replace_extension(".out");
		std::string out_file = out_path;
		if (access(out_file.c_str(), F_OK) == 0) {
			noprintf("[%s] previously repaired\n", hash.c_str());
			continue; /* Chunk was already repaired */
		}

		std::filesystem::path fail_path = dir_entry.path();
		fail_path.replace_extension(".1fail");
		std::string fail_file = fail_path;
		bool repair_1_bitflip_failed = (access(fail_file.c_str(), F_OK) == 0);

		if (repair_depth == 1) {
			if (repair_1_bitflip_failed) {
				noprintf("[%s] could previously not be repaired\n", hash.c_str());
				continue; /* Chunk could already not be repaired */
			}
			results.emplace_back(
				pool.enqueue([store_path, hash] {
					return process_chunk_max_1_bitflip(store_path, hash);
				})
			);
		} else if (repair_depth == 2) {
			if (!repair_1_bitflip_failed) {
				fprintf(stderr, "[%s] 2 bit-flips repair requested but 1 bit-flip repair has not been tried", hash.c_str());
				exit(1);
			}
			int ret = schedule_max_2_bitflips(store_path, hash, first_mini_i, first_maxi_i, pool, results);
			if (ret != 0) {
				fprintf(stderr, "schedule_max_2_bitflips failed\n");
				exit(1);
			}
		}
	}

	/* Wait until all jobs are done */
	for(auto && result: results) {
		int ret = result.get();
		if (ret != 0) {
			std::cout << "Some thread failed. Aborting." << std::endl;
			return 1;
		}
	}
	return 0;
}

static void usage(char *argv[])
{
	fprintf(stderr, "Usage: %s store_path repair_depth target_hash <mini_i> <maxi_i>\n", argv[0]);
	fprintf(stderr, "  store_path: Path to the data store.\n");
	fprintf(stderr, "  repair_depth: 1 or 2. Use 1 before 2.\n");
	fprintf(stderr, "  target_hash: Use empty string for 'any'.\n");
	fprintf(stderr, "               'repair_depth == 2' does not accept any (too slow).\n");
	fprintf(stderr, "  mini_i: (only with 'repair_depth == 2'): minimum (included) byte to try the first bit-flip.\n");
	fprintf(stderr, "  maxi_i: (only with 'repair_depth == 2'): maximum (excluded) byte to try the first bit-flip.\n");
}

int main(int argc, char *argv[])
{
	if(argc < 4) {
		usage(argv);
		return 1;
	}

	/* Parse command-line arguments */
	std::string store_path(argv[1]);
	size_t repair_depth = std::stoul(argv[2]);
	if (repair_depth < 1 || (repair_depth > 2)) {
		usage(argv);
		fprintf(stderr, "\nInvalid repair_depth value: %zu\n", repair_depth);
	}
	std::string target_hash(argv[3]);
	size_t first_mini_i = 0;
	size_t first_maxi_i = SIZE_MAX;
	if (repair_depth == 2) {
		if (target_hash == "") {
			usage(argv);
			fprintf(stderr, "\n`target_hash` must be set for repair == 2\n");
			return 1;
		}
		if(argc < 6) {
			usage(argv);
			return 1;
		}
		first_mini_i = std::stoul(argv[4]);
		first_maxi_i = std::stoul(argv[5]);
	}

	setvbuf(stdout, NULL, _IOLBF, 0);

	unsigned int threads_number = std::thread::hardware_concurrency();
	if (threads_number == 0) {
		threads_number = 1; /* unknown, use 1 */
	}
	//threads_number = 1; /* For debugging use */

	ThreadPool pool(threads_number);
	std::vector< std::future<int> > results;

	int ret = process_store(store_path, target_hash, repair_depth, first_mini_i, first_maxi_i, threads_number);

	std::cout << "Finished!" << std::endl;
	return ret;
}
