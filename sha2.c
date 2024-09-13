/*
 * Copyright 2011 ArtForz
 * Copyright 2011-2013 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#define _GNU_SOURCE
#include "cpuminer-config.h"
#include "miner.h"
#include "randomx.h"
#include "affinity.h"
#include <string.h>
#include <inttypes.h>
#include "sha256.h"
#include <pthread.h>
#include <sched.h>

#ifdef __x86_64__
#include <cpuid.h>
#endif

static const uint32_t sha256_h[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

void sha256_init(uint32_t *state)
{
	memcpy(state, sha256_h, 32);
}

static const uint32_t sha256d_hash1[16] = {
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x80000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000100};


void sha256d(unsigned char *hash, const unsigned char *data, int len)
{
	// BYTE buf[SHA256_BLOCK_SIZE];
	// SHA256_CTX ctx;
	// sha256_init_(&ctx);
	// sha256_update_(&ctx, data, len);
	// sha256_final_(&ctx, buf);
	// sha256_init_(&ctx);
	// sha256_update_(&ctx, buf, SHA256_BLOCK_SIZE);
	// sha256_final_(&ctx, hash);
	uint32_t S[16], T[16];
	int i, r;

	sha256_init(S);
	for (r = len; r > -9; r -= 64)
	{
		if (r < 64)
			memset(T, 0, 64);
		memcpy(T, data + len - r, r > 64 ? 64 : (r < 0 ? 0 : r));
		if (r >= 0 && r < 64)
			((unsigned char *)T)[r] = 0x80;
		for (i = 0; i < 16; i++)
			T[i] = be32dec(T + i);
		if (r < 56)
			T[15] = 8 * len;
		sha256_transform(S, T, 0);
	}
	memcpy(S + 8, sha256d_hash1 + 8, 32);
	sha256_init(T);
	sha256_transform(T, S, 0);
	for (i = 0; i < 8; i++)
		be32enc((uint32_t *)hash + i, T[i]);
}



typedef struct  {
	randomx_dataset *dataset;
	randomx_cache *cache;
	uint32_t startItem;
	uint32_t itemCount;
	int cpu_id;
}dataset_init_thread_args;

static inline void set_cpu_affinity(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    int result = sched_setaffinity(0, sizeof(set), &set);
    if (result == 0) {
        applog(LOG_INFO, "Successfully set CPU affinity to CPU %d.\n", cpu);
    } else {
        applog(LOG_ERR, "Failed to set CPU affinity.\n");
    }
}

void randomx_init_dataset_thread(dataset_init_thread_args* args) {
    // Set CPU affinity
    set_cpu_affinity(args->cpu_id % 20);
    randomx_init_dataset(args->dataset, args->cache, args->startItem, args->itemCount);
}

static uint8_t previous_seed[32] = {0};
static randomx_dataset *current_dataset = NULL;
static randomx_vm **current_vms = NULL;

int scanhash_randomx(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                     uint32_t max_nonce, unsigned long *hashes_done)
{
    struct timeval tv_start, tv_end, diff;
    randomx_dataset *dataset = NULL;
    randomx_vm **vms = NULL;
    int miningThreadCount = opt_mining_threads;
    int initThreadCount = opt_init_threads;
    gettimeofday(&tv_start, NULL);
    randomx_flags flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES;
    
    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    uint8_t seed[32];
    // pdata[19] = 0;
    uint32_t keystore[4] = {pdata[0], pdata[17]/345678, pdata[18], 0};
    char pdata_hex[161] = {0};
    bin2hex(pdata_hex, (unsigned char *)pdata, 80);
    applog(LOG_INFO, "pdata_for_seed: %s", pdata_hex);
    sha256d(seed, (unsigned char *)keystore, 16);

    char seed_hex[65] = {0};
    bin2hex(seed_hex, (unsigned char *)seed, 32);

    applog(LOG_INFO, "seed: %s", seed_hex);
    char target_str[65] = {0};
    uint32_t target_be[8];
    for (int i = 0; i < 8; i++)
    {
        be32enc(target_be + i, ptarget[7 - i]);
    }
    bin2hex(target_str, (unsigned char *)target_be, 32);
    applog(LOG_INFO, "target: %s", target_str);

    // Check if the seed has changed
    if (memcmp(seed, previous_seed, 32) != 0) {
        // Seed has changed, reinitialize everything
        if (current_dataset) {
            randomx_release_dataset(current_dataset);
            current_dataset = NULL;
        }
        if (current_vms) {
            for (int i = 0; i < miningThreadCount; ++i) {
                if (current_vms[i]) {
                    randomx_destroy_vm(current_vms[i]);
                }
            }
            free(current_vms);
            current_vms = NULL;
        }

		randomx_cache *cache = randomx_alloc_cache(flags);
		if (!cache)
		{
			applog(LOG_ERR, "randomx_alloc_cache() failed");
			return 0;
		}
        randomx_init_cache(cache, seed, sizeof(seed));

        // Initialize dataset
        dataset = randomx_alloc_dataset(flags);
        if (!dataset)
        {
            applog(LOG_ERR, "randomx_alloc_dataset() failed");
            randomx_release_cache(cache);
            return 0;
        }
        uint32_t datasetItemCount = randomx_dataset_item_count();
        pthread_t* init_threads = malloc(sizeof(pthread_t) * initThreadCount);
        dataset_init_thread_args* init_thread_args = malloc(sizeof(dataset_init_thread_args) * initThreadCount);

        if (!init_threads || !init_thread_args) {
            applog(LOG_ERR, "Failed to allocate memory for init threads");
            randomx_release_dataset(dataset);
            randomx_release_cache(cache);
            free(init_threads);
            free(init_thread_args);
            return 0;
        }

        int perThread = datasetItemCount / initThreadCount;
        int remainder = datasetItemCount % initThreadCount;
        uint32_t startItem = 0;
        for (int i = 0; i < initThreadCount; ++i) {
            int count = perThread + (i == initThreadCount - 1 ? remainder : 0);
            init_thread_args[i] = (dataset_init_thread_args){
                dataset,
                cache,
                startItem,
                count,
                i  // Use thread index as CPU ID for affinity
            };
            if (pthread_create(&init_threads[i], NULL, (void *)randomx_init_dataset_thread, &init_thread_args[i]) != 0) {
                applog(LOG_ERR, "Failed to create init thread %d", i);
                // Clean up and return
                for (int j = 0; j < i; ++j) {
                    pthread_join(init_threads[j], NULL);
                }
                randomx_release_dataset(dataset);
                randomx_release_cache(cache);
                free(init_threads);
                free(init_thread_args);
                return 0;
            }
            startItem += count;
        }
        for (int i = 0; i < initThreadCount; ++i) {
            pthread_join(init_threads[i], NULL);
        }

        free(init_threads);
        free(init_thread_args);
        randomx_release_cache(cache);

        // Create new VMs
        vms = malloc(sizeof(randomx_vm*) * miningThreadCount);
        if (!vms) {
            applog(LOG_ERR, "Failed to allocate memory for VMs");
            randomx_release_dataset(dataset);
            return 0;
        }
        for (int i = 0; i < miningThreadCount; ++i) {
            vms[i] = randomx_create_vm(flags, NULL, dataset);
            if (!vms[i]) {
                applog(LOG_ERR, "randomx_create_vm() failed for thread %d", i);
                for (int j = 0; j < i; ++j) {
                    randomx_destroy_vm(vms[j]);
                }
                randomx_release_dataset(dataset);
                free(vms);
                return 0;
            }
        }

        // Update the previous seed
        memcpy(previous_seed, seed, 32);
        current_dataset = dataset;
        current_vms = vms;
    } else {
        // Seed hasn't changed, use existing dataset and VMs
        dataset = current_dataset;
        vms = current_vms;
    }

    gettimeofday(&tv_end, NULL);
    timeval_subtract(&diff, &tv_end, &tv_start);
    applog(LOG_DEBUG, "randomx initializing in %d ms",
            diff.tv_sec * 1000 + diff.tv_usec / 1000);

    // Mining thread function
    struct mining_thread_args {
        randomx_vm *vm;
        uint32_t *pdata;
        const uint32_t *ptarget;
        uint32_t start_nonce;
        uint32_t end_nonce;
        int *found;
        uint32_t *result_nonce;
        int cpu_id;
        unsigned long *thread_hashes_done;
        int thr_id;
        volatile unsigned long *restart_flag;
    };

    void *mining_thread(void *arg) {
        struct mining_thread_args *args = (struct mining_thread_args *)arg;
        set_cpu_affinity(args->cpu_id);
        uint32_t hash[8] __attribute__((aligned(32)));
        uint32_t input[20];
        memcpy(input, args->pdata, 80);

        unsigned long hashes_done = 0;
        for (uint32_t n = args->start_nonce; n < args->end_nonce && !(*args->found); ++n) {
            if (*args->restart_flag) {
                *args->thread_hashes_done = hashes_done;
                return NULL;
            }
            input[19] = n;
            randomx_calculate_hash(args->vm, input, 80, hash);
            hashes_done++;
            if (fulltest(hash, args->ptarget)) {
                *args->found = 1;
                *args->result_nonce = n;
                *args->thread_hashes_done = hashes_done;
                return NULL;
            }
        }
        *args->thread_hashes_done = hashes_done;
        return NULL;
    }

    // Start mining threads
    pthread_t *mining_threads = malloc(sizeof(pthread_t) * miningThreadCount);
    struct mining_thread_args *thread_args = malloc(sizeof(struct mining_thread_args) * miningThreadCount);
    if (!mining_threads || !thread_args) {
        applog(LOG_ERR, "Failed to allocate memory for mining threads");
        free(mining_threads);
        free(thread_args);
        return 0;
    }

    int found = 0;
    uint32_t result_nonce = 0;
    uint32_t nonces_per_thread = (max_nonce - n) / miningThreadCount;

    unsigned long *thread_hashes_done = calloc(miningThreadCount, sizeof(unsigned long));
    if (!thread_hashes_done) {
        applog(LOG_ERR, "Failed to allocate memory for thread hash counters");
        free(mining_threads);
        free(thread_args);
        return 0;
    }

    for (int i = 0; i < miningThreadCount; ++i) {
        thread_args[i].vm = vms[i];
        thread_args[i].pdata = pdata;
        thread_args[i].ptarget = ptarget;
        thread_args[i].start_nonce = n + i * nonces_per_thread;
        thread_args[i].end_nonce = (i == miningThreadCount - 1) ? max_nonce : n + (i + 1) * nonces_per_thread;
        thread_args[i].found = &found;
        thread_args[i].result_nonce = &result_nonce;
        thread_args[i].cpu_id = (i + 1);  // Offset CPU IDs to avoid overlap with init threads
        thread_args[i].thread_hashes_done = &thread_hashes_done[i];
        thread_args[i].thr_id = thr_id;
        thread_args[i].restart_flag = &work_restart[thr_id].restart;
        if (pthread_create(&mining_threads[i], NULL, mining_thread, &thread_args[i]) != 0) {
            applog(LOG_ERR, "Failed to create mining thread %d", i);
            // Clean up and return
            for (int j = 0; j < i; ++j) {
                pthread_join(mining_threads[j], NULL);
            }
            free(mining_threads);
            free(thread_args);
            free(thread_hashes_done);
            return 0;
        }
    }

    // Wait for mining threads to complete
    for (int i = 0; i < miningThreadCount; ++i) {
        pthread_join(mining_threads[i], NULL);
    }

    // Clean up
    free(mining_threads);
    free(thread_args);

    unsigned long total_hashes_done = 0;
    for (int i = 0; i < miningThreadCount; ++i) {
        total_hashes_done += thread_hashes_done[i];
    }

    *hashes_done = total_hashes_done;

    free(thread_hashes_done);

    if (found) {
        pdata[19] = result_nonce;
        return 1;
    }

    return 0;
}