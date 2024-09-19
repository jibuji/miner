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
#include <unistd.h>
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
	BYTE buf[SHA256_BLOCK_SIZE];
	SHA256_CTX ctx;
	sha256_init_(&ctx);
	sha256_update_(&ctx, data, len);
	sha256_final_(&ctx, buf);
	sha256_init_(&ctx);
	sha256_update_(&ctx, buf, SHA256_BLOCK_SIZE);
	sha256_final_(&ctx, hash);
}


static inline void set_cpu_affinity(int cpu) {
#ifdef __linux__
	cpu = cpu % num_processors;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);

    int result = sched_setaffinity(0, sizeof(set), &set);
    if (result == 0) {
        // applog(LOG_INFO, "Successfully set CPU affinity to CPU %d.\n", cpu);
    } else {
        applog(LOG_ERR, "Failed to set CPU %d affinity.\n", cpu);
    }
#elif defined(__APPLE__)
    // macOS doesn't support setting CPU affinity in the same way
    // You might want to use thread_policy_set() here if you need similar functionality
    // For now, we'll just log a message
    applog(LOG_INFO, "CPU affinity setting is not supported on macOS (requested CPU: %d).\n", cpu);
#else
    applog(LOG_INFO, "CPU affinity setting is not supported on this platform (requested CPU: %d).\n", cpu);
#endif
}

typedef struct  {
       randomx_dataset *dataset;
       randomx_cache *cache;
       uint32_t startItem;
       uint32_t itemCount;
       int cpu_id;
}dataset_init_thread_args;



void randomx_init_dataset_thread(dataset_init_thread_args* args) {
    // Set CPU affinity
    set_cpu_affinity(args->cpu_id);
    randomx_init_dataset(args->dataset, args->cache, args->startItem, args->itemCount);
}



// Step 1: Refactor configuration variables
static int miningThreadCount;
static int initThreadCount;
static randomx_flags flags;

static bool huge_page_working = true; //  0: no, 1: yes
static void init_randomx_config() {
    miningThreadCount = opt_mining_threads;
    initThreadCount = opt_init_threads;
    flags = randomx_get_flags() | RANDOMX_FLAG_FULL_MEM | (huge_page_working ? RANDOMX_FLAG_LARGE_PAGES : 0);
}

// Step 2: Introduce randomx_context struct
typedef struct {
    randomx_dataset *dataset;
    randomx_vm **vms;
    uint8_t seed[32];
    int found;
    uint32_t result_nonce;
} randomx_context;

static randomx_context ctx = {0};
static uint8_t previous_seed[32] = {0};

// Step 3: Extract RandomX initialization
static bool initialize_randomx(randomx_context *ctx, randomx_flags flags) {
    if (ctx->dataset) {
        randomx_release_dataset(ctx->dataset);
        ctx->dataset = NULL;
    }
    if (ctx->vms) {
        for (int i = 0; i < miningThreadCount; ++i) {
            if (ctx->vms[i]) {
                randomx_destroy_vm(ctx->vms[i]);
            }
        }
        free(ctx->vms);
        ctx->vms = NULL;
    }

    randomx_cache *cache = randomx_alloc_cache(flags);
    if (!cache) {
		if (huge_page_working) {
			applog(LOG_WARNING, "randomx_alloc_cache() failed, trying to allocate without huge pages");
			huge_page_working = false;
			flags = flags & ~RANDOMX_FLAG_LARGE_PAGES;
			cache = randomx_alloc_cache(flags);
			if (!cache) {
				applog(LOG_ERR, "randomx_alloc_cache() failed even without huge pages");
				return false;
			}
			applog(LOG_WARNING, "randomx_alloc_cache() succeeded without huge pages");
		} else {
			applog(LOG_ERR, "randomx_alloc_cache() failed");
			return false;
		}
    }

    randomx_init_cache(cache, ctx->seed, sizeof(ctx->seed));

    ctx->dataset = randomx_alloc_dataset(flags);
    if (!ctx->dataset) {
        applog(LOG_ERR, "randomx_alloc_dataset() failed");
        randomx_release_cache(cache);
        return false;
    }

    uint32_t datasetItemCount = randomx_dataset_item_count();
    pthread_t* init_threads = malloc(sizeof(pthread_t) * initThreadCount);
    dataset_init_thread_args* init_thread_args = malloc(sizeof(dataset_init_thread_args) * initThreadCount);

    if (!init_threads || !init_thread_args) {
        applog(LOG_ERR, "Failed to allocate memory for init threads");
        randomx_release_dataset(ctx->dataset);
        randomx_release_cache(cache);
        free(init_threads);
        free(init_thread_args);
        return false;
    }

    int perThread = datasetItemCount / initThreadCount;
    int remainder = datasetItemCount % initThreadCount;
    uint32_t startItem = 0;
    for (int i = 0; i < initThreadCount; ++i) {
        int count = perThread + (i == initThreadCount - 1 ? remainder : 0);
        init_thread_args[i] = (dataset_init_thread_args){
            ctx->dataset,
            cache,
            startItem,
            count,
            i
        };
        if (pthread_create(&init_threads[i], NULL, (void *)randomx_init_dataset_thread, &init_thread_args[i]) != 0) {
            applog(LOG_ERR, "Failed to create init thread %d", i);
            for (int j = 0; j < i; ++j) {
                pthread_join(init_threads[j], NULL);
            }
            randomx_release_dataset(ctx->dataset);
            randomx_release_cache(cache);
            free(init_threads);
            free(init_thread_args);
            return false;
        }
        startItem += count;
    }

    for (int i = 0; i < initThreadCount; ++i) {
        pthread_join(init_threads[i], NULL);
    }

    free(init_threads);
    free(init_thread_args);
    randomx_release_cache(cache);

    ctx->vms = malloc(sizeof(randomx_vm*) * miningThreadCount);
    if (!ctx->vms) {
        applog(LOG_ERR, "Failed to allocate memory for VMs");
        randomx_release_dataset(ctx->dataset);
        return false;
    }

    for (int i = 0; i < miningThreadCount; ++i) {
        ctx->vms[i] = randomx_create_vm(flags, NULL, ctx->dataset);
        if (!ctx->vms[i]) {
            applog(LOG_ERR, "randomx_create_vm() failed for thread %d", i);
            for (int j = 0; j < i; ++j) {
                randomx_destroy_vm(ctx->vms[j]);
            }
            randomx_release_dataset(ctx->dataset);
            free(ctx->vms);
            return false;
        }
    }

    return true;
}

static void cleanup_mining_threads(pthread_t *threads, int count) {
    for (int i = 0; i < count; ++i) {
        pthread_join(threads[i], NULL);
    }
}

static unsigned long sum_hashes_done(unsigned long *thread_hashes, int count) {
    unsigned long total = 0;
    for (int i = 0; i < count; ++i) {
        total += thread_hashes[i];
    }
    return total;
}

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
    const uint32_t start = args->start_nonce;
    const uint32_t end = args-> end_nonce;
    const int* found = args->found;
    const volatile unsigned long *restart_flag = args->restart_flag;
    for (uint32_t n = start; n < end && !(*found); ++n) {
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

int scanhash_randomx(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
                     uint32_t max_nonce, unsigned long *hashes_done)
{
    init_randomx_config();

    struct timeval tv_start, tv_end, diff;
    gettimeofday(&tv_start, NULL);

    uint32_t n = pdata[19] - 1;
    const uint32_t first_nonce = pdata[19];
    uint32_t keystore[4] = {pdata[0], pdata[17]/345678, pdata[18], 0};
    char pdata_hex[161] = {0};
    bin2hex(pdata_hex, (unsigned char *)pdata, 80);
    applog(LOG_INFO, "pdata_for_seed: %s", pdata_hex);
    sha256d(ctx.seed, (unsigned char *)keystore, 16);

    char seed_hex[65] = {0};
    bin2hex(seed_hex, (unsigned char *)ctx.seed, 32);

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
    if (memcmp(ctx.seed, previous_seed, 32) != 0) {
        if (!initialize_randomx(&ctx, flags)) {
            return 0;
        }
        memcpy(previous_seed, ctx.seed, 32);
    }

    gettimeofday(&tv_end, NULL);
    timeval_subtract(&diff, &tv_end, &tv_start);
    applog(LOG_DEBUG, "randomx initializing in %d ms",
            diff.tv_sec * 1000 + diff.tv_usec / 1000);

    // Start mining threads
    pthread_t *mining_threads = malloc(sizeof(pthread_t) * miningThreadCount);
    struct mining_thread_args *thread_args = malloc(sizeof(struct mining_thread_args) * miningThreadCount);
    unsigned long *thread_hashes_done = calloc(miningThreadCount, sizeof(unsigned long));

    if (!mining_threads || !thread_args || !thread_hashes_done) {
        applog(LOG_ERR, "Failed to allocate memory for mining threads");
        free(mining_threads);
        free(thread_args);
        free(thread_hashes_done);
        return 0;
    }

    ctx.found = 0;
    ctx.result_nonce = 0;
    uint32_t nonces_per_thread = (max_nonce - pdata[19]) / miningThreadCount;

    // Point 4: Simplify thread creation
    for (int i = 0; i < miningThreadCount; ++i) {
        thread_args[i] = (struct mining_thread_args){
            .vm = ctx.vms[i],
            .pdata = pdata,
            .ptarget = ptarget,
            .start_nonce = pdata[19] + i * nonces_per_thread,
            .end_nonce = (i == miningThreadCount - 1) ? max_nonce : pdata[19] + (i + 1) * nonces_per_thread,
            .found = &ctx.found,
            .result_nonce = &ctx.result_nonce,
            .cpu_id = i + 1,
            .thread_hashes_done = &thread_hashes_done[i],
            .thr_id = thr_id,
            .restart_flag = &work_restart[thr_id].restart
        };

        if (pthread_create(&mining_threads[i], NULL, mining_thread, &thread_args[i]) != 0) {
            applog(LOG_ERR, "Failed to create mining thread %d", i);
            cleanup_mining_threads(mining_threads, i);
            free(mining_threads);
            free(thread_args);
            free(thread_hashes_done);
            return 0;
        }
    }

    // Wait for mining threads to complete
    cleanup_mining_threads(mining_threads, miningThreadCount);
    // Clean up
    free(mining_threads);
    free(thread_args);

    *hashes_done = sum_hashes_done(thread_hashes_done, miningThreadCount);

    free(thread_hashes_done);

    if (ctx.found) {
        pdata[19] = ctx.result_nonce;
        return 1;
    }

    return 0;
}