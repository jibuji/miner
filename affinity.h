

#ifndef AFFINITY_H
#define AFFINITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int set_thread_affinity(const unsigned int cpuid);
int set_thread_affinity_native(void* thread, const unsigned int cpuid);
unsigned int cpuid_from_mask(uint64_t mask, const unsigned int thread_index);
char* mask_to_string(uint64_t mask);

#ifdef __cplusplus
}
#endif

#endif /* AFFINITY_H */
