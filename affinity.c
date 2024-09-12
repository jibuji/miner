#include <stdio.h>
#include <stdlib.h>
#include "affinity.h"
#include "miner.h"

#if defined(_WIN32) || defined(__CYGWIN__)
  #include <windows.h>
#else
  #ifdef __APPLE__
    #include <mach/thread_act.h>
    #include <mach/thread_policy.h>
  #else
    #define _GNU_SOURCE
    #include <sched.h>
  #endif
  #include <pthread.h>
#endif


int
set_thread_affinity(const unsigned int cpuid)
{
    void* thread;
#if defined(_WIN32) || defined(__CYGWIN__)
    thread = (void*)GetCurrentThread();
#else
    thread = (void*)pthread_self();
#endif
    return set_thread_affinity_native(thread, cpuid);
}

int
set_thread_affinity_native(void* thread, const unsigned int cpuid)
{
    int rc = -1;
#ifdef __APPLE__
    thread_port_t mach_thread;
    thread_affinity_policy_data_t policy = { (integer_t)cpuid };
    mach_thread = pthread_mach_thread_np((pthread_t)thread);
    rc = thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
            (thread_policy_t)&policy, 1);
    if (rc != 0) {
        applog(LOG_ERR, "Failed to set thread affinity on macOS: %d", rc);
    }
#elif defined(_WIN32) || defined(__CYGWIN__)
    rc = SetThreadAffinityMask((HANDLE)thread, 1ULL << cpuid) == 0 ? -2 : 0;
    if (rc != 0) {
        applog(LOG_ERR, "Failed to set thread affinity on Windows: %d", GetLastError());
    }
#elif !defined(__OpenBSD__) && !defined(__FreeBSD__) && !defined(__ANDROID__) && !defined(__NetBSD__)
    #ifdef CPU_ZERO
    cpu_set_t cs;
    CPU_ZERO(&cs);
    CPU_SET(cpuid, &cs);
    rc = pthread_setaffinity_np((pthread_t)thread, sizeof(cpu_set_t), &cs);
    if (rc != 0) {
        applog(LOG_ERR, "Failed to set thread affinity: %s", strerror(rc));
    }
    #else
    rc = -1; // Indicate that affinity setting is not supported
    applog(LOG_WARNING, "Thread affinity not supported on this system");
    #endif
#endif
    return rc;
}

unsigned int
cpuid_from_mask(uint64_t mask, const unsigned int thread_index)
{
    static unsigned int lookup[64];
    static int init = 0;
    if (init)
        return lookup[thread_index];
    unsigned int count_found = 0;
    for (unsigned int i = 0; i < 64; i++)
    {
        if (1ULL & mask)
        {
            lookup[count_found] = i;
            count_found++;
        }
        mask >>= 1;
    }
    init = 1;
    return lookup[thread_index];
}

char*
mask_to_string(uint64_t mask)
{
    char* result = (char*)malloc(65 * sizeof(char));  // 64 bits + null terminator
    if (result == NULL) {
        return NULL;
    }

    unsigned int len = 0;
    unsigned int v = 0;
    unsigned int i = 64;
    int pos = 0;

    while (i--)
    {
        v = mask >> i;
        if (1ULL & v)
        {
            if (len == 0) len = i + 1;
            result[pos++] = '1';
        }
        else if (len > 0)
        {
            result[pos++] = '0';
        }
    }
    result[pos] = '\0';

    return result;
}
