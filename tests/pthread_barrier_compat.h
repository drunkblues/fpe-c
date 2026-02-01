/**
 * @file pthread_barrier_compat.h
 * @brief pthread_barrier compatibility layer for macOS
 *
 * macOS does not support pthread_barrier_t (not part of POSIX on macOS).
 * This file provides a compatibility implementation using pthread condition variables.
 */

#ifndef PTHREAD_BARRIER_COMPAT_H
#define PTHREAD_BARRIER_COMPAT_H

#include <pthread.h>
#include <errno.h>

#ifdef __APPLE__

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int count;
    int trip_count;
} pthread_barrier_t;

#define PTHREAD_BARRIER_SERIAL_THREAD (-1)

int pthread_barrier_init(pthread_barrier_t *barrier,
                       const void *attr,
                       unsigned int count);

int pthread_barrier_destroy(pthread_barrier_t *barrier);

int pthread_barrier_wait(pthread_barrier_t *barrier);

#endif

#endif
