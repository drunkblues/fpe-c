/**
 * @file pthread_barrier_compat.c
 * @brief pthread_barrier compatibility implementation for macOS
 */

#include "pthread_barrier_compat.h"
#include <stdlib.h>

#ifdef __APPLE__

int pthread_barrier_init(pthread_barrier_t *barrier,
                       const void *attr,
                       unsigned int count) {
    if (count == 0) {
        return EINVAL;
    }

    int rc;

    if (pthread_mutex_init(&barrier->mutex, NULL) != 0) {
        return -1;
    }

    if (pthread_cond_init(&barrier->cond, NULL) != 0) {
        pthread_mutex_destroy(&barrier->mutex);
        return -1;
    }

    barrier->count = 0;
    barrier->trip_count = count;

    return 0;
}

int pthread_barrier_destroy(pthread_barrier_t *barrier) {
    pthread_mutex_destroy(&barrier->mutex);
    pthread_cond_destroy(&barrier->cond);
    return 0;
}

int pthread_barrier_wait(pthread_barrier_t *barrier) {
    pthread_mutex_lock(&barrier->mutex);

    ++(barrier->count);

    if (barrier->count >= barrier->trip_count) {
        barrier->count = 0;
        pthread_cond_broadcast(&barrier->cond);
        pthread_mutex_unlock(&barrier->mutex);
        return PTHREAD_BARRIER_SERIAL_THREAD;
    } else {
        pthread_cond_wait(&barrier->cond, &barrier->mutex);
        pthread_mutex_unlock(&barrier->mutex);
        return 0;
    }
}

#endif
