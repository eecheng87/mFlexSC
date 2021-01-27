/*

    This program is profiling performance use

*/

#include "../lib/flexsc.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define test_file "log_file"
#define test_msg "/testmsg"
#define WORKER_IT_TIME 10
#define FLEXSC 1

pthread_mutex_t lock;

long get_elapse(struct timespec start, struct timespec end) {
    return ((long)1.0e+9 * end.tv_sec + end.tv_nsec) -
           ((long)1.0e+9 * start.tv_sec + start.tv_nsec);
}

/* general function to request system call from user space */
void *worker(void *arg) {
    /* for convenient force syscall be `getpid()` in experiment */
    long retval;
    struct flexsc_sysentry *entry;
    struct timespec t1, t2;
    int cpu = *((int *)arg);
    for (int i = 0; i < WORKER_IT_TIME; i++) {
        clock_gettime(CLOCK_REALTIME, &t1);
#ifdef FLEXSC

        /* find empty entry in cpux's syspage */
        entry = get_free_syscall_entry(cpu);

        entry->sysnum = 39;
        /*
            if there're some argument, example:
            entry->args[0] = ...

        */

        /* busy->submitted */
        entry->rstatus = FLEXSC_STATUS_SUBMITTED;
        while (entry->rstatus != FLEXSC_STATUS_DONE) {
            pthread_yield();
        }
        /* status must be FLEXSC_STATUS_FREE now */
        entry->rstatus = FLEXSC_STATUS_FREE;

#else
        /* normal(synchronous) system call */
        syscall(39);
        pthread_yield();
#endif
        clock_gettime(CLOCK_REALTIME, &t2);
        pthread_mutex_lock(&lock);
        printf("%ld\n", get_elapse(t1, t2));
        pthread_mutex_unlock(&lock);
    }
}

int main() {
    int i;

    struct flexsc_init_info *flexsc_info =
        (struct flexsc_init_info *)malloc(sizeof(struct flexsc_init_info));

    if (pthread_mutex_init(&lock, NULL) != 0) {
        printf("Fail to initialize mutex lock\n");
        exit(-1);
    }
    if (flexsc_register(flexsc_info) < 0) {
        printf("Fail to register\n");
        exit(-1);
    }

    /* create user thread */
    create_kv_thread(worker);

    /* join thread */
    destroy_kv_thread();
    flexsc_exit();
    ttest();
    return 0;
}
