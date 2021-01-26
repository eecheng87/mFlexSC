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
#include <unistd.h>

#define test_file "log_file"
#define test_msg "/testmsg"

/* thread worker */
void *worker(void *para) { printf("hihi "); }

int main() {
    pthread_t thread[USR_THREAD_NUM];
    int i;
    // fd = open(test_file, O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR | S_IRGRP |
    // S_IWGRP | S_IROTH);

    // struct flexsc_init_info *flexsc_info = (struct flexsc_init_info*)
    // malloc(sizeof(struct flexsc_init_info));

    /*if (flexsc_register(flexsc_info) < 0) {
        printf("Fail to register\n");
        exit(-1);
    }*/

    /* create user thread */
    create_kv_thread(worker);

    /*struct flexsc_sysentry *entry = flexsc_info->sysentry;
    entry[0].sysnum = 39;
    entry[0].rstatus = FLEXSC_STATUS_SUBMITTED;

    while(entry[0].rstatus != FLEXSC_STATUS_DONE);
    printf("return value: %d\n", entry[0].sysret);
    printf("pid: %d\n", getpid());
    close(fd);*/

    /* join thread */
    destroy_kv_thread();
    // flexsc_exit();
    ttest();
    return 0;
}
