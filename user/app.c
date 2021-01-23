#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "../lib/flexsc.h"

#define test_file "log_file"
#define test_msg "test_msg"

int main(){
    int fd;
    char test[8] = test_msg;
    fd = open(test_file, O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR | S_IRGRP | S_IWGRP | S_IROTH);
    /*write(fd, test, sizeof(test));
    close(fd);*/
    struct flexsc_init_info *flexsc_info = (struct flexsc_init_info*) malloc(sizeof(struct flexsc_init_info));

    if (flexsc_register(flexsc_info) < 0) {
        printf("Fail to register\n");
        exit(-1);
    }

    struct flexsc_sysentry *entry = flexsc_info->sysentry;
    entry[0].sysnum = 1;
    entry[0].args[0] = fd;
    entry[0].args[1] = (long)test;
    entry[0].args[2] = sizeof(test);
    printf("%ld, %ld, %ld\n", entry[0].args[0], entry[0].args[1], entry[0].args[2]);
    entry[0].rstatus = FLEXSC_STATUS_SUBMITTED;

    while(entry[0].rstatus != FLEXSC_STATUS_DONE);

    flexsc_exit();
    ttest();
    return 0;
}
