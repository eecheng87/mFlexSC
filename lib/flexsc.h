#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "flexsc_type.h"

/* we use these flags to determine if syscall need handled */
#define IDLE 1
#define IN_PROGRESS 2
#define DONE 3

/* if reached, we consider requested syscalls are all done */
#define DONE_CNT 3

/* cpu info */
#define FLEXSC_CPU_CLEAR 0x00000000
#define FLEXSC_CPU_0 0x00000001
#define FLEXSC_CPU_1 0x00000002
#define FLEXSC_CPU_2 0x00000004
#define FLEXSC_CPU_3 0x00000008
void ttest();

static void __flexsc_register(struct flexsc_init_info *);
static void init_cpuinfo_default(struct flexsc_cpuinfo *);
static int init_user_affinity(struct flexsc_cpuinfo *);
static int init_lock_syspage(struct flexsc_init_info *);
static int init_map_syspage(struct flexsc_init_info *);
static int init_info_default(struct flexsc_init_info *);
static int init_info(struct flexsc_init_info *);
void print_init_info(struct flexsc_init_info *);
struct flexsc_init_info *flexsc_register(struct flexsc_init_info *);
long flexsc_exit(void);
static void create_kv_thread(struct flexsc_init_info *);
static inline int user_lock_init(void);
void flexsc_start_syscall(void);


