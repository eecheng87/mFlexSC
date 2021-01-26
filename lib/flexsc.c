#include "flexsc.h"
#include <pthread.h>

#define ENTRY_PER_SYSPAGE 64

static void create_kv_thread(struct flexsc_init_info *info);
static inline int user_lock_init(void);
static void __flexsc_register(struct flexsc_init_info *info);
// static void flexsc_wait(void);

pthread_spinlock_t spin_free_entry[NUM_OF_USRCPU], spin_user_pending;

struct flexsc_init_info *u_info;
int entry_per_syspage = 0;

static void __flexsc_register(struct flexsc_init_info *info) {
    syscall(__NR_flexsc_register, info);
}

/* return empty entry */
static struct flexsc_sysentry *get_free_syscall_entry(int cpu) {
retry:
    pthread_spin_lock(&spin_free_entry[cpu]);
    int i, j;
    for (i = USR_CPU_BASE + cpu * entry_per_syspage, j = 0;
         j < entry_per_syspage; j++, i++) {
        if (u_info->sysentry[i].rstatus == FLEXSC_STATUS_FREE) {
            u_info->sysentry[i].rstatus = FLEXSC_STATUS_BUSY;
            pthread_spin_unlock(&spin_free_entry[cpu]);
            return &u_info->sysentry[i];
        }
    }

    pthread_spin_unlock(&spin_free_entry[cpu]);
    if (syscall_runner == IDLE)
        syscall_runner = IN_PROGRESS;
    else if (syscall_runner == DONE) {
        puts("warning: get free syscall page at DONE state");
        syscall_runner = IN_PROGRESS;
    }
    pthread_yield();
    goto retry;
}

/* general function to request system call from user space */
long flexsc_do_syscall(int cpu) {
    /* for convenient force syscall be `getpid()` in experiment */
    long retval;
    struct flexsc_sysentry *entry = entry = get_free_syscall_entry(cpu);

    entry->sysnum = 39;
    /*
        entry->args[0] = ...

    */
    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_yield();
    }
    /* status must be FLEXSC_STATUS_FREE now */
    return entry->sysret;
}

static void init_cpuinfo_default(struct flexsc_cpuinfo *cpuinfo) {

    cpuinfo->user_cpu = FLEXSC_CPU_0 | FLEXSC_CPU_1;
    cpuinfo->kernel_cpu = FLEXSC_CPU_2 | FLEXSC_CPU_3;
}

static int init_user_affinity(struct flexsc_cpuinfo *ucpu) {
    cpu_set_t user_set;
    int ucpus = ucpu->user_cpu;
    int cpu_no = 0;

    /* init */
    CPU_ZERO(&user_set);

    while (ucpus) {
        if (ucpus & 0x1) {
            CPU_SET(cpu_no, &user_set);
        }

        ucpus >>= 1;
        ++cpu_no;
    }

    if (-1 == sched_setaffinity(0, sizeof(cpu_set_t), &user_set)) {
        return -1;
    }

    return 0;
}

/* Prevent syspage from swapped out */
static int init_lock_syspage(struct flexsc_init_info *info) {
    int error;

    if (!info->sysentry) {
        printf("info->sysentry is NULL");
        return -1;
    }

    error = mlock(
        info->sysentry,
        info->total_bytes); /* mlock treat unit of `len` as pages, which means
                               we don't need to care redundant bytes */
    if (error) {
        printf("Failed to mlock `syspage`");
        return -1;
    }

    /*if (!info->write_page) {
        printf("info->sysentry is NULL at -->> %s\n", __func__);
        return -1;
    }

    error = mlock(info->write_page, 100000);
    if (error) {
        printf("Failed to mlock `syspage` at -->> %s\n", __func__);
        return -1;
    }*/

    return 0;
}

/* ok */
static int init_map_syspage(struct flexsc_init_info *info) {
    size_t pgsize = getpagesize();

    size_t total = pgsize;

    /* it is guaranteed that mod 0 */
    /* each user cpu has their own syspage */
    entry_per_syspage =
        total / (NUM_OF_USRCPU * (sizeof(struct flexsc_sysentry)));
    struct flexsc_sysentry *entry;

    info->npages = NUM_OF_USRCPU;

    /* only support single page mapping to kernel */
    /* but we cut one continuous memory(syspage) into several segments */
    /* each segment belong to each user cpu */
    /* size must be integral multiple of alignment */
    entry = (struct flexsc_sysentry *)aligned_alloc(pgsize, pgsize);
    if (!entry)
        return -1;

    for (int i = 0; i < info->npages * entry_per_syspage; i++) {
        entry[i].rstatus = FLEXSC_STATUS_FREE;
    }

    info->nentry = entry_per_syspage;
    info->sysentry = entry;
    info->total_bytes = total;

    /* print_sysentry(&(info->sysentry[0])); */

    return 0;
}

/* ok */
static int init_info_default(struct flexsc_init_info *info) {
    /* Allocate syspage and map it to user space */
    if (init_map_syspage(info) < 0) {
        return -1;
    }

    if (init_lock_syspage(info) < 0) {
        return -1;
    }

    init_cpuinfo_default(&(info->cpuinfo));

    /* set CPU affinity for user threads */
    init_user_affinity(&(info->cpuinfo));

    return 0;
}

/* ok */
static int init_info(struct flexsc_init_info *info) {
    return init_info_default(info);
}

struct flexsc_init_info *flexsc_register(struct flexsc_init_info *info) {
    if (!info) {
        printf("info is NULL\n");
        return NULL;
    }

    u_info = info;

    if (init_info(u_info) < 0) {
        printf("Fail to initial info");
        return NULL;
    }

    if (user_lock_init() < 0)
        /* TODO: cleanup should be impl (free(syspage...etc)) */
        return NULL;

    /* kernel initial */
    __flexsc_register(u_info);

    return info;
}

long flexsc_exit(void) {
    long ret;

    ret = syscall(__NR_flexsc_exit);

    pthread_spin_destroy(&spin_free_entry);
    pthread_spin_destroy(&spin_user_pending);

    free(u_info->sysentry);
    free(u_info);

    return ret;
}

/*
static void flexsc_wait(void)
{
    syscall(SYSCALL_FLEXSC_WAIT);
}
*/

/* create kernel-visible threads for per core */
static void create_kv_thread(void *(*u_worker)(void *)) {
    int i;

    /* set user thread's affinity */
    for (i = 0; i < USR_THREAD_NUM; i++) {
        CPU_ZERO(&(u_cpu[i]));
        /* need to re-write if num of usr cpu change */
        if (i & 0x1)
            CPU_SET(0, &(u_cpu[i]));
        else
            CPU_SET(1, &(u_cpu[i]));

        if (pthread_attr_init(&(u_attr[i]))) {
            printf("Fail to initialize u%d attr\n", i);
            exit(-1);
        }

        if (pthread_attr_setaffinity_np(&(u_attr[i]), sizeof(cpu_set_t),
                                        &(u_cpu[i]))) {
            printf("Fail to initialize u%d's cpu affinity\n", i);
            exit(-1);
        }
    }
    /* spawn user thread */
    for (i = 0; i < USR_THREAD_NUM; i++) {
        pthread_create(&user_thread[i], &u_attr[i], worker, NULL);
    }
}

static void destroy_kv_thread() {
    for (int i = 0; i < USR_THREAD_NUM; i++) {
        pthread_join(user_thread[i], NULL);
    }
}

static inline int user_lock_init(void) {
    for (int i = USR_CPU_BASE; i < USR_CPU_BASE + NUM_OF_USRCPU; i++)
        if (pthread_spin_init(&spin_free_entry[i], PTHREAD_PROCESS_PRIVATE))
            return -1;
    if (pthread_spin_init(&spin_user_pending, PTHREAD_PROCESS_PRIVATE))
        return -1;

    return 0;
}

void ttest() { return; }