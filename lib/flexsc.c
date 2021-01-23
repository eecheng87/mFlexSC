#include <pthread.h>
#include "flexsc.h"

/* from the Linux kernel */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#define ENTRY_PER_SYSPAGE 64

static void create_kv_thread(struct flexsc_init_info *info);
static inline int user_lock_init(void);
static void __flexsc_register(struct flexsc_init_info *info);
//static void flexsc_wait(void);


pthread_spinlock_t spin_free_entry, spin_user_pending;
pthread_cond_t user_wait = PTHREAD_COND_INITIALIZER;
pthread_mutex_t user_wait_cond = PTHREAD_MUTEX_INITIALIZER;

uint8_t syscall_runner = IDLE; /* this flag is set when user want syscalls to be executed or there has no free sysentry */

struct flexsc_init_info *u_info;

int entry_per_syspage = 0;

kv_thread_list_t kv_thread_list = {
    .tid = 0,
    .next = NULL,
};

static void __flexsc_register(struct flexsc_init_info *info)
{
    syscall(__NR_flexsc_register, info);
}

#if 0
/* flexsc_syscall start */
static struct flexsc_sysentry *get_free_syscall_entry(void)
{
retry:
    pthread_spin_lock(&spin_free_entry);

    for (int i = 0; i < u_info->npages; i++) {
        if (u_info->sysentry[i].rstatus == FLEXSC_STATUS_FREE) {
            /**
             * change rstatus to BUSY due to the page may being robbed once the lock is released
             * because it is not set to !FREE immediately after accquired by current thread.
             */
            u_info->sysentry[i].rstatus = FLEXSC_STATUS_BUSY;
            pthread_spin_unlock(&spin_free_entry);
            //printf("entry found (i = %d)\n", i);
            return &u_info->sysentry[i];
        }
    }

    pthread_spin_unlock(&spin_free_entry);
    //puts("entry not found");

/**
 * if we have plenty of user threads waiting here, we may facing high usage issue,
 * but if we use pthread_cond_wait on this, the wake up time from cond_wait
 * may be the penalty of performance.
 */
    //pthread_spin_lock(&spin_user_pending); //seems this is not need, because the correctness is not affected by it

    if (syscall_runner == IDLE)
        syscall_runner = IN_PROGRESS;
    else if (syscall_runner == DONE) {
        puts("warning: get free syscall page at DONE state");
        syscall_runner = IN_PROGRESS;
    }

    //pthread_spin_unlock(&spin_user_pending);

    pthread_yield();
    goto retry;
}
static inline ssize_t _flexsc_write(unsigned int fd, char *buf, size_t count)
{
    long retval;

    struct flexsc_sysentry *entry;

    entry = get_free_syscall_entry();

    /* fill syspage entry */
    request_syscall_write(entry, fd, buf, count);

    memcpy(u_info->write_page + (count * 10 /* sizeof dummy string */), buf, 10);
    __sync_synchronize();

    entry->rstatus = FLEXSC_STATUS_SUBMITTED;
    while (entry->rstatus != FLEXSC_STATUS_DONE) {
        pthread_yield();
    }
    retval = entry->args[0];

    entry->rstatus = FLEXSC_STATUS_FREE;

    return retval;
}

ssize_t flexsc_write(unsigned int fd, char *buf, size_t count, int exe)
{
    if (unlikely(exe)) {
        pthread_spin_lock(&spin_user_pending);
        syscall_runner = IN_PROGRESS;
        pthread_spin_unlock(&spin_user_pending);
    }
    return (ssize_t) _flexsc_write(fd, buf, count);
}
/* flexsc_syscall end */
#endif
/* worker of kernel-visible thread */
static void *kv_thread_worker(void *arg)
{
    struct kv_handle_syspg_num *handle_tmp = (struct kv_handle_syspg_num*) arg;

    /* copy to per-thread context */
    int start = handle_tmp->start;
    int end = handle_tmp->end;
    int idx;

    /**
     * syscall_runner is set by flexsc_syscall_start or when syspage is full,
     * once it's set, we start marking (marked syspage is processed ASAP) the
     * sumbitted syspage. As long as there exist at least one syspage is done,
     * we wake up waiting threads
     */
    while (1) {
        #if 0
        pthread_spin_lock(&spin_user_pending);
        if (likely(syscall_runner == IN_PROGRESS)) {
            //puts("kv_thread: syscall runner is still IN_PROGRESS");
            pthread_spin_unlock(&spin_user_pending);

            for (idx = start; idx < end; idx++) {
                //printf("current idx of kv_thread is: %d\n", idx);
                if (u_info->sysentry[idx].rstatus == FLEXSC_STATUS_SUBMITTED)
                    u_info->sysentry[idx].rstatus = FLEXSC_STATUS_MARKED;                    
                else if (u_info->sysentry[idx].rstatus == FLEXSC_STATUS_DONE)
                    pthread_cond_broadcast(&user_wait); /* application threads wait on this cond (SOME SYSCALL ONLY BUSYWAITING, WHICH MEANS THEY DON'T NEED THIS)*/
            }

            goto restart; /* calling pthread_spin_unlock twice is undefined-behavior */
        }

        pthread_spin_unlock(&spin_user_pending);
/* after test, jump to here won't make a notable performance penalty, if it does, we should use continue; in the context of if statement above */
restart:
        pthread_yield();
        #endif
    }

    // unreachable, just to silence gcc warning
    pthread_exit(NULL);
}

/* ok */
static void init_cpuinfo_default(struct flexsc_cpuinfo *cpuinfo)
{

    cpuinfo->user_cpu = FLEXSC_CPU_0 | FLEXSC_CPU_1;
    cpuinfo->kernel_cpu =  FLEXSC_CPU_2 | FLEXSC_CPU_3;
}

/* ok */
static int init_user_affinity(struct flexsc_cpuinfo *ucpu)
{
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

/* ok */
/* Prevent syspage from swapped out */
static int init_lock_syspage(struct flexsc_init_info *info)
{
    int error;

    if (!info->sysentry) {
        printf("info->sysentry is NULL");
        return -1;
    }

    error = mlock(info->sysentry, info->total_bytes); /* mlock treat unit of `len` as pages, which means we don't need to care redundant bytes */
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
static int init_map_syspage(struct flexsc_init_info *info)
{
    size_t pgsize = getpagesize();

    size_t total = pgsize;

    /* it is guaranteed that mod 0 */
    /* each user cpu has their own syspage */
    entry_per_syspage = total / (NUM_OF_USRCPU * (sizeof(struct flexsc_sysentry)));
    struct flexsc_sysentry *entry;

    info->npages = NUM_OF_USRCPU;

    /* only support single page mapping to kernel */
    /* but we cut one continuous memory(syspage) into several segments */
    /* each segment belong to each user cpu */
    /* size must be integral multiple of alignment */
    entry = (struct flexsc_sysentry*) aligned_alloc(pgsize, pgsize);
    if (!entry)
        return -1;

    for (int i = 0; i < info->npages * entry_per_syspage; i++) {
        entry[i].rstatus = FLEXSC_STATUS_FREE;
    }

    /*info->write_page = (char*) aligned_alloc(pgsize, 100000);
    if (!info->write_page) {
        puts("allocation for `write_page` failed");
        return -1;
    }*/

    info->nentry = entry_per_syspage;
    info->sysentry = entry;
    info->total_bytes = total;

    /* print_sysentry(&(info->sysentry[0])); */

    return 0;
}

/* ok */
static int init_info_default(struct flexsc_init_info *info)
{
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
static int init_info(struct flexsc_init_info *info)
{
    return init_info_default(info);
}

void print_init_info(struct flexsc_init_info *info)
{
    printf("flexsc_init_info\n");
    printf("number of sysentry: %ld\n", info->npages);
    printf("starting address of sysentry: %p\n", info->sysentry);
    printf("user cpu:%x, kernel cpu:%x\n", (info->cpuinfo).user_cpu, (info->cpuinfo).kernel_cpu);
    printf("npage: %ld\n", info->npages);
    printf("nentry: %ld\n", info->nentry);
    printf("total_bytes: %ld\n", info->total_bytes);
    printf("user pid: %d, ppid: %d\n", getpid(), getppid());
}

struct flexsc_init_info *
flexsc_register(struct flexsc_init_info *info)
{
    if (!info) {
        printf("info is NULL\n");
        return NULL;
    }

    u_info = info;

    if (init_info(u_info) < 0) {
        printf("Fail to initial info");
        return NULL;
    }

    // print_init_info(u_info);

    /*create_kv_thread(u_info);*/


    if (user_lock_init() < 0)
    /* TODO: cleanup should be impl (free(syspage...etc)) */
        return NULL;
    printf("ADDR: %p\n", &u_info->sysentry[0]);

    /* kernel initial */
    __flexsc_register(u_info);

    return info;
}


long flexsc_exit(void)
{
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

/* ok */
/* create kernel-visible threads for per core */
static void create_kv_thread(struct flexsc_init_info *info)
{
    kv_thread_list_t *kv_thread_tmp = &kv_thread_list;
    int idx;
    int ucpus = info->cpuinfo.user_cpu;
    int cpu_no = 0, cpu_qnt = 0;
    int part, remain, acc = 0;
    struct kv_handle_syspg_num *kv_handle_tmp;

    /* iterate user_cpu to get affinity for each kernel-visible thread */
    for (; ucpus; cpu_no++, ucpus >>= 1) {
        if (ucpus & 0x1) {
            CPU_ZERO(&(kv_thread_tmp->cpu));
            CPU_SET(cpu_no, &(kv_thread_tmp->cpu));
            cpu_qnt++;

            if (pthread_attr_init(&(kv_thread_tmp->t_attr))) {
                printf("pthread_attr_init failed\n");
                exit(-1);
            }

            if (pthread_attr_setaffinity_np(&(kv_thread_tmp->t_attr), sizeof(cpu_set_t), &(kv_thread_tmp->cpu))) {
                printf("pthread_attr_setaffinity_np failed\n");
                exit(-1);
            }

            /* snoop for next cpu */
            if (ucpus >> 1) {
                kv_thread_tmp->next = (kv_thread_list_t*) malloc(sizeof(kv_thread_list_t));
                if (!kv_thread_tmp->next) {
                    printf("Fail to allocate new kv thread\n");
                    exit(-1);
                }

                kv_thread_tmp = kv_thread_tmp->next;
            }

        }
    }

    part = info->npages / cpu_qnt;
    remain = info->npages % cpu_qnt;
    //kv_handle_tmp = (struct kv_handle_syspg_num*) malloc(sizeof(struct kv_handle_syspg_num) * cpu_qnt);
    /* due to glibc impl (2.28+), using memory allocated by malloc somehow cause error (malloc: invalid size (unsorted)). We use aligned_alloc() instead */
    kv_handle_tmp = (struct kv_handle_syspg_num*) aligned_alloc(getpagesize(), sizeof(struct kv_handle_syspg_num) * cpu_qnt);
    printf("num of cpu_qnt: %d\n", cpu_qnt);
    for (idx = 0; idx < cpu_qnt; idx++) {
        kv_handle_tmp[idx].start = acc;
        acc += part;
        kv_handle_tmp[idx].end = acc - 1;
    }
    if (remain) {
        kv_handle_tmp[idx].end = (remain == 1) ? 1: remain - 1;
    }

    for (idx = 0, kv_thread_tmp = &kv_thread_list;;) {
        pthread_create(&(kv_thread_tmp->tid), &(kv_thread_tmp->t_attr), kv_thread_worker, &kv_handle_tmp[idx]);
        if (++idx < cpu_qnt)
            kv_thread_tmp = kv_thread_tmp->next;
        else {
            kv_thread_tmp->next = NULL; /* make sure last element has its `next` NULL */
            break;
        }
    }
}

static inline int user_lock_init(void)
{
    if (pthread_spin_init(&spin_free_entry, PTHREAD_PROCESS_PRIVATE))
        return -1;
    if (pthread_spin_init(&spin_user_pending, PTHREAD_PROCESS_PRIVATE))
        return -1;

    return 0;
}

/**
 * @brief force flexSC to process syscalls, upon return, all syspage is free
 * by DONE_CNT times of check with SCAN_INTERVAL_us as the scan interval.
 *
 * note: this func is required if you have requested syscalls less than size
 * of syspage, or you just want flexSC to start processing your requested
 * syscalls. Besides, this is a busy waiting API currently (TODO).
 */
#if 0
void flexsc_start_syscall(void)
{
    int done_cnt = 0;
    int idx;

    pthread_spin_lock(&spin_user_pending);
    syscall_runner = IN_PROGRESS;
    pthread_spin_unlock(&spin_user_pending);
    return;
retry:
    for (idx = 0; idx < u_info->npages; idx++) {
        if (u_info->sysentry[idx].rstatus != FLEXSC_STATUS_FREE) {
            //printf("status of not freed syspage: %u\n", u_info->sysentry[idx].rstatus);
            break;
        }
    }
    printf("flexsc_start_syscall scanning\n");
    if (idx == u_info->npages) {
        done_cnt++;
        if (done_cnt == DONE_CNT) {
            pthread_spin_lock(&spin_user_pending);
            syscall_runner = IDLE;
            pthread_spin_unlock(&spin_user_pending);
            return;
        }
    }
    else {
        if (done_cnt) {
            puts("\n\n\ndone_cnt != 0 \n\n");
        }

        done_cnt = 0;

        /* kv_threads thoughts all syspages is processed, they are wrong, here restart the execution */
        if (syscall_runner == DONE) {
            pthread_spin_lock(&spin_user_pending);
            syscall_runner = IN_PROGRESS;
            pthread_spin_unlock(&spin_user_pending);
        }
    }

    // pthread_yield(); too much intensive
    usleep(SCAN_INTERVAL_us);
    goto retry;
}
#endif
void ttest(){
    return;
}