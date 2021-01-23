#define __NR_flexsc_register 400
#define __NR_flexsc_exit 401
#define NUM_SYSENTRY 64

/* FIXME: only support one cpu now */
#define NUM_OF_USRCPU 2
#define DEFAULT_CPU 0


/* state for entry in syscall table */
#define FLEXSC_STATUS_FREE 0
#define FLEXSC_STATUS_SUBMITTED 1
#define FLEXSC_STATUS_DONE 2
#define FLEXSC_STATUS_BUSY 3

struct flexsc_cpuinfo {
    int user_cpu;
    int kernel_cpu;
};

struct flexsc_sysentry {
    unsigned nargs;
    unsigned rstatus;
    unsigned sysnum;
    unsigned sysret;
    long args[6];
} ____cacheline_aligned_in_smp;

struct flexsc_init_info {
    struct flexsc_sysentry *sysentry; /* Pointer to first sysentry */
    struct flexsc_cpuinfo cpuinfo; /* cpu bound info */
    char *write_page; /* shared page for test write() */
    size_t npages; /* Number of Syspages */
    size_t nentry; /* # of workers should be equal to # of sysentries */
    size_t total_bytes;
};

/* mapping sys_work to specific parameter */
struct flexsc_data_set
{
    struct work_struct *__sys_works;
    struct flexsc_sysentry *__entry;
};

struct work_struct *sys_works; /* workqueue node */
struct task_struct *scanner_task_struct;
struct workqueue_struct *sys_workqueue;
struct flexsc_data_set *sys_container;
