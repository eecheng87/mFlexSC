#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h> // for signal.*()
#endif
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/kthread.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include "flexsc_type.h"
#include "systab.h"

#define DEBUG 1
#define WORKER_THREAD_DELAY 4
#define DEFAULT_THREAD_DELAY 6

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Cheng");
MODULE_DESCRIPTION("mini Flex-SC module");
MODULE_VERSION("0.1");

static void **syscall_table = 0;

/* restore original syscall for recover */
void *syscall_register_ori;
void *syscall_exit_ori;

struct page *pinned_pages[1];

/* routine of thread, find target submitted */
int scanner(void *arg) {
    struct flexsc_sysentry *entry = (struct flexsc_sysentry *)arg;
    int i, cpu, ret;
    cpu = smp_processor_id();
    allow_signal(SIGKILL);
    /*BUG_ON(DEFAULT_CPU != cpu);*/
    printk("kthread[%d %d], user[%d, %d] starts\n", current->pid,
           current->parent->pid, utask->pid, utask->parent->pid);
    while (!kthread_should_stop()) {
        /* set_current_state(TASK_UNINTERRUPTIBLE); */
        /* FIXME: wrong range NUM_SYSENTRY */
        for (i = 0; i < entry_per_kcpu * NUM_OF_KERCPU; i++) {
            if (entry[i].rstatus == FLEXSC_STATUS_SUBMITTED) {
                printk("entry[%d].rstatus == SUBMITTED\n", i);

                entry[i].rstatus = FLEXSC_STATUS_BUSY;
                /* do qworker */
                /* FIXME: system call handler always execute on defualt cpu */
                ret = queue_work_on(DEFAULT_CPU, sys_workqueue,
                                    &(sys_container[i].__sys_works));

                if (!ret) {
                    printk("sys_work already queued\n");
                }
            }
        }
        if (signal_pending(scanner_task_struct))
            break;
        schedule_timeout(HZ);
    }

    do_exit(0);

    return 0;
}

typedef long (*sys_call_ptr_t)(const struct __user pt_regs *);
static long do_syscall(unsigned int num, long __user args[]) {
    /* assume sysnum and sysargs are always valid */

    /*
        example for get string from entry of syspage:
        copy_from_user(dest, (void*)args[0], sizeof(dest));
        no need to copy because already mapping to user space
    */

    struct pt_regs *reg =
        (struct pt_regs *)kmalloc(sizeof(struct pt_regs), GFP_KERNEL);

    long ret;
    /* storing argument into register */
    reg->di = args[0];
    reg->si = args[1];
    reg->dx = args[2];
    reg->r10 = args[3];
    reg->r8 = args[4];
    reg->r9 = args[5];
    ret = ((sys_call_ptr_t *)syscall_table)[num](reg);
    return ret;
}

/* routine for work queue */
static void qworker(struct work_struct *work) {
    /* extract entry from data set */
    struct flexsc_data_set *container =
        container_of(work, struct flexsc_data_set, __sys_works);
    struct flexsc_sysentry *entry = phy_entry + container->index;
    long ret;

    ret = do_syscall(entry->sysnum, entry->args);

    if (ret == -ENOSYS) {
        printk("Fail to do syscall\n");
    }

    entry->sysret = ret;
    entry->rstatus = FLEXSC_STATUS_DONE;
    return;
}

struct flexsc_sysentry *kmap_tmp;

/* after linux kernel 4.7, parameter was restricted into pt_regs type */
asmlinkage long sys_flexsc_register(const struct __user pt_regs *regs) {
#if DEBUG
    printk(KERN_INFO "FlexSC register was called\n");
#endif

    struct flexsc_init_info *info = (struct flexsc_init_info *)regs->di;

    /* #define current get_current() */
    struct task_struct *cur_task = current;
    struct flexsc_sysentry *entry;
    int n_page, i;

#if DEBUG
    printk("Address of sysentry is %p\n", &(info->sysentry[0]));
#endif

    utask = current;
    printk("Current upid is %d\n", utask->pid);
    /* map sys table in user space */
    /* prototype after linux 5.x.x */
    n_page = get_user_pages(
        (unsigned long)(&(info->sysentry[0])), /* Start address to map */
        1, /* Number of pinned pages. 4096 btyes in this machine */
        FOLL_FORCE | FOLL_WRITE, /* Force flag */
        pinned_pages,            /* struct page ** pointer to pinned pages */
        NULL);

    entry_per_kcpu = 4096 / (NUM_OF_KERCPU * (sizeof(struct flexsc_sysentry)));

    if (n_page < 0) {
        printk("Fail to pinning pages\n");
    }

    sys_container = (struct flexsc_data_set *)kmalloc(
        sizeof(struct flexsc_data_set) * entry_per_kcpu * NUM_OF_KERCPU,
        GFP_KERNEL);
    phy_entry = entry = (struct flexsc_sysentry *)kmap(pinned_pages[0]);
    for (i = 0; i < entry_per_kcpu * NUM_OF_KERCPU; i++)
        sys_container[i].index = i;

    sys_workqueue = create_workqueue("flexsc_workqueue");

    for (i = 0; i < entry_per_kcpu * NUM_OF_KERCPU; i++) {
        INIT_WORK(&(sys_container[i].__sys_works), qworker);
    }
    scanner_task_struct =
        kthread_create(scanner, (void *)entry, "flexsc scanner thread");
    // kthread_bind(kstruct, DEFAULT_CPU);

    if (IS_ERR(scanner_task_struct)) {
        printk("Fail to create kthread\n");
        return -1;
    }

    wake_up_process(scanner_task_struct);

    return 0;
}

asmlinkage void sys_flexsc_exit(void) {
    printk(KERN_INFO "FlexSC exit was called\n");
}

extern unsigned long __force_order __weak;
#define store_cr0(x) asm volatile("mov %0,%%cr0" : "+r"(x), "+m"(__force_order))
static void allow_writes(void) {
    unsigned long cr0 = read_cr0();
    clear_bit(16, &cr0);
    store_cr0(cr0);
}
static void disallow_writes(void) {
    unsigned long cr0 = read_cr0();
    set_bit(16, &cr0);
    store_cr0(cr0);
}

static int __init mFlexSC_init(void) {

    /* hooking system call */

    /* avoid effect of KALSR, get address of syscall table by adding offset */
    syscall_table = (void **)(scTab + ((char *)&system_wq - sysWQ));

    /* allow write */
    allow_writes();

    /* backup */
    syscall_register_ori = (void *)syscall_table[__NR_flexsc_register];
    syscall_exit_ori = (void *)syscall_table[__NR_flexsc_exit];

    /* hooking */
    syscall_table[__NR_flexsc_register] = (void *)sys_flexsc_register;
    syscall_table[__NR_flexsc_exit] = (void *)sys_flexsc_exit;

    /* dis-allow write */
    disallow_writes();

    return 0;
}
static void __exit mFlexSC_exit(void) {
    /* recover */
    allow_writes();
    syscall_table[__NR_flexsc_register] = (void *)syscall_register_ori;
    syscall_table[__NR_flexsc_exit] = (void *)syscall_exit_ori;
    disallow_writes();

    /* cleanup for workqueue */
    /* maybe cancel_work_sync(&work); is needed */
    if (sys_workqueue) {
        destroy_workqueue(sys_workqueue);
    }

    /* correspond cleanup for kmap */
    kunmap(pinned_pages[0]);

    /* clean kthread */
    if (scanner_task_struct)
        kthread_stop(scanner_task_struct);
}
module_init(mFlexSC_init);
module_exit(mFlexSC_exit);