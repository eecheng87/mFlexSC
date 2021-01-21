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

#include "../lib/flexsc_type.h"
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

/*static int worker_task_handler_fn(void *arguments) {
    allow_signal(SIGKILL);

    while (!kthread_should_stop()) {
        ssleep(WORKER_THREAD_DELAY);
        printk(KERN_INFO "in worker");

        if (signal_pending(worker_task))
            break;
    }
    do_exit(0);
    return 0;
}

static int default_task_handler_fn(void *arguments) {
    allow_signal(SIGKILL);

    while (!kthread_should_stop()) {
        ssleep(DEFAULT_THREAD_DELAY);
        printk(KERN_INFO "in default");

        if (signal_pending(default_task))
            break;
    }

    do_exit(0);

    return 0;
}*/

/* routine of thread, find target submitted */
int scanner(void *arg) {
    struct flexsc_sysentry *entry = (struct flexsc_sysentry *)arg;
    int i, cpu, ret;
    cpu = smp_processor_id();
    allow_signal(SIGKILL);
    /*BUG_ON(DEFAULT_CPU != cpu);*/

    while (!kthread_should_stop()) {
        set_current_state(TASK_UNINTERRUPTIBLE);

        for (i = 0; i < NUM_SYSENTRY; i++) {
            if (entry[i].rstatus == FLEXSC_STATUS_SUBMITTED) {
                printk("entry[%d].rstatus == SUBMITTED\n", i);

                entry[i].rstatus = FLEXSC_STATUS_BUSY;
                /* do qworker */
                ret = queue_work_on(DEFAULT_CPU, sys_workqueue, &sys_works[i]);

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

typedef long (*sys_call_ptr_t)(long, long, long);
static long do_syscall(unsigned int num, long args[]) {
    /* assume sysnum and sysargs are always valid */
    /* assume always call system call: write */
    return ((sys_call_ptr_t *)syscall_table)[num](args[0], args[1], args[2]);
}

/* routine for work queue */
static void qworker(struct work_struct *work) {
    /* extract entry from data set */
    struct flexsc_data_set *container =
        container_of(&work, struct flexsc_data_set, __sys_works);
    struct flexsc_sysentry *entry = container->__entry;
    long ret;

    ret = do_syscall(entry->sysnum, entry->args);

    if (ret == -ENOSYS) {
        printk("Fail to do syscall\n");
    }

    entry->sysret = ret;
    entry->rstatus = FLEXSC_STATUS_DONE;
    return;
}

asmlinkage long sys_flexsc_register(struct flexsc_init_info *info) {
#if DEBUG
    printk(KERN_INFO "FlexSC register was called\n");
#endif
    /* #define current get_current() */
    struct task_struct *cur_task = current;
    struct flexsc_sysentry *entry;
    int n_page, i;

    /* map sys table in user space */
    /* after linux 5.x.x */
    n_page = get_user_pages(
        (unsigned long)(&(info->sysentry[0])), /* Start address to map */
        1, /* Number of pinned pages. 4096 btyes in this machine */
        FOLL_FORCE | FOLL_WRITE, /* Force flag */
        pinned_pages,            /* struct page ** pointer to pinned pages */
        NULL);

    if (n_page < 0) {
        printk("Fail to pinning pages\n");
    }

    sys_container = (struct flexsc_data_set *)kmalloc(
        sizeof(struct flexsc_data_set) * NUM_SYSENTRY, GFP_KERNEL);
    entry = (struct flexsc_sysentry *)kmap(pinned_pages[0]);
    for (i = 0; i < NUM_SYSENTRY; i++)
        sys_container[i].__entry = &entry[i];

    sys_workqueue = create_workqueue("flexsc_workqueue");

    sys_works = (struct work_struct *)kmalloc(
        sizeof(struct work_struct) * NUM_SYSENTRY, GFP_KERNEL);
    for (i = 0; i < NUM_SYSENTRY; i++)
        sys_container[i].__sys_works = &sys_works[i];

    if (!sys_works) {
        printk("Fail to allocate\n");
        return -1;
    }

    for (i = 0; i < NUM_SYSENTRY; i++) {
        INIT_WORK(&sys_works[i], qworker);
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

    /*worker_task = kthread_create(worker_task_handler_fn,
                        (void*)"arguments as char pointer","flex_worker");
        kthread_bind(worker_task,get_current_cpu);

        set_current_cpu = 2;

        default_task = kthread_create(default_task_handler_fn,
                                (void*)"arguments as char
       pointer","flex_default"); kthread_bind(default_task,set_current_cpu);

        wake_up_process(worker_task);
        wake_up_process(default_task);*/

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

    if (sys_works) {
        kfree(sys_works);
    }
    /*if(worker_task)
                kthread_stop(worker_task);
        if(default_task)
                kthread_stop(default_task);*/
}
module_init(mFlexSC_init);
module_exit(mFlexSC_exit);