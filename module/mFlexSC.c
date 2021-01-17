#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h> // for signal.*()
#endif
#include <linux/delay.h>   //used for ssleep()
#include <linux/kthread.h> //used for kthread_create

#include "systab.h"

static struct task_struct *worker_task, *default_task;
static int get_current_cpu, set_current_cpu;
#define WORKER_THREAD_DELAY 4
#define DEFAULT_THREAD_DELAY 6
#define __NR_flexsc_register 400
#define __NR_flexsc_exit 401

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Cheng");
MODULE_DESCRIPTION("mini Flex-SC module");
MODULE_VERSION("0.1");

static void **syscall_table = 0;

/* restore original syscall for recover */
void *syscall_register_ori;
void *syscall_exit_ori;

static int worker_task_handler_fn(void *arguments) {
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
}

asmlinkage long sys_flexsc_register(void) {
  printk(KERN_INFO "FlexSC register was called\n");
}

asmlinkage long sys_flexsc_exit(void) {
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
  /*if(worker_task)
              kthread_stop(worker_task);
      if(default_task)
              kthread_stop(default_task);*/
}
module_init(mFlexSC_init);
module_exit(mFlexSC_exit);