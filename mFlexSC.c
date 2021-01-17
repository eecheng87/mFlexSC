#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/signal.h> // for signal.*()
#endif
#include <linux/kthread.h>          //used for kthread_create
#include <linux/delay.h>            //used for ssleep()


static struct task_struct *worker_task,*default_task;
static int get_current_cpu,set_current_cpu;
#define WORKER_THREAD_DELAY 4
#define DEFAULT_THREAD_DELAY 6


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Cheng");
MODULE_DESCRIPTION("mini Flex-SC module");
MODULE_VERSION("0.1");

static int worker_task_handler_fn(void *arguments)
{
	allow_signal(SIGKILL);

	while(!kthread_should_stop()){
		ssleep(WORKER_THREAD_DELAY);
        printk(KERN_INFO "in worker");

		if (signal_pending(worker_task))
			            break;
	}
	do_exit(0);
	return 0;
}

static int default_task_handler_fn(void *arguments)
{
	allow_signal(SIGKILL);

	while(!kthread_should_stop())
	{
		ssleep(DEFAULT_THREAD_DELAY);
        printk(KERN_INFO "in default");

	    if (signal_pending(default_task))
		            break;
	}

	do_exit(0);

	return 0;
}



static int __init mFlexSC_init(void) {

	worker_task = kthread_create(worker_task_handler_fn,
			(void*)"arguments as char pointer","flex_worker");
	kthread_bind(worker_task,get_current_cpu);

	set_current_cpu = 2;

	default_task = kthread_create(default_task_handler_fn,
				(void*)"arguments as char pointer","flex_default");
	kthread_bind(default_task,set_current_cpu);

	wake_up_process(worker_task);
	wake_up_process(default_task);

	return 0;
}
static void __exit mFlexSC_exit(void) {
	if(worker_task)
		kthread_stop(worker_task);
	if(default_task)
		kthread_stop(default_task);
}
module_init(mFlexSC_init);
module_exit(mFlexSC_exit);