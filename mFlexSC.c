#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Steven Cheng");
MODULE_DESCRIPTION("mini Flex-SC module");
MODULE_VERSION("0.1");

static int __init mFlexSC_init(void) {
    printk(KERN_INFO "Hello\n");
    return 0;
}
static void __exit mFlexSC_exit(void) {
    printk(KERN_INFO "Bye\n");
}
module_init(mFlexSC_init);
module_exit(mFlexSC_exit);