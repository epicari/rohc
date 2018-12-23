#include <linux/module.h>
#include <linux/init.h>
#include <printk.h>

static int setup(void) {
    printk(KERN_INFO "Hello, World !\n");
    pr_info("pr_info\n");
    return 0;
}

static void shutdown(void) {
    printk(KERN_INFO "Goodbye, Worid !\n");
    pr_info("pr_info\n");
}

module_init(setup);
module_exit(shutdown);
