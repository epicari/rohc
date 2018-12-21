#include <linux/module.h>
#include <linux/init.h>

static int setup(void) {
    printk(KERN_INFO "Hello, World !\n");
    return 0;
}

static void shutdown(void) {
    printk(KERN_INFO "Goodbye, Worid !\n");
}

module_init(setup);
module_exit(shutdown);
