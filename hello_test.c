#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;

static unsigned int hook_func (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    printk(KERN_INFO "Packet !\n");

    return NF_ACCEPT;
}

static int init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(NULL, &nfho);

    return 0;
}

static void exit(void) {
    nf_unregister_net_hook(NULL, &nfho);
}

module_init(init);
module_exit(exit);

