#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>

static struct nf_hook_ops nfho;
static struct net hook_net;

static unsigned int hook_func (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    printk(KERN_INFO "Packet !\n");
    pr_info("Packet !\n");

    return NF_ACCEPT;
}

static int my_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&hook_net, &nfho);

    return 0;
}

static void my_exit(void) {
    nf_unregister_net_hook(&hook_net, &nfho);
}

module_init(my_init);
module_exit(my_exit);
