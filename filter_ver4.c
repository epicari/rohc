#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/net_namespace.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;

static unsigned int hook_func (void *priv,
								struct sk_buff *skb,
								const struct nf_hook_state *state) {

	struct iphdr *iph;
	
	iph = (struct iphdr *)skb_network_header(skb);

	if (iph->protocol == IPPROTO_ICMP) {
		printk(KERN_INFO "=== BEGIN ICMP ===\n");
		printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));

		iph->saddr = iph->saddr ^ 0x10000000;

		printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
		printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
		printk(KERN_INFO "=== END ICMP ===\n");
	}

    return NF_ACCEPT;

}

static int my_init(void) {

	nfho.hook = hook_func;
	nfho.pf = PF_INET;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = 1;
	nf_register_net_hook (NULL, &nfho);

	return 0;
}

static void my_exit(void) {

	nf_unregister_net_hook (NULL, &nfho);
}

module_init (my_init);
module_exit (my_exit);

