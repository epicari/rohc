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

	struct iphdr *iph = ip_hdr(skb);
	struct ethhdr *eth = eth_hdr(skb);

	if (!iph) {
		
		return NF_ACCEPT;
	}

	printk("NF_IP_HOOK:\n");
	printk("src mac %pM, dst mac %pM\n", eth->h_source, eth->h_dest);

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

