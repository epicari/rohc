#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/net_namespace.h>

static struct nf_hook_ops nfho;

static unsigned int hook_func (void *priv,
								struct sk_buff *skb,
								const struct nf_hook_state *state) {

	//struct iphdr *iph = ip_hdr(skb);
	//struct ethhdr *eth = eth_hdr(skb);
	//struct icmphdr *icmh = icmp_hdr(skb);

	if (!skb)
		return NF_ACCEPT;

	struct iphdr *iph;
	iph = (struct iphdr *)skb_network_header(skb);

	printk(KERN_INFO "NF_IP_HOOK:\n");
	printk(KERN_INFO "IP address = %u DEST = %u\n", iph->saddr, iph->daddr);
	//printk("src mac %pM, dst mac %pM\n", eth->h_source, eth->h_dest);

    return NF_ACCEPT;

}

static int my_init(void) {

	nfho.hook = hook_func;
	nfho.pf = PF_INET;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = NF_IP_PRI_FIRST;
	
	nf_register_net_hook (NULL, &nfho);

	return 0;

}

static void my_exit(void) {

	nf_unregister_net_hook (NULL, &nfho);
}

module_init (my_init);
module_exit (my_exit);

