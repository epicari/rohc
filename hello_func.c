#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linun/ip.h>
#include <linun/tcp.h>

static struct nf_hook_ops nfho;
static struct net hook_net;

static unsigned int hook_func (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;
	
	iph = (struct iphdr *)skb_network_header(skb);

    pr_info("Packet !\n");

	if (!skb)
		return NF_ACCEPT;
	
	if (iph->protocol == IPPROTO_TCP) {
		tph = (struct tcphdr *)(skb_transport_header(skb) + ip_hdrlen(skb));
		if (tph)
			pr_info("SRC: (%pI4):%d --> DST: (%pI4):%d\n",
					&iph->saddr,
					ntohs(tph->source),
					&iph->daddr,
					ntohs(tph->dest));
		else
			return NF_DROP;
	}

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

