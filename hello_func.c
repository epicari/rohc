#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

static struct nf_hook_ops nfhi;
static struct nf_hook_ops nfho;

static unsigned int hook_func_i (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;
	
	iph = ip_hdr(skb);
	tph = tcp_hdr(skb);

    pr_info("Packet In !\n");

	if (!skb)
		return NF_ACCEPT;
	
	if (iph->protocol == IPPROTO_TCP) {
		
		if (tph)
/*		
			pr_info("SRC: (%pI4):%d --> DST: (%pI4):%d\n",
					&iph->saddr,
					ntohs(tph->source),
					&iph->daddr,
					ntohs(tph->dest));
*/
			pr_info("In tph\n");
		else
			return NF_DROP;
	}

    return NF_ACCEPT;
}

static unsigned int hook_func_o (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;
	
	iph = ip_hdr(skb);
	tph = tcp_hdr(skb);

    pr_info("Packet Out !\n");

	if (!skb)
		return NF_ACCEPT;
	
	if (iph->protocol == IPPROTO_TCP) {
		
		if (tph)
			pr_info("Out tph\n");
		else
			return NF_DROP;
	}

    return NF_ACCEPT;
}

static int testfuc (void) {
	pr_info("test case\n");
	return 0;
}

static int my_init(void) {

	testfuc();

    nfhi.hook = hook_func_i;
    nfhi.hooknum = NF_INET_LOCAL_IN;
    nfhi.pf = NFPROTO_IPV4;
    nfhi.priority = NF_IP_PRI_FIRST;
	nfhi.priv = NULL;

    nfho.hook = hook_func_o;
    nfho.hooknum = NF_INET_LOCAL_OUT;
    nfho.pf = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_FIRST;
	nfho.priv = NULL;

    nf_register_net_hook(&init_net, &nfhi);
    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static void my_exit(void) {
    nf_unregister_net_hook(&init_net, &nfhi);
	nf_unregister_net_hook(&init_net, &nfho);
}

module_init(my_init);
module_exit(my_exit);

