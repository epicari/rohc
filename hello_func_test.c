#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <rohc/rohc_comp.h>
#include <rohc/rohc.h>

static struct nf_hook_ops nfho;

static int gen_false_random_num(const struct rohc_comp *const comp,
								void *const user_context);

static unsigned int hook_func (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;

	struct rohc_comp *compressor;
	
	iph = ip_hdr(skb);
	tph = tcp_hdr(skb);

    pr_info("Packet !\n");

	if (!skb)
		return NF_ACCEPT;
	
	if (iph->protocol == IPPROTO_TCP) {
		
		if (tph) {
			pr_info("compressor\n");
/*			
			compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
										gen_false_random_num, NULL);
			if (compressor == NULL) {
				pr_info("failed\n");
				return NF_DROP;
			}
			rohc_comp_free(compressor);
		}
		else
			return NF_DROP;
	}
*/
    return NF_ACCEPT;
}

static int gen_false_random_num(const struct rohc_comp *const comp,
								void *const user_context) {
	return 0;
}

static int __init my_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_CONNTRACK_CONFIRM - 1;
	nfho.priv = NULL;

    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static void __exit my_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(my_init);
module_exit(my_exit);

