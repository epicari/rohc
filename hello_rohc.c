#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/time.h>
#include <linux/rohc.h>
#include <linux/rohc_comp.h>
#include <linux/rohc_decomp.h>

#define BUFFER_SIZE 2048

static struct nf_hook_ops nfho;

static int gen_random_num(const struct rohc_comp *const comp,
							void *const user_context);

static int rohc_comp(struct sk_buff *skb);

static struct rohc_comp * create_compressor(void);

static unsigned int hook_func (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;
	
	iph = ip_hdr(skb);
	tph = tcp_hdr(skb);

	if (!skb)
		return NF_ACCEPT;
	
	if (iph->protocol == IPPROTO_TCP) {
		pr_info("Hello, TCP\n");

		rohc_comp(skb);
	}

    return NF_ACCEPT;
}

static int rohc_comp(struct sk_buff *skb) {

	struct rohc_comp *compressor;
	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
	
	unsigned int seed;
	seed = time(NULL);
	srand(seed);

	compressor = create_compressor();

	status = rohc_compress4(compressor, &skb->data, &rohc_packet);

	if(status == ROHC_STATUS_SEGMENT) {
		pr_info("ROHC segment\n");
	}

	else if(status == ROHC_STATUS_OK) {
		pr_info("ROHC ok\n");
	}

	else {
		pr_info("ROHC failed\n");
		goto release_compressor;
	}

	static struct rohc_comp * create_compressor(void) {
	
		struct rohc_comp *compressor;

		compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
									gen_random_num, NULL);

		rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP);

		return compressor;
	}
release_compressor:
	rohc_comp_free(compressor);
	return 1;
}

static int my_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_CONNTRACK_CONFIRM - 1;
	nfho.priv = NULL;

    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static void my_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(my_init);
module_exit(my_exit);

