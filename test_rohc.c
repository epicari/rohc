#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/rohc.h>
#include <linux/rohc_comp.h>
#include <linux/rohc_decomp.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2048

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]
	
static int gen_random_num(const struct rohc_comp *const comp,
							void *const user_context);

static struct rohc_comp * create_compressor(void);

static unsigned int hook_func (unsigned int hooknum,
						struct sk_buff **skb,
		       			const struct net_device *in,
		       			const struct net_device *out,
		       			int (*okfn)(struct sk_buff *)) {

	struct iphdr *iph = ip_hdr(*skb);
	struct tcphdr *tcph = (struct tcphdr *)((char *)iph + sizeof(struct iphdr));
	char *data = (char *)tcph + sizeof( *tcph);

	if (!iph){
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP){
		

		
		return NF_ACCEPT;
	}

    return NF_ACCEPT;

}

static struct nf_hook_ops nfho = {
    .hook     = hook_func,
    .hooknum  = NF_INET_PRE_ROUTING,
    .pf       = PF_INET,
    .priority = NF_IP_PRI_FIRST,
};

static __init int my_init(void){

	return nf_register_hook (&nfho);
}

static __exit void my_exit(void) {
	nf_unregister_hook (&nfho);
}

static rohc_comp() {

	struct rohc_comp *compressor;
	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
	
	unsigned int seed;
	seed = time(NULL);
	srand(seed);

	compressor = create_compressor();

	static struct rohc_comp * create_compressor(void) {
	
		struct rohc_comp *compressor;

		compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
									gen_random_num, NULL);

		rohc_comp_enable_profile(compressor, ROHC_PROFILE_TCP);

		return compressor;
	}

	rohc_comp_free(compressor);
}

module_init (my_init);
module_exit (my_exit);

