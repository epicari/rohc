#include <linux/module.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/rohc/rohc.h>
#include <linux/rohc/rohc_comp.h>
#include <linux/rohc/rohc_decomp.h>

#define BUFFER_SIZE 10000
#define FAKE_PAYLOAD "hello, world!"

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

		test();
//		rohc_comp(skb);

	}

    return NF_ACCEPT;
}

static int test(void) {

	unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	struct iphdr *rohc_iph;
	size_t i;

	pr_info("Test Fake Packet\n");

	rohc_iph = (struct iphdr *) rohc_buf_data(ip_packet);
	rohc_iph->version = 4;
	rohc_iph->ihl = 5;
	ip_packet.len += rohc_iph->ihl * 4;
	rohc_iph->tos = 0;
	rohc_iph->tot_len = htons(ip_packet.len + skb->data_len);
	rohc_iph->id = 0;
	rohc_iph->frag_off = 0;
	rohc_iph->ttl = 1;
	rohc_iph->protocol = 134;
	rohc_iph->check = 0x3fa9;
	rohc_iph->saddr = htonl(0x01020304);
	rohc_iph->daddr = htonl(0x05060708);

	rohc_buf_append(&ip_packet, (uint8_t *)FAKE_PAYLOAD, strlen(FAKE_PAYLOAD));

	for (i=0; i<ip_packet.len; i++) {
		pr_info("0x%02x ", rohc_buf_byte_at(ip_packet, i));
		if (i != 0 && ((i + 1) % 8) == 0) {
			pr_info("\n");
		}
	}
	if (i != 0 && (i % 8) != 0) {
		pr_info("\n");
	}
}


/*
static int rohc_comp(struct sk_buff *skb) {

	struct rohc_comp *compressor;
	rohc_status_t status;
	
	unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);

	unsigned char rohc_buffer[BUFFER_SIZE];
	struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_buffer, BUFFER_SIZE);
	struct iphdr *rohc_iph;

	rohc_iph = (struct iphdr *) rohc_buf_data(ip_packet);
	rohc_iph->version = 4;
	rohc_iph->ihl = 5;
	ip_packet.len += rohc_iph->ihl * 4;
	rohc_iph->tos = 0;
	rohc_iph->tot_len = htons(ip_packet.len + skb->data_len);
	rohc_iph->id = 0;
	rohc_iph->frag_off = 0;
	rohc_iph->ttl = 1;
	rohc_iph->protocol = 134;
	rohc_iph->check = 0x3fa9;
	rohc_iph->saddr = htonl(0x01020304);
	rohc_iph->daddr = htonl(0x05060708);

	rohc_buf_append(&ip_packet, skb->data, skb->data_len);

	compressor = create_compressor();

	status = rohc_compress4(compressor, ip_packet, &rohc_packet);

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

release_compressor:
	rohc_comp_free(compressor);
	return 1;
}

static struct rohc_comp * create_compressor(void) {
	
	struct rohc_comp *compressor;

	compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
								gen_random_num, NULL);

	rohc_comp_enable_profile(compressor, ROHC_PROFILE_IP);

	return compressor;
}
*/
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

