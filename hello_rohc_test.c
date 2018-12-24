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

static unsigned int hook_func (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;

	unsigned char ip_buffer[BUFFER_SIZE];
	struct rohc_buf ip_packet = rohc_buf_init_empty(ip_buffer, BUFFER_SIZE);
	struct iphdr *rohc_iph;
	size_t i;
	
	iph = ip_hdr(skb);
	tph = tcp_hdr(skb);

	if (!skb)
		return NF_ACCEPT;
	
	if (iph->protocol == IPPROTO_TCP) {
		pr_info("Hello, TCP\n");

		pr_info("Test Fake Packet\n");

		rohc_iph = (struct iphdr *) rohc_buf_data(ip_packet);
		rohc_iph->version = 4;
		rohc_iph->ihl = 5;
		ip_packet.len += rohc_iph->ihl * 4;
		rohc_iph->tos = 0;
		rohc_iph->tot_len = htons(ip_packet.len + strlen(FAKE_PAYLOAD));
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

    else
		return NF_ACCEPT;
}

static __init int my_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_LOCAL_IN;
    nfho.pf = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_CONNTRACK_CONFIRM - 1;
	nfho.priv = NULL;

    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static __exit void my_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(my_init);
module_exit(my_exit);

