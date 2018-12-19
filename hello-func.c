#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

unsigned int hook_func (unsigned int hooknum,
						struct sk_buff **skb,
		       			const struct net_device *in,
		       			const struct net_device *out,
		       			int (*okfn)(struct sk_buff *)) {

	struct iphdr *iph = ip_hdr(*skb);

	if (!iph){
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_TCP){
		return NF_ACCEPT;
	}

	if (iph->protocol == IPPROTO_ICMP){
		printk(KERN_INFO "=== BEGIN ICMP ===\n");
		printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));

		iph->saddr = iph->saddr ^ 0x10000000;

		printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
		printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
		printk(KERN_INFO "=== END ICMP ===\n");

		return NF_ACCEPT;
	}

    return NF_ACCEPT;

}

static struct nf_hook_ops nfho = {
    .hook     = hook_func,
    .hooknum  = NF_INET_PRE_ROUTING,
    .pf       = PF_INET,
    .Priority = NF_IP_PRI_FIRST,
};

static __init int my_init(void){

	return nf_register_hook (&nfho);
}

static __exit void my_exit(void) {
	nf_unregister_hook (&nfho);
}

module_init (my_init);
module_exit (my_exit);

