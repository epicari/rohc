#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/in.h>

#define NIPQUAD(addr) \
	((unsigned char *)&addr)[0], \
	((unsigned char *)&addr)[1], \
	((unsigned char *)&addr)[2], \
	((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
struct sk_buff *sock_buff;

static unsigned int hook_func (unsigned int hooknum,
						struct sk_buff *skb,
		       			const struct net_device *in,
		       			const struct net_device *out,
		       			int (*okfn)(struct sk_buff *)) {

	struct iphdr *iph = ip_hdr(skb);

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

static int my_init(void){

	nfho.hook = hook_func;
	nfho.pf = PF_INET;
	nfho.hooknum = NF_INET_PRE_ROUTING;
	nfho.priority = 1;
	nf_register_hook (&nfho);

	return 0;
}

static void my_exit(void) {

	nf_unregister_hook (&nfho);
}

//module_init (my_init);
//module_exit (my_exit);

