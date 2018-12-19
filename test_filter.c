#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* Port we want to drop packets on */
static const uint16_t port = 25;

/* This is the hook function itself */
static unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **pskb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
{
        struct iphdr *iph = ip_hdr(*pskb);
        struct tcphdr *tcph, tcpbuf;

        if (iph->protocol != IPPROTO_TCP)
                return NF_ACCEPT;

        tcph = skb_header_pointer(*pskb, ip_hdrlen(*pskb), sizeof(*tcph), &tcpbuf);
        if (tcph == NULL)
                return NF_ACCEPT;

        return (tcph->dest == port) ? NF_DROP : NF_ACCEPT;
}

/* Used to register our hook function */
static struct nf_hook_ops nfho = {
        .hook     = hook_func,
        .hooknum  = NF_IP_PRE_ROUTING,
        .pf       = NFPROTO_IPV4,
        .priority = NF_IP_PRI_FIRST,
};

static __init int my_init(void)
{
        return nf_register_hook(&nfho);
}

static __exit void my_exit(void)
{
    nf_unregister_hook(&nfho);
}

module_init(my_init);
module_exit(my_exit);