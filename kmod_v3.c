/*
 * Copyright 2013,2016 Didier Barvaux
 * Copyright 2013,2014 Mikhail Gruzdev
 * Copyright 2009,2010 Thales Communications
 * Copyright 2013,2014 Viveris Technologies
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/**
 * @file   kmod_netfilter
 * @brief  Export the ROHC library to the Linux kernel
 * @author Suho CHOI <aiek261247@gmail.com>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/net_namespace.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>

#include "config.h"
#include "rohc.h"
#include "rohc_comp.h"
#include "rohc_decomp.h"

#define BUFFER_SIZE 2048

struct rohc_init {

	struct rohc_comp *compressor;
	struct rohc_decomp *decompressor;

	unsigned char *rohc_packet_out; // comp ROHC packet
	unsigned char *rohc_packet_in; // ROHC packet to decomp

	unsigned char *feedback_to_send_buf; // feedback to send decomp
	unsigned char *rcvd_feedback_buf; // comp feedback rcvd

	struct rohc_buf feedback_to_send; // feedback to send decomp with the ROHC by

};

static struct rohc_init rinit;

static struct nf_hook_ops nfho;

static int gen_false_random_num(const struct rohc_comp *const comp,
								void *const user_context);

static void rohc_print_traces(void *const priv_ctxt __attribute__((unused)),
			      const rohc_trace_level_t level,
			      const rohc_trace_entity_t entity,
			      const int profile,
			      const char *const format,
			      ...)
{
	va_list args;

	va_start(args, format);
	vprintk(format, args);
	va_end(args);
}

static unsigned int hook_init (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct tcphdr *tph;
	const struct iphdr *ih;

	iph = ip_hdr(skb);
	tph = tcp_hdr(skb);
	ih = skb_header_pointer(skb, iph->frag_off, sizeof(iph), &iph);

	if (ih == NULL) {
		pr_info("TRUNCATED\n");
		return NF_DROP;
	}

	pr_info("Origin IP LEN=%u TTL=%u ID=%u DATA=%u",
			ntohs(ih->tot_len), ih->ttl, ntohs(ih->id), skb->data);

	if (iph->protocol == IPPROTO_TCP) {
		int i;

		pr_info("ROHC COMP / DECOMP INIT Start\n");
	
		i = rohc_comp_init(&rinit);
		if (i != 0) {
			pr_info("failed to init ROHC Compressor\n");
			return NF_DROP;
		}

		i = rohc_decomp_init(&rinit);
		if (i != 0) {
			pr_info("failed to init ROHC Decompressor\n");
			return NF_DROP;
		}
/*
		unsigned char *rohc_packet_out = kzalloc(BUFFER_SIZE, GFP_KERNEL);
		//unsigned char *ip_packet_in = kmalloc(BUFFER_SIZE, GFP_KERNEL);
		unsigned char *feedback_to_send_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);

		struct rohc_buf rohc_packet = rohc_buf_init_empty(rohc_packet_out, BUFFER_SIZE);
		struct rohc_buf ip_packet = rohc_buf_init_full(skb->data, ntohs(ih->tot_len), 0);

		struct rohc_buf feedback_to_send = rohc_buf_init_empty(rohc_packet_out, BUFFER_SIZE);
		
		rohc_status_t status;

		status = rohc_compress4(comp->compressor, ip_packet, &rohc_packet);
				
		if (status == ROHC_STATUS_OK) {
			pr_info("ROHC Compression\n");
			pr_info("Compress Header LEN=%u TTL=%u ID=%u DATA=%u",
					ntohs(ih->tot_len), ih->ttl, ntohs(ih->id), skb->data);
		}
		else {
			pr_info("Compression failed\n");
			goto free_comp;
		}
*/
		return NF_ACCEPT;

	}
}

int rohc_comp_init(struct rohc_init *comp) {

	pr_info("ROHC_COMP_INIT\n");
	comp = kzalloc(BUFFER_SIZE, GFP_KERNEL);

	comp->compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
									gen_false_random_num, NULL);

	if (comp->compressor == NULL) {
		pr_info("failed create the ROHC compressor\n");
		goto free_comp;
	}
/*
	if(!rohc_comp_set_traces_cb2(comp->compressor, rohc_print_traces, NULL)) {
		pr_info("cannot set trace callback for compressor\n");
		goto free_comp;
	}
	
	if(!rohc_comp_set_features(comp->compressor, ROHC_COMP_FEATURE_DUMP_PACKETS)) {
		pr_info("failed to enable packet dumps\n");
		goto free_comp;
	}
*/
	if(!rohc_comp_enable_profile(comp->compressor, ROHC_PROFILE_TCP)) {
		pr_info("failed to enable the TCP profile\n");
		goto free_comp;
	}

	free(comp);

	return 0;

free_comp:
	rohc_comp_free(comp->compressor);
	return NF_DROP;
}

int rohc_decomp_init(struct rohc_init *decomp) {

	pr_info("ROHC_DECOMP_INIT\n");
	decomp = kzalloc(BUFFER_SIZE, GFP_KERNEL);

	decomp->decompressor = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
											ROHC_O_MODE);

	if (decomp->decompressor == NULL) {
		pr_info("failed create the ROHC compressor\n");
		goto free_decomp;
	}
/*
	if(!rohc_decomp_set_traces_cb2(decomp->decompressor, rohc_print_traces, NULL)) {
		pr_info("cannot set trace callback for compressor\n");
		goto free_decomp;
	}
	
	if(!rohc_decomp_set_features(decomp->decompressor, ROHC_DECOMP_FEATURE_DUMP_PACKETS)) {
		pr_info("failed to enable packet dumps\n");
		goto free_decomp;
	}
*/
	if(!rohc_decomp_enable_profile(decomp->decompressor, ROHC_PROFILE_TCP)) {
		pr_info("failed to enable the TCP profile\n");
		goto free_decomp;
	}

	decomp->rohc_pkt_out = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	
	decomp->rcvd_feedback_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);

	decomp->feedback_to_send_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);

	kfree(decomp);
	kfree(rohc_pkt_out);
	kfree(rcvd_feedback_buf);
	kfree(feedback_to_send_buf);

	return 0;

free_decomp:
	rohc_comp_free(comp->compressor);
	return NF_DROP;
}


static int gen_false_random_num(const struct rohc_comp *const comp,
								void *const user_context) {
	return 0;
}

static int my_comp(void) {
    nfho.hook = hook_init;
    nfho.hooknum = NF_INET_POST_ROUTING; // hook in ip_finish_output()
    nfho.pf = NFPROTO_IPV4;
    nfho.priority = NF_IP_PRI_FIRST;
	nfho.priv = NULL;

    nf_register_net_hook(&init_net, &nfho);

    return 0;
}

static void my_comp_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
}

module_init(my_comp);
module_exit(my_comp_exit);

MODULE_VERSION(PACKAGE_VERSION PACKAGE_REVNO);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Didier Barvaux, Mikhail Gruzdev, Thales Communications, Viveris Technologies");
MODULE_DESCRIPTION(PACKAGE_NAME
	", version " PACKAGE_VERSION PACKAGE_REVNO " (" PACKAGE_URL ")");


/*
 * General API
 */

EXPORT_SYMBOL_GPL(rohc_version);
EXPORT_SYMBOL_GPL(rohc_get_mode_descr);
EXPORT_SYMBOL_GPL(rohc_get_profile_descr);
EXPORT_SYMBOL_GPL(rohc_profile_is_rohcv1);
EXPORT_SYMBOL_GPL(rohc_profile_is_rohcv2);
EXPORT_SYMBOL_GPL(rohc_profile_get_other_version);
EXPORT_SYMBOL_GPL(rohc_get_packet_descr);
EXPORT_SYMBOL_GPL(rohc_get_ext_descr);
EXPORT_SYMBOL_GPL(rohc_get_packet_type);
EXPORT_SYMBOL_GPL(rohc_packet_is_ir);
EXPORT_SYMBOL_GPL(rohc_packet_carry_static_info);
EXPORT_SYMBOL_GPL(rohc_packet_carry_crc_7_or_8);

EXPORT_SYMBOL_GPL(rohc_buf_is_malformed);
EXPORT_SYMBOL_GPL(rohc_buf_is_empty);
EXPORT_SYMBOL_GPL(rohc_buf_push);
EXPORT_SYMBOL_GPL(rohc_buf_pull);
EXPORT_SYMBOL_GPL(rohc_buf_avail_len);
EXPORT_SYMBOL_GPL(rohc_buf_data_at);
EXPORT_SYMBOL_GPL(rohc_buf_data);
EXPORT_SYMBOL_GPL(rohc_buf_prepend);
EXPORT_SYMBOL_GPL(rohc_buf_append);
EXPORT_SYMBOL_GPL(rohc_buf_append_buf);
EXPORT_SYMBOL_GPL(rohc_buf_reset);


/*
 * Compression API
 */

/* general */
EXPORT_SYMBOL_GPL(rohc_comp_new2);
EXPORT_SYMBOL_GPL(rohc_comp_free);
EXPORT_SYMBOL_GPL(rohc_compress4);
EXPORT_SYMBOL_GPL(rohc_comp_pad);
EXPORT_SYMBOL_GPL(rohc_comp_force_contexts_reinit);

/* segment */
EXPORT_SYMBOL_GPL(rohc_comp_get_segment2);

/* feedback */
EXPORT_SYMBOL_GPL(rohc_comp_deliver_feedback2);

/* statistics */
EXPORT_SYMBOL_GPL(rohc_comp_get_state_descr);
EXPORT_SYMBOL_GPL(rohc_comp_get_general_info);
EXPORT_SYMBOL_GPL(rohc_comp_get_last_packet_info2);

/* configuration */
EXPORT_SYMBOL_GPL(rohc_comp_profile_enabled);
EXPORT_SYMBOL_GPL(rohc_comp_enable_profile);
EXPORT_SYMBOL_GPL(rohc_comp_disable_profile);
EXPORT_SYMBOL_GPL(rohc_comp_enable_profiles);
EXPORT_SYMBOL_GPL(rohc_comp_disable_profiles);
EXPORT_SYMBOL_GPL(rohc_comp_set_mrru);
EXPORT_SYMBOL_GPL(rohc_comp_get_mrru);
EXPORT_SYMBOL_GPL(rohc_comp_get_max_cid);
EXPORT_SYMBOL_GPL(rohc_comp_get_cid_type);
EXPORT_SYMBOL_GPL(rohc_comp_set_wlsb_window_width);
EXPORT_SYMBOL_GPL(rohc_comp_set_reorder_ratio);
EXPORT_SYMBOL_GPL(rohc_comp_set_periodic_refreshes);
EXPORT_SYMBOL_GPL(rohc_comp_set_periodic_refreshes_time);
EXPORT_SYMBOL_GPL(rohc_comp_set_traces_cb2);
EXPORT_SYMBOL_GPL(rohc_comp_set_features);

/* RTP-specific configuration */
EXPORT_SYMBOL_GPL(rohc_comp_set_rtp_detection_cb);


/*
 * Decompression API
 */

/* general */
EXPORT_SYMBOL_GPL(rohc_decomp_new2);
EXPORT_SYMBOL_GPL(rohc_decomp_free);
EXPORT_SYMBOL_GPL(rohc_decompress3);

/* statistics */
EXPORT_SYMBOL_GPL(rohc_decomp_get_state_descr);
EXPORT_SYMBOL_GPL(rohc_decomp_get_general_info);
EXPORT_SYMBOL_GPL(rohc_decomp_get_context_info);
EXPORT_SYMBOL_GPL(rohc_decomp_get_last_packet_info);

/* configuration */
EXPORT_SYMBOL_GPL(rohc_decomp_profile_enabled);
EXPORT_SYMBOL_GPL(rohc_decomp_enable_profile);
EXPORT_SYMBOL_GPL(rohc_decomp_disable_profile);
EXPORT_SYMBOL_GPL(rohc_decomp_enable_profiles);
EXPORT_SYMBOL_GPL(rohc_decomp_disable_profiles);
EXPORT_SYMBOL_GPL(rohc_decomp_get_cid_type);
EXPORT_SYMBOL_GPL(rohc_decomp_get_max_cid);
EXPORT_SYMBOL_GPL(rohc_decomp_set_mrru);
EXPORT_SYMBOL_GPL(rohc_decomp_get_mrru);
EXPORT_SYMBOL_GPL(rohc_decomp_set_rate_limits);
EXPORT_SYMBOL_GPL(rohc_decomp_get_rate_limits);
EXPORT_SYMBOL_GPL(rohc_decomp_set_prtt);
EXPORT_SYMBOL_GPL(rohc_decomp_get_prtt);
EXPORT_SYMBOL_GPL(rohc_decomp_set_traces_cb2);
EXPORT_SYMBOL_GPL(rohc_decomp_set_features);

