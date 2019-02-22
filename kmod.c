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
 * @file   kmod
 * @brief  Export the ROHC library to the Linux kernel with netfilter
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

#define BUFFER_SIZE 10241

struct rohc_init {

	struct rohc_comp *compressor;
	struct rohc_decomp *decompressor;

	unsigned char *rohc_packet_out; // comp ROHC packet
	unsigned char *rohc_packet_in; // ROHC packet to decomp

	unsigned char *feedback_to_send_buf; // feedback to send decomp
	unsigned char *rcvd_feedback_buf; // comp feedback rcvd

	unsigned char *ip_pkt_out; // decomp IP packet
	unsigned char *ip_pkt_in; // comp IP packet

	struct rohc_buf feedback_to_send; // feedback to send decomp with the ROHC by

	size_t rohc_out_size; // comp ROHC packet
	size_t ip_out_size; // decomp IP packet

};

static struct rohc_init rinit;

static struct nf_hook_ops nfin;
static struct nf_hook_ops nfout;

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

int rohc_comp(struct rohc_init *rcouple,
				struct sk_buff *skb,
				struct iphdr *ih) {

	pr_info("ROHC_COMP_INIT\n");

	memset(rcouple, 0, sizeof(struct rohc_init));

	rcouple->rohc_packet_out = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if(rcouple->rohc_packet_out == NULL)
		goto free_comp;
	rcouple->rcvd_feedback_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if(rcouple->rcvd_feedback_buf == NULL)
		goto free_rcvd_feedback;
	rcouple->feedback_to_send_buf = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if(rcouple->feedback_to_send_buf == NULL)
		goto free_feedback_send;

	struct rohc_buf rohc_packet = rohc_buf_init_empty(rcouple->rohc_packet_out, BUFFER_SIZE);
	struct rohc_buf ip_packet = rohc_buf_init_full(skb->data, ntohs(ih->tot_len), 0);

	rohc_status_t status;

	rcouple->rohc_out_size = 0;

	rcouple->compressor = rohc_comp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
									gen_false_random_num, NULL);

	if (rcouple->compressor == NULL) {
		pr_info("failed create the ROHC compressor\n");
		goto free_comp;
	}

	if(!rohc_comp_set_traces_cb2(rcouple->compressor, rohc_print_traces, NULL)) {
		pr_info("cannot set trace callback for compressor\n");
		goto free_comp;
	}
	
	if(!rohc_comp_set_features(rcouple->compressor, ROHC_COMP_FEATURE_DUMP_PACKETS)) {
		pr_info("failed to enable packet dumps\n");
		goto free_comp;
	}

	if(!rohc_comp_enable_profiles(rcouple->compressor,
			ROHC_PROFILE_UNCOMPRESSED, ROHC_PROFILE_RTP,
			ROHC_PROFILE_UDP, ROHC_PROFILE_ESP, ROHC_PROFILE_IP,
			ROHC_PROFILE_TCP, ROHC_PROFILE_UDPLITE, -1)) {
		pr_info("failed to enable the TCP profile\n");
		goto free_comp;
	}

	rcouple->feedback_to_send.time.sec = 0;
	rcouple->feedback_to_send.time.nsec = 0;
	rcouple->feedback_to_send.data = rcouple->feedback_to_send_buf;
	rcouple->feedback_to_send.max_len = BUFFER_SIZE;
	rcouple->feedback_to_send.offset = 0;
	rcouple->feedback_to_send.len = 0;

	rohc_buf_append_buf(&rohc_packet, rcouple->feedback_to_send);
	rohc_buf_pull(&rohc_packet, rcouple->feedback_to_send.len);

	pr_info("ROHC_COMP_START\n");

	status = rohc_compress4(rcouple->compressor, ip_packet, &rohc_packet);

	if (status == ROHC_STATUS_OK) {
		pr_info("ROHC Compression\n");
	}
	else {
		pr_info("Compression failed\n");
		goto free_comp;
	}

	rohc_buf_push(&rohc_packet, rcouple->feedback_to_send.len);

	rcouple->rohc_out_size = rohc_packet.len;
	pr_info("Compression Packet len = %u", rcouple->rohc_out_size);

	rohc_buf_reset(&rcouple->feedback_to_send);

	return NF_ACCEPT;

free_pkt_out:
	kfree(rcouple->rohc_packet_out);
free_rcvd_feedback:
	kfree(rcouple->rcvd_feedback_buf);
free_feedback_send:
	kfree(rcouple->feedback_to_send_buf);
free_comp:
	rohc_comp_free(rcouple->compressor);
	return 0;
}

int rohc_decomp(struct rohc_init *rcouple,
				struct sk_buff *skb,
				struct iphdr *ih) {

	pr_info("ROHC_DECOMP_INIT\n");

	rcouple->rohc_packet_in = kzalloc(BUFFER_SIZE, GFP_KERNEL);
	if(rcouple->rohc_packet_in == NULL)
		goto free_pkt_in;
	
	struct rohc_buf rohc_packet = rohc_buf_init_full(rcouple->rohc_packet_out, 
													ntohs(ih->tot_len), 0);
	struct rohc_buf ip_packet = rohc_buf_init_empty(rcouple->rohc_packet_in, BUFFER_SIZE);
	struct rohc_buf rcvd_feedback = rohc_buf_init_empty(rcouple->rcvd_feedback_buf, 
														BUFFER_SIZE);
	struct rohc_buf *feedback_to_send = &rcouple->feedback_to_send;
	struct rohc_comp *comp_associated = rcouple->compressor;

	rohc_status_t status;

	rcouple->ip_out_size = 0;

	rcouple->decompressor = rohc_decomp_new2(ROHC_SMALL_CID, ROHC_SMALL_CID_MAX, 
											ROHC_O_MODE);

	if (rcouple->decompressor == NULL) {
		pr_info("failed create the ROHC compressor\n");
		goto free_decomp;
	}

	if(!rohc_decomp_set_traces_cb2(rcouple->decompressor, rohc_print_traces, NULL)) {
		pr_info("cannot set trace callback for compressor\n");
		goto free_decomp;
	}
	
	if(!rohc_decomp_set_features(rcouple->decompressor, ROHC_DECOMP_FEATURE_DUMP_PACKETS)) {
		pr_info("failed to enable packet dumps\n");
		goto free_decomp;
	}

	if(!rohc_decomp_enable_profiles(rcouple->decompressor, 
			ROHC_PROFILE_UNCOMPRESSED, ROHC_PROFILE_RTP,
			ROHC_PROFILE_UDP, ROHC_PROFILE_ESP, ROHC_PROFILE_IP,
			ROHC_PROFILE_TCP, ROHC_PROFILE_UDPLITE, -1)) {
		pr_info("failed to enable the TCP profile\n");
		goto free_decomp;
	}

	pr_info("ROHC_DECOMP_START\n");

	status = rohc_decompress3(rcouple->decompressor, rohc_packet, &ip_packet, 
							&rcvd_feedback, feedback_to_send);

	if(status == ROHC_STATUS_OK) {
		pr_info("ROHC Decompression\n");
	}

	else {
		pr_info("ROHC decomp failed\n");
		goto free_decomp;
	}

	rcouple->ip_out_size = ip_packet.len;
	pr_info("Decompression Packet len = %u", rcouple->ip_out_size);

	if(!rohc_comp_deliver_feedback2(comp_associated, rcvd_feedback)) {
		pr_info("failed to deliver received feedback to comp.\n");
		goto free_decomp;
	}

	return NF_ACCEPT;

free_pkt_in:
	kfree(rcouple->rohc_packet_in);

free_decomp:
	rohc_decomp_free(rcouple->decompressor);
	return 0;

}

static int gen_false_random_num(const struct rohc_comp *const comp,
								void *const user_context) {
	return 0;
}

static unsigned int hook_comp (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct iphdr *ih;

	iph = ip_hdr(skb);
	ih = skb_header_pointer(skb, iph->frag_off, sizeof(iph), &iph);

	if (ih == NULL) {
		pr_info("TRUNCATED\n");
		return NF_ACCEPT;
	}
/*
	if (iph->protocol == IPPROTO_TCP) {

		rohc_comp(&rinit, skb, ih);
	}
*/
	rohc_comp(&rinit, skb, ih);

}

static unsigned int hook_decomp (void *priv,
                        struct sk_buff *skb,
                        const struct nf_hook_state *state) {
    
    struct iphdr *iph;
	struct iphdr *ih;

	iph = ip_hdr(skb);
	ih = skb_header_pointer(skb, iph->frag_off, sizeof(iph), &iph);

	if (ih == NULL) {
		pr_info("TRUNCATED\n");
		return NF_ACCEPT;
	}
/*
	if (iph->protocol == IPPROTO_TCP) {
	
		rohc_decomp(&rinit, skb, ih);
	}
*/
	rohc_decomp(&rinit, skb, ih);
}

static int my_comp(void) {
    nfin.hook = hook_comp;
    //nfin.hooknum = NF_INET_POST_ROUTING; // hook in ip_finish_output()
	nfin.hooknum = NF_INET_LOCAL_OUT;
    nfin.pf = PF_INET;
    nfin.priority = NF_IP_PRI_FIRST;
	nfin.priv = NULL;
	nf_register_net_hook(&init_net, &nfin);

	nfout.hook = hook_decomp;
    //nfout.hooknum = NF_INET_PRE_ROUTING; // hook in ip_rcv()
	nfout.hooknum = NF_INET_LOCAL_IN;
    nfout.pf = PF_INET;
    nfout.priority = NF_IP_PRI_FIRST;
	nfout.priv = NULL;
	nf_register_net_hook(&init_net, &nfout);

    return 0;
}

static void my_comp_exit(void) {
    nf_unregister_net_hook(&init_net, &nfin);
	nf_unregister_net_hook(&init_net, &nfout);
}

module_init(my_comp);
module_exit(my_comp_exit);

MODULE_VERSION(PACKAGE_VERSION PACKAGE_REVNO);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Suho CHOI");
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

