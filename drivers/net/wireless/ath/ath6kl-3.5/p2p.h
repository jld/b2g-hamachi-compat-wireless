/*
 * Copyright (c) 2004-2012 Atheros Communications Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef P2P_H
#define P2P_H

#define ATH6KL_P2P_PS_MAX_NOA_DESCRIPTORS		4

#define ATH6KL_P2P_PS_FLAGS_NOA_ENABLED			BIT(0)
#define ATH6KL_P2P_PS_FLAGS_OPPPS_ENABLED		BIT(1)

/* FIXME : move to ieee80211.h */
enum {
	IEEE80211_P2P_ATTR_NOTICE_OF_ABSENCE = 12,
};

struct ieee80211_p2p_noa_descriptor {
	u8 count_or_type; 	/* 255: continuous schedule, 0: reserved */
	__le32 duration;
	__le32 interval;
	__le32 start_or_offset;
} __attribute__((packed));

struct ieee80211_p2p_noa_info {
	u8 index;
	u8 ctwindow_opps_param;
	struct ieee80211_p2p_noa_descriptor noas[ATH6KL_P2P_PS_MAX_NOA_DESCRIPTORS];
} __attribute__((packed));

struct ieee80211_p2p_noa_ie {
	u8 element_id;
	u8 len;
	u32 oui;
	u8 attr;
	u16 attr_len;
	struct ieee80211_p2p_noa_info noa_info;
} __attribute__((packed));

struct p2p_ps_info {
	struct ath6kl_vif *vif;
	spinlock_t p2p_ps_lock;

	/* P2P-GO */
	u32 go_flags;
	u8 go_noa_enable_idx;
	struct ieee80211_p2p_noa_info go_noa;

	/* Cached information */
	u8 *go_last_beacon_app_ie;
	u16 go_last_beacon_app_ie_len;
	u8 *go_last_noa_ie;
	u16 go_last_noa_ie_len;	
	u8 *go_working_buffer;
};

struct p2p_ps_info *ath6kl_p2p_ps_init(struct ath6kl_vif *vif);
void ath6kl_p2p_ps_deinit(struct ath6kl_vif *vif);

int ath6kl_p2p_ps_reset_noa(struct p2p_ps_info *p2p_ps);
int ath6kl_p2p_ps_setup_noa(struct p2p_ps_info *p2p_ps,
			    int noa_id,
			    u8 count_type,
			    u32 interval,
			    u32 start_offset,
			    u32 duration);

int ath6kl_p2p_ps_reset_opps(struct p2p_ps_info *p2p_ps);
int ath6kl_p2p_ps_setup_opps(struct p2p_ps_info *p2p_ps,
			     u8 enabled,
			     u8 ctwindows);

int ath6kl_p2p_ps_update_notif(struct p2p_ps_info *p2p_ps);
void ath6kl_p2p_ps_user_app_ie(struct p2p_ps_info *p2p_ps, 
	 		       u8 mgmt_frm_type,
	 		       u8 **ie, 
			       int *len);
#endif

