/*
 * Copyright (c) 2004-2011 Atheros Communications Inc.
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

#include "core.h"
#include "hif-ops.h"
#include "htc-ops.h"
#include "cfg80211.h"
#include "target.h"
#include "debug.h"

static int _string_to_mac(char *string, int len, u8 *macaddr)
{
	int i, k;
	char temp[3] = {0};

	/* assume string is "00:11:22:33:44:55". */
	if ( !string && (len < 17) ){
		return -1;
	}

	i = k = 0;
	while (i < len){
		memcpy(temp, string + i, 2);
		macaddr[k++] = (u8)simple_strtoul(temp, NULL, 16);
		i += 3;
	}

	return 0;
}

struct ath6kl_sta *ath6kl_find_sta(struct ath6kl_vif *vif, u8 *node_addr)
{
	struct ath6kl_sta *conn = NULL;
	u8 i, max_conn;

	if (vif->nw_type != AP_NETWORK)
		return &vif->sta_list[0];

	max_conn = (vif->nw_type == AP_NETWORK) ? AP_MAX_NUM_STA : 0;

	for (i = 0; i < max_conn; i++) {
		if (memcmp(node_addr, vif->sta_list[i].mac, ETH_ALEN) == 0) {
			conn = &vif->sta_list[i];
			break;
		}
	}

	return conn;
}

struct ath6kl_sta *ath6kl_find_sta_by_aid(struct ath6kl_vif *vif, u8 aid)
{
	struct ath6kl_sta *conn = NULL;
	u8 ctr;

	if (vif->nw_type != AP_NETWORK) {
		conn = &vif->sta_list[0];
	} else {
		for (ctr = 0; ctr < AP_MAX_NUM_STA; ctr++) {
			if (vif->sta_list[ctr].aid == aid) {
				conn = &vif->sta_list[ctr];
				break;
			}
		}
	}

	return conn;
}

static void ath6kl_add_new_sta(struct ath6kl_vif *vif, u8 *mac, u16 aid, u8 *wpaie,
			u8 ielen, u8 keymgmt, u8 ucipher, u8 auth, u8 apsd_info)
{
	struct ath6kl_sta *sta;
	u8 free_slot;

	free_slot = aid - 1;

	sta = &vif->sta_list[free_slot];

	spin_lock_bh(&sta->lock);
	memcpy(sta->mac, mac, ETH_ALEN);
	if (ielen <= ATH6KL_MAX_IE)
		memcpy(sta->wpa_ie, wpaie, ielen);
	sta->aid = aid;
	sta->keymgmt = keymgmt;
	sta->ucipher = ucipher;
	sta->auth = auth;
	sta->apsd_info = apsd_info;
	sta->vif = vif;
	init_timer(&sta->psq_age_timer);
	sta->psq_age_timer.function = ath6kl_psq_age_handler;
	sta->psq_age_timer.data = (unsigned long)sta;
	aggr_reset_state(sta->aggr_conn_cntxt);

	vif->sta_list_index = vif->sta_list_index | (1 << free_slot);
	vif->ap_stats.sta[free_slot].aid = cpu_to_le32(aid);
	spin_unlock_bh(&sta->lock);
}

static void ath6kl_sta_cleanup(struct ath6kl_vif *vif, u8 i)
{
	struct ath6kl_sta *sta = &vif->sta_list[i];

	del_timer_sync(&sta->psq_age_timer);

	spin_lock_bh(&sta->lock);
	sta->vif = NULL;

	/* empty the queued pkts in the PS queue if any */
	skb_queue_purge(&sta->psq);
	ath6kl_mgmt_queue_purge(&sta->mgmt_psq);

	memset(&vif->ap_stats.sta[sta->aid - 1], 0,
	       sizeof(struct wmi_per_sta_stat));
	memset(sta->mac, 0, ETH_ALEN);
	memset(sta->wpa_ie, 0, ATH6KL_MAX_IE);
	sta->aid = 0;
	sta->sta_flags = 0;
	aggr_reset_state(sta->aggr_conn_cntxt);

	vif->sta_list_index = vif->sta_list_index & ~(1 << i);
	spin_unlock_bh(&sta->lock);
}

static u8 ath6kl_remove_sta(struct ath6kl_vif *vif, u8 *mac, u16 reason)
{
	u8 i, removed = 0;

	if (is_zero_ether_addr(mac))
		return removed;

	if (is_broadcast_ether_addr(mac)) {
		ath6kl_dbg(ATH6KL_DBG_TRC, "deleting all station\n");

		for (i = 0; i < AP_MAX_NUM_STA; i++) {
			if (!is_zero_ether_addr(vif->sta_list[i].mac)) {
				ath6kl_sta_cleanup(vif, i);
				removed = 1;
			}
		}
	} else {
		for (i = 0; i < AP_MAX_NUM_STA; i++) {
			if (memcmp(vif->sta_list[i].mac, mac, ETH_ALEN) == 0) {
				ath6kl_dbg(ATH6KL_DBG_TRC,
					   "deleting station %pM aid=%d reason=%d\n",
					   mac, vif->sta_list[i].aid, reason);
				ath6kl_sta_cleanup(vif, i);
				removed = 1;
				break;
			}
		}
	}

	return removed;
}

void ath6kl_mgmt_queue_init(struct ath6kl_mgmt_buf_head *psq)
{
	INIT_LIST_HEAD(&psq->list);
	psq->len = 0;
	spin_lock_init(&psq->lock);
}

void ath6kl_mgmt_queue_purge(struct ath6kl_mgmt_buf_head *psq)
{
	unsigned long flags;
	struct ath6kl_mgmt_buf_head *mgmt_buf, *mgmt_n;

	spin_lock_irqsave(&psq->lock, flags);
	if (psq->len <= 0) {
		spin_unlock_irqrestore(&psq->lock, flags);
		return;
	}
	list_for_each_entry_safe(mgmt_buf, mgmt_n, &psq->list, list) {
		kfree(mgmt_buf);
	}
	psq->len = 0;
	spin_unlock_irqrestore(&psq->lock, flags);
}

int ath6kl_mgmt_queue_empty(struct ath6kl_mgmt_buf_head *psq)
{
	unsigned long flags;
	int empty;

	spin_lock_irqsave(&psq->lock, flags);
	empty = (psq->len == 0);
	spin_unlock_irqrestore(&psq->lock, flags);

	return empty;
}

int ath6kl_mgmt_queue_tail(struct ath6kl_mgmt_buf_head *psq, 
								const u8 *buf, 
								u16 len, 
								u32 id, 
								u32 freq, 
								u32 wait, 
								bool no_cck, 
								bool dont_wait_for_ack)
{
	unsigned long flags;
	struct ath6kl_mgmt_buf* mgmt_buf;
	int mgmt_buf_size;

	mgmt_buf_size = len + sizeof(struct ath6kl_mgmt_buf) - 1;
	mgmt_buf = kmalloc(mgmt_buf_size, GFP_KERNEL);
	if (!mgmt_buf)
		return -ENOMEM;
	
	INIT_LIST_HEAD(&mgmt_buf->list);
	mgmt_buf->id = id;
	mgmt_buf->freq = freq;
	mgmt_buf->wait = wait;
	mgmt_buf->no_cck = no_cck;
	mgmt_buf->dont_wait_for_ack = dont_wait_for_ack;
	mgmt_buf->len = len;
	mgmt_buf->age = 0;
	memcpy(mgmt_buf->buf, buf, len);
	
	spin_lock_irqsave(&psq->lock, flags);
	list_add_tail(&mgmt_buf->list, &psq->list);
	psq->len++;
	spin_unlock_irqrestore(&psq->lock, flags);

	return 0;
}

struct ath6kl_mgmt_buf* ath6kl_mgmt_dequeue_head(struct ath6kl_mgmt_buf_head *psq)
{
	unsigned long flags;
	struct ath6kl_mgmt_buf *mgmt_buf;
	
	spin_lock_irqsave(&psq->lock, flags);
	if (psq->len == 0) {
		spin_unlock_irqrestore(&psq->lock, flags);
		return NULL;
	}
	
	mgmt_buf = list_first_entry(&psq->list, struct ath6kl_mgmt_buf, list);
	list_del(&mgmt_buf->list);
	psq->len--;
	spin_unlock_irqrestore(&psq->lock, flags);

	return mgmt_buf;
}

static void ath6kl_data_psq_aging(struct ath6kl_sta *conn)
{
	struct sk_buff* skb;
	struct sk_buff* skb_n = NULL;
	u32 age;
	bool last = false;

	if (skb_queue_empty(&conn->psq))
		return;

	skb = skb_peek(&conn->psq);
	do {
		if (skb_queue_is_last(&conn->psq, skb))
			last = true;
		else
			skb_n = skb_queue_next(&conn->psq, skb);

		age = ath6kl_data_get_age(skb);
		age++;
		if (age >= ATH6KL_PSQ_MAX_AGE) {
			skb_unlink(skb, &conn->psq);
			kfree_skb(skb);
		} else
			ath6kl_data_set_age(skb, age);

		if (last)
			break;
		else
			skb = skb_n;		
	} while (1);

	if (ath6kl_mgmt_queue_empty(&conn->mgmt_psq) && 
		skb_queue_empty(&conn->psq)) {
		struct ath6kl_vif *vif = conn->vif;

		ath6kl_wmi_set_pvb_cmd(vif->ar->wmi, vif->fw_vif_idx, conn->aid, 0);
	}
}

static void ath6kl_mgmt_psq_aging(struct ath6kl_sta *conn)
{
	struct ath6kl_mgmt_buf* mgmt_buf, *mgmt_n;
	unsigned long flags;
	u32 age;	
	int is_empty;

	spin_lock_irqsave(&conn->mgmt_psq.lock, flags);
	if (conn->mgmt_psq.len == 0) {
		spin_unlock_irqrestore(&conn->mgmt_psq.lock, flags);
		return;
	}
	list_for_each_entry_safe(mgmt_buf, mgmt_n, &conn->mgmt_psq.list, list) {
		age = ath6kl_mgmt_get_age(mgmt_buf);
		age++;
		if (age >= ATH6KL_PSQ_MAX_AGE) {
			list_del(&mgmt_buf->list);
			kfree(mgmt_buf);
			conn->mgmt_psq.len--;
		} else
			ath6kl_mgmt_set_age(mgmt_buf, age);
	}
	is_empty = (conn->mgmt_psq.len == 0) && skb_queue_empty(&conn->psq);
	spin_unlock_irqrestore(&conn->mgmt_psq.lock, flags);

	if (is_empty) {
		struct ath6kl_vif *vif = conn->vif;

		ath6kl_wmi_set_pvb_cmd(vif->ar->wmi, vif->fw_vif_idx, conn->aid, 0);
	}
}

void ath6kl_psq_age_handler(unsigned long ptr)
{
	struct ath6kl_sta *conn = (struct ath6kl_sta*)ptr;

	spin_lock_bh(&conn->lock);
	ath6kl_data_psq_aging(conn);
	ath6kl_mgmt_psq_aging(conn);
	spin_unlock_bh(&conn->lock);

	mod_timer(&conn->psq_age_timer, jiffies + msecs_to_jiffies(ATH6KL_PSQ_CHECK_AGE));
}

void ath6kl_psq_age_start(struct ath6kl_sta *conn)
{
	mod_timer(&conn->psq_age_timer, jiffies + msecs_to_jiffies(ATH6KL_PSQ_CHECK_AGE));
}

void ath6kl_psq_age_stop(struct ath6kl_sta *conn)
{
	del_timer_sync(&conn->psq_age_timer);
}

enum htc_endpoint_id ath6kl_ac2_endpoint_id(void *devt, u8 ac)
{
	struct ath6kl *ar = devt;
	return ar->ac2ep_map[ac];
}

struct ath6kl_cookie *ath6kl_alloc_cookie(struct ath6kl *ar)
{
	struct ath6kl_cookie *cookie;

	cookie = ar->cookie_list;
	if (cookie != NULL) {
		ar->cookie_list = cookie->arc_list_next;
		ar->cookie_count--;
	}

	return cookie;
}

void ath6kl_cookie_init(struct ath6kl *ar)
{
	u32 i;

	ar->cookie_list = NULL;
	ar->cookie_count = 0;

	memset(ar->cookie_mem, 0, sizeof(ar->cookie_mem));

	for (i = 0; i < MAX_COOKIE_NUM; i++)
		ath6kl_free_cookie(ar, &ar->cookie_mem[i]);
}

void ath6kl_cookie_cleanup(struct ath6kl *ar)
{
	ar->cookie_list = NULL;
	ar->cookie_count = 0;
}

void ath6kl_free_cookie(struct ath6kl *ar, struct ath6kl_cookie *cookie)
{
	/* Insert first */

	if (!ar || !cookie)
		return;

	cookie->arc_list_next = ar->cookie_list;
	ar->cookie_list = cookie;
	ar->cookie_count++;
}

/*
 * Read from the hardware through its diagnostic window. No cooperation
 * from the firmware is required for this.
 */
int ath6kl_diag_read32(struct ath6kl *ar, u32 address, u32 *value)
{
	int ret;

	ret = ath6kl_hif_diag_read32(ar, address, value);
	if (ret) {
		ath6kl_warn("failed to read32 through diagnose window: %d\n",
			    ret);
		return ret;
	}

	return 0;
}

/*
 * Write to the ATH6KL through its diagnostic window. No cooperation from
 * the Target is required for this.
 */
int ath6kl_diag_write32(struct ath6kl *ar, u32 address, __le32 value)
{
	int ret;

	ret = ath6kl_hif_diag_write32(ar, address, value);

	if (ret) {
		ath6kl_err("failed to write 0x%x during diagnose window to 0x%d\n",
			   address, value);
		return ret;
	}

	return 0;
}

int ath6kl_diag_read(struct ath6kl *ar, u32 address, void *data, u32 length)
{
	u32 count, *buf = data;
	int ret;

	if (WARN_ON(length % 4))
		return -EINVAL;

	for (count = 0; count < length / 4; count++, address += 4) {
		ret = ath6kl_diag_read32(ar, address, &buf[count]);
		if (ret)
			return ret;
	}

	return 0;
}

int ath6kl_diag_write(struct ath6kl *ar, u32 address, void *data, u32 length)
{
	u32 count;
	__le32 *buf = data;
	int ret;

	if (WARN_ON(length % 4))
		return -EINVAL;

	for (count = 0; count < length / 4; count++, address += 4) {
		ret = ath6kl_diag_write32(ar, address, buf[count]);
		if (ret)
			return ret;
	}

	return 0;
}

int ath6kl_read_fwlogs(struct ath6kl *ar)
{
	struct ath6kl_dbglog_hdr debug_hdr;
	struct ath6kl_dbglog_buf debug_buf;
	u32 address, length, dropped, firstbuf, debug_hdr_addr;
	int ret = 0, loop;
	u8 *buf;

	buf = kmalloc(ATH6KL_FWLOG_PAYLOAD_SIZE, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	address = TARG_VTOP(ar->target_type,
			    ath6kl_get_hi_item_addr(ar,
						    HI_ITEM(hi_dbglog_hdr)));

	ret = ath6kl_diag_read32(ar, address, &debug_hdr_addr);
	if (ret)
		goto out;

	/* Get the contents of the ring buffer */
	if (debug_hdr_addr == 0) {
		ath6kl_warn("Invalid address for debug_hdr_addr\n");
		ret = -EINVAL;
		goto out;
	}

	address = TARG_VTOP(ar->target_type, debug_hdr_addr);
	ath6kl_diag_read(ar, address, &debug_hdr, sizeof(debug_hdr));

	address = TARG_VTOP(ar->target_type,
			    le32_to_cpu(debug_hdr.dbuf_addr));
	firstbuf = address;
	dropped = le32_to_cpu(debug_hdr.dropped);
	ath6kl_diag_read(ar, address, &debug_buf, sizeof(debug_buf));

	loop = 100;

	do {
		address = TARG_VTOP(ar->target_type,
				    le32_to_cpu(debug_buf.buffer_addr));
		length = le32_to_cpu(debug_buf.length);

		if (length != 0 && (le32_to_cpu(debug_buf.length) <=
				    le32_to_cpu(debug_buf.bufsize))) {
			length = ALIGN(length, 4);

			ret = ath6kl_diag_read(ar, address,
					       buf, length);
			if (ret)
				goto out;

			ath6kl_debug_fwlog_event(ar, buf, length);
		}

		address = TARG_VTOP(ar->target_type,
				    le32_to_cpu(debug_buf.next));
		ath6kl_diag_read(ar, address, &debug_buf, sizeof(debug_buf));
		if (ret)
			goto out;

		loop--;

		if (WARN_ON(loop == 0)) {
			ret = -ETIMEDOUT;
			goto out;
		}
	} while (address != firstbuf);

out:
	kfree(buf);

	return ret;
}

/* FIXME: move to a better place, target.h? */
#define AR6003_RESET_CONTROL_ADDRESS 0x00004000
#define AR6004_RESET_CONTROL_ADDRESS 0x00004000
#define AR6006_RESET_CONTROL_ADDRESS 0x00004000

void ath6kl_reset_device(struct ath6kl *ar, u32 target_type,
			 bool wait_fot_compltn, bool cold_reset)
{
	int status = 0;
	u32 address;
	__le32 data;

	if (target_type != TARGET_TYPE_AR6003 &&
		target_type != TARGET_TYPE_AR6004 &&
		target_type != TARGET_TYPE_AR6006)
		return;

	data = cold_reset ? cpu_to_le32(RESET_CONTROL_COLD_RST) :
			    cpu_to_le32(RESET_CONTROL_MBOX_RST);

	switch (target_type) {
	case TARGET_TYPE_AR6003:
		address = AR6003_RESET_CONTROL_ADDRESS;
		break;
	case TARGET_TYPE_AR6004:
		address = AR6004_RESET_CONTROL_ADDRESS;
		break;
	case TARGET_TYPE_AR6006:
		address = AR6006_RESET_CONTROL_ADDRESS;
		break;
	default:
		address = AR6003_RESET_CONTROL_ADDRESS;
		break;
	}

	status = ath6kl_diag_write32(ar, address, data);

	if (status)
		ath6kl_err("failed to reset target\n");
}

static void ath6kl_install_static_wep_keys(struct ath6kl_vif *vif)
{
	u8 index;
	u8 keyusage;

	for (index = WMI_MIN_KEY_INDEX; index <= WMI_MAX_KEY_INDEX; index++) {
		if (vif->wep_key_list[index].key_len) {
			keyusage = GROUP_USAGE;
			if (index == vif->def_txkey_index)
				keyusage |= TX_USAGE;

			ath6kl_wmi_addkey_cmd(vif->ar->wmi, vif->fw_vif_idx,
					      index,
					      WEP_CRYPT,
					      keyusage,
					      vif->wep_key_list[index].key_len,
					      NULL, 0,
					      vif->wep_key_list[index].key,
					      KEY_OP_INIT_VAL, NULL,
					      NO_SYNC_WMIFLAG);
		}
	}
}

void ath6kl_connect_ap_mode_bss(struct ath6kl_vif *vif, u16 channel)
{
	struct ath6kl *ar = vif->ar;
	struct ath6kl_req_key *ik;
	int res;
	u8 key_rsc[ATH6KL_KEY_SEQ_LEN];

	ik = &vif->ap_mode_bkey;

	ath6kl_dbg(ATH6KL_DBG_WLAN_CFG, "AP mode started on %u MHz\n", channel);

	switch (vif->auth_mode) {
	case NONE_AUTH:
		if (vif->prwise_crypto == WEP_CRYPT)
			ath6kl_install_static_wep_keys(vif);
		break;
	case WPA_PSK_AUTH:
	case WPA2_PSK_AUTH:
	case (WPA_PSK_AUTH | WPA2_PSK_AUTH):
		if (!ik->valid)
			break;

		ath6kl_dbg(ATH6KL_DBG_WLAN_CFG, "Delayed addkey for "
			   "the initial group key for AP mode\n");
		memset(key_rsc, 0, sizeof(key_rsc));
		res = ath6kl_wmi_addkey_cmd(
			ar->wmi, vif->fw_vif_idx, ik->key_index, ik->key_type,
			GROUP_USAGE, ik->key_len, key_rsc, ATH6KL_KEY_SEQ_LEN,
			ik->key,
			KEY_OP_INIT_VAL, NULL, SYNC_BOTH_WMIFLAG);
		if (res) {
			ath6kl_dbg(ATH6KL_DBG_WLAN_CFG, "Delayed "
				   "addkey failed: %d\n", res);
		}
		break;
	}

	ath6kl_wmi_bssfilter_cmd(ar->wmi, vif->fw_vif_idx, NONE_BSS_FILTER, 0);
	set_bit(CONNECTED, &vif->flags);
	netif_carrier_on(vif->ndev);
}

void ath6kl_connect_ap_mode_sta(struct ath6kl_vif *vif, u16 aid, u8 *mac_addr,
				u8 keymgmt, u8 ucipher, u8 auth,
				u8 assoc_req_len, u8 *assoc_info, u8 apsd_info)
{
	u8 *ies = NULL, *wpa_ie = NULL, *pos;
	size_t ies_len = 0;
	struct station_info sinfo;

	ath6kl_dbg(ATH6KL_DBG_TRC, "new station %pM aid=%d\n", mac_addr, aid);

	if (assoc_req_len > sizeof(struct ieee80211_hdr_3addr)) {
		struct ieee80211_mgmt *mgmt =
			(struct ieee80211_mgmt *) assoc_info;
		if (ieee80211_is_assoc_req(mgmt->frame_control) &&
		    assoc_req_len >= sizeof(struct ieee80211_hdr_3addr) +
		    sizeof(mgmt->u.assoc_req)) {
			ies = mgmt->u.assoc_req.variable;
			ies_len = assoc_info + assoc_req_len - ies;
		} else if (ieee80211_is_reassoc_req(mgmt->frame_control) &&
			   assoc_req_len >= sizeof(struct ieee80211_hdr_3addr)
			   + sizeof(mgmt->u.reassoc_req)) {
			ies = mgmt->u.reassoc_req.variable;
			ies_len = assoc_info + assoc_req_len - ies;
		}
	}

	pos = ies;
	while (pos && pos + 1 < ies + ies_len) {
		if (pos + 2 + pos[1] > ies + ies_len)
			break;
		if (pos[0] == WLAN_EID_RSN)
			wpa_ie = pos; /* RSN IE */
		else if (pos[0] == WLAN_EID_VENDOR_SPECIFIC &&
			 pos[1] >= 4 &&
			 pos[2] == 0x00 && pos[3] == 0x50 && pos[4] == 0xf2) {
			if (pos[5] == 0x01)
				wpa_ie = pos; /* WPA IE */
			else if (pos[5] == 0x04) {
				wpa_ie = pos; /* WPS IE */
				break; /* overrides WPA/RSN IE */
			}
		} else if (pos[0] == 0x44 && wpa_ie == NULL) {
			/*
			 * Note: WAPI Parameter Set IE re-uses Element ID that
			 * was officially allocated for BSS AC Access Delay. As
			 * such, we need to be a bit more careful on when
			 * parsing the frame. However, BSS AC Access Delay
			 * element is not supposed to be included in
			 * (Re)Association Request frames, so this should not
			 * cause problems.
			 */
			wpa_ie = pos; /* WAPI IE */
			break;
		}
		pos += 2 + pos[1];
	}

	ath6kl_add_new_sta(vif, mac_addr, aid, wpa_ie,
			   wpa_ie ? 2 + wpa_ie[1] : 0,
			   keymgmt, ucipher, auth, apsd_info);

	/* send event to application */
	memset(&sinfo, 0, sizeof(sinfo));

	/* TODO: sinfo.generation */

	sinfo.assoc_req_ies = ies;
	sinfo.assoc_req_ies_len = ies_len;
	sinfo.filled |= STATION_INFO_ASSOC_REQ_IES;

	cfg80211_new_sta(vif->ndev, mac_addr, &sinfo, GFP_KERNEL);

	netif_wake_queue(vif->ndev);
}

void disconnect_timer_handler(unsigned long ptr)
{
	struct net_device *dev = (struct net_device *)ptr;
	struct ath6kl_vif *vif = netdev_priv(dev);

	ath6kl_init_profile_info(vif);
	ath6kl_disconnect(vif);
}

int ath6kl_disconnect(struct ath6kl_vif *vif)
{
	int ret = 0;
	
	if (test_bit(CONNECTED, &vif->flags) ||
	    test_bit(CONNECT_PEND, &vif->flags)) {
		ret = ath6kl_wmi_disconnect_cmd(vif->ar->wmi, vif->fw_vif_idx);
		/*
		 * Disconnect command is issued, clear the connect pending
		 * flag. The connected flag will be cleared in
		 * disconnect event notification.
		 */
		clear_bit(CONNECT_PEND, &vif->flags);
	}

	return ret;
}

/* WMI Event handlers */

void ath6kl_ready_event(void *devt, u8 *datap, u32 sw_ver, u32 abi_ver)
{
	struct ath6kl *ar = devt;

	memcpy(ar->mac_addr, datap, ETH_ALEN);
	ath6kl_dbg(ATH6KL_DBG_TRC, "%s: mac addr = %pM\n",
		   __func__, ar->mac_addr);

	ar->version.wlan_ver = sw_ver;
	ar->version.abi_ver = abi_ver;

	snprintf(ar->wiphy->fw_version,
		 sizeof(ar->wiphy->fw_version),
		 "%u.%u.%u.%u",
		 (ar->version.wlan_ver & 0xf0000000) >> 28,
		 (ar->version.wlan_ver & 0x0f000000) >> 24,
		 (ar->version.wlan_ver & 0x00ff0000) >> 16,
		 (ar->version.wlan_ver & 0x0000ffff));

	/* indicate to the waiting thread that the ready event was received */
	set_bit(WMI_READY, &ar->flag);
	wake_up(&ar->event_wq);
}

void ath6kl_scan_complete_evt(struct ath6kl_vif *vif, int status)
{
	struct ath6kl *ar = vif->ar;
	bool aborted = false;

	if (status != WMI_SCAN_STATUS_SUCCESS)
		aborted = true;

	/* FIXME : bad, may use call-back instead. */
	if (ath6kl_htcoex_scan_complete_event(vif, aborted) == HTCOEX_PASS_SCAN_DONE)
		ath6kl_cfg80211_scan_complete_event(vif, aborted);

	if (!vif->usr_bss_filter) {
		clear_bit(CLEAR_BSSFILTER_ON_BEACON, &vif->flags);
		ath6kl_wmi_bssfilter_cmd(ar->wmi, vif->fw_vif_idx,
					 NONE_BSS_FILTER, 0);
	}

	ath6kl_dbg(ATH6KL_DBG_WLAN_CFG, "scan complete: %d\n", status);
}

void ath6kl_connect_event(struct ath6kl_vif *vif, u16 channel, u8 *bssid,
			  u16 listen_int, u16 beacon_int,
			  enum network_type net_type, u8 beacon_ie_len,
			  u8 assoc_req_len, u8 assoc_resp_len,
			  u8 *assoc_info)
{
	struct ath6kl *ar = vif->ar;

	ath6kl_cfg80211_connect_event(vif, channel, bssid,
				      listen_int, beacon_int,
				      net_type, beacon_ie_len,
				      assoc_req_len, assoc_resp_len,
				      assoc_info);

	memcpy(vif->bssid, bssid, sizeof(vif->bssid));
	vif->bss_ch = channel;

	if ((vif->nw_type == INFRA_NETWORK)) {
		ath6kl_wmi_disctimeout_cmd(ar->wmi, vif->fw_vif_idx,
		   	 		   ATH6KL_DISCONNECT_TIMEOUT);
		ath6kl_wmi_listeninterval_cmd(ar->wmi, vif->fw_vif_idx,
					      ar->listen_intvl_t,
					      ar->listen_intvl_b);
	}

	netif_wake_queue(vif->ndev);

	/* Update connect & link status atomically */
	spin_lock_bh(&vif->if_lock);
	set_bit(CONNECTED, &vif->flags);
	clear_bit(CONNECT_PEND, &vif->flags);
	netif_carrier_on(vif->ndev);
	spin_unlock_bh(&vif->if_lock);

	aggr_reset_state(vif->sta_list[0].aggr_conn_cntxt);
	vif->reconnect_flag = 0;

	if ((vif->nw_type == ADHOC_NETWORK) && ar->ibss_ps_enable) {
		memset(ar->node_map, 0, sizeof(ar->node_map));
		ar->node_num = 0;
		ar->next_ep_id = ENDPOINT_2;
	}

	if (!vif->usr_bss_filter) {
		set_bit(CLEAR_BSSFILTER_ON_BEACON, &vif->flags);
		ath6kl_wmi_bssfilter_cmd(ar->wmi, vif->fw_vif_idx,
					 CURRENT_BSS_FILTER, 0);
	}

	/* Hook connection event */
	ath6kl_htcoex_connect_event(vif);
}

void ath6kl_tkip_micerr_event(struct ath6kl_vif *vif, u8 keyid, bool ismcast)
{
	struct ath6kl_sta *sta;
	u8 tsc[6];

	/*
	 * For AP case, keyid will have aid of STA which sent pkt with
	 * MIC error. Use this aid to get MAC & send it to hostapd.
	 */
	if (vif->nw_type == AP_NETWORK) {
		sta = ath6kl_find_sta_by_aid(vif, (keyid >> 2));
		if (!sta)
			return;

		ath6kl_dbg(ATH6KL_DBG_TRC,
			   "ap tkip mic error received from aid=%d\n", keyid);

		memset(tsc, 0, sizeof(tsc)); /* FIX: get correct TSC */
		cfg80211_michael_mic_failure(vif->ndev, sta->mac,
					     NL80211_KEYTYPE_PAIRWISE, keyid,
					     tsc, GFP_KERNEL);
	} else
		ath6kl_cfg80211_tkip_micerr_event(vif, keyid, ismcast);

}

static void ath6kl_update_target_stats(struct ath6kl_vif *vif, u8 *ptr, u32 len)
{
	struct wmi_target_stats *tgt_stats =
		(struct wmi_target_stats *) ptr;
	struct ath6kl *ar = vif->ar;
	struct target_stats *stats = &vif->target_stats;
	struct tkip_ccmp_stats *ccmp_stats;
	u8 ac;

	if (len < sizeof(*tgt_stats))
		return;

	ath6kl_dbg(ATH6KL_DBG_TRC, "updating target stats\n");

	stats->tx_pkt += le32_to_cpu(tgt_stats->stats.tx.pkt);
	stats->tx_byte += le32_to_cpu(tgt_stats->stats.tx.byte);
	stats->tx_ucast_pkt += le32_to_cpu(tgt_stats->stats.tx.ucast_pkt);
	stats->tx_ucast_byte += le32_to_cpu(tgt_stats->stats.tx.ucast_byte);
	stats->tx_mcast_pkt += le32_to_cpu(tgt_stats->stats.tx.mcast_pkt);
	stats->tx_mcast_byte += le32_to_cpu(tgt_stats->stats.tx.mcast_byte);
	stats->tx_bcast_pkt  += le32_to_cpu(tgt_stats->stats.tx.bcast_pkt);
	stats->tx_bcast_byte += le32_to_cpu(tgt_stats->stats.tx.bcast_byte);
	stats->tx_rts_success_cnt +=
		le32_to_cpu(tgt_stats->stats.tx.rts_success_cnt);

	for (ac = 0; ac < WMM_NUM_AC; ac++)
		stats->tx_pkt_per_ac[ac] +=
			le32_to_cpu(tgt_stats->stats.tx.pkt_per_ac[ac]);

	stats->tx_err += le32_to_cpu(tgt_stats->stats.tx.err);
	stats->tx_fail_cnt += le32_to_cpu(tgt_stats->stats.tx.fail_cnt);
	stats->tx_retry_cnt += le32_to_cpu(tgt_stats->stats.tx.retry_cnt);
	stats->tx_mult_retry_cnt +=
		le32_to_cpu(tgt_stats->stats.tx.mult_retry_cnt);
	stats->tx_rts_fail_cnt +=
		le32_to_cpu(tgt_stats->stats.tx.rts_fail_cnt);
	if (ar->target_type == TARGET_TYPE_AR6004) {
        stats->tx_ucast_rate =
            ath6kl_wmi_get_rate_ar6004(
                    a_sle32_to_cpu(tgt_stats->stats.tx.ucast_rate));
            stats->tx_rate_index = tgt_stats->stats.tx.ucast_rate;
    } else {
        stats->tx_ucast_rate =
        ath6kl_wmi_get_rate(a_sle32_to_cpu(tgt_stats->stats.tx.ucast_rate));
    }

	stats->rx_pkt += le32_to_cpu(tgt_stats->stats.rx.pkt);
	stats->rx_byte += le32_to_cpu(tgt_stats->stats.rx.byte);
	stats->rx_ucast_pkt += le32_to_cpu(tgt_stats->stats.rx.ucast_pkt);
	stats->rx_ucast_byte += le32_to_cpu(tgt_stats->stats.rx.ucast_byte);
	stats->rx_mcast_pkt += le32_to_cpu(tgt_stats->stats.rx.mcast_pkt);
	stats->rx_mcast_byte += le32_to_cpu(tgt_stats->stats.rx.mcast_byte);
	stats->rx_bcast_pkt += le32_to_cpu(tgt_stats->stats.rx.bcast_pkt);
	stats->rx_bcast_byte += le32_to_cpu(tgt_stats->stats.rx.bcast_byte);
	stats->rx_frgment_pkt += le32_to_cpu(tgt_stats->stats.rx.frgment_pkt);
	stats->rx_err += le32_to_cpu(tgt_stats->stats.rx.err);
	stats->rx_crc_err += le32_to_cpu(tgt_stats->stats.rx.crc_err);
	stats->rx_key_cache_miss +=
		le32_to_cpu(tgt_stats->stats.rx.key_cache_miss);
	stats->rx_decrypt_err += le32_to_cpu(tgt_stats->stats.rx.decrypt_err);
	stats->rx_dupl_frame += le32_to_cpu(tgt_stats->stats.rx.dupl_frame);
	stats->rx_ucast_rate =
	    ath6kl_wmi_get_rate(a_sle32_to_cpu(tgt_stats->stats.rx.ucast_rate));

	ccmp_stats = &tgt_stats->stats.tkip_ccmp_stats;

	stats->tkip_local_mic_fail +=
		le32_to_cpu(ccmp_stats->tkip_local_mic_fail);
	stats->tkip_cnter_measures_invoked +=
		le32_to_cpu(ccmp_stats->tkip_cnter_measures_invoked);
	stats->tkip_fmt_err += le32_to_cpu(ccmp_stats->tkip_fmt_err);

	stats->ccmp_fmt_err += le32_to_cpu(ccmp_stats->ccmp_fmt_err);
	stats->ccmp_replays += le32_to_cpu(ccmp_stats->ccmp_replays);

	stats->pwr_save_fail_cnt +=
		le32_to_cpu(tgt_stats->pm_stats.pwr_save_failure_cnt);
	stats->noise_floor_calib =
		a_sle32_to_cpu(tgt_stats->noise_floor_calib);

	stats->cs_bmiss_cnt +=
		le32_to_cpu(tgt_stats->cserv_stats.cs_bmiss_cnt);
	stats->cs_low_rssi_cnt +=
		le32_to_cpu(tgt_stats->cserv_stats.cs_low_rssi_cnt);
	stats->cs_connect_cnt +=
		le16_to_cpu(tgt_stats->cserv_stats.cs_connect_cnt);
	stats->cs_discon_cnt +=
		le16_to_cpu(tgt_stats->cserv_stats.cs_discon_cnt);

	stats->cs_ave_beacon_rssi =
		a_sle16_to_cpu(tgt_stats->cserv_stats.cs_ave_beacon_rssi);

	stats->cs_last_roam_msec =
		tgt_stats->cserv_stats.cs_last_roam_msec;
	stats->cs_snr = tgt_stats->cserv_stats.cs_snr;
	stats->cs_rssi = a_sle16_to_cpu(tgt_stats->cserv_stats.cs_rssi);

	stats->lq_val = le32_to_cpu(tgt_stats->lq_val);

	stats->wow_pkt_dropped +=
		le32_to_cpu(tgt_stats->wow_stats.wow_pkt_dropped);
	stats->wow_host_pkt_wakeups +=
		tgt_stats->wow_stats.wow_host_pkt_wakeups;
	stats->wow_host_evt_wakeups +=
		tgt_stats->wow_stats.wow_host_evt_wakeups;
	stats->wow_evt_discarded +=
		le16_to_cpu(tgt_stats->wow_stats.wow_evt_discarded);

}

static void ath6kl_add_le32(__le32 *var, __le32 val)
{
	*var = cpu_to_le32(le32_to_cpu(*var) + le32_to_cpu(val));
}

void ath6kl_tgt_stats_event(struct ath6kl_vif *vif, u8 *ptr, u32 len)
{
	struct wmi_ap_mode_stat *p = (struct wmi_ap_mode_stat *) ptr;
	struct wmi_ap_mode_stat *ap = &vif->ap_stats;
	struct wmi_per_sta_stat *st_ap, *st_p;
	u8 ac;

	if (vif->nw_type == AP_NETWORK) {
		if ((len + 4) >= sizeof(*p)) {
			for (ac = 0; ac < AP_MAX_NUM_STA; ac++) {
				st_ap = &ap->sta[ac];
				st_p = &p->sta[ac];

				ath6kl_add_le32(&st_ap->tx_bytes, st_p->tx_bytes);
				ath6kl_add_le32(&st_ap->tx_pkts, st_p->tx_pkts);
				ath6kl_add_le32(&st_ap->tx_error, st_p->tx_error);
				ath6kl_add_le32(&st_ap->tx_discard, st_p->tx_discard);
				ath6kl_add_le32(&st_ap->rx_bytes, st_p->rx_bytes);
				ath6kl_add_le32(&st_ap->rx_pkts, st_p->rx_pkts);
				ath6kl_add_le32(&st_ap->rx_error, st_p->rx_error);
				ath6kl_add_le32(&st_ap->rx_discard, st_p->rx_discard);
				st_ap->aid = st_p->aid;
				st_ap->tx_ucast_rate = st_p->tx_ucast_rate;
			}
		}
	} else {
		ath6kl_update_target_stats(vif, ptr, len);
	}

	if (test_bit(STATS_UPDATE_PEND, &vif->flags)) {
		clear_bit(STATS_UPDATE_PEND, &vif->flags);
		wake_up(&vif->ar->event_wq);
	}
}

void ath6kl_wakeup_event(void *dev)
{
	struct ath6kl *ar = (struct ath6kl *) dev;

	wake_up(&ar->event_wq);
}

void ath6kl_txpwr_rx_evt(void *devt, u8 tx_pwr)
{
	struct ath6kl *ar = (struct ath6kl *) devt;

	ar->tx_pwr = tx_pwr;
	wake_up(&ar->event_wq);
}

void ath6kl_pspoll_event(struct ath6kl_vif *vif, u8 aid)
{
	struct ath6kl_sta *conn;
	struct sk_buff *skb;
	bool psq_empty = false;
	bool is_data_psq_empty, is_mgmt_psq_empty;
	struct ath6kl *ar = vif->ar;

	conn = ath6kl_find_sta_by_aid(vif, aid);

	if (!conn)
		return;
	/*
	 * Send out a packet queued on ps queue. When the ps queue
	 * becomes empty update the PVB for this station.
	 */
	spin_lock_bh(&conn->lock);
	is_data_psq_empty = skb_queue_empty(&conn->psq);
	is_mgmt_psq_empty = ath6kl_mgmt_queue_empty(&conn->mgmt_psq);
	psq_empty  = is_data_psq_empty && is_mgmt_psq_empty;

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE, 
				"%s: aid %d sta_flags %x psq %d mgmt_psq %d\n",
				__func__, conn->aid, conn->sta_flags, !is_data_psq_empty, !is_mgmt_psq_empty);

	if (psq_empty) {
		/* TODO: Send out a NULL data frame */
		spin_unlock_bh(&conn->lock);
		return;
	}

	if (!is_mgmt_psq_empty) {
		struct ath6kl_mgmt_buf *mgmt_buf;

		mgmt_buf = ath6kl_mgmt_dequeue_head(&conn->mgmt_psq);
		spin_unlock_bh(&conn->lock);
    
		conn->sta_flags |= STA_PS_POLLED;
		ath6kl_wmi_send_action_cmd(ar->wmi, 
									vif->fw_vif_idx,
									mgmt_buf->id, 
									mgmt_buf->freq, 
									mgmt_buf->wait, 
									mgmt_buf->buf,
									mgmt_buf->len);
		conn->sta_flags &= ~STA_PS_POLLED;
		kfree(mgmt_buf);
	} else {
		skb = skb_dequeue(&conn->psq);
		spin_unlock_bh(&conn->lock);

		WARN_ON(!skb);
		if (skb) {
			conn->sta_flags |= STA_PS_POLLED;
			ath6kl_data_tx(skb, vif->ndev);
			conn->sta_flags &= ~STA_PS_POLLED;
		}
	}

	spin_lock_bh(&conn->lock);
	psq_empty  = skb_queue_empty(&conn->psq) && 
					ath6kl_mgmt_queue_empty(&conn->mgmt_psq);
	spin_unlock_bh(&conn->lock);

	if (psq_empty)
		ath6kl_wmi_set_pvb_cmd(ar->wmi, vif->fw_vif_idx, conn->aid, 0);
}

void ath6kl_dtimexpiry_event(struct ath6kl_vif *vif)
{
	bool mcastq_empty = false;
	struct sk_buff *skb;
	struct ath6kl *ar = vif->ar;

	/*
	 * If there are no associated STAs, ignore the DTIM expiry event.
	 * There can be potential race conditions where the last associated
	 * STA may disconnect & before the host could clear the 'Indicate
	 * DTIM' request to the firmware, the firmware would have just
	 * indicated a DTIM expiry event. The race is between 'clear DTIM
	 * expiry cmd' going from the host to the firmware & the DTIM
	 * expiry event happening from the firmware to the host.
	 */
	if (!vif->sta_list_index)
		return;

	spin_lock_bh(&vif->mcastpsq_lock);
	mcastq_empty = skb_queue_empty(&vif->mcastpsq);
	spin_unlock_bh(&vif->mcastpsq_lock);

	if (mcastq_empty)
		return;

	/* set the STA flag to dtim_expired for the frame to go out */
	set_bit(DTIM_EXPIRED, &vif->flags);

	spin_lock_bh(&vif->mcastpsq_lock);
	while ((skb = skb_dequeue(&vif->mcastpsq)) != NULL) {
		spin_unlock_bh(&vif->mcastpsq_lock);

		ath6kl_data_tx(skb, vif->ndev);

		spin_lock_bh(&vif->mcastpsq_lock);
	}
	spin_unlock_bh(&vif->mcastpsq_lock);

	clear_bit(DTIM_EXPIRED, &vif->flags);

	/* clear the LSB of the BitMapCtl field of the TIM IE */
	ath6kl_wmi_set_pvb_cmd(ar->wmi, vif->fw_vif_idx, MCAST_AID, 0);
}

void ath6kl_disconnect_event(struct ath6kl_vif *vif, u8 reason, u8 *bssid,
			     u8 assoc_resp_len, u8 *assoc_info,
			     u16 prot_reason_status)
{
	struct ath6kl *ar = vif->ar;

	if (vif->nw_type == AP_NETWORK) {
		if (!ath6kl_remove_sta(vif, bssid, prot_reason_status))
			return;

		/* if no more associated STAs, empty the mcast PS q */
		if (vif->sta_list_index == 0) {
			spin_lock_bh(&vif->mcastpsq_lock);
			skb_queue_purge(&vif->mcastpsq);
			spin_unlock_bh(&vif->mcastpsq_lock);

			/* clear the LSB of the TIM IE's BitMapCtl field */
			if (test_bit(WMI_READY, &ar->flag))
				ath6kl_wmi_set_pvb_cmd(ar->wmi, vif->fw_vif_idx,
						       MCAST_AID, 0);
		}

		if (!is_broadcast_ether_addr(bssid)) {
			/* send event to application */
			cfg80211_del_sta(vif->ndev, bssid, GFP_KERNEL);
		}

		if (memcmp(vif->ndev->dev_addr, bssid, ETH_ALEN) == 0) {
			memset(vif->wep_key_list, 0, sizeof(vif->wep_key_list));
			clear_bit(CONNECTED, &vif->flags);
		}
		return;
	} else if (vif->nw_type == INFRA_NETWORK) {
		ath6kl_wmi_disctimeout_cmd(ar->wmi, vif->fw_vif_idx,
		   	 		   ATH6KL_DISCONNECT_TIMEOUT);

		/* Support to triger supplicant to have another try. */
		if (!is_valid_ether_addr(bssid) &&
		    is_valid_ether_addr(vif->req_bssid))
			bssid = vif->req_bssid;
	}
	
	ath6kl_cfg80211_disconnect_event(vif, reason, bssid,
				       assoc_resp_len, assoc_info,
				       prot_reason_status);

	aggr_reset_state(vif->sta_list[0].aggr_conn_cntxt);

	del_timer(&vif->disconnect_timer);

	ath6kl_dbg(ATH6KL_DBG_WLAN_CFG, "disconnect reason is %d\n", reason);

	/*
	 * If the event is due to disconnect cmd from the host, only they
	 * the target would stop trying to connect. Under any other
	 * condition, target would keep trying to connect.
	 */
	if (reason == DISCONNECT_CMD) {
		if (!vif->usr_bss_filter && test_bit(WMI_READY, &ar->flag))
			ath6kl_wmi_bssfilter_cmd(ar->wmi, vif->fw_vif_idx,
						 NONE_BSS_FILTER, 0);
	} else {
		set_bit(CONNECT_PEND, &vif->flags);
		if (((reason == ASSOC_FAILED) &&
		    (prot_reason_status == 0x11)) ||
		    ((reason == ASSOC_FAILED) && (prot_reason_status == 0x0)
		     && (vif->reconnect_flag == 1))) {
			set_bit(CONNECTED, &vif->flags);
			return;
		}
	}

	/* update connect & link status atomically */
	spin_lock_bh(&vif->if_lock);
	clear_bit(CONNECTED, &vif->flags);
	netif_carrier_off(vif->ndev);
	spin_unlock_bh(&vif->if_lock);

	if ((reason != CSERV_DISCONNECT) || (vif->reconnect_flag != 1))
		vif->reconnect_flag = 0;

	if (reason != CSERV_DISCONNECT)
		ar->user_key_ctrl = 0;

	netif_stop_queue(vif->ndev);
	memset(vif->bssid, 0, sizeof(vif->bssid));
	vif->bss_ch = 0;

	ath6kl_tx_data_cleanup(ar);

	/* Hook disconnection event */
	ath6kl_htcoex_disconnect_event(vif);
}

struct ath6kl_vif *ath6kl_vif_first(struct ath6kl *ar)
{
	struct ath6kl_vif *vif;

	spin_lock_bh(&ar->list_lock);
	if (list_empty(&ar->vif_list)) {
		spin_unlock_bh(&ar->list_lock);
		return NULL;
	}

	vif = list_first_entry(&ar->vif_list, struct ath6kl_vif, list);

	spin_unlock_bh(&ar->list_lock);

	return vif;
}

static int ath6kl_open(struct net_device *dev)
{
	struct ath6kl_vif *vif = netdev_priv(dev);
	struct ath6kl *ar = ath6kl_priv(dev);

	set_bit(WLAN_ENABLED, &vif->flags);

	if (test_bit(CONNECTED, &vif->flags) ||
	    test_bit(TESTMODE_EPPING, &ar->flag)) {
		netif_carrier_on(dev);
		netif_wake_queue(dev);
	} else
		netif_carrier_off(dev);

	return 0;
}

static int ath6kl_close(struct net_device *dev)
{
	struct ath6kl *ar = ath6kl_priv(dev);
	struct ath6kl_vif *vif = netdev_priv(dev);

	netif_stop_queue(dev);

	ath6kl_disconnect(vif);

	if (test_bit(WMI_READY, &ar->flag)) {
		if (ath6kl_wmi_scanparams_cmd(ar->wmi, vif->fw_vif_idx, 0xFFFF,
					      0, 0, 0, 0, 0, 0, 0, 0, 0))
			return -EIO;

	}

	ath6kl_cfg80211_scan_complete_event(vif, true);

	clear_bit(WLAN_ENABLED, &vif->flags);

	return 0;
}

static struct net_device_stats *ath6kl_get_stats(struct net_device *dev)
{
	struct ath6kl_vif *vif = netdev_priv(dev);

	return &vif->net_stats;
}

static int ath6kl_ioctl_standard(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct ath6kl_vif *vif = netdev_priv(dev);
	void *data = (void *)(rq->ifr_data);
	int ret = 0;

	switch(cmd) {
	case ATH6KL_IOCTL_STANDARD01:
	{	/* FIXME : not yet support all Android private commands. */
		struct ath6kl_android_wifi_priv_cmd android_cmd;
		char *user_cmd, *pos;
		u8 pwr_mode;

		if(copy_from_user(&android_cmd, data, sizeof(struct ath6kl_android_wifi_priv_cmd)))
			ret = -EIO;
		else {
			user_cmd = kzalloc(android_cmd.total_len, GFP_KERNEL);
			if (!user_cmd) {
				ret = -ENOMEM;
				break;
			}

			if(copy_from_user(user_cmd, android_cmd.buf, android_cmd.used_len)) 
				ret = -EIO;
			else {
				if ((pos = strstr(user_cmd, "P2P_SET_PS ")) != NULL) {
					/* P2P_SET_PS {legacy_ps} {opp_ps} {ctwindow} */
					if (android_cmd.used_len > 12) {
						if (down_interruptible(&vif->ar->sem)) {
							ath6kl_err("busy, couldn't get access\n");
							ret = -EIO;
							break;
						}

						ret = 0;
						/* FIXME : better parsing... */
						pwr_mode = (pos[11] != '0' ? 
								REC_POWER : MAX_PERF_POWER);
						if (ath6kl_wmi_powermode_cmd(vif->ar->wmi, 
									     vif->fw_vif_idx,
									     pwr_mode))
							ret = -EIO;

						up(&vif->ar->sem);
					} else
						ret = -EFAULT;
				} else {
					ath6kl_err("%s : not yet support \"%s\"\n", 
									__func__, 
									user_cmd);
					ret = -EOPNOTSUPP;
				}
			}

			kfree(user_cmd);
		}
		break;
	}
	case ATH6KL_IOCTL_STANDARD02:
	{
		struct ath6kl_ioctl_cmd ioctl_cmd;

		if(copy_from_user(&ioctl_cmd, data, sizeof(struct ath6kl_ioctl_cmd)))
			ret = -EIO;
		else {
			switch(ioctl_cmd.subcmd){
			case ATH6KL_IOCTL_AP_APSD:
				ath6kl_wmi_ap_set_apsd(vif->ar->wmi, vif->fw_vif_idx, ioctl_cmd.options);
				break;
			case ATH6KL_IOCTL_AP_INTRABSS:
				vif->intra_bss = ioctl_cmd.options;
				break;
			default:
				ret = -EOPNOTSUPP;
				break;
			}
		}
		break;
	}
	default:
		ret = -EOPNOTSUPP;
		break;
	}
	
	return ret;
}

static int ath6kl_ioctl_linkspeed(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct ath6kl *ar = ath6kl_priv(dev);
	struct ath6kl_vif *vif = netdev_priv(dev);
	struct iwreq *req = (struct iwreq *)(rq);
	char user_cmd[32];
	u8 macaddr[6];
	long left;
	s32 rate = 0;

	/* FIXME : only AR6004 now */
	if (ar->target_type != TARGET_TYPE_AR6004)
		return -EOPNOTSUPP;

	if ((!req->u.data.pointer) || (!req->u.data.length))
		return -EFAULT;

	memset(user_cmd, 0, 32);
	if (copy_from_user(user_cmd, req->u.data.pointer, req->u.data.length))
		return -EFAULT;

	if (_string_to_mac(user_cmd, req->u.data.length, macaddr))
		return -EFAULT;

	if (down_interruptible(&ar->sem))
		return -EBUSY;

	set_bit(STATS_UPDATE_PEND, &vif->flags);

	if (ath6kl_wmi_get_stats_cmd(ar->wmi, vif->fw_vif_idx) != 0) {
		up(&ar->sem);
		return -EIO;
	}

	left = wait_event_interruptible_timeout(ar->event_wq,
						!test_bit(STATS_UPDATE_PEND,
							  &vif->flags),
						WMI_TIMEOUT);

	up(&ar->sem);

	if (left == 0)
		return -ETIMEDOUT;
	else if (left < 0)
		return left;

	memset(user_cmd, 0, 32);
	if (vif->nw_type == AP_NETWORK) {
		struct wmi_ap_mode_stat *ap = &vif->ap_stats;
		struct ath6kl_sta *conn;

		conn = ath6kl_find_sta(vif, macaddr);
		if (conn){	
			for (left = 0; left < AP_MAX_NUM_STA; left++) {
				if (conn->aid == ap->sta[left].aid) {
					rate = ath6kl_wmi_get_rate_ar6004(ap->sta[left].tx_ucast_rate);
					break;
				}
			}

			WARN_ON(left == AP_MAX_NUM_STA);
		}
	} else
		rate = vif->target_stats.tx_ucast_rate;

	snprintf(user_cmd, 32, "%u", rate / 1000);
	req->u.data.length = strlen(user_cmd);
	user_cmd[req->u.data.length] = '\0';

	return (copy_to_user(req->u.data.pointer, user_cmd, req->u.data.length + 1) 
			? -EFAULT : 0);
}

int ath6kl_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct ath6kl *ar = ath6kl_priv(dev);
	int ret = true;
	s8 *userdata;

	/*
	* ioctl operations may have to wait for the Target, so we cannot hold rtnl.
	* Prevent the device from disappearing under us and release the lock during
	* the ioctl operation.
	*/
	dev_hold(dev);
	rtnl_unlock();

	switch(cmd) {
	case ATH6KL_IOCTL_STANDARD01: 	/* Reserved for Android PNO */
	case ATH6KL_IOCTL_STANDARD02:	/* supplicant escape purpose to support WiFi-Direct Cert. */
	case ATH6KL_IOCTL_STANDARD12: 	/* hole, please reserved */
	case ATH6KL_IOCTL_STANDARD13: 	/* TX99 */
	case ATH6KL_IOCTL_STANDARD15: 	/* hole, please reserved */
		ret = ath6kl_ioctl_standard(dev, rq, cmd);
		break;
	case ATH6KL_IOCTL_WEXT_PRIV26:	/* endpoint loopback purpose */
		get_user(cmd, (int *)rq->ifr_data);
		userdata = (char *)(((unsigned int *)rq->ifr_data)+1);

		switch(cmd) {
		case ATH6KL_XIOCTL_TRAFFIC_ACTIVITY_CHANGE:
			if (ar->htc_target!= NULL) {
				struct ath6kl_traffic_activity_change data;
				if (copy_from_user(&data, userdata, sizeof(data))) {
					ret = -EFAULT;
					goto ioctl_done;
				}
				ath6kl_htc_indicate_activity_change(ar->htc_target,
		                                            (u8)data.stream_id,
		                                            data.active ? true : false);
			}
			break;
		}
		break;
	case ATH6KL_IOCTL_WEXT_PRIV27:	/* QCSAP (old) */
	case ATH6KL_IOCTL_WEXT_PRIV31:	/* QCSAP */
		ret = ath6kl_ioctl_linkspeed(dev, rq, cmd);
		break;
	default:
		ret = -EOPNOTSUPP;
		goto ioctl_done;
	}

ioctl_done:
    rtnl_lock(); /* restore rtnl state */
    dev_put(dev);

    return ret;
}

static struct net_device_ops ath6kl_netdev_ops = {
	.ndo_open               = ath6kl_open,
	.ndo_stop               = ath6kl_close,
	.ndo_start_xmit         = ath6kl_data_tx,
	.ndo_get_stats          = ath6kl_get_stats,
	.ndo_do_ioctl           = ath6kl_ioctl,
};

void init_netdev(struct net_device *dev)
{
	netdev_attach_ops(dev, &ath6kl_netdev_ops);
	dev->destructor = free_netdev;
	dev->watchdog_timeo = ATH6KL_TX_TIMEOUT;

	dev->needed_headroom = ETH_HLEN;
	dev->needed_headroom += sizeof(struct ath6kl_llc_snap_hdr) +
				sizeof(struct wmi_data_hdr) + HTC_HDR_LENGTH
				+ WMI_MAX_TX_META_SZ + ATH6KL_HTC_ALIGN_BYTES;

	return;
}
