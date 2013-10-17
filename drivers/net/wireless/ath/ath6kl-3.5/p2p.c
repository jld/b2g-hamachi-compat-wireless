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

#include "core.h"
#include "debug.h"

struct p2p_ps_info *ath6kl_p2p_ps_init(struct ath6kl_vif *vif)
{
	struct p2p_ps_info *p2p_ps;

	p2p_ps = kzalloc(sizeof(struct p2p_ps_info), GFP_KERNEL);
	if (!p2p_ps) {
		ath6kl_err("failed to alloc memory for p2p_ps\n");
		return NULL;
	}

	p2p_ps->vif = vif;
	spin_lock_init(&p2p_ps->p2p_ps_lock);

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps init (vif %p) type %d\n",
		   vif,
		   vif->wdev.iftype);
		
	return p2p_ps;
}

void ath6kl_p2p_ps_deinit(struct ath6kl_vif *vif)
{
	struct p2p_ps_info *p2p_ps = vif->p2p_ps_info_ctx;

	if (p2p_ps) {
		spin_lock(&p2p_ps->p2p_ps_lock);
		if (p2p_ps->go_last_beacon_app_ie)
			kfree(p2p_ps->go_last_beacon_app_ie);

		if (p2p_ps->go_last_noa_ie)
			kfree(p2p_ps->go_last_noa_ie);

		if (p2p_ps->go_working_buffer)
			kfree(p2p_ps->go_working_buffer);
		spin_unlock(&p2p_ps->p2p_ps_lock);
		
		kfree(p2p_ps);
	}

	vif->p2p_ps_info_ctx = NULL;

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps deinit (vif %p)\n",
		   vif);
		
	return;
}

int ath6kl_p2p_ps_reset_noa(struct p2p_ps_info *p2p_ps)
{
	if ((!p2p_ps) || 
	    (p2p_ps->vif->wdev.iftype != NL80211_IFTYPE_P2P_GO)) {
	    ath6kl_err("failed to reset P2P-GO noa\n");
	    return -1;
	}

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps reset NoA (vif %p) index %d\n",
		   p2p_ps->vif,
		   p2p_ps->go_noa.index);

	spin_lock(&p2p_ps->p2p_ps_lock);
	p2p_ps->go_flags &= ~ATH6KL_P2P_PS_FLAGS_NOA_ENABLED;
	p2p_ps->go_noa.index++;
	p2p_ps->go_noa_enable_idx = 0;
	memset(p2p_ps->go_noa.noas,
		0,
		sizeof(struct ieee80211_p2p_noa_descriptor) * 
			ATH6KL_P2P_PS_MAX_NOA_DESCRIPTORS);
	spin_unlock(&p2p_ps->p2p_ps_lock);
	
	return 0;
}

int ath6kl_p2p_ps_setup_noa(struct p2p_ps_info *p2p_ps,
			    int noa_id,
			    u8 count_type,
			    u32 interval,
			    u32 start_offset,
			    u32 duration)
{
	struct ieee80211_p2p_noa_descriptor *noa_descriptor;
		
	if ((!p2p_ps) || 
	    (p2p_ps->vif->wdev.iftype != NL80211_IFTYPE_P2P_GO)) {
	    ath6kl_err("failed to setup P2P-GO noa\n");
	    return -1;
	}

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps setup NoA (vif %p) idx %d ct %d intval %x so %x dur %x\n",
		   p2p_ps->vif,
		   noa_id,
		   count_type,
		   interval,
		   start_offset,
		   duration);

	spin_lock(&p2p_ps->p2p_ps_lock);
	if (noa_id < ATH6KL_P2P_PS_MAX_NOA_DESCRIPTORS) {
		noa_descriptor = &p2p_ps->go_noa.noas[noa_id];

		noa_descriptor->count_or_type = count_type;
		noa_descriptor->interval = interval;
		noa_descriptor->start_or_offset = start_offset;
		noa_descriptor->duration = duration;
	} else {
		spin_unlock(&p2p_ps->p2p_ps_lock);
		ath6kl_err("wrong NoA index %d\n", noa_id);

		return -2;
	}

	p2p_ps->go_noa_enable_idx |= (1 << noa_id);
	p2p_ps->go_flags |= ATH6KL_P2P_PS_FLAGS_NOA_ENABLED;
	spin_unlock(&p2p_ps->p2p_ps_lock);

	return 0;
}

int ath6kl_p2p_ps_reset_opps(struct p2p_ps_info *p2p_ps)
{
	if ((!p2p_ps) || 
	    (p2p_ps->vif->wdev.iftype != NL80211_IFTYPE_P2P_GO)) {
	    ath6kl_err("failed to reset P2P-GO OppPS\n");
	    return -1;
	}

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps reset OppPS (vif %p) index %d\n",
		   p2p_ps->vif,
		   p2p_ps->go_noa.index);

	spin_lock(&p2p_ps->p2p_ps_lock);
	p2p_ps->go_flags &= ~ATH6KL_P2P_PS_FLAGS_OPPPS_ENABLED;
	p2p_ps->go_noa.index++;
	p2p_ps->go_noa.ctwindow_opps_param = 0;
	spin_unlock(&p2p_ps->p2p_ps_lock);
	
	return 0;
}

int ath6kl_p2p_ps_setup_opps(struct p2p_ps_info *p2p_ps, 
			     u8 enabled,
			     u8 ctwindows)
{
	if ((!p2p_ps) || 
	    (p2p_ps->vif->wdev.iftype != NL80211_IFTYPE_P2P_GO)) {
	    ath6kl_err("failed to setup P2P-GO noa\n");
	    return -1;
	}

	WARN_ON(enabled && (!(ctwindows & 0x7f)));

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps setup OppPS (vif %p) enabled %d ctwin %d\n",
		   p2p_ps->vif,
		   enabled,
		   ctwindows);

	spin_lock(&p2p_ps->p2p_ps_lock);
	if (enabled)
		p2p_ps->go_noa.ctwindow_opps_param = (0x80 | (ctwindows & 0x7f));
	else
		p2p_ps->go_noa.ctwindow_opps_param = 0;
	p2p_ps->go_flags |= ATH6KL_P2P_PS_FLAGS_OPPPS_ENABLED;
	spin_unlock(&p2p_ps->p2p_ps_lock);

	return 0;
}

int ath6kl_p2p_ps_update_notif(struct p2p_ps_info *p2p_ps)
{
	struct ath6kl_vif *vif;
	struct ieee80211_p2p_noa_ie *noa_ie;
	struct ieee80211_p2p_noa_descriptor *noa_descriptor;
	int i, idx, len, ret = 0;
	u8 *buf;

	WARN_ON(!p2p_ps);
	WARN_ON(!p2p_ps->go_last_beacon_app_ie_len);

	vif = p2p_ps->vif;

	/* 
	 * FIXME : No availabe NL80211 event to update to supplicant so far.
	 *         Instead, we try to set back to target here.
	 */
	spin_lock(&p2p_ps->p2p_ps_lock);
	if ((p2p_ps->go_flags & ATH6KL_P2P_PS_FLAGS_NOA_ENABLED) ||
	    (p2p_ps->go_flags & ATH6KL_P2P_PS_FLAGS_OPPPS_ENABLED)) {
		WARN_ON(((p2p_ps->go_flags & ATH6KL_P2P_PS_FLAGS_NOA_ENABLED) &&
			 (!p2p_ps->go_noa_enable_idx)));

		len = p2p_ps->go_last_beacon_app_ie_len +
		      sizeof(struct ieee80211_p2p_noa_ie);

		buf = kmalloc(len, GFP_ATOMIC);
		if (buf == NULL) {
			spin_unlock(&p2p_ps->p2p_ps_lock);

			return -ENOMEM;
		}

		/* Append NoA IE after user's IEs. */
		memcpy(buf, 
			p2p_ps->go_last_beacon_app_ie,
			p2p_ps->go_last_beacon_app_ie_len);

		noa_ie = (struct ieee80211_p2p_noa_ie *)(buf + p2p_ps->go_last_beacon_app_ie_len);
		noa_ie->element_id = WLAN_EID_VENDOR_SPECIFIC;
		noa_ie->oui = cpu_to_be32((WLAN_OUI_WFA << 8) | (WLAN_OUI_TYPE_WFA_P2P));
		noa_ie->attr = IEEE80211_P2P_ATTR_NOTICE_OF_ABSENCE;
		noa_ie->noa_info.index = p2p_ps->go_noa.index;
		noa_ie->noa_info.ctwindow_opps_param = p2p_ps->go_noa.ctwindow_opps_param;

		idx = 0;
		for (i = 0; i < ATH6KL_P2P_PS_MAX_NOA_DESCRIPTORS; i++) {
			if (p2p_ps->go_noa_enable_idx & (1 << i)) {
				noa_descriptor = &noa_ie->noa_info.noas[idx++];
				noa_descriptor->count_or_type = p2p_ps->go_noa.noas[i].count_or_type;
				noa_descriptor->duration = cpu_to_le32(p2p_ps->go_noa.noas[i].duration);
				noa_descriptor->interval = cpu_to_le32(p2p_ps->go_noa.noas[i].interval);
				noa_descriptor->start_or_offset = cpu_to_le32(p2p_ps->go_noa.noas[i].start_or_offset);
			}
				
		}
		
		/* Update length */
		noa_ie->attr_len = cpu_to_le16(2 + (sizeof(struct ieee80211_p2p_noa_descriptor) * idx));
		noa_ie->len = noa_ie->attr_len + 
			      4 + 1 + 2; /* OUI, attr, attr_len */
		len = p2p_ps->go_last_beacon_app_ie_len + (noa_ie->len + 2);

		/* Backup NoA IE for origional code path if need. */
		p2p_ps->go_last_noa_ie_len = 0;
		if (p2p_ps->go_last_noa_ie)
			kfree(p2p_ps->go_last_noa_ie);
		p2p_ps->go_last_noa_ie = kmalloc(noa_ie->len + 2, GFP_ATOMIC);
		if (p2p_ps->go_last_noa_ie) {
			p2p_ps->go_last_noa_ie_len = noa_ie->len + 2;
			memcpy(p2p_ps->go_last_noa_ie,
				noa_ie,
				p2p_ps->go_last_noa_ie_len);
		}

		spin_unlock(&p2p_ps->p2p_ps_lock);

		ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
			   "p2p_ps update app IE (vif %p) flags %x idx %d noa_ie->len %d len %d\n",
			   vif,
			   p2p_ps->go_flags,
			   idx,
			   noa_ie->len,
			   len);
	} else {
		/* Remove NoA IE. */
		p2p_ps->go_last_noa_ie_len = 0;
		if (p2p_ps->go_last_noa_ie) {
			kfree(p2p_ps->go_last_noa_ie);
			p2p_ps->go_last_noa_ie = NULL;
		}

		buf = kmalloc(p2p_ps->go_last_beacon_app_ie_len, GFP_ATOMIC);
		if (buf == NULL) {
			spin_unlock(&p2p_ps->p2p_ps_lock);

			return -ENOMEM;
		}

		/* Back to origional Beacon IEs. */
		len = p2p_ps->go_last_beacon_app_ie_len;
		memcpy(buf, 
			p2p_ps->go_last_beacon_app_ie,
			len);

		spin_unlock(&p2p_ps->p2p_ps_lock);

		ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
			   "p2p_ps update app IE (vif %p) flags %x beacon_ie %p len %d\n",
			   vif,
			   p2p_ps->go_flags,
			   p2p_ps->go_last_beacon_app_ie,
			   p2p_ps->go_last_beacon_app_ie_len);
	}

	if (down_interruptible(&vif->ar->sem)) {
		ath6kl_err("busy, couldn't get access\n");
		ret = -ERESTARTSYS;
		goto done;
	}

	/* 
	 * Only need to update Beacon's IE. The ProbeResp'q IE is settled 
	 * while sending. 
	 */	
	ret = ath6kl_wmi_set_appie_cmd(vif->ar->wmi, 
				       vif->fw_vif_idx,
				       WMI_FRAME_BEACON,
				       buf,
				       len);

	up(&vif->ar->sem);

done:
	kfree(buf);

	return ret;
}

/* 
 * FIXME : This's too bad solution to hook user's IEs then appended it in 
 *         next ath6kl_p2p_ps_update_notif() call.
 */
void ath6kl_p2p_ps_user_app_ie(struct p2p_ps_info *p2p_ps, 
	 		       u8 mgmt_frm_type,
	 		       u8 **ie, 
			       int *len)
{
	if ((!p2p_ps) || 
	    (p2p_ps->vif->wdev.iftype != NL80211_IFTYPE_P2P_GO)) {
	    ath6kl_err("Not need to hook user's app IE!\n");
	    return;
	}

	ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
		   "p2p_ps hook app IE (vif %p) flags %x mgmt_frm_type %d len %d \n",
		   p2p_ps->vif,
		   p2p_ps->go_flags,
		   mgmt_frm_type,
		   *len);

	if (mgmt_frm_type == WMI_FRAME_BEACON) {
		WARN_ON((*len) == 0);
		
		spin_lock(&p2p_ps->p2p_ps_lock);
		p2p_ps->go_last_beacon_app_ie_len = 0;
		if (p2p_ps->go_last_beacon_app_ie)
			kfree(p2p_ps->go_last_beacon_app_ie);

		p2p_ps->go_last_beacon_app_ie = kmalloc(*len, GFP_ATOMIC);
		if (p2p_ps->go_last_beacon_app_ie == NULL) {
			spin_unlock(&p2p_ps->p2p_ps_lock);
			return;
		}

		/* Update to the latest one. */
		p2p_ps->go_last_beacon_app_ie_len = *len;
		memcpy(p2p_ps->go_last_beacon_app_ie, *ie, *len);

		spin_unlock(&p2p_ps->p2p_ps_lock);

		/* TODO : Need filter if the user's IEs include NoA or not? */

	} else if (mgmt_frm_type == WMI_FRAME_PROBE_RESP) {
		/* Assume non-zero means P2P node. */
		if ((*len) == 0) 
			return;
	}

	/* Hack : Change ie/len to let caller use the new one. */
	spin_lock(&p2p_ps->p2p_ps_lock);
	if ((p2p_ps->go_flags & ATH6KL_P2P_PS_FLAGS_NOA_ENABLED) ||
	    (p2p_ps->go_flags & ATH6KL_P2P_PS_FLAGS_OPPPS_ENABLED)){
#if 0
		/* Bypass it if don't care this. */
		ath6kl_err("this setting (frame type %d) will not include NoA IE!\n", 
	    			mgmt_frm_type);
#else
		/*
		 * Append the last NoA IE to *ie and also update *len to let caller
		 * use the new one.
		 */
		WARN_ON(!p2p_ps->go_last_noa_ie);

		if (p2p_ps->go_working_buffer)
			kfree(p2p_ps->go_working_buffer);
		p2p_ps->go_working_buffer = kmalloc((p2p_ps->go_last_noa_ie_len + *len), 
						      GFP_ATOMIC); 
		if (p2p_ps->go_working_buffer) {
			if (*len)
				memcpy(p2p_ps->go_working_buffer, *ie, *len);
			memcpy(p2p_ps->go_working_buffer + (*len),
			       p2p_ps->go_last_noa_ie, 
			       p2p_ps->go_last_noa_ie_len);

			if (mgmt_frm_type == WMI_FRAME_PROBE_RESP) {
				/* caller will release it. */
				kfree(*ie);
				*ie = p2p_ps->go_working_buffer;
				p2p_ps->go_working_buffer = NULL; 
			} else 
				*ie = p2p_ps->go_working_buffer;
			*len += p2p_ps->go_last_noa_ie_len;
		}

		ath6kl_dbg(ATH6KL_DBG_POWERSAVE,
			   "p2p_ps change app IE len -> %d\n",
			   *len);
#endif
	}
	spin_unlock(&p2p_ps->p2p_ps_lock);

	return;
}

