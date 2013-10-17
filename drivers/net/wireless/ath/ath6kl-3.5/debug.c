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

#include <linux/circ_buf.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/export.h>

#include "debug.h"
#include "target.h"
#include "wlan_location_defs.h"
#include "rttapi.h"
#include "htc-ops.h"
#include "hif-ops.h"

extern unsigned int debug_mask;

struct ath6kl_fwlog_slot {
	__le32 timestamp;
	__le32 length;

	/* max ATH6KL_FWLOG_PAYLOAD_SIZE bytes */
	u8 payload[0];
};

#define ATH6KL_FWLOG_SIZE 32768
#define ATH6KL_FWLOG_SLOT_SIZE (sizeof(struct ath6kl_fwlog_slot) + \
				ATH6KL_FWLOG_PAYLOAD_SIZE)
#define ATH6KL_FWLOG_VALID_MASK 0x1ffff

int ath6kl_printk(const char *level, const char *fmt, ...)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))
	struct va_format vaf;
#endif
	va_list args;
	int rtn;

	va_start(args, fmt);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,36))
	vaf.fmt = fmt;
	vaf.va = &args;

	rtn = printk("%sath6kl: %pV", level, &vaf);
#else
	printk("%sath6kl: ", level);
	rtn = vprintk(fmt, args);
#endif

	va_end(args);

	return rtn;
}

#ifdef CONFIG_ATH6KL_DEBUG

#define REG_OUTPUT_LEN_PER_LINE	25
#define REGTYPE_STR_LEN		100

struct ath6kl_diag_reg_info {
	u32 reg_start;
	u32 reg_end;
	const char *reg_info;
};

static const struct ath6kl_diag_reg_info diag_reg[] = {
	{ 0x20000, 0x200fc, "General DMA and Rx registers" },
	{ 0x28000, 0x28900, "MAC PCU register & keycache" },
	{ 0x20800, 0x20a40, "QCU" },
	{ 0x21000, 0x212f0, "DCU" },
	{ 0x4000,  0x42e4, "RTC" },
	{ 0x540000, 0x540000 + (256 * 1024), "RAM" },
	{ 0x29800, 0x2B210, "Base Band" },
	{ 0x1C000, 0x1C748, "Analog" },
	{ 0x5000, 0x5160, "WLAN RTC" },
	{ 0x18000, 0x18170, "GPIO" },
};

void ath6kl_dump_registers(struct ath6kl_device *dev,
			   struct ath6kl_irq_proc_registers *irq_proc_reg,
			   struct ath6kl_irq_enable_reg *irq_enable_reg)
{

	ath6kl_dbg(ATH6KL_DBG_ANY, ("<------- Register Table -------->\n"));

	if (irq_proc_reg != NULL) {
		ath6kl_dbg(ATH6KL_DBG_ANY,
			"Host Int status:           0x%x\n",
			irq_proc_reg->host_int_status);
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "CPU Int status:            0x%x\n",
			irq_proc_reg->cpu_int_status);
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "Error Int status:          0x%x\n",
			irq_proc_reg->error_int_status);
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "Counter Int status:        0x%x\n",
			irq_proc_reg->counter_int_status);
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "Mbox Frame:                0x%x\n",
			irq_proc_reg->mbox_frame);
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "Rx Lookahead Valid:        0x%x\n",
			irq_proc_reg->rx_lkahd_valid);
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "Rx Lookahead 0:            0x%x\n",
			le32_to_cpu(irq_proc_reg->rx_lkahd[0]));
		ath6kl_dbg(ATH6KL_DBG_ANY,
			   "Rx Lookahead 1:            0x%x\n",
			le32_to_cpu(irq_proc_reg->rx_lkahd[1]));

		if (dev->ar->mbox_info.gmbox_addr != 0) {
			/*
			 * If the target supports GMBOX hardware, dump some
			 * additional state.
			 */
			ath6kl_dbg(ATH6KL_DBG_ANY,
				"GMBOX Host Int status 2:   0x%x\n",
				irq_proc_reg->host_int_status2);
			ath6kl_dbg(ATH6KL_DBG_ANY,
				"GMBOX RX Avail:            0x%x\n",
				irq_proc_reg->gmbox_rx_avail);
			ath6kl_dbg(ATH6KL_DBG_ANY,
				"GMBOX lookahead alias 0:   0x%x\n",
				le32_to_cpu(irq_proc_reg->rx_gmbox_lkahd_alias[0]));
			ath6kl_dbg(ATH6KL_DBG_ANY,
				"GMBOX lookahead alias 1:   0x%x\n",
				le32_to_cpu(irq_proc_reg->rx_gmbox_lkahd_alias[1]));
		}

	}

	if (irq_enable_reg != NULL) {
		ath6kl_dbg(ATH6KL_DBG_ANY,
			"Int status Enable:         0x%x\n",
			irq_enable_reg->int_status_en);
		ath6kl_dbg(ATH6KL_DBG_ANY, "Counter Int status Enable: 0x%x\n",
			irq_enable_reg->cntr_int_status_en);
	}
	ath6kl_dbg(ATH6KL_DBG_ANY, "<------------------------------->\n");
}

static void dump_cred_dist(struct htc_endpoint_credit_dist *ep_dist)
{
	ath6kl_dbg(ATH6KL_DBG_CREDIT,
		   "--- endpoint: %d  svc_id: 0x%X ---\n",
		   ep_dist->endpoint, ep_dist->svc_id);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " dist_flags     : 0x%X\n",
		   ep_dist->dist_flags);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " cred_norm      : %d\n",
		   ep_dist->cred_norm);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " cred_min       : %d\n",
		   ep_dist->cred_min);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " credits        : %d\n",
		   ep_dist->credits);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " cred_assngd    : %d\n",
		   ep_dist->cred_assngd);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " seek_cred      : %d\n",
		   ep_dist->seek_cred);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " cred_sz        : %d\n",
		   ep_dist->cred_sz);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " cred_per_msg   : %d\n",
		   ep_dist->cred_per_msg);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " cred_to_dist   : %d\n",
		   ep_dist->cred_to_dist);
	ath6kl_dbg(ATH6KL_DBG_CREDIT, " txq_depth      : %d\n",
		   get_queue_depth(&ep_dist->htc_ep->txq));
	ath6kl_dbg(ATH6KL_DBG_CREDIT,
		   "----------------------------------\n");
}

/* FIXME: move to htc.c */
void dump_cred_dist_stats(struct htc_target *target)
{
	struct htc_endpoint_credit_dist *ep_list;

	if (!AR_DBG_LVL_CHECK(ATH6KL_DBG_CREDIT))
		return;

	list_for_each_entry(ep_list, &target->cred_dist_list, list)
		dump_cred_dist(ep_list);

	ath6kl_dbg(ATH6KL_DBG_CREDIT,
		   "credit distribution total %d free %d\n",
		   target->credit_info->total_avail_credits,
		   target->credit_info->cur_free_credits);
}

static int ath6kl_debugfs_open(struct inode *inode, struct file *file)
{
         file->private_data = inode->i_private;
	return 0;
}

void ath6kl_debug_war(struct ath6kl *ar, enum ath6kl_war war)
{
	switch (war) {
	case ATH6KL_WAR_INVALID_RATE:
		ar->debug.war_stats.invalid_rate++;
		break;
	}
}

static ssize_t read_file_war_stats(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char *buf;
	unsigned int len = 0, buf_len = 1500;
	ssize_t ret_cnt;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%25s\n",
			 "Workaround stats");
	len += scnprintf(buf + len, buf_len - len, "%25s\n\n",
			 "=================");
	len += scnprintf(buf + len, buf_len - len, "%20s %10u\n",
			 "Invalid rates", ar->debug.war_stats.invalid_rate);

	if (WARN_ON(len > buf_len))
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_war_stats = {
	.read = read_file_war_stats,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static void ath6kl_debug_fwlog_add(struct ath6kl *ar, const void *buf,
				   size_t buf_len)
{
	struct circ_buf *fwlog = &ar->debug.fwlog_buf;
	size_t space;
	int i;

	/* entries must all be equal size */
	if (WARN_ON(buf_len != ATH6KL_FWLOG_SLOT_SIZE))
		return;

	space = CIRC_SPACE(fwlog->head, fwlog->tail, ATH6KL_FWLOG_SIZE);
	if (space < buf_len)
		/* discard oldest slot */
		fwlog->tail = (fwlog->tail + ATH6KL_FWLOG_SLOT_SIZE) &
			(ATH6KL_FWLOG_SIZE - 1);

	for (i = 0; i < buf_len; i += space) {
		space = CIRC_SPACE_TO_END(fwlog->head, fwlog->tail,
					  ATH6KL_FWLOG_SIZE);

		if ((size_t) space > buf_len - i)
			space = buf_len - i;

		memcpy(&fwlog->buf[fwlog->head], buf, space);
		fwlog->head = (fwlog->head + space) & (ATH6KL_FWLOG_SIZE - 1);
	}

}

void ath6kl_debug_fwlog_event(struct ath6kl *ar, const void *buf, size_t len)
{
	struct ath6kl_fwlog_slot *slot = ar->debug.fwlog_tmp;
	size_t slot_len;

	if (WARN_ON(len > ATH6KL_FWLOG_PAYLOAD_SIZE))
		return;

	spin_lock_bh(&ar->debug.fwlog_lock);

	slot->timestamp = cpu_to_le32(jiffies);
	slot->length = cpu_to_le32(len);
	memcpy(slot->payload, buf, len);

	slot_len = sizeof(*slot) + len;

	if (slot_len < ATH6KL_FWLOG_SLOT_SIZE)
		memset(slot->payload + len, 0,
		       ATH6KL_FWLOG_SLOT_SIZE - slot_len);

	ath6kl_debug_fwlog_add(ar, slot, ATH6KL_FWLOG_SLOT_SIZE);

	spin_unlock_bh(&ar->debug.fwlog_lock);
}

static bool ath6kl_debug_fwlog_empty(struct ath6kl *ar)
{
	return CIRC_CNT(ar->debug.fwlog_buf.head,
			ar->debug.fwlog_buf.tail,
			ATH6KL_FWLOG_SLOT_SIZE) == 0;
}

static ssize_t ath6kl_fwlog_read(struct file *file, char __user *user_buf,
				 size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct circ_buf *fwlog = &ar->debug.fwlog_buf;
	size_t len = 0, buf_len = count;
	ssize_t ret_cnt;
	char *buf;
	int ccnt;

	buf = vmalloc(buf_len);
	if (!buf)
		return -ENOMEM;

	/* read undelivered logs from firmware */
	ath6kl_read_fwlogs(ar);

	spin_lock_bh(&ar->debug.fwlog_lock);

	while (len < buf_len && !ath6kl_debug_fwlog_empty(ar)) {
		ccnt = CIRC_CNT_TO_END(fwlog->head, fwlog->tail,
				       ATH6KL_FWLOG_SIZE);

		if ((size_t) ccnt > buf_len - len)
			ccnt = buf_len - len;

		memcpy(buf + len, &fwlog->buf[fwlog->tail], ccnt);
		len += ccnt;

		fwlog->tail = (fwlog->tail + ccnt) &
			(ATH6KL_FWLOG_SIZE - 1);
	}

	spin_unlock_bh(&ar->debug.fwlog_lock);

	if (WARN_ON(len > buf_len))
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	vfree(buf);

	return ret_cnt;
}

static const struct file_operations fops_fwlog = {
	.open = ath6kl_debugfs_open,
	.read = ath6kl_fwlog_read,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_fwlog_mask_read(struct file *file, char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[16];
	int len;

	len = snprintf(buf, sizeof(buf), "0x%x\n", ar->debug.fwlog_mask);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_fwlog_mask_write(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0, &ar->debug.fwlog_mask);
	if (ret)
		return ret;

	ret = ath6kl_wmi_config_debug_module_cmd(ar->wmi,
						 ATH6KL_FWLOG_VALID_MASK,
						 ar->debug.fwlog_mask);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations fops_fwlog_mask = {
	.open = ath6kl_debugfs_open,
	.read = ath6kl_fwlog_mask_read,
	.write = ath6kl_fwlog_mask_write,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t read_file_tgt_stats(struct file *file, char __user *user_buf,
				   size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	struct target_stats *tgt_stats;
	char *buf;
	unsigned int len = 0, buf_len = 1500;
	int i;
	long left;
	ssize_t ret_cnt;

	vif = ath6kl_vif_first(ar);
	if (!vif)
		return -EIO;

	tgt_stats = &vif->target_stats;

	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	if (down_interruptible(&ar->sem)) {
		kfree(buf);
		return -EBUSY;
	}

	set_bit(STATS_UPDATE_PEND, &vif->flags);

	if (ath6kl_wmi_get_stats_cmd(ar->wmi, 0)) {
		up(&ar->sem);
		kfree(buf);
		return -EIO;
	}

	left = wait_event_interruptible_timeout(ar->event_wq,
						!test_bit(STATS_UPDATE_PEND,
						&vif->flags), WMI_TIMEOUT);

	up(&ar->sem);

	if (left <= 0) {
		kfree(buf);
		return -ETIMEDOUT;
	}

	len += scnprintf(buf + len, buf_len - len, "\n");
	len += scnprintf(buf + len, buf_len - len, "%25s\n",
			 "Target Tx stats");
	len += scnprintf(buf + len, buf_len - len, "%25s\n\n",
			 "=================");
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Ucast packets", tgt_stats->tx_ucast_pkt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Bcast packets", tgt_stats->tx_bcast_pkt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Ucast byte", tgt_stats->tx_ucast_byte);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Bcast byte", tgt_stats->tx_bcast_byte);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Rts success cnt", tgt_stats->tx_rts_success_cnt);
	for (i = 0; i < 4; i++)
		len += scnprintf(buf + len, buf_len - len,
				 "%18s %d %10llu\n", "PER on ac",
				 i, tgt_stats->tx_pkt_per_ac[i]);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Error", tgt_stats->tx_err);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Fail count", tgt_stats->tx_fail_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Retry count", tgt_stats->tx_retry_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Multi retry cnt", tgt_stats->tx_mult_retry_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Rts fail cnt", tgt_stats->tx_rts_fail_cnt);
	len += scnprintf(buf + len, buf_len - len, "%25s %10llu\n\n",
			 "TKIP counter measure used",
			 tgt_stats->tkip_cnter_measures_invoked);

	len += scnprintf(buf + len, buf_len - len, "%25s\n",
			 "Target Rx stats");
	len += scnprintf(buf + len, buf_len - len, "%25s\n",
			 "=================");

	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Ucast packets", tgt_stats->rx_ucast_pkt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10d\n",
			 "Ucast Rate", tgt_stats->rx_ucast_rate);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Bcast packets", tgt_stats->rx_bcast_pkt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Ucast byte", tgt_stats->rx_ucast_byte);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Bcast byte", tgt_stats->rx_bcast_byte);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Fragmented pkt", tgt_stats->rx_frgment_pkt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Error", tgt_stats->rx_err);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "CRC Err", tgt_stats->rx_crc_err);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Key chache miss", tgt_stats->rx_key_cache_miss);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Decrypt Err", tgt_stats->rx_decrypt_err);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Duplicate frame", tgt_stats->rx_dupl_frame);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Tkip Mic failure", tgt_stats->tkip_local_mic_fail);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "TKIP format err", tgt_stats->tkip_fmt_err);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "CCMP format Err", tgt_stats->ccmp_fmt_err);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n\n",
			 "CCMP Replay Err", tgt_stats->ccmp_replays);

	len += scnprintf(buf + len, buf_len - len, "%25s\n",
			 "Misc Target stats");
	len += scnprintf(buf + len, buf_len - len, "%25s\n",
			 "=================");
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Beacon Miss count", tgt_stats->cs_bmiss_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Num Connects", tgt_stats->cs_connect_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10llu\n",
			 "Num disconnects", tgt_stats->cs_discon_cnt);
	len += scnprintf(buf + len, buf_len - len, "%20s %10d\n",
			 "Beacon avg rssi", tgt_stats->cs_ave_beacon_rssi);

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_tgt_stats = {
	.read = read_file_tgt_stats,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

#define print_credit_info(fmt_str, ep_list_field)		\
	(len += scnprintf(buf + len, buf_len - len, fmt_str,	\
			 ep_list->ep_list_field))
#define CREDIT_INFO_DISPLAY_STRING_LEN	200
#define CREDIT_INFO_LEN	128

static ssize_t read_file_credit_dist_stats(struct file *file,
					   char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct htc_target *target = ar->htc_target;
	struct htc_endpoint_credit_dist *ep_list;
	char *buf;
	unsigned int buf_len, len = 0;
	ssize_t ret_cnt;

	if ( WARN_ON(&target->cred_dist_list) )
		return -EFAULT;

	buf_len = CREDIT_INFO_DISPLAY_STRING_LEN +
		  get_queue_depth(&target->cred_dist_list) * CREDIT_INFO_LEN;
	buf = kzalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	len += scnprintf(buf + len, buf_len - len, "%25s%5d\n",
			 "Total Avail Credits: ",
			 target->credit_info->total_avail_credits);
	len += scnprintf(buf + len, buf_len - len, "%25s%5d\n",
			 "Free credits :",
			 target->credit_info->cur_free_credits);

	len += scnprintf(buf + len, buf_len - len,
			 " Epid  Flags    Cred_norm  Cred_min  Credits  Cred_assngd"
			 "  Seek_cred  Cred_sz  Cred_per_msg  Cred_to_dist"
			 "  qdepth\n");

	list_for_each_entry(ep_list, &target->cred_dist_list, list) {
		print_credit_info("  %2d", endpoint);
		print_credit_info("%10x", dist_flags);
		print_credit_info("%8d", cred_norm);
		print_credit_info("%9d", cred_min);
		print_credit_info("%9d", credits);
		print_credit_info("%10d", cred_assngd);
		print_credit_info("%13d", seek_cred);
		print_credit_info("%12d", cred_sz);
		print_credit_info("%9d", cred_per_msg);
		print_credit_info("%14d", cred_to_dist);
		len += scnprintf(buf + len, buf_len - len, "%12d\n",
				 get_queue_depth(&ep_list->htc_ep->txq));
	}

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_credit_dist_stats = {
	.read = read_file_credit_dist_stats,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static unsigned int print_endpoint_stat(struct htc_target *target, char *buf,
					unsigned int buf_len, unsigned int len,
					int offset, const char *name)
{
	int i;
	struct htc_endpoint_stats *ep_st;
	u32 *counter;

	len += scnprintf(buf + len, buf_len - len, "%s:", name);
	for (i = 0; i < ENDPOINT_MAX; i++) {
		ep_st = &target->endpoint[i].ep_st;
		counter = ((u32 *) ep_st) + (offset / 4);
		len += scnprintf(buf + len, buf_len - len, " %u", *counter);
	}
	len += scnprintf(buf + len, buf_len - len, "\n");

	return len;
}

static ssize_t ath6kl_endpoint_stats_read(struct file *file,
					  char __user *user_buf,
					  size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct htc_target *target = ar->htc_target;
	char *buf;
	unsigned int buf_len, len = 0;
	ssize_t ret_cnt;

	buf_len = sizeof(struct htc_endpoint_stats) / sizeof(u32) *
		(25 + ENDPOINT_MAX * 11);
	buf = kmalloc(buf_len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

#define EPSTAT(name)							\
	len = print_endpoint_stat(target, buf, buf_len, len,		\
				  offsetof(struct htc_endpoint_stats, name), \
				  #name)
	EPSTAT(cred_low_indicate);
	EPSTAT(tx_issued);
	EPSTAT(tx_pkt_bundled);
	EPSTAT(tx_bundles);
	EPSTAT(tx_dropped);
	EPSTAT(tx_cred_rpt);
	EPSTAT(cred_rpt_from_rx);
	EPSTAT(cred_rpt_from_other);
	EPSTAT(cred_rpt_ep0);
	EPSTAT(cred_from_rx);
	EPSTAT(cred_from_other);
	EPSTAT(cred_from_ep0);
	EPSTAT(cred_cosumd);
	EPSTAT(cred_retnd);
	EPSTAT(rx_pkts);
	EPSTAT(rx_lkahds);
	EPSTAT(rx_bundl);
	EPSTAT(rx_bundle_lkahd);
	EPSTAT(rx_bundle_from_hdr);
	EPSTAT(rx_alloc_thresh_hit);
	EPSTAT(rxalloc_thresh_byte);
#undef EPSTAT

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	kfree(buf);
	return ret_cnt;
}

static ssize_t ath6kl_endpoint_stats_write(struct file *file,
					   const char __user *user_buf,
					   size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct htc_target *target = ar->htc_target;
	int ret, i;
	u32 val;
	struct htc_endpoint_stats *ep_st;

	ret = kstrtou32_from_user(user_buf, count, 0, &val);
	if (ret)
		return ret;
	if (val == 0) {
		for (i = 0; i < ENDPOINT_MAX; i++) {
			ep_st = &target->endpoint[i].ep_st;
			memset(ep_st, 0, sizeof(*ep_st));
		}
	}

	return count;
}

static const struct file_operations fops_endpoint_stats = {
	.open = ath6kl_debugfs_open,
	.read = ath6kl_endpoint_stats_read,
	.write = ath6kl_endpoint_stats_write,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static unsigned long ath6kl_get_num_reg(void)
{
	int i;
	unsigned long n_reg = 0;

	for (i = 0; i < ARRAY_SIZE(diag_reg); i++)
		n_reg = n_reg +
		     (diag_reg[i].reg_end - diag_reg[i].reg_start) / 4 + 1;

	return n_reg;
}

static bool ath6kl_dbg_is_diag_reg_valid(u32 reg_addr)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(diag_reg); i++) {
		if (reg_addr >= diag_reg[i].reg_start &&
		    reg_addr <= diag_reg[i].reg_end)
			return true;
	}

	return false;
}

static ssize_t ath6kl_regread_read(struct file *file, char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[50];
	unsigned int len = 0;

	if (ar->debug.dbgfs_diag_reg)
		len += scnprintf(buf + len, sizeof(buf) - len, "0x%x\n",
				ar->debug.dbgfs_diag_reg);
	else
		len += scnprintf(buf + len, sizeof(buf) - len,
				 "All diag registers\n");

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_regread_write(struct file *file,
				    const char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[50];
	unsigned int len;
	unsigned long reg_addr;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';

	if (strict_strtoul(buf, 0, &reg_addr))
		return -EINVAL;

	if ((reg_addr % 4) != 0)
		return -EINVAL;

	if (reg_addr && !ath6kl_dbg_is_diag_reg_valid(reg_addr))
		return -EINVAL;

	ar->debug.dbgfs_diag_reg = reg_addr;

	return count;
}

static const struct file_operations fops_diag_reg_read = {
	.read = ath6kl_regread_read,
	.write = ath6kl_regread_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath6kl_regdump_open(struct inode *inode, struct file *file)
{
	struct ath6kl *ar = inode->i_private;
	u8 *buf;
	unsigned long int reg_len;
	unsigned int len = 0, n_reg;
	u32 addr;
	__le32 reg_val;
	int i, status;

	/* Dump all the registers if no register is specified */
	if (!ar->debug.dbgfs_diag_reg)
		n_reg = ath6kl_get_num_reg();
	else
		n_reg = 1;

	reg_len = n_reg * REG_OUTPUT_LEN_PER_LINE;
	if (n_reg > 1)
		reg_len += REGTYPE_STR_LEN;

	buf = vmalloc(reg_len);
	if (!buf)
		return -ENOMEM;

	if (n_reg == 1) {
		addr = ar->debug.dbgfs_diag_reg;

		status = ath6kl_diag_read32(ar,
				TARG_VTOP(ar->target_type, addr),
				(u32 *)&reg_val);
		if (status)
			goto fail_reg_read;

		len += scnprintf(buf + len, reg_len - len,
				 "0x%06x 0x%08x\n", addr, le32_to_cpu(reg_val));
		goto done;
	}

	for (i = 0; i < ARRAY_SIZE(diag_reg); i++) {
		len += scnprintf(buf + len, reg_len - len,
				"%s\n", diag_reg[i].reg_info);
		for (addr = diag_reg[i].reg_start;
		     addr <= diag_reg[i].reg_end; addr += 4) {
			status = ath6kl_diag_read32(ar,
					TARG_VTOP(ar->target_type, addr),
					(u32 *)&reg_val);
			if (status)
				goto fail_reg_read;

			len += scnprintf(buf + len, reg_len - len,
					"0x%06x 0x%08x\n",
					addr, le32_to_cpu(reg_val));
		}
	}

done:
	file->private_data = buf;
	return 0;

fail_reg_read:
	ath6kl_warn("Unable to read memory:%u\n", addr);
	vfree(buf);
	return -EIO;
}

static ssize_t ath6kl_regdump_read(struct file *file, char __user *user_buf,
				  size_t count, loff_t *ppos)
{
	u8 *buf = file->private_data;
	return simple_read_from_buffer(user_buf, count, ppos, buf, strlen(buf));
}

static int ath6kl_regdump_release(struct inode *inode, struct file *file)
{
	vfree(file->private_data);
	return 0;
}

static const struct file_operations fops_reg_dump = {
	.open = ath6kl_regdump_open,
	.read = ath6kl_regdump_read,
	.release = ath6kl_regdump_release,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_lrssi_roam_write(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	unsigned long lrssi_roam_threshold;
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (strict_strtoul(buf, 0, &lrssi_roam_threshold))
		return -EINVAL;

	ar->lrssi_roam_threshold = lrssi_roam_threshold;

	ath6kl_wmi_set_roam_lrssi_cmd(ar->wmi, ar->lrssi_roam_threshold);

	return count;
}

static ssize_t ath6kl_lrssi_roam_read(struct file *file,
				      char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[32];
	unsigned int len;

	len = snprintf(buf, sizeof(buf), "%u\n", ar->lrssi_roam_threshold);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_lrssi_roam_threshold = {
	.read = ath6kl_lrssi_roam_read,
	.write = ath6kl_lrssi_roam_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_regwrite_read(struct file *file,
				    char __user *user_buf,
				    size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[32];
	unsigned int len = 0;

	len = scnprintf(buf, sizeof(buf), "Addr: 0x%x Val: 0x%x\n",
			ar->debug.diag_reg_addr_wr, ar->debug.diag_reg_val_wr);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_regwrite_write(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[32];
	char *sptr, *token;
	unsigned int len = 0;
	u32 reg_addr, reg_val;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	sptr = buf;

	token = strsep(&sptr, "=");
	if (!token)
		return -EINVAL;

	if (kstrtou32(token, 0, &reg_addr))
		return -EINVAL;

	if (!ath6kl_dbg_is_diag_reg_valid(reg_addr))
		return -EINVAL;

	if (kstrtou32(sptr, 0, &reg_val))
		return -EINVAL;

	ar->debug.diag_reg_addr_wr = reg_addr;
	ar->debug.diag_reg_val_wr = reg_val;

	if (ath6kl_diag_write32(ar, ar->debug.diag_reg_addr_wr,
				cpu_to_le32(ar->debug.diag_reg_val_wr)))
		return -EIO;

	return count;
}

static const struct file_operations fops_diag_reg_write = {
	.read = ath6kl_regwrite_read,
	.write = ath6kl_regwrite_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

int ath6kl_debug_roam_tbl_event(struct ath6kl *ar, const void *buf,
				size_t len)
{
	const struct wmi_target_roam_tbl *tbl;
	u16 num_entries;

	if (len < sizeof(*tbl))
		return -EINVAL;

	tbl = (const struct wmi_target_roam_tbl *) buf;
	num_entries = le16_to_cpu(tbl->num_entries);
	if (sizeof(*tbl) + num_entries * sizeof(struct wmi_bss_roam_info) >
	    len)
		return -EINVAL;

	if (ar->debug.roam_tbl == NULL ||
	    ar->debug.roam_tbl_len < (unsigned int) len) {
		kfree(ar->debug.roam_tbl);
		ar->debug.roam_tbl = kmalloc(len, GFP_ATOMIC);
		if (ar->debug.roam_tbl == NULL)
			return -ENOMEM;
	}

	memcpy(ar->debug.roam_tbl, buf, len);
	ar->debug.roam_tbl_len = len;

	if (test_bit(ROAM_TBL_PEND, &ar->flag)) {
		clear_bit(ROAM_TBL_PEND, &ar->flag);
		wake_up(&ar->event_wq);
	}

	return 0;
}

static ssize_t ath6kl_roam_table_read(struct file *file, char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;
	long left;
	struct wmi_target_roam_tbl *tbl;
	u16 num_entries, i;
	char *buf;
	unsigned int len, buf_len;
	ssize_t ret_cnt;

	if (down_interruptible(&ar->sem))
		return -EBUSY;

	set_bit(ROAM_TBL_PEND, &ar->flag);

	ret = ath6kl_wmi_get_roam_tbl_cmd(ar->wmi);
	if (ret) {
		up(&ar->sem);
		return ret;
	}

	left = wait_event_interruptible_timeout(
		ar->event_wq, !test_bit(ROAM_TBL_PEND, &ar->flag), WMI_TIMEOUT);
	up(&ar->sem);

	if (left <= 0)
		return -ETIMEDOUT;

	if (ar->debug.roam_tbl == NULL)
		return -ENOMEM;

	tbl = (struct wmi_target_roam_tbl *) ar->debug.roam_tbl;
	num_entries = le16_to_cpu(tbl->num_entries);

	buf_len = 100 + num_entries * 100;
	buf = kzalloc(buf_len, GFP_KERNEL);
	if (buf == NULL)
		return -ENOMEM;
	len = 0;
	len += scnprintf(buf + len, buf_len - len,
			 "roam_mode=%u\n\n"
			 "# roam_util bssid rssi rssidt last_rssi util bias\n",
			 le16_to_cpu(tbl->roam_mode));

	for (i = 0; i < num_entries; i++) {
		struct wmi_bss_roam_info *info = &tbl->info[i];
		len += scnprintf(buf + len, buf_len - len,
				 "%d %pM %d %d %d %d %d\n",
				 a_sle32_to_cpu(info->roam_util), info->bssid,
				 info->rssi, info->rssidt, info->last_rssi,
				 info->util, info->bias);
	}

	if (len > buf_len)
		len = buf_len;

	ret_cnt = simple_read_from_buffer(user_buf, count, ppos, buf, len);

	kfree(buf);
	return ret_cnt;
}

static const struct file_operations fops_roam_table = {
	.read = ath6kl_roam_table_read,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_force_roam_write(struct file *file,
				       const char __user *user_buf,
				       size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;
	char buf[20];
	size_t len;
	u8 bssid[ETH_ALEN];
	int i;
	int addr[ETH_ALEN];

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';

	if (sscanf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		   &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5])
	    != ETH_ALEN)
		return -EINVAL;
	for (i = 0; i < ETH_ALEN; i++)
		bssid[i] = addr[i];

	ret = ath6kl_wmi_force_roam_cmd(ar->wmi, bssid);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations fops_force_roam = {
	.write = ath6kl_force_roam_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_roam_mode_read(struct file *file, 
            char __user *user_buf, size_t count, loff_t *ppos)
{
    struct ath6kl *ar = file->private_data;
    u8 buf[32];
    unsigned int len = 0;
    char *str;

    if (ar->debug.roam_mode == WMI_DEFAULT_ROAM_MODE)
        str = "default";
    else if (ar->debug.roam_mode == WMI_HOST_BIAS_ROAM_MODE)
        str = "bssbias";
    else if (ar->debug.roam_mode == WMI_LOCK_BSS_MODE)
        str = "lock";
    else
        str = "NONE";

    len = scnprintf(buf, sizeof(buf), "roam mode: %s\n",
                str);
                            
    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_roam_mode_write(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;
	char buf[20];
	size_t len;
	enum wmi_roam_mode mode;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';
	if (len > 0 && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	if (strcasecmp(buf, "default") == 0)
		mode = WMI_DEFAULT_ROAM_MODE;
	else if (strcasecmp(buf, "bssbias") == 0)
		mode = WMI_HOST_BIAS_ROAM_MODE;
	else if (strcasecmp(buf, "lock") == 0)
		mode = WMI_LOCK_BSS_MODE;
	else
		return -EINVAL;

    ar->debug.roam_mode = mode;

	ret = ath6kl_wmi_set_roam_mode_cmd(ar->wmi, mode);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations fops_roam_mode = {
    .read = ath6kl_roam_mode_read,
	.write = ath6kl_roam_mode_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

void ath6kl_debug_set_keepalive(struct ath6kl *ar, u8 keepalive)
{
	ar->debug.keepalive = keepalive;
}

static ssize_t ath6kl_keepalive_read(struct file *file, char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[16];
	int len;

	len = snprintf(buf, sizeof(buf), "%u\n", ar->debug.keepalive);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_keepalive_write(struct file *file,
				      const char __user *user_buf,
				      size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;
	u8 val;

	ret = kstrtou8_from_user(user_buf, count, 0, &val);
	if (ret)
		return ret;

	ret = ath6kl_wmi_set_keepalive_cmd(ar->wmi, 0, val);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations fops_keepalive = {
	.open = ath6kl_debugfs_open,
	.read = ath6kl_keepalive_read,
	.write = ath6kl_keepalive_write,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

void ath6kl_debug_set_disconnect_timeout(struct ath6kl *ar, u8 timeout)
{
	ar->debug.disc_timeout = timeout;
}

static ssize_t ath6kl_disconnect_timeout_read(struct file *file,
					      char __user *user_buf,
					      size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[16];
	int len;

	len = snprintf(buf, sizeof(buf), "%u\n", ar->debug.disc_timeout);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_disconnect_timeout_write(struct file *file,
					       const char __user *user_buf,
					       size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;
	u8 val;

	ret = kstrtou8_from_user(user_buf, count, 0, &val);
	if (ret)
		return ret;

	ret = ath6kl_wmi_disctimeout_cmd(ar->wmi, 0, val);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations fops_disconnect_timeout = {
	.open = ath6kl_debugfs_open,
	.read = ath6kl_disconnect_timeout_read,
	.write = ath6kl_disconnect_timeout_write,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_create_qos_write(struct file *file,
						const char __user *user_buf,
						size_t count, loff_t *ppos)
{

	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	char buf[200];
	ssize_t len;
	char *sptr, *token;
	struct wmi_create_pstream_cmd pstream;
	u32 val32;
	u16 val16;

	vif = ath6kl_vif_first(ar);
	if (!vif)
		return -EIO;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';
	sptr = buf;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &pstream.user_pri))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &pstream.traffic_direc))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &pstream.traffic_class))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &pstream.traffic_type))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &pstream.voice_psc_cap))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.min_service_int = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.max_service_int = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.inactivity_int = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.suspension_int = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.service_start_time = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &pstream.tsid))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &val16))
		return -EINVAL;
	pstream.nominal_msdu = cpu_to_le16(val16);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &val16))
		return -EINVAL;
	pstream.max_msdu = cpu_to_le16(val16);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.min_data_rate = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.mean_data_rate = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.peak_data_rate = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.max_burst_size = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.delay_bound = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.min_phy_rate = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.sba = cpu_to_le32(val32);

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou32(token, 0, &val32))
		return -EINVAL;
	pstream.medium_time = cpu_to_le32(val32);

	ath6kl_wmi_create_pstream_cmd(ar->wmi, vif->fw_vif_idx, &pstream);

	return count;
}

static const struct file_operations fops_create_qos = {
	.write = ath6kl_create_qos_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_delete_qos_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{

	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	char buf[100];
	ssize_t len;
	char *sptr, *token;
	u8 traffic_class;
	u8 tsid;

	vif = ath6kl_vif_first(ar);
	if (!vif)
		return -EIO;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';
	sptr = buf;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &traffic_class))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou8(token, 0, &tsid))
		return -EINVAL;

	ath6kl_wmi_delete_pstream_cmd(ar->wmi, vif->fw_vif_idx,
				      traffic_class, tsid);

	return count;
}

static const struct file_operations fops_delete_qos = {
	.write = ath6kl_delete_qos_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_bgscan_int_read(struct file *file,
        char __user *user_buf, size_t count, loff_t *ppos)
{
    struct ath6kl *ar = file->private_data;
    u8 buf[128];
    unsigned int len = 0;

    len = scnprintf(buf, sizeof(buf), "bgscan interval: %d\n",
            ar->debug.bgscan_int);

    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_bgscan_int_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u16 bgscan_int;
	char buf[32];
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtou16(buf, 0, &bgscan_int))
		return -EINVAL;

	if (bgscan_int == 0)
		bgscan_int = 0xffff;

    ar->debug.bgscan_int = bgscan_int;

	ath6kl_wmi_scanparams_cmd(ar->wmi, 0, 0, 0, bgscan_int, 0, 0, 0, 3,
				  0, 0, 0);

	return count;
}

static const struct file_operations fops_bgscan_int = {
	.read = ath6kl_bgscan_int_read,
	.write = ath6kl_bgscan_int_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_listen_int_write(struct file *file,
						const char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u16 listen_int_t, listen_int_b;
	char buf[32];
	char *sptr, *token;
	ssize_t len;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	sptr = buf;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;

	if (kstrtou16(token, 0, &listen_int_t))
		return -EINVAL;

	if (kstrtou16(sptr, 0, &listen_int_b))
		return -EINVAL;

	if ((listen_int_t < 15) || (listen_int_t > 5000))
		return -EINVAL;

	if ((listen_int_b < 1) || (listen_int_b > 50))
		return -EINVAL;

	ar->listen_intvl_t = listen_int_t;
	ar->listen_intvl_b = listen_int_b;

	ath6kl_wmi_listeninterval_cmd(ar->wmi, 0, ar->listen_intvl_t,
				      ar->listen_intvl_b);

	return count;
}

static ssize_t ath6kl_listen_int_read(struct file *file,
						char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[32];
	int len;

	len = scnprintf(buf, sizeof(buf), "%u %u\n", ar->listen_intvl_t,
					ar->listen_intvl_b);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_listen_int = {
	.read = ath6kl_listen_int_read,
	.write = ath6kl_listen_int_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_power_params_write(struct file *file,
						const char __user *user_buf,
						size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[100];
	unsigned int len = 0;
	char *sptr, *token;
	u16 idle_period, ps_poll_num, dtim,
		tx_wakeup, num_tx;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;
	buf[len] = '\0';
	sptr = buf;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &idle_period))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &ps_poll_num))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &dtim))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &tx_wakeup))
		return -EINVAL;

	token = strsep(&sptr, " ");
	if (!token)
		return -EINVAL;
	if (kstrtou16(token, 0, &num_tx))
		return -EINVAL;

	ar->debug.power_params.idle_period = idle_period;
	ar->debug.power_params.ps_poll_num = ps_poll_num;
	ar->debug.power_params.dtim = dtim;
	ar->debug.power_params.tx_wakeup = tx_wakeup;
	ar->debug.power_params.num_tx = num_tx;

	ath6kl_wmi_pmparams_cmd(ar->wmi, 0, idle_period, ps_poll_num,
				dtim, tx_wakeup, num_tx, 0);

	return count;
}

static ssize_t ath6kl_power_params_read(struct file *file, 
                      char __user *user_buf,
                                            size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[256];
	unsigned int len = 0;
	                
	len = scnprintf(buf, sizeof(buf),
			"idle_period: %d, ps_poll_num: %d, dtim: %d, tx_wakeup:%d , num_tx: %d\n",
			ar->debug.power_params.idle_period,
			ar->debug.power_params.ps_poll_num,
			ar->debug.power_params.dtim,
			ar->debug.power_params.tx_wakeup,
			ar->debug.power_params.num_tx);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_power_params = {
	.read = ath6kl_power_params_read,
	.write = ath6kl_power_params_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_rtt_write(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct nsp_mrqst stmrqst;
	struct nsp_rtt_config strttcfg;
        u8 ftype = ((struct nsp_header *)user_buf)->frame_type;

        //printk("RTT Request FrameType : %d\n",ftype);

        if(ftype == NSP_MRQST)
        {
	 if (copy_from_user(&stmrqst, user_buf+sizeof(struct nsp_header), sizeof(struct nsp_mrqst)))
		return -EFAULT;

	 if (wmi_rtt_req_meas(ar->wmi,&stmrqst))
		return -EIO;
        }
        else if(ftype == NSP_RTTCONFIG)
        {
	 if (copy_from_user(&strttcfg, user_buf+sizeof(struct nsp_header), sizeof(struct nsp_rtt_config)))
		return -EFAULT;

	 if (wmi_rtt_config(ar->wmi,&strttcfg))
		return -EIO;

        }

	return 0;
}

static ssize_t ath6kl_rtt_read(struct file *file, 
                      char __user *user_buf,
                      size_t count, loff_t *ppos)
{
	u8 *buf=NULL;
	u32 len = 0;
    
	rttm_getbuf((void **)&buf,&len);
    
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_rtt = {
	.read = ath6kl_rtt_read,
	.write = ath6kl_rtt_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

#define SKIP_SPACE                         \
    while (*p == ' ' && *p != '\0')        \
        p++;

#define SEEK_SPACE                         \
    while (*p != ' ' && *p != '\0')        \
        p++;

static int ath6kl_parse_lpl_force_enable_params(const char __user *user_buf, size_t count,
				struct lpl_force_enable_param *param)
{
	char buf[64];
	char *p;
	unsigned int len;
	int value;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

        SKIP_SPACE

	sscanf(p, "%d", &value);
	param->lpl_policy = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->no_blocker_detect = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->no_rfb_detect = value;

	return 0;
}

/* File operation functions for low power listen */
static ssize_t ath6kl_lpl_force_enable_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;

	ret = ath6kl_parse_lpl_force_enable_params(user_buf, count,
			&ar->debug.lpl_force_enable_params);
	if (ret)
		return ret;

	if (ath6kl_wmi_lpl_enable_cmd(ar->wmi,
			(struct wmi_lpl_force_enable_cmd *)&ar->debug.lpl_force_enable_params))
		return -EIO;

	return count;
}

static ssize_t ath6kl_lpl_force_enable_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[128];
	unsigned int len = 0;

	len = scnprintf(buf, sizeof(buf), "lplPolicy: %d, noBlockerDetect: %d, noRfbDetect: %d\n",
				ar->debug.lpl_force_enable_params.lpl_policy,
				ar->debug.lpl_force_enable_params.no_blocker_detect,
				ar->debug.lpl_force_enable_params.no_rfb_detect);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for low power listen */
static const struct file_operations fops_lpl_force_enable = {
	.read = ath6kl_lpl_force_enable_read,
	.write = ath6kl_lpl_force_enable_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/* File operation functions for mimo power saving */
static ssize_t ath6kl_mimo_ps_enable_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;

	ret = kstrtou8_from_user(user_buf, count, 0, &ar->debug.mimo_ps_enable);
	if (ret)
		return ret;

	if (ath6kl_wmi_smps_enable(ar->wmi,
			(struct wmi_config_enable_cmd*)&ar->debug.mimo_ps_enable))
		return -EIO;

	return count;
}

static ssize_t ath6kl_mimo_ps_enable_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
    struct ath6kl *ar = file->private_data;
    u8 buf[32];
    unsigned int len = 0;
    
    len = scnprintf(buf, sizeof(buf), "MIMO Power Saving: %d\n", ar->debug.mimo_ps_enable);

    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for mimo power saving */
static const struct file_operations fops_mimo_ps_enable = {
	.read = ath6kl_mimo_ps_enable_read,
	.write = ath6kl_mimo_ps_enable_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath6kl_parse_mimo_ps_params(const char __user *user_buf, size_t count,
				struct smps_param *param)
{
	char buf[64];
	char *p;
	unsigned int len;
	int value;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

	SKIP_SPACE;

	sscanf(p, "%d", &value);

	if (value == 1) {
		param->mode = WMI_SMPS_MODE_STATIC;
	}
	else if (value == 2) {
		param->mode = WMI_SMPS_MODE_DYNAMIC;
	}
	else {
		return -EINVAL;
	}

	param->flags = WMI_SMPS_OPTION_MODE;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->automatic = value;

	if (value == 0 || value == 1)
		param->flags |= WMI_SMPS_OPTION_AUTO;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);

	if (value != -1) {
		param->data_thresh = value;
		param->flags |= WMI_SMPS_OPTION_DATATHRESH;
	}

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);

	if (value != -1) {
		param->rssi_thresh = value;
		param->flags |= WMI_SMPS_OPTION_RSSITHRESH;
	}

	return 0;
}

/* File operation functions for mimo power saving */
static ssize_t ath6kl_mimo_ps_params_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;

	ret = ath6kl_parse_mimo_ps_params(user_buf, count, &ar->debug.smps_params);
	if (ret)
		return ret;

	if (ath6kl_wmi_smps_config(ar->wmi,
			(struct wmi_config_smps_cmd *)&ar->debug.smps_params))
		return -EIO;

	return count;
}

static ssize_t ath6kl_mimo_ps_params_read(struct file *file,
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[128];
	unsigned int len = 0;

	len = scnprintf(buf, sizeof(buf), "flags: %d, mode: %d, automatic: %d, dataThresh: %d, rssiThresh: %d\n",
			ar->debug.smps_params.flags, ar->debug.smps_params.mode,
			ar->debug.smps_params.automatic, ar->debug.smps_params.data_thresh,
			ar->debug.smps_params.rssi_thresh);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for mimo power saving */
static const struct file_operations fops_mimo_ps_params = {
	.read = ath6kl_mimo_ps_params_read,
	.write = ath6kl_mimo_ps_params_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};


/* File operation functions for Green Tx */
static ssize_t ath6kl_green_tx_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0,
			&ar->debug.green_tx_params.green_tx_enable);

	if (ret)
		return ret;

	if (ath6kl_wmi_set_green_tx_params(ar->wmi,
			(struct wmi_green_tx_params *) &ar->debug.green_tx_params))
		return -EIO;

	return count;
}

static ssize_t ath6kl_green_tx_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
    struct ath6kl *ar = file->private_data;
    u8 buf[32];
    unsigned int len = 0;
    
    len = scnprintf(buf, sizeof(buf), "Green Tx: %d\n",
			ar->debug.green_tx_params.green_tx_enable);

    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for green tx */
static const struct file_operations fops_green_tx = {
	.read = ath6kl_green_tx_read,
	.write = ath6kl_green_tx_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath6kl_parse_green_tx_params(const char __user *user_buf, size_t count,
				struct green_tx_param *param)
{
	char buf[64];
	char *p;
	unsigned int len;
	int value;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->next_probe_count = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->max_backoff = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->min_gtx_rssi = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	param->force_backoff = value;

	return 0;
}

static ssize_t ath6kl_green_tx_params_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	int ret;

	ret = ath6kl_parse_green_tx_params(user_buf, count, &ar->debug.green_tx_params);

	if (ret)
		return ret;

	if (ath6kl_wmi_set_green_tx_params(ar->wmi,
			(struct wmi_green_tx_params *) &ar->debug.green_tx_params))
		return -EIO;

	return count;
}

static ssize_t ath6kl_green_tx_params_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[128];
	unsigned int len = 0;

	len = scnprintf(buf, sizeof(buf), "nextProbeCount: %d, maxBackOff: %d, minGtxRssi: %d, forceBackOff: %d\n",
			ar->debug.green_tx_params.next_probe_count, ar->debug.green_tx_params.max_backoff,
			ar->debug.green_tx_params.min_gtx_rssi, ar->debug.green_tx_params.force_backoff);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_green_tx_params = {
	.read = ath6kl_green_tx_params_read,
	.write = ath6kl_green_tx_params_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};


static int ath6kl_parse_ht_cap_params(const char __user *user_buf, size_t count,
				struct ht_cap_param *htCapParam)
{
	char buf[64];
	char *p;
	unsigned int len;
	int value;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

	SKIP_SPACE;

	sscanf(p, "%d", &value);
	htCapParam->band = (u8) value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	htCapParam->chan_width_40M_supported = (u8) value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	htCapParam->short_GI = (u8) value;

	return 0;
}

/* File operation functions for HT Cap */
static ssize_t ath6kl_ht_cap_params_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ht_cap_param tempHtCap;
	int ret;

	memset(&tempHtCap, 0, sizeof(struct ht_cap_param));
	ret = ath6kl_parse_ht_cap_params(user_buf, count, &tempHtCap);

	if (ret)
		return ret;

	/* TBD : Per virutal interface. */
	if (ath6kl_wmi_set_ht_cap_cmd(ar->wmi,
			tempHtCap.band, 
			tempHtCap.chan_width_40M_supported,
			tempHtCap.short_GI))
		return -EIO;

	tempHtCap.isConfig = 1;
	memcpy(&ar->debug.ht_cap_param[tempHtCap.band], &tempHtCap, sizeof(struct ht_cap_param));

	return count;
}

static ssize_t ath6kl_ht_cap_params_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[128];
	unsigned int len = 0;
	int band;

	for (band = 0; band < A_NUM_BANDS; band++) {
		if (ar->debug.ht_cap_param[band].isConfig)
			len += scnprintf(buf + len, sizeof(buf) - len, "%s chan_width_40M_supported: %d, short_GI: %d\n",
					(ar->debug.ht_cap_param[band].band == A_BAND_24GHZ ? "24GHZ" : "5GHZ"),
					ar->debug.ht_cap_param[band].chan_width_40M_supported,
					ar->debug.ht_cap_param[band].short_GI);
	}

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for HT Cap */
static const struct file_operations fops_ht_cap_params = {
	.read = ath6kl_ht_cap_params_read,
	.write = ath6kl_ht_cap_params_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_debug_mask_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	int ret;

	ret = kstrtou32_from_user(user_buf, count, 0, &debug_mask);

	if (ret)
		return ret;

	return count;
}

static ssize_t ath6kl_debug_mask_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	char buf[32];
	int len;

	len = snprintf(buf, sizeof(buf), "debug_mask: 0x%x\n", debug_mask);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_debug_mask = {
	.read = ath6kl_debug_mask_read,
	.write = ath6kl_debug_mask_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/* File operation functions for HT Coex */
static ssize_t ath6kl_ht_coex_params_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	char *p;
	int scan_interval, rate_interval;
	char buf[32];
	ssize_t len;
	int i;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;
	
	SKIP_SPACE;

	sscanf(p, "%d", &scan_interval);

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &rate_interval);
	
	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if (vif)
			ath6kl_htcoex_config(vif, 
					     (u32)scan_interval,
					     (u8)rate_interval);
	}

	return count;
}

static ssize_t ath6kl_ht_coex_params_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	u8 buf[128];
	unsigned int len = 0;
	int i;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->htcoex_ctx))
			len += scnprintf(buf + len, sizeof(buf) - len, 
					"int-%d flags %x, scan %d ms, num_scan %d, rate %d, t_cnt %d\n",
					i,
					vif->htcoex_ctx->flags,
					vif->htcoex_ctx->scan_interval,
					vif->htcoex_ctx->num_scan,
					vif->htcoex_ctx->rate_rollback_interval,
					vif->htcoex_ctx->tolerant40_cnt);
	}

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for HT Coex */
static const struct file_operations fops_ht_coex_params = {
	.read = ath6kl_ht_coex_params_read,
	.write = ath6kl_ht_coex_params_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath6kl_parse_tx_amsdu_params(const char __user *user_buf, size_t count,
				struct ath6kl_vif *vif)
{
	char buf[64];
	char *p;
	unsigned int len;
	int value;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

	SKIP_SPACE;

	sscanf(p, "%d", &value);
	if (value == 0) 
		value = AGGR_TX_MAX_NUM;
	vif->aggr_cntxt->tx_amsdu_max_aggr_num = value;
				
	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	if (value == 0) 
		value = AGGR_TX_MAX_PDU_SIZE;
	else if (value < AGGR_TX_MIN_PDU_SIZE)
		value = AGGR_TX_MIN_PDU_SIZE;
	vif->aggr_cntxt->tx_amsdu_max_pdu_len = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	if (value == 0) 
		value = AGGR_TX_TIMEOUT;
	vif->aggr_cntxt->tx_amsdu_timeout = value;

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &value);
	if (value) 
		vif->aggr_cntxt->tx_amsdu_seq_pkt = true;
	else
		vif->aggr_cntxt->tx_amsdu_seq_pkt = false;

	return 0;
}

/* File operation functions for TX A-MSDU Params */
static ssize_t ath6kl_tx_amsdu_params_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	int i, ret;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->aggr_cntxt)) {
			ret = ath6kl_parse_tx_amsdu_params(user_buf, count, vif);

			if (ret)
				return ret;
		}
	}

	return count;
}

static ssize_t ath6kl_tx_amsdu_params_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	struct ath6kl_sta *conn;
	struct txtid *txtid;
	static u8 buf[2048];
	unsigned int len = 0;
	int i, j, k, num_sta;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->aggr_cntxt)) {
			len += scnprintf(buf + len, sizeof(buf) - len, "DEV-%d %s max_num: %d, max_len: %d, timeout = %d ms, seq_pkt %s\n",
					i,
					(vif->aggr_cntxt->tx_amsdu_enable == true ? "Enable" : "Disable"),
					vif->aggr_cntxt->tx_amsdu_max_aggr_num,
					vif->aggr_cntxt->tx_amsdu_max_pdu_len,
					vif->aggr_cntxt->tx_amsdu_timeout,
					(vif->aggr_cntxt->tx_amsdu_seq_pkt == true ? "Yes" : "No"));

			num_sta = (vif->nw_type == INFRA_NETWORK) ? 1 : AP_MAX_NUM_STA;
			for (j = 0; j < num_sta; j++) {
				conn = &vif->sta_list[j];
				len += scnprintf(buf + len, sizeof(buf) - len, " [%02x:%02x:%02x:%02x:%02x:%02x] \n",
						conn->mac[0],conn->mac[1],conn->mac[2],conn->mac[3],conn->mac[4],conn->mac[5]);
				for (k = 0; k < NUM_OF_TIDS; k++) {
					txtid = AGGR_GET_TXTID(conn->aggr_conn_cntxt, k);
					len += scnprintf(buf + len, sizeof(buf) - len, "   %d-%d AMSDU: %d PDU: %d TIMEOUT/FLUSH/NULL: %d/%d/%d \n",
							txtid->tid,
							txtid->aid,
							txtid->num_amsdu,
							txtid->num_pdu,
							txtid->num_timeout,
							txtid->num_flush,
							txtid->num_tx_null);
				}
			}
		}
	}

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for TX A-MSDU Params */
static const struct file_operations fops_tx_amsdu_params = {
	.read = ath6kl_tx_amsdu_params_read,
	.write = ath6kl_tx_amsdu_params_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static int ath6kl_parse_tx_amsdu(const char __user *user_buf, size_t count,
				struct ath6kl_vif *vif)
{
	char buf[64];
	char *p;
	unsigned int len;
	int value;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

	SKIP_SPACE;

	sscanf(p, "%d", &value);
	if (value) 
		set_bit(AMSDU_ENABLED, &vif->flags);
	else
		clear_bit(AMSDU_ENABLED, &vif->flags);

	return 0;
}

/* File operation functions for TX A-MSDU */
static ssize_t ath6kl_tx_amsdu_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	int i, ret;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->aggr_cntxt)) {
			ret = ath6kl_parse_tx_amsdu(user_buf, count, vif);

			if (ret)
				return ret;
		}
	}

	return count;
}

static ssize_t ath6kl_tx_amsdu_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	u8 buf[128];
	unsigned int len = 0;
	int i;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->aggr_cntxt))
			len += scnprintf(buf + len, sizeof(buf) - len, "DEV-%d %s \n",
					i,
					(test_bit(AMSDU_ENABLED, &vif->flags) ? "ON" : "OFF"));
	}

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

/* debug fs for TX A-MSDU */
static const struct file_operations fops_tx_amsdu = {
	.read = ath6kl_tx_amsdu_read,
	.write = ath6kl_tx_amsdu_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_htc_stat_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	static u8 buf[2048];
	unsigned int len;

	len = ath6kl_htc_stat(ar->htc_target, buf, 2048);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}


/* debug fs for HTC EP Stats. */
static const struct file_operations fops_htc_stat = {
	.read = ath6kl_htc_stat_read,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_hif_stat_read(struct file *file, 
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	static u8 buf[2048];
	unsigned int len;

	len = ath6kl_hif_stat(ar, buf, 2048);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}


/* debug fs for HIF Stats. */
static const struct file_operations fops_hif_stat = {
	.read = ath6kl_hif_stat_read,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/* File operation functions for HIF-PIPE Max. Schedule packages */
static ssize_t ath6kl_hif_pipe_max_sche_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	char buf[64];
	char *p;
	unsigned int len;
	u32 max_sche_tx, max_sche_rx;

	if (ar->hif_type |= ATH6KL_HIF_TYPE_USB)
		return -EIO;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	p = buf;

	SKIP_SPACE;

	sscanf(p, "%d", &max_sche_tx);

	SEEK_SPACE;
	SKIP_SPACE;

	sscanf(p, "%d", &max_sche_rx);

	ath6kl_hif_pipe_set_max_sche(ar, max_sche_tx, max_sche_rx);

	return count;
}

/* debug fs for HIF-PIPE Max. Schedule packages */
static const struct file_operations fops_hif_pipe_max_sche = {
	.write = ath6kl_hif_pipe_max_sche_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/* File operation functions for AP-APSD */
static ssize_t ath6kl_ap_apsd_read(struct file *file,
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	static u8 buf[128];
	unsigned int len = 0;
	int i;
	
	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) && (vif->nw_type == AP_NETWORK)) {
			len += scnprintf(buf, sizeof(buf), "VAP(%d), apsd: %d\n", i,
				vif->ap_apsd);
		}
	}
	
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_ap_apsd_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	u32 ap_apsd;
	char buf[32];
	ssize_t len;
	int i;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtou32(buf, 0, &ap_apsd))
		return -EINVAL;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->nw_type == AP_NETWORK)) {
			ath6kl_wmi_ap_set_apsd(vif->ar->wmi, vif->fw_vif_idx,
						ap_apsd ? WMI_AP_APSD_ENABLED : WMI_AP_APSD_DISABLED);
			vif->ap_apsd = ap_apsd;
		}
	}

	return count;
}

/* debug fs for AP-APSD */
static const struct file_operations fops_ap_apsd = {
	.read = ath6kl_ap_apsd_read,
	.write = ath6kl_ap_apsd_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

/* File operation functions for AP-IntraBss */
static ssize_t ath6kl_ap_intrabss_read(struct file *file,
				char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	u8 buf[256];
	unsigned int len = 0;
	int i;
	
	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) && (vif->nw_type == AP_NETWORK)) {
			len += scnprintf(buf, sizeof(buf), "VAP(%d), ap_intrabss: %d\n", i,
				vif->intra_bss);
		}
	}
	
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_ap_intrabss_write(struct file *file,
				const char __user *user_buf,
				size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	u32 ap_intrabss;
	char buf[32];
	ssize_t len;
	int i;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtou32(buf, 0, &ap_intrabss))
		return -EINVAL;

	for (i = 0; i < ar->vif_max; i++) {
		vif = ath6kl_get_vif_by_index(ar, i);
		if ((vif) &&
			(vif->nw_type == AP_NETWORK))
			vif->intra_bss = (ap_intrabss ? 1 : 0);
	}

	return count;
}

/* debug fs for AP-IntraBss */
static const struct file_operations fops_ap_intrabss = {
	.read = ath6kl_ap_intrabss_read,
	.write = ath6kl_ap_intrabss_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_get_force_passcan(struct file *file,
                                char __user *user_buf,
                                size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	u8 buf[128];
	unsigned int len = 0;

	len = scnprintf(buf, sizeof(buf), "force passive: %d\n", ar->debug.force_passive);

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t ath6kl_set_force_passcan(struct file *file,
                                const char __user *user_buf,
                                size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	unsigned int len = 0;
	u8 buf[16];
	u32 force_passcan;

	vif = ath6kl_vif_first(ar);
	if (!vif)
		return -EIO;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtou32(buf, 0, &force_passcan))
		return -EINVAL;

	if (force_passcan == 1)
		vif->sc_params.scan_ctrl_flags &= ~ACTIVE_SCAN_CTRL_FLAGS;
	else	
		vif->sc_params.scan_ctrl_flags |= ACTIVE_SCAN_CTRL_FLAGS;

	ar->debug.force_passive = force_passcan;

	ath6kl_wmi_scanparams_cmd(ar->wmi, vif->fw_vif_idx,
				vif->sc_params.fg_start_period,
				vif->sc_params.fg_end_period,
				vif->sc_params.bg_period,
				vif->sc_params.minact_chdwell_time,
				vif->sc_params.maxact_chdwell_time,
				vif->sc_params.pas_chdwell_time,
				vif->sc_params.short_scan_ratio,
				vif->sc_params.scan_ctrl_flags,
				vif->sc_params.max_dfsch_act_time,
				vif->sc_params.maxact_scan_per_ssid);

	return count;
}

static const struct file_operations fops_force_passcan = {
	.read = ath6kl_get_force_passcan,
	.write = ath6kl_set_force_passcan,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_get_pmkid_list(struct file *file,
                                char __user *user_buf,
                                size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	unsigned int len = 0, buf_len;
	u8 *p;
	u8 buf[512];
	struct wmi_pmkid_list_reply *reply;
	long left;

	vif = ath6kl_vif_first(ar);
	if (!vif)
		return -EIO;

	if (down_interruptible(&ar->sem))
                return -EBUSY;

	set_bit(PMKLIST_GET_PEND, &vif->flags);

	if (ath6kl_wmi_get_pmkid_list(ar->wmi, 0)) {
		up(&ar->sem);
		return -EIO;
	}

	left = wait_event_interruptible_timeout(ar->event_wq,
						!test_bit(PMKLIST_GET_PEND,
						&vif->flags), WMI_TIMEOUT);

	up(&ar->sem);

	if (left <= 0)
		return -ETIMEDOUT;

	reply = (struct wmi_pmkid_list_reply *) vif->pmkid_list_buf;
	p = buf;
	buf_len = sizeof(buf);

	len += scnprintf(p + len, buf_len - len, "PMKID List\n");

	if (reply->num_pmkid != 0 && reply->num_pmkid <= WMI_MAX_PMKID_CACHE)
	{
		int i;
		char *bssid = (char *)reply->bssid_list;
		char *pmkid = (char *)reply->pmkid_list;

		for (i = 0; i < reply->num_pmkid; i++) {
			len += scnprintf(p + len, buf_len - len, "bssid: %02x:%02x:%02x:%02x:%02x:%02x\n",
					(bssid[0] & 0xff), (bssid[1] & 0xff), (bssid[2] & 0xff),
					(bssid[3] & 0xff), (bssid[4] & 0xff), (bssid[5] & 0xff));
			len += scnprintf(p + len, buf_len - len,
				"pmkid: %02x:%02x:%02x:%02x:%02x:%02x%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
				(pmkid[0] & 0xff), (pmkid[1] & 0xff), (pmkid[2] & 0xff), (pmkid[3] & 0xff),
				(pmkid[4] & 0xff), (pmkid[5] & 0xff), (pmkid[6] & 0xff), (pmkid[7] & 0xff),
				(pmkid[8] & 0xff), (pmkid[9] & 0xff), (pmkid[10] & 0xff), (pmkid[11] & 0xff),
				(pmkid[12] & 0xff), (pmkid[13] & 0xff), (pmkid[14] & 0xff), (pmkid[15] & 0xff));

			bssid += (sizeof(struct wmi_pmkid) + ETH_ALEN);
			pmkid += (sizeof(struct wmi_pmkid) + ETH_ALEN);
		}
	}

	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_pmkid_list = {
	.read = ath6kl_get_pmkid_list,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

static ssize_t ath6kl_txseries_write(struct file *file,
				     const char __user *user_buf,
				     size_t count, loff_t *ppos)
{
	struct ath6kl *ar = file->private_data;
	struct ath6kl_vif *vif;
	u64 tx_series;
	int ret;

	vif = ath6kl_vif_first(ar);
	if (!vif)
		return -EIO;

	ret = kstrtou64_from_user(user_buf, count, 0, &tx_series);
	if (ret)
		return ret;

	ar->debug.set_tx_series = tx_series;

	if (ath6kl_wmi_set_tx_select_rates_on_all_mode(ar->wmi, vif->fw_vif_idx,
                                                    tx_series))
		return -EIO;

	return count;
}

static ssize_t ath6kl_txseries_read(struct file *file, 
                      char __user *user_buf,
                      size_t count, loff_t *ppos)
{
    struct ath6kl *ar = file->private_data;
    u8 buf[32];
    unsigned int len = 0;
    
    len = scnprintf(buf, sizeof(buf), "Txratemask is 0x%llx\n",
            ar->debug.set_tx_series);
    
    return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static const struct file_operations fops_txseries_write = {
	.read = ath6kl_txseries_read,
	.write = ath6kl_txseries_write,
	.open = ath6kl_debugfs_open,
	.owner = THIS_MODULE,
	.llseek = default_llseek,
};

int ath6kl_debug_init(struct ath6kl *ar)
{
	ar->debug.fwlog_buf.buf = vmalloc(ATH6KL_FWLOG_SIZE);
	if (ar->debug.fwlog_buf.buf == NULL)
		return -ENOMEM;

	ar->debug.fwlog_tmp = kmalloc(ATH6KL_FWLOG_SLOT_SIZE, GFP_KERNEL);
	if (ar->debug.fwlog_tmp == NULL) {
		vfree(ar->debug.fwlog_buf.buf);
		return -ENOMEM;
	}

	spin_lock_init(&ar->debug.fwlog_lock);

	/*
	 * Actually we are lying here but don't know how to read the mask
	 * value from the firmware.
	 */
	ar->debug.fwlog_mask = 0;

	ar->debugfs_phy = debugfs_create_dir("ath6kl",
					     ar->wiphy->debugfsdir);
	if (!ar->debugfs_phy) {
		vfree(ar->debug.fwlog_buf.buf);
		kfree(ar->debug.fwlog_tmp);
		return -ENOMEM;
	}

	debugfs_create_file("tgt_stats", S_IRUSR, ar->debugfs_phy, ar,
			    &fops_tgt_stats);

	debugfs_create_file("credit_dist_stats", S_IRUSR, ar->debugfs_phy, ar,
			    &fops_credit_dist_stats);

	debugfs_create_file("endpoint_stats", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_endpoint_stats);

	debugfs_create_file("fwlog", S_IRUSR, ar->debugfs_phy, ar,
			    &fops_fwlog);

	debugfs_create_file("fwlog_mask", S_IRUSR | S_IWUSR, ar->debugfs_phy,
			    ar, &fops_fwlog_mask);

	debugfs_create_file("reg_addr", S_IRUSR | S_IWUSR, ar->debugfs_phy, ar,
			    &fops_diag_reg_read);

	debugfs_create_file("reg_dump", S_IRUSR, ar->debugfs_phy, ar,
			    &fops_reg_dump);

	debugfs_create_file("lrssi_roam_threshold", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_lrssi_roam_threshold);

	debugfs_create_file("reg_write", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_diag_reg_write);

	debugfs_create_file("war_stats", S_IRUSR, ar->debugfs_phy, ar,
			    &fops_war_stats);

	debugfs_create_file("roam_table", S_IRUSR, ar->debugfs_phy, ar,
			    &fops_roam_table);

	debugfs_create_file("force_roam", S_IWUSR, ar->debugfs_phy, ar,
			    &fops_force_roam);

	debugfs_create_file("roam_mode", S_IWUSR, ar->debugfs_phy, ar,
			    &fops_roam_mode);

	debugfs_create_file("keepalive", S_IRUSR | S_IWUSR, ar->debugfs_phy, ar,
			    &fops_keepalive);

	debugfs_create_file("disconnect_timeout", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_disconnect_timeout);

	debugfs_create_file("create_qos", S_IWUSR, ar->debugfs_phy, ar,
				&fops_create_qos);

	debugfs_create_file("delete_qos", S_IWUSR, ar->debugfs_phy, ar,
				&fops_delete_qos);

	debugfs_create_file("bgscan_interval", S_IWUSR,
				ar->debugfs_phy, ar, &fops_bgscan_int);

	debugfs_create_file("power_params", S_IWUSR, ar->debugfs_phy, ar,
				&fops_power_params);

	debugfs_create_file("rtt", S_IRUSR | S_IWUSR,ar->debugfs_phy, ar, 
				&fops_rtt);

	debugfs_create_file("lpl_force_enable", S_IRUSR | S_IWUSR,
				ar->debugfs_phy, ar, &fops_lpl_force_enable);

	debugfs_create_file("mimo_ps_enable", S_IRUSR | S_IWUSR,
				ar->debugfs_phy, ar, &fops_mimo_ps_enable);

	debugfs_create_file("mimo_ps_params", S_IRUSR | S_IWUSR,
				ar->debugfs_phy, ar, &fops_mimo_ps_params);

	debugfs_create_file("green_tx_enable", S_IRUSR | S_IWUSR,
				ar->debugfs_phy, ar, &fops_green_tx);

	debugfs_create_file("green_tx_params", S_IRUSR | S_IWUSR,
				ar->debugfs_phy, ar, &fops_green_tx_params);

	debugfs_create_file("ht_cap_params", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_ht_cap_params);

	debugfs_create_file("ht_coex_params", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_ht_coex_params);

	debugfs_create_file("debug_mask", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_debug_mask);

	debugfs_create_file("tx_amsdu", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_tx_amsdu);

	debugfs_create_file("tx_amsdu_params", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_tx_amsdu_params);

	debugfs_create_file("htc_stat", S_IRUSR,
			    ar->debugfs_phy, ar, &fops_htc_stat);

	debugfs_create_file("hif_stat", S_IRUSR,
			    ar->debugfs_phy, ar, &fops_hif_stat);

	debugfs_create_file("hif_max_sche", S_IWUSR,
			    ar->debugfs_phy, ar, &fops_hif_pipe_max_sche);

	debugfs_create_file("ap_apsd", S_IWUSR,
			    ar->debugfs_phy, ar, &fops_ap_apsd);

	debugfs_create_file("ap_intrabss", S_IWUSR,
			    ar->debugfs_phy, ar, &fops_ap_intrabss);

	debugfs_create_file("force_passcan", S_IRUSR | S_IWUSR,
			    ar->debugfs_phy, ar, &fops_force_passcan);

	debugfs_create_file("pmkid_list", S_IRUSR,
			    ar->debugfs_phy, ar, &fops_pmkid_list);

	debugfs_create_file("txrate_sereies", S_IWUSR,
			    ar->debugfs_phy, ar, &fops_txseries_write);

	return 0;
}


void ath6kl_debug_cleanup(struct ath6kl *ar)
{
	vfree(ar->debug.fwlog_buf.buf);
	kfree(ar->debug.fwlog_tmp);
	kfree(ar->debug.roam_tbl);
}

#endif
