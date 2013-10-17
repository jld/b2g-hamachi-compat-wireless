/*
 * Copyright (c) 2011 Atheros Communications Inc.
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

#ifndef DEBUG_H
#define DEBUG_H

#include "hif.h"

enum ATH6KL_MODULE_QUIRKS {
	ATH6KL_MODULE_SUSPEND_CUTPOWER  = BIT(0), /* enable suspend cutpower */
	AT6HKL_MODULE_LPL_ENABLE        = BIT(1), /* enable lpl */
	ATH6KL_MODULE_MIMO_PS_ENABLE    = BIT(2), /* enable mimo ps */
	ATH6KL_MODULE_P2P_ENABLE        = BIT(3), /* enable p2p */
	ATH6KL_MODULE_TESTMODE_ENABLE   = BIT(4), /* enable test mode */
	ATH6KL_MODULES_ANI_ENABLE       = BIT(5), /* anti-noise-immunity */
	ATH6KL_MODULE_ENABLE_EPPING		= BIT(6), /* enable endpoing loopback */
	ATH6KL_MODULE_DISABLE_5G		= BIT(7), /* disable 5G support */
};

enum ATH6KL_MODULE_P2P {
	ATH6KL_MODULEP2P_P2P_ENABLE			= BIT(0), /* enable single interface p2p */
	AT6HKL_MODULEP2P_CONCURRENT_ENABLE  = BIT(1), /* enable p2p_concurrent */
};

enum ATH6K_DEBUG_MASK {
	ATH6KL_DBG_CREDIT	= BIT(0),
	/* hole */
	ATH6KL_DBG_WLAN_TX      = BIT(2),     /* wlan tx */
	ATH6KL_DBG_WLAN_RX      = BIT(3),     /* wlan rx */
	ATH6KL_DBG_BMI		= BIT(4),     /* bmi tracing */
	ATH6KL_DBG_HTC		= BIT(5),
	ATH6KL_DBG_HIF		= BIT(6),
	ATH6KL_DBG_IRQ		= BIT(7),     /* interrupt processing */
	/* hole */
	/* hole */
	ATH6KL_DBG_WMI          = BIT(10),    /* wmi tracing */
	ATH6KL_DBG_TRC	        = BIT(11),    /* generic func tracing */
	ATH6KL_DBG_SCATTER	= BIT(12),    /* hif scatter tracing */
	ATH6KL_DBG_WLAN_CFG     = BIT(13),    /* cfg80211 i/f file tracing */
	ATH6KL_DBG_RAW_BYTES    = BIT(14),    /* dump tx/rx frames */
	ATH6KL_DBG_AGGR		= BIT(15),    /* aggregation */
	ATH6KL_DBG_SDIO		= BIT(16),
	ATH6KL_DBG_SDIO_DUMP	= BIT(17),
	ATH6KL_DBG_BOOT		= BIT(18),    /* driver init and fw boot */
	ATH6KL_DBG_WMI_DUMP	= BIT(19),
	ATH6KL_DBG_SUSPEND	= BIT(20),
	ATH6KL_DBG_USB		= BIT(21),
	ATH6KL_DBG_USB_BULK	= BIT(22),
	ATH6KL_DBG_HTCOEX	= BIT(23),		/* HT20/40 Coexist */
	ATH6KL_DBG_WLAN_TX_AMSDU = BIT(24),    /* wlan tx a-msdu */
	ATH6KL_DBG_POWERSAVE 	= BIT(25),    /* power-saving */
	ATH6KL_DBG_WOWLAN	= BIT(26),    /* wowlan tracing */
        ATH6KL_DBG_RTT          = BIT(27),
	ATH6KL_DBG_ANY	        = 0xffffffff  /* enable all logs */
};

extern unsigned int debug_mask;
extern __printf(2, 3)
int ath6kl_printk(const char *level, const char *fmt, ...);

#define ath6kl_info(fmt, ...)				\
	ath6kl_printk(KERN_INFO, fmt, ##__VA_ARGS__)
#define ath6kl_err(fmt, ...)					\
	ath6kl_printk(KERN_ERR, fmt, ##__VA_ARGS__)
#define ath6kl_warn(fmt, ...)					\
	ath6kl_printk(KERN_WARNING, fmt, ##__VA_ARGS__)

#define AR_DBG_LVL_CHECK(mask)	(debug_mask & mask)

enum ath6kl_war {
	ATH6KL_WAR_INVALID_RATE,
};

static inline int ath6kl_mod_debug_quirks(struct ath6kl *ar,
                  enum ATH6KL_MODULE_QUIRKS mask)
{
	if(ar->mod_debug_quirks & mask)
		return 1;
	else
		return 0;
}

#ifdef CONFIG_QC_INTERNAL
int ath6kl_set_rd(struct ath6kl *ar);
#else
static inline int ath6kl_set_rd(struct ath6kl *ar)
{
	return 0;
}
#endif

#ifdef CONFIG_ATH6KL_DEBUG
#define ath6kl_dbg(mask, fmt, ...)					\
	({								\
	 int rtn;							\
	 if (debug_mask & mask)						\
		rtn = ath6kl_printk(KERN_DEBUG, fmt, ##__VA_ARGS__);	\
	 else								\
		rtn = 0;						\
									\
	 rtn;								\
	 })

static inline void ath6kl_dbg_dump(enum ATH6K_DEBUG_MASK mask,
				   const char *msg, const char *prefix,
				   const void *buf, size_t len)
{
	if (debug_mask & mask) {
		if (msg)
			ath6kl_dbg(mask, "%s\n", msg);

		print_hex_dump_bytes(prefix, DUMP_PREFIX_OFFSET, buf, len);
	}
}

void ath6kl_dump_registers(struct ath6kl_device *dev,
			   struct ath6kl_irq_proc_registers *irq_proc_reg,
			   struct ath6kl_irq_enable_reg *irq_en_reg);
void dump_cred_dist_stats(struct htc_target *target);
void ath6kl_debug_fwlog_event(struct ath6kl *ar, const void *buf, size_t len);
void ath6kl_debug_war(struct ath6kl *ar, enum ath6kl_war war);
int ath6kl_debug_roam_tbl_event(struct ath6kl *ar, const void *buf,
				size_t len);
void ath6kl_debug_set_keepalive(struct ath6kl *ar, u8 keepalive);
void ath6kl_debug_set_disconnect_timeout(struct ath6kl *ar, u8 timeout);
int ath6kl_debug_init(struct ath6kl *ar);
void ath6kl_debug_cleanup(struct ath6kl *ar);

#else
static inline int ath6kl_dbg(enum ATH6K_DEBUG_MASK dbg_mask,
			     const char *fmt, ...)
{
	return 0;
}

static inline void ath6kl_dbg_dump(enum ATH6K_DEBUG_MASK mask,
				   const char *msg, const char *prefix,
				   const void *buf, size_t len)
{
}

static inline void ath6kl_dump_registers(struct ath6kl_device *dev,
		struct ath6kl_irq_proc_registers *irq_proc_reg,
		struct ath6kl_irq_enable_reg *irq_en_reg)
{

}
static inline void dump_cred_dist_stats(struct htc_target *target)
{
}

static inline void ath6kl_debug_fwlog_event(struct ath6kl *ar,
					    const void *buf, size_t len)
{
}

static inline void ath6kl_debug_war(struct ath6kl *ar, enum ath6kl_war war)
{
}

static inline int ath6kl_debug_roam_tbl_event(struct ath6kl *ar,
					      const void *buf, size_t len)
{
	return 0;
}

static inline void ath6kl_debug_set_keepalive(struct ath6kl *ar, u8 keepalive)
{
}

static inline void ath6kl_debug_set_disconnect_timeout(struct ath6kl *ar,
						       u8 timeout)
{
}

static inline int ath6kl_debug_init(struct ath6kl *ar)
{
	return 0;
}

static inline void ath6kl_debug_cleanup(struct ath6kl *ar)
{
}

#endif
#endif
