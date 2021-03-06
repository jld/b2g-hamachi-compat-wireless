/*
 * Copyright (c) 2010-2011 Atheros Communications Inc.
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

#ifndef CORE_H
#define CORE_H

#include <linux/etherdevice.h>
#include <linux/rtnetlink.h>
#include <linux/firmware.h>
#include <linux/sched.h>
#include <linux/circ_buf.h>
#include <linux/ip.h>
#include <net/cfg80211.h>
#ifdef CONFIG_ANDROID
#ifdef CONFIG_HAS_WAKELOCK
#include <linux/wakelock.h>
#endif
#endif
#ifdef CONFIG_HAS_EARLYSUSPEND
#include <linux/earlysuspend.h>
#endif
#include "htc.h"
#include "wmi.h"
#include "bmi.h"
#include "target.h"
#include "wmi_btcoex.h"
#include "htcoex.h"
#include "p2p.h"
#include <linux/wireless.h>

#define MAKE_STR(symbol) #symbol
#define TO_STR(symbol) MAKE_STR(symbol)

/* The script (used for release builds) modifies the following line. */
#define __BUILD_VERSION_ 3.5.0.9999

#define DRV_VERSION		TO_STR(__BUILD_VERSION_)

/* enable diagnostic by default in this version */
#define ATH6KL_DIAGNOSTIC 1
#ifdef ATH6KL_DIAGNOSTIC
#include "diagnose.h"
#endif

#define MAX_ATH6KL                        1
#define ATH6KL_MAX_RX_BUFFERS             16
#define ATH6KL_BUFFER_SIZE                1664
#define ATH6KL_MAX_AMSDU_RX_BUFFERS       4
#define ATH6KL_AMSDU_REFILL_THRESHOLD     3
#define ATH6KL_AMSDU_BUFFER_SIZE     (WMI_MAX_AMSDU_RX_DATA_FRAME_LENGTH + 128)
#define MAX_MSDU_SUBFRAME_PAYLOAD_LEN	1508
#define MIN_MSDU_SUBFRAME_PAYLOAD_LEN	46

#define USER_SAVEDKEYS_STAT_INIT     0
#define USER_SAVEDKEYS_STAT_RUN      1

#define ATH6KL_TX_TIMEOUT      10
#define ATH6KL_MAX_ENDPOINTS   4
#define MAX_NODE_NUM           15

/* Extra bytes for htc header alignment */
#define ATH6KL_HTC_ALIGN_BYTES 3

/* MAX_HI_COOKIE_NUM are reserved for high priority traffic */
#define MAX_DEF_COOKIE_NUM                180
#define MAX_HI_COOKIE_NUM                 18	/* 10% of MAX_COOKIE_NUM */
#define MAX_COOKIE_NUM                 (MAX_DEF_COOKIE_NUM + MAX_HI_COOKIE_NUM)

#define MAX_DEFAULT_SEND_QUEUE_DEPTH      (MAX_DEF_COOKIE_NUM / WMM_NUM_AC)

#define DISCON_TIMER_INTVAL               10000  /* in msec */
#define A_DEFAULT_LISTEN_INTERVAL         100
#define A_MAX_WOW_LISTEN_INTERVAL         1000

#define ATH6KL_DISCONNECT_TIMEOUT 	  3

/* includes also the null byte */
#define ATH6KL_FIRMWARE_MAGIC               "QCA-ATH6KL"

enum ath6kl_fw_ie_type {
	ATH6KL_FW_IE_FW_VERSION = 0,
	ATH6KL_FW_IE_TIMESTAMP = 1,
	ATH6KL_FW_IE_OTP_IMAGE = 2,
	ATH6KL_FW_IE_FW_IMAGE = 3,
	ATH6KL_FW_IE_PATCH_IMAGE = 4,
	ATH6KL_FW_IE_RESERVED_RAM_SIZE = 5,
	ATH6KL_FW_IE_CAPABILITIES = 6,
	ATH6KL_FW_IE_PATCH_ADDR = 7,
	ATH6KL_FW_IE_BOARD_ADDR = 8,
	ATH6KL_FW_IE_VIF_MAX = 9,
};

enum ath6kl_fw_capability {
	ATH6KL_FW_CAPABILITY_HOST_P2P = 0,

	/* this needs to be last */
	ATH6KL_FW_CAPABILITY_MAX,
};

#define ATH6KL_CAPABILITY_LEN (ALIGN(ATH6KL_FW_CAPABILITY_MAX, 32) / 32)

struct ath6kl_fw_ie {
	__le32 id;
	__le32 len;
	u8 data[0];
};

#define ATH6KL_IOCTL_STANDARD01		(SIOCDEVPRIVATE+1)		/* Reserved for Android PNO and vendor specific functions */
#define ATH6KL_IOCTL_STANDARD02		(SIOCDEVPRIVATE+2)		/* Standard do_ioctl() ioctl interface */
#define ATH6KL_IOCTL_STANDARD12		(SIOCDEVPRIVATE+12)		/* hole, please reserved */
#define ATH6KL_IOCTL_STANDARD13		(SIOCDEVPRIVATE+13)		/* TX99 */
#define ATH6KL_IOCTL_STANDARD15		(SIOCDEVPRIVATE+15)		/* hole, please reserved */
#define ATH6KL_IOCTL_WEXT_PRIV26	(SIOCIWFIRSTPRIV+26)		/* ATH6KL_IOCTL_EXTENDED - extended ioctl */
#define ATH6KL_IOCTL_WEXT_PRIV27	(SIOCIWFIRSTPRIV+27)		/* reserved for QCSAP (old) */
#define ATH6KL_IOCTL_WEXT_PRIV31	(SIOCIWFIRSTPRIV+31)		/* reserved for QCSAP */

#define ATH6KL_IOCTL_AP_APSD		(0)
#define ATH6KL_IOCTL_AP_INTRABSS	(1)

/* TBD: ioctl number is aligned to olca branch 
 *      will refine one the loopback tool is ready for native ath6kl
 */
typedef enum {
	ATH6KL_XIOCTL_TRAFFIC_ACTIVITY_CHANGE = 80,
} XTND_IOCLTS;


struct ath6kl_traffic_activity_change {
    u32    stream_id;   /* stream ID to indicate activity change */
    u32    active;     /* active (1) or inactive (0) */
};

/* FIXME : to support variable options. */
struct ath6kl_ioctl_cmd {
	u32 subcmd;
	u32 options;
};

struct ath6kl_android_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
};

#define ATH6KL_FW_API2_FILE "fw-2.bin"

/* AR6003 1.0 definitions */
#define AR6003_HW_1_0_VERSION                 0x300002ba

/* AR6003 2.0 definitions */
#define AR6003_HW_2_0_VERSION                 0x30000384
#define AR6003_HW_2_0_PATCH_DOWNLOAD_ADDRESS  0x57e910
#define AR6003_HW_2_0_FW_DIR			"ath6k/AR6003/hw2.0"
#define AR6003_HW_2_0_OTP_FILE			"otp.bin.z77"
#define AR6003_HW_2_0_FIRMWARE_FILE		"athwlan.bin.z77"
#define AR6003_HW_2_0_TCMD_FIRMWARE_FILE	"athtcmd_ram.bin"
#define AR6003_HW_2_0_PATCH_FILE		"data.patch.bin"
#define AR6003_HW_2_0_BOARD_DATA_FILE "ath6k/AR6003/hw2.0/bdata.bin"
#define AR6003_HW_2_0_DEFAULT_BOARD_DATA_FILE \
			"ath6k/AR6003/hw2.0/bdata.SD31.bin"

/* AR6003 3.0 definitions */
#define AR6003_HW_2_1_1_VERSION                 0x30000582
#define AR6003_HW_2_1_1_FW_DIR			"ath6k/AR6003/hw2.1.1"
#define AR6003_HW_2_1_1_OTP_FILE		"otp.bin"
#define AR6003_HW_2_1_1_FIRMWARE_FILE		"athwlan.bin"
#define AR6003_HW_2_1_1_TCMD_FIRMWARE_FILE	"athtcmd_ram.bin"
#define AR6003_HW_2_1_1_UTF_FIRMWARE_FILE	"utf.bin"
#define AR6003_HW_2_1_1_TESTSCRIPT_FILE	"nullTestFlow.bin"
#define AR6003_HW_2_1_1_PATCH_FILE		"data.patch.bin"
#define AR6003_HW_2_1_1_BOARD_DATA_FILE "ath6k/AR6003/hw2.1.1/bdata.bin"
#define AR6003_HW_2_1_1_DEFAULT_BOARD_DATA_FILE	\
			"ath6k/AR6003/hw2.1.1/bdata.SD31.bin"

/* AR6004 1.0 definitions */
#define AR6004_HW_1_0_VERSION                 0x30000623
#define AR6004_HW_1_0_FW_DIR			"ath6k/AR6004/hw1.0"
#define AR6004_HW_1_0_FIRMWARE_FILE		"fw.ram.bin"
#define AR6004_HW_1_0_BOARD_DATA_FILE         "ath6k/AR6004/hw1.0/bdata.bin"
#define AR6004_HW_1_0_DEFAULT_BOARD_DATA_FILE \
	"ath6k/AR6004/hw1.0/bdata.DB132.bin"

/* AR6004 1.1 definitions */
#define AR6004_HW_1_1_VERSION                 0x30000001
#define AR6004_HW_1_1_FW_DIR			"ath6k/AR6004/hw1.1"
#define AR6004_HW_1_1_FIRMWARE_FILE		"fw.ram.bin"
#define AR6004_HW_1_1_TCMD_FIRMWARE_FILE           "utf.bin"
#define AR6004_HW_1_1_UTF_FIRMWARE_FILE	"utf.bin"
#define AR6004_HW_1_1_TESTSCRIPT_FILE	"nullTestFlow.bin"
#define AR6004_HW_1_1_BOARD_DATA_FILE         "ath6k/AR6004/hw1.1/bdata.bin"
#define AR6004_HW_1_1_DEFAULT_BOARD_DATA_FILE \
	"ath6k/AR6004/hw1.1/bdata.DB132.bin"
#define AR6004_HW_1_1_EPPING_FILE             "ath6k/AR6004/hw1.1/epping.bin"
#define AR6004_HW_1_1_SOFTMAC_FILE            "ath6k/AR6004/hw1.1/softmac.bin"

/* AR6004 1.2 definitions */
#define AR6004_HW_1_2_VERSION                 0x300007e8
#define AR6004_HW_1_2_FW_DIR			"ath6k/AR6004/hw1.2"
#define AR6004_HW_1_2_FIRMWARE_2_FILE         "fw-2.bin"
#define AR6004_HW_1_2_FIRMWARE_FILE           "fw.ram.bin"
#define AR6004_HW_1_2_TCMD_FIRMWARE_FILE      "utf.bin"
#define AR6004_HW_1_2_UTF_FIRMWARE_FILE	"utf.bin"
#define AR6004_HW_1_2_TESTSCRIPT_FILE	"nullTestFlow.bin"
#define AR6004_HW_1_2_BOARD_DATA_FILE         "ath6k/AR6004/hw1.2/bdata.bin"
#define AR6004_HW_1_2_DEFAULT_BOARD_DATA_FILE \
	"ath6k/AR6004/hw1.2/bdata.bin"
#define AR6004_HW_1_2_EPPING_FILE             "ath6k/AR6004/hw1.2/epping.bin"
#define AR6004_HW_1_2_SOFTMAC_FILE            "ath6k/AR6004/hw1.2/softmac.bin"

/* AR6004 1.3 definitions */
#define AR6004_HW_1_3_VERSION                 0x31c8088a
#define AR6004_HW_1_3_FW_DIR			"ath6k/AR6004/hw1.3"
#define AR6004_HW_1_3_FIRMWARE_2_FILE         "fw-2.bin"
#define AR6004_HW_1_3_FIRMWARE_FILE           "fw.ram.bin"
#define AR6004_HW_1_3_TCMD_FIRMWARE_FILE      "utf.bin"
#define AR6004_HW_1_3_UTF_FIRMWARE_FILE	"utf.bin"
#define AR6004_HW_1_3_TESTSCRIPT_FILE	"nullTestFlow.bin"
#define AR6004_HW_1_3_BOARD_DATA_FILE         "ath6k/AR6004/hw1.3/bdata.bin"
#define AR6004_HW_1_3_DEFAULT_BOARD_DATA_FILE \
	"ath6k/AR6004/hw1.3/bdata.bin"
#define AR6004_HW_1_3_EPPING_FILE             "ath6k/AR6004/hw1.3/epping.bin"
#define AR6004_HW_1_3_SOFTMAC_FILE            "ath6k/AR6004/hw1.3/softmac.bin"

/* AR6004 1.6 definitions */
#define AR6004_HW_1_6_VERSION                 0x31c808c1
#define AR6004_HW_1_6_FW_DIR			"ath6k/AR6004/hw1.6"
#define AR6004_HW_1_6_FIRMWARE_2_FILE         "fw-2.bin"
#define AR6004_HW_1_6_FIRMWARE_FILE           "fw.ram.bin"
#define AR6004_HW_1_6_TCMD_FIRMWARE_FILE      "utf.bin"
#define AR6004_HW_1_6_UTF_FIRMWARE_FILE	"utf.bin"
#define AR6004_HW_1_6_TESTSCRIPT_FILE	"nullTestFlow.bin"
#define AR6004_HW_1_6_BOARD_DATA_FILE         "ath6k/AR6004/hw1.6/bdata.bin"
#define AR6004_HW_1_6_DEFAULT_BOARD_DATA_FILE \
	"ath6k/AR6004/hw1.6/bdata.bin"
#define AR6004_HW_1_6_EPPING_FILE             "ath6k/AR6004/hw1.6/epping.bin"
#define AR6004_HW_1_6_SOFTMAC_FILE            "ath6k/AR6004/hw1.6/softmac.bin"

/* AR6006 1.0 definitions */
#define AR6006_HW_1_0_VERSION                 0x3000270f
#define AR6006_HW_1_0_FW_DIR			"ath6k/AR6006/hw1.0"
#define AR6006_HW_1_0_FIRMWARE_2_FILE         "fw-2.bin"
#define AR6006_HW_1_0_FIRMWARE_FILE           "fw.ram.bin"
#define AR6006_HW_1_0_BOARD_DATA_FILE         "ath6k/AR6006/hw1.0/bdata.bin"
#define AR6006_HW_1_0_DEFAULT_BOARD_DATA_FILE \
	"ath6k/AR6006/hw1.0/bdata.bin"

#define BDATA_CHECKSUM_OFFSET                 4
#define BDATA_MAC_ADDR_OFFSET                 8

/* Per STA data, used in AP mode */
#define STA_PS_AWAKE		BIT(0)
#define	STA_PS_SLEEP		BIT(1)
#define	STA_PS_POLLED		BIT(2)
#define STA_PS_APSD_TRIGGER	BIT(3)
#define STA_PS_APSD_EOSP	BIT(4)

/* HTC TX packet tagging definitions */
#define ATH6KL_CONTROL_PKT_TAG    HTC_TX_PACKET_TAG_USER_DEFINED
#define ATH6KL_DATA_PKT_TAG       (ATH6KL_CONTROL_PKT_TAG + 1)

#define AR6003_CUST_DATA_SIZE 16

#define AGGR_WIN_IDX(x, y)          ((x) % (y))
#define AGGR_INCR_IDX(x, y)         AGGR_WIN_IDX(((x) + 1), (y))
#define AGGR_DCRM_IDX(x, y)         AGGR_WIN_IDX(((x) - 1), (y))
#define ATH6KL_MAX_SEQ_NO		0xFFF
#define ATH6KL_NEXT_SEQ_NO(x)		(((x) + 1) & ATH6KL_MAX_SEQ_NO)

#define NUM_OF_TIDS         8
#define AGGR_SZ_DEFAULT     8

#define AGGR_WIN_SZ_MIN     2
#define AGGR_WIN_SZ_MAX     8

#define TID_WINDOW_SZ(_x)   ((_x) << 1)

#define AGGR_NUM_OF_FREE_NETBUFS    16

#define AGGR_RX_TIMEOUT          50	/* in ms */

#define AGGR_GET_RXTID_STATS(_p, _x)     (&(_p->stat[(_x)]))
#define AGGR_GET_RXTID(_p, _x)           (&(_p->rx_tid[(_x)]))

#define AGGR_BA_EVT_GET_CONNID(_conn)    ((_conn) >> 4)
#define AGGR_BA_EVT_GET_TID(_tid)        ((_tid) & 0xF)

#define AGGR_TX_MAX_AGGR_SIZE   1600	/* Sync to max. PDU size of host size. */
#define AGGR_TX_MAX_PDU_SIZE    120
#define AGGR_TX_MIN_PDU_SIZE    64		/* 802.3(14) + LLC(8) + IP/TCP(20) = 42 */
#define AGGR_TX_MAX_NUM			6
#define AGGR_TX_TIMEOUT         4

#define AGGR_GET_TXTID(_p, _x)           (&(_p->tx_tid[(_x)]))

#define WMI_TIMEOUT (2 * HZ)

#define MBOX_YIELD_LIMIT 99

#define ATH6KL_PSQ_CHECK_AGE   (1 * 1000)  				/* 1 sec. */
#define ATH6KL_PSQ_MAX_AGE     (5)					/* 5 cycles */

#define ATH6KL_RSN_CAP_NULLCONF		(0xffff)

/* configuration lags */
/*
 * ATH6KL_CONF_IGNORE_ERP_BARKER: Ignore the barker premable in
 * ERP IE of beacon to determine the short premable support when
 * sending (Re)Assoc req.
 * ATH6KL_CONF_IGNORE_PS_FAIL_EVT_IN_SCAN: Don't send the power
 * module state transition failure events which happen during
 * scan, to the host.
 */
#define ATH6KL_CONF_IGNORE_ERP_BARKER		BIT(0)
#define ATH6KL_CONF_IGNORE_PS_FAIL_EVT_IN_SCAN  BIT(1)
#define ATH6KL_CONF_ENABLE_11N			BIT(2)
#define ATH6KL_CONF_ENABLE_TX_BURST		BIT(3)
#define ATH6KL_CONF_SUSPEND_CUTPOWER		BIT(4)

enum wlan_low_pwr_state {
	WLAN_POWER_STATE_ON,
	WLAN_POWER_STATE_CUT_PWR,
	WLAN_POWER_STATE_DEEP_SLEEP,
	WLAN_POWER_STATE_WOW
};

enum sme_state {
	SME_DISCONNECTED,
	SME_CONNECTING,
	SME_CONNECTED
};

struct skb_hold_q {
	struct sk_buff *skb;
	bool is_amsdu;
	u16 seq_no;
};

struct rxtid {
	bool aggr;
	bool progress;
	bool timer_mon;
	u16 win_sz;
	u16 seq_next;
	u32 hold_q_sz;
	struct skb_hold_q *hold_q;
	struct sk_buff_head q;
	spinlock_t lock;
};

struct rxtid_stats {
	u32 num_into_aggr;
	u32 num_dups;
	u32 num_oow;
	u32 num_mpdu;
	u32 num_amsdu;
	u32 num_delivered;
	u32 num_timeouts;
	u32 num_hole;
	u32 num_bar;
};

enum {
	AGGR_TX_OK = 0,
	AGGR_TX_DONE,
	AGGR_TX_BYPASS,
	AGGR_TX_DROP,
	AGGR_TX_UNKNOW,
};

struct txtid {
	u8 tid;
	u16 aid;
	u16 max_aggr_sz;			/* 0 means disable */
	struct timer_list timer;
	struct sk_buff *amsdu_skb;
	u8 amsdu_cnt;				/* current aggr count */
	u8 *amsdu_start;			/* start pointer of amsdu frame */
	u16 amsdu_len;				/* current aggr length */
	u16 amsdu_lastpdu_len;		/* last PDU length */
	spinlock_t lock;
	struct ath6kl_vif *vif;

	u32 num_pdu;
	u32 num_amsdu;
	u32 num_timeout;
	u32 num_flush;
	u32 num_tx_null;
};

struct aggr_info {
	struct ath6kl_vif *vif;
	struct sk_buff_head free_q;

	/* TX A-MSDU */
	bool tx_amsdu_enable;		/* IOT : treat A-MPDU & A-MSDU are exclusive. */
	bool tx_amsdu_seq_pkt;
	u8 tx_amsdu_max_aggr_num;
	u16 tx_amsdu_max_pdu_len;
	u16 tx_amsdu_timeout; 		/* in ms */
};

struct aggr_conn_info {
	u8 aggr_sz;
	u8 timer_scheduled;
	struct timer_list timer;
	struct aggr_info *aggr_cntxt;
	struct net_device *dev;
	struct rxtid rx_tid[NUM_OF_TIDS];
	struct rxtid_stats stat[NUM_OF_TIDS];

	/* TX A-MSDU */
	struct txtid tx_tid[NUM_OF_TIDS];
};

struct ath6kl_wep_key {
	u8 key_index;
	u8 key_len;
	u8 key[64];
};

#define ATH6KL_KEY_SEQ_LEN 8

struct ath6kl_key {
	u8 key[WLAN_MAX_KEY_LEN];
	u8 key_len;
	u8 seq[ATH6KL_KEY_SEQ_LEN];
	u8 seq_len;
	u32 cipher;
};

struct ath6kl_node_mapping {
	u8 mac_addr[ETH_ALEN];
	u8 ep_id;
	u8 tx_pend;
};

struct ath6kl_cookie {
	struct sk_buff *skb;
	u32 map_no;
	struct htc_packet htc_pkt;
	struct ath6kl_cookie *arc_list_next;
};

struct ath6kl_mgmt_buf {
	struct list_head list;
	u32 freq;
	u32 wait;
	u32 id;
	bool no_cck;
	bool dont_wait_for_ack;
	u32 age;
	size_t len;
	u8 buf[1];
};

struct ath6kl_mgmt_buf_head {
	struct list_head list;
	spinlock_t lock;
	u32 len;
};

struct ath6kl_data_buf_cb {
	/* total 48 bytes */
	u32 reserved;		/* used by cfg80211? */
	u32 ps_age;
	u8 reserved2[40];
};

struct ath6kl_sta {
	u16 sta_flags;
	u8 mac[ETH_ALEN];
	u8 aid;
	u8 keymgmt;
	u8 ucipher;
	u8 auth;
	u8 wpa_ie[ATH6KL_MAX_IE];
	struct ath6kl_vif *vif;
	spinlock_t lock;			/* ath6kl_sta global lock, psq & mgmt_psq also use it. */

	/* AP-PS*/
	struct sk_buff_head psq;
	struct ath6kl_mgmt_buf_head mgmt_psq;
	struct timer_list psq_age_timer;
	u8 apsd_info;

	/* TX/RX-AMSDU */
	struct aggr_conn_info *aggr_conn_cntxt;	
};

struct ath6kl_version {
	u32 target_ver;
	u32 wlan_ver;
	u32 abi_ver;
};

struct ath6kl_bmi {
	u32 cmd_credits;
	bool done_sent;
	u8 *cmd_buf;
	u32 max_data_size;
	u32 max_cmd_size;
};

struct target_stats {
	u64 tx_pkt;
	u64 tx_byte;
	u64 tx_ucast_pkt;
	u64 tx_ucast_byte;
	u64 tx_mcast_pkt;
	u64 tx_mcast_byte;
	u64 tx_bcast_pkt;
	u64 tx_bcast_byte;
	u64 tx_rts_success_cnt;
	u64 tx_pkt_per_ac[4];

	u64 tx_err;
	u64 tx_fail_cnt;
	u64 tx_retry_cnt;
	u64 tx_mult_retry_cnt;
	u64 tx_rts_fail_cnt;

	u64 rx_pkt;
	u64 rx_byte;
	u64 rx_ucast_pkt;
	u64 rx_ucast_byte;
	u64 rx_mcast_pkt;
	u64 rx_mcast_byte;
	u64 rx_bcast_pkt;
	u64 rx_bcast_byte;
	u64 rx_frgment_pkt;

	u64 rx_err;
	u64 rx_crc_err;
	u64 rx_key_cache_miss;
	u64 rx_decrypt_err;
	u64 rx_dupl_frame;

	u64 tkip_local_mic_fail;
	u64 tkip_cnter_measures_invoked;
	u64 tkip_replays;
	u64 tkip_fmt_err;
	u64 ccmp_fmt_err;
	u64 ccmp_replays;

	u64 pwr_save_fail_cnt;

	u64 cs_bmiss_cnt;
	u64 cs_low_rssi_cnt;
	u64 cs_connect_cnt;
	u64 cs_discon_cnt;

	s32 tx_ucast_rate;
    s8 tx_rate_index;
	s32 rx_ucast_rate;

	u32 lq_val;

	u32 wow_pkt_dropped;
	u16 wow_evt_discarded;

	s16 noise_floor_calib;
	s16 cs_rssi;
	s16 cs_ave_beacon_rssi;
	u8 cs_ave_beacon_snr;
	u8 cs_last_roam_msec;
	u8 cs_snr;

	u8 wow_host_pkt_wakeups;
	u8 wow_host_evt_wakeups;

	u32 arp_received;
	u32 arp_matched;
	u32 arp_replied;
};

struct ath6kl_mbox_info {
	u32 htc_addr;
	u32 htc_ext_addr;
	u32 htc_ext_sz;

	u32 block_size;

	u32 gmbox_addr;

	u32 gmbox_sz;
};

/*
 * 802.11i defines an extended IV for use with non-WEP ciphers.
 * When the EXTIV bit is set in the key id byte an additional
 * 4 bytes immediately follow the IV for TKIP.  For CCMP the
 * EXTIV bit is likewise set but the 8 bytes represent the
 * CCMP header rather than IV+extended-IV.
 */

#define ATH6KL_KEYBUF_SIZE 16
#define ATH6KL_MICBUF_SIZE (8+8)	/* space for both tx and rx */

#define ATH6KL_KEY_XMIT  0x01
#define ATH6KL_KEY_RECV  0x02
#define ATH6KL_KEY_DEFAULT   0x80	/* default xmit key */

/* Initial group key for AP mode */
struct ath6kl_req_key {
	bool valid;
	u8 key_index;
	int key_type;
	u8 key[WLAN_MAX_KEY_LEN];
	u8 key_len;
};

/*
 * Bluetooth WiFi co-ex information.
 * This structure keeps track of the Bluetooth related status.
 * This involves the Bluetooth ACL link role, Bluetooth remote lmp version.
 */
struct ath6kl_btcoex {
	u32 acl_role; /* Master/slave role of Bluetooth ACL link */
	u32 remote_lmp_ver; /* LMP version of the remote device. */
	u32 bt_vendor; /* Keeps track of the Bluetooth chip vendor */
};
enum ath6kl_hif_type {
	ATH6KL_HIF_TYPE_SDIO,
	ATH6KL_HIF_TYPE_USB,
};

/*
 * Driver's maximum limit, note that some firmwares support only one vif
 * and the runtime (current) limit must be checked from ar->vif_max.
 */
#define ATH6KL_VIF_MAX	3

/* vif flags info */
enum ath6kl_vif_state {
	CONNECTED,
	CONNECT_PEND,
	WMM_ENABLED,
	NETQ_STOPPED,
	DTIM_EXPIRED,
	NETDEV_REGISTERED,
	CLEAR_BSSFILTER_ON_BEACON,
	DTIM_PERIOD_AVAIL,
	WLAN_ENABLED,
	STATS_UPDATE_PEND,
	AMSDU_ENABLED,
	HOST_SLEEP_MODE_CMD_PROCESSED,
	ROC_ONGOING,
	ROC_CANCEL_PEND,
	DISCONNECT_PEND,
	PMKLIST_GET_PEND,
};

struct ath6kl_vif {
	struct list_head list;
	struct wireless_dev wdev;
	struct net_device *ndev;
	struct ath6kl *ar;
	/* Lock to protect vif specific net_stats and flags */
	spinlock_t if_lock;
	u8 fw_vif_idx;
	unsigned long flags;
	int ssid_len;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	u8 dot11_auth_mode;
	u8 auth_mode;
	u8 prwise_crypto;
	u8 prwise_crypto_len;
	u8 grp_crypto;
	u8 grp_crypto_len;
	u8 def_txkey_index;
	u8 next_mode;
	u8 nw_type;
	u8 bssid[ETH_ALEN];
	u8 req_bssid[ETH_ALEN];
	u16 ch_hint;
	u16 bss_ch;
	struct ath6kl_wep_key wep_key_list[WMI_MAX_KEY_INDEX + 1];
	struct ath6kl_key keys[WMI_MAX_KEY_INDEX + 1];
	struct aggr_info *aggr_cntxt;
	struct timer_list disconnect_timer;
	u32 connect_ctrl_flags;
	u8 usr_bss_filter;
	struct cfg80211_scan_request *scan_req;
	enum sme_state sme_state;
	u8 intra_bss;
	u8 ap_apsd;
	struct wmi_ap_mode_stat ap_stats;
	u8 ap_country_code[3];
	struct ath6kl_sta sta_list[AP_MAX_NUM_STA];
	u8 sta_list_index;
	struct ath6kl_req_key ap_mode_bkey;
	struct sk_buff_head mcastpsq;
	spinlock_t mcastpsq_lock;
	int reconnect_flag;
	u32 last_roc_id;
	u32 last_cancel_roc_id;
	u32 send_action_id;
	bool probe_req_report;
	u16 next_chan;
	u16 assoc_bss_beacon_int;
	u8 assoc_bss_dtim_period;
	struct net_device_stats net_stats;
	struct target_stats target_stats;
	struct htcoex *htcoex_ctx;
	struct wmi_scan_params_cmd sc_params;
	u8 pmkid_list_buf[MAX_PMKID_LIST_SIZE];
	u16 last_rsn_cap;
#ifdef ATH6KL_DIAGNOSTIC
	struct wifi_diag diag;
#endif    
        u8 connid;
	struct p2p_ps_info *p2p_ps_info_ctx;
};

#define WOW_LIST_ID		0
#define WOW_HOST_REQ_DELAY	500 /* ms */

/* Flag info */
enum ath6kl_dev_state {
	WMI_ENABLED,
	WMI_READY,
	WMI_CTRL_EP_FULL,
	TESTMODE,
	TESTMODE_EPPING,
	DESTROY_IN_PROGRESS,
	SKIP_SCAN,
	ROAM_TBL_PEND,
	FIRST_BOOT,
};

enum ath6kl_state {
	ATH6KL_STATE_OFF,
	ATH6KL_STATE_ON,
	ATH6KL_STATE_DEEPSLEEP,
	ATH6KL_STATE_CUTPOWER,
	ATH6KL_STATE_WOW,
};

struct ath6kl_conn_list
{
    struct list_head conn_queue;
    struct list_head re_queue;

    union
    {
        struct
        {
            u8 bk_uapsd    : 1;
            u8 be_uapsd    : 1;
            u8 vi_uapsd    : 1;
            u8 vo_uapsd    : 1;
            u8 ps          : 1;  // 1 means power saved
            u8 ocs         : 1;  // 1 means off channel
            u8 res         : 2;
        };
        u8 connect_status;
    };
    bool previous_can_send;
};

struct ath6kl {
	struct device *dev;
	struct wiphy *wiphy;

	enum ath6kl_state state;
	unsigned int testmode;

	struct ath6kl_bmi bmi;
	const struct ath6kl_hif_ops *hif_ops;
	const struct ath6kl_htc_ops *htc_ops;
	struct wmi *wmi;
	int tx_pending[ENDPOINT_MAX];
	int total_tx_data_pend;
	struct htc_target *htc_target;
	enum ath6kl_hif_type hif_type;
	void *hif_priv;
	struct list_head vif_list;
	/* Lock to avoid race in vif_list entries among add/del/traverse */
	spinlock_t list_lock;
	u8 num_vif;
	unsigned int vif_max;
	u8 max_norm_iface;
	u8 avail_idx_map;
	spinlock_t lock;
	struct semaphore sem;
	struct semaphore wmi_evt_sem;
	u16 listen_intvl_b;
	u16 listen_intvl_t;
	u8 lrssi_roam_threshold;
	struct ath6kl_version version;
	u32 target_type;
	u8 tx_pwr;
	struct ath6kl_node_mapping node_map[MAX_NODE_NUM];
	u8 ibss_ps_enable;
	bool ibss_if_active;
	u8 node_num;
	u8 next_ep_id;
	struct ath6kl_cookie *cookie_list;
	u32 cookie_count;
	enum htc_endpoint_id ac2ep_map[WMM_NUM_AC];
	bool ac_stream_active[WMM_NUM_AC];
	u8 ac_stream_pri_map[WMM_NUM_AC];
	u8 hiac_stream_active_pri;
	u8 ep2ac_map[ENDPOINT_MAX];
	enum htc_endpoint_id ctrl_ep;
	struct ath6kl_htc_credit_info credit_state_info;
	u32 user_key_ctrl;          /* FIXME : NEED? */
	struct list_head amsdu_rx_buffer_queue;
	u8 rx_meta_ver;
	enum wlan_low_pwr_state wlan_pwr_state;
	u8 mac_addr[ETH_ALEN];
#define AR_MCAST_FILTER_MAC_ADDR_SIZE  4
	struct {
		void *rx_report;
		size_t rx_report_len;
	} tm;

	struct ath6kl_hw {
		u32 id;
		const char *name;
		u32 dataset_patch_addr;
		u32 app_load_addr;
		u32 app_start_override_addr;
		u32 board_ext_data_addr;
		u32 reserved_ram_size;
		u32 board_addr;
		u32 testscript_addr;

		struct ath6kl_hw_fw {
			const char *dir;
			const char *otp;
			const char *fw;
			const char *tcmd;
			const char *patch;
			const char *api2;
			const char *utf;
			const char *testscript;
		} fw;

		const char *fw_board;
		const char *fw_default_board;
		const char *fw_epping;
		const char *fw_softmac;
	} hw;

	u16 conf_flags;
	wait_queue_head_t event_wq;
	struct ath6kl_mbox_info mbox_info;

	struct ath6kl_cookie cookie_mem[MAX_COOKIE_NUM];
	unsigned long flag;

	u8 *fw_board;
	size_t fw_board_len;

	u8 *fw_otp;
	size_t fw_otp_len;

	u8 *fw;
	size_t fw_len;

	u8 *fw_patch;
	size_t fw_patch_len;

	u8 *fw_testscript;
	size_t fw_testscript_len;

	u8 *fw_softmac;
	size_t fw_softmac_len;

	unsigned long fw_capabilities[ATH6KL_CAPABILITY_LEN];

	struct workqueue_struct *ath6kl_wq;

	struct dentry *debugfs_phy;

	bool p2p;
	bool p2p_concurrent;

	struct ath6kl_btcoex btcoex_info;
	u32 mod_debug_quirks;

#ifdef CONFIG_ATH6KL_DEBUG
	struct {
		struct circ_buf fwlog_buf;
		spinlock_t fwlog_lock;
		void *fwlog_tmp;
		u32 fwlog_mask;
		unsigned int dbgfs_diag_reg;
		u32 diag_reg_addr_wr;
		u32 diag_reg_val_wr;
		u64 set_tx_series;

		struct {
			unsigned int invalid_rate;
		} war_stats;

		u8 *roam_tbl;
		unsigned int roam_tbl_len;

		u8 keepalive;
		u8 disc_timeout;
		u8 mimo_ps_enable;
		u8 force_passive;
        u16 bgscan_int;
        enum wmi_roam_mode roam_mode;

		struct green_tx_param {
			u32 green_tx_enable;
			u8 next_probe_count;
			u8 max_backoff;
			u8 min_gtx_rssi;
			u8 force_backoff;
		} green_tx_params;

		struct smps_param {
			u8 flags;
			u8 rssi_thresh;
			u8 data_thresh;
			u8 mode;
			u8 automatic;
		} smps_params;

		struct lpl_force_enable_param {
			u8 lpl_policy;
			u8 no_blocker_detect;
			u8 no_rfb_detect;
		} lpl_force_enable_params;

        struct power_param {
            u16 idle_period;
            u16 ps_poll_num;
            u16 dtim;
            u16 tx_wakeup;
            u16 num_tx;
        } power_params;

		struct ht_cap_param {
			u8 isConfig;
			u8 band;
			u8 chan_width_40M_supported;
			u8 short_GI;
		} ht_cap_param[IEEE80211_NUM_BANDS];
	} debug;
#endif /* CONFIG_ATH6KL_DEBUG */

	int wow_irq;
#ifdef CONFIG_ANDROID
#ifdef CONFIG_HAS_WAKELOCK
	struct wake_lock wake_lock;
#endif /* CONFIG_HAS_WAKELOCK */
#endif
    struct ath6kl_conn_list conn_list[NUM_CONN];
#ifdef CONFIG_HAS_EARLYSUSPEND
    struct early_suspend early_suspend;
#endif /* CONFIG_HAS_EARLYSUSPEND */

};

static inline void *ath6kl_priv(struct net_device *dev)
{
	return ((struct ath6kl_vif *) netdev_priv(dev))->ar;
}

static inline u32 ath6kl_get_hi_item_addr(struct ath6kl *ar,
					  u32 item_offset)
{
	u32 addr = 0;

	if (ar->target_type == TARGET_TYPE_AR6003)
		addr = ATH6KL_AR6003_HI_START_ADDR + item_offset;
	else if (ar->target_type == TARGET_TYPE_AR6004)
		addr = ATH6KL_AR6004_HI_START_ADDR + item_offset;
	else if (ar->target_type == TARGET_TYPE_AR6006)
		addr = ATH6KL_AR6006_HI_START_ADDR + item_offset;

	return addr;
}

static inline u32 ath6kl_data_get_age(struct sk_buff *buf)
{
	struct ath6kl_data_buf_cb *data_buf_cb = (struct ath6kl_data_buf_cb *)(buf->cb);

	return data_buf_cb->ps_age;
}

static inline void ath6kl_data_set_age(struct sk_buff *buf, u32 age)
{
	struct ath6kl_data_buf_cb *data_buf_cb = (struct ath6kl_data_buf_cb *)(buf->cb);
	
	data_buf_cb->ps_age = age;
}

static inline u32 ath6kl_mgmt_get_age(struct ath6kl_mgmt_buf *buf)
{
	return buf->age;
}

static inline void ath6kl_mgmt_set_age(struct ath6kl_mgmt_buf *buf, u32 age)
{
	buf->age = age;
}

int ath6kl_configure_target(struct ath6kl *ar);
void ath6kl_detect_error(unsigned long ptr);
void disconnect_timer_handler(unsigned long ptr);
void init_netdev(struct net_device *dev);
void ath6kl_cookie_init(struct ath6kl *ar);
void ath6kl_cookie_cleanup(struct ath6kl *ar);
void ath6kl_rx(struct htc_target *target, struct htc_packet *packet);
void ath6kl_tx_complete(struct htc_target *context,
						struct list_head *packet_queue);
enum htc_send_full_action ath6kl_tx_queue_full(struct htc_target *target,
					       struct htc_packet *packet);
void ath6kl_stop_txrx(struct ath6kl *ar);
void ath6kl_cleanup_amsdu_rxbufs(struct ath6kl *ar);
int ath6kl_diag_write32(struct ath6kl *ar, u32 address, __le32 value);
int ath6kl_diag_write(struct ath6kl *ar, u32 address, void *data, u32 length);
int ath6kl_diag_read32(struct ath6kl *ar, u32 address, u32 *value);
int ath6kl_diag_read(struct ath6kl *ar, u32 address, void *data, u32 length);
int ath6kl_read_fwlogs(struct ath6kl *ar);
void ath6kl_init_profile_info(struct ath6kl_vif *vif);
void ath6kl_tx_data_cleanup(struct ath6kl *ar);

struct ath6kl_cookie *ath6kl_alloc_cookie(struct ath6kl *ar);
void ath6kl_free_cookie(struct ath6kl *ar, struct ath6kl_cookie *cookie);
bool ath6kl_mgmt_powersave_ap(struct ath6kl_vif *vif, 
                                     u32 id,
                                     u32 freq,
                                     u32 wait,
                                     const u8* buf,
                                     size_t len,
                                     bool no_cck,
                                     bool dont_wait_for_ack,
                                     u32 *flags);
int ath6kl_data_tx(struct sk_buff *skb, struct net_device *dev);
int ath6kl_conn_list_init(struct ath6kl *ar);
void ath6kl_tx_scheduler(struct ath6kl_vif *vif);
void ath6kl_flowctrl_change(struct ath6kl_vif *vif);

struct aggr_info *aggr_init(struct ath6kl_vif *vif);
struct aggr_conn_info *aggr_init_conn(struct ath6kl_vif *vif);

void ath6kl_rx_refill(struct htc_target *target,
		      enum htc_endpoint_id endpoint);
void ath6kl_refill_amsdu_rxbufs(struct ath6kl *ar, int count);
struct htc_packet *ath6kl_alloc_amsdu_rxbuf(struct htc_target *target,
					    enum htc_endpoint_id endpoint,
					    int len);

void aggr_module_destroy(struct aggr_info *aggr);
void aggr_module_destroy_conn(struct aggr_conn_info *aggr_conn);
void aggr_reset_state(struct aggr_conn_info *aggr_conn);

struct ath6kl_sta *ath6kl_find_sta(struct ath6kl_vif *vif, u8 * node_addr);
struct ath6kl_sta *ath6kl_find_sta_by_aid(struct ath6kl_vif *vif, u8 aid);

void ath6kl_ready_event(void *devt, u8 * datap, u32 sw_ver, u32 abi_ver);
int ath6kl_control_tx(void *devt, struct sk_buff *skb,
		      enum htc_endpoint_id eid);
void ath6kl_connect_event(struct ath6kl_vif *vif, u16 channel,
			  u8 *bssid, u16 listen_int,
			  u16 beacon_int, enum network_type net_type,
			  u8 beacon_ie_len, u8 assoc_req_len,
			  u8 assoc_resp_len, u8 *assoc_info);
void ath6kl_connect_ap_mode_bss(struct ath6kl_vif *vif, u16 channel);
void ath6kl_connect_ap_mode_sta(struct ath6kl_vif *vif, u16 aid, u8 *mac_addr,
				u8 keymgmt, u8 ucipher, u8 auth,
				u8 assoc_req_len, u8 *assoc_info, u8 apsd_info);
void ath6kl_disconnect_event(struct ath6kl_vif *vif, u8 reason,
			     u8 *bssid, u8 assoc_resp_len,
			     u8 *assoc_info, u16 prot_reason_status);
void ath6kl_tkip_micerr_event(struct ath6kl_vif *vif, u8 keyid, bool ismcast);
void ath6kl_txpwr_rx_evt(void *devt, u8 tx_pwr);
void ath6kl_scan_complete_evt(struct ath6kl_vif *vif, int status);
void ath6kl_tgt_stats_event(struct ath6kl_vif *vif, u8 *ptr, u32 len);
void ath6kl_indicate_tx_activity(void *devt, u8 traffic_class, bool active);
enum htc_endpoint_id ath6kl_ac2_endpoint_id(void *devt, u8 ac);

void ath6kl_pspoll_event(struct ath6kl_vif *vif, u8 aid);

void ath6kl_dtimexpiry_event(struct ath6kl_vif *vif);
int ath6kl_disconnect(struct ath6kl_vif *vif);
void aggr_recv_delba_req_evt(struct ath6kl_vif *vif, u8 tid);
void aggr_recv_addba_req_evt(struct ath6kl_vif *vif, u8 tid, u16 seq_no,
			     u8 win_sz);
void aggr_recv_addba_resp_evt(struct ath6kl_vif *vif, u8 tid, u16 amsdu_sz, u8 status);
void ath6kl_wakeup_event(void *dev);

void ath6kl_reset_device(struct ath6kl *ar, u32 target_type,
			 bool wait_fot_compltn, bool cold_reset);
void ath6kl_init_control_info(struct ath6kl_vif *vif);
void ath6kl_deinit_if_data(struct ath6kl_vif *vif);
void ath6kl_core_free(struct ath6kl *ar);
struct ath6kl_vif *ath6kl_vif_first(struct ath6kl *ar);
void ath6kl_cleanup_vif(struct ath6kl_vif *vif, bool wmi_ready);
int ath6kl_init_hw_start(struct ath6kl *ar);
int ath6kl_init_hw_stop(struct ath6kl *ar);
void ath6kl_check_wow_status(struct ath6kl *ar);
void ath6kl_htc_pipe_attach(struct ath6kl *ar);
void ath6kl_htc_mbox_attach(struct ath6kl *ar);

void ath6kl_mgmt_queue_init(struct ath6kl_mgmt_buf_head *psq);
void ath6kl_mgmt_queue_purge(struct ath6kl_mgmt_buf_head *psq);
int ath6kl_mgmt_queue_empty(struct ath6kl_mgmt_buf_head *psq);
int ath6kl_mgmt_queue_tail(struct ath6kl_mgmt_buf_head *psq, 
								const u8 *buf, 
								u16 len, 
								u32 id, 
								u32 freq, 
								u32 wait, 
								bool no_cck, 
								bool dont_wait_for_ack);
struct ath6kl_mgmt_buf *ath6kl_mgmt_dequeue_head(struct ath6kl_mgmt_buf_head *psq);
void ath6kl_psq_age_handler(unsigned long ptr);
void ath6kl_psq_age_start(struct ath6kl_sta *conn);
void ath6kl_psq_age_stop(struct ath6kl_sta *conn);
#ifdef CONFIG_ANDROID
void ath6kl_sdio_init_msm(void);
void ath6kl_sdio_exit_msm(void);
#endif

#endif /* CORE_H */
