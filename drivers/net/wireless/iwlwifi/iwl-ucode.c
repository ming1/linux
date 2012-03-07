/******************************************************************************
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2008 - 2012 Intel Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110,
 * USA
 *
 * The full GNU General Public License is included in this distribution
 * in the file called LICENSE.GPL.
 *
 * Contact Information:
 *  Intel Linux Wireless <ilw@linux.intel.com>
 * Intel Corporation, 5200 N.E. Elam Young Parkway, Hillsboro, OR 97124-6497
 *
 *****************************************************************************/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>

#include "iwl-ucode.h"
#include "iwl-wifi.h"
#include "iwl-dev.h"
#include "iwl-core.h"
#include "iwl-io.h"
#include "iwl-agn-hw.h"
#include "iwl-agn.h"
#include "iwl-agn-calib.h"
#include "iwl-trans.h"
#include "iwl-fh.h"
#include "iwl-op-mode.h"

static struct iwl_wimax_coex_event_entry cu_priorities[COEX_NUM_OF_EVENTS] = {
	{COEX_CU_UNASSOC_IDLE_RP, COEX_CU_UNASSOC_IDLE_WP,
	 0, COEX_UNASSOC_IDLE_FLAGS},
	{COEX_CU_UNASSOC_MANUAL_SCAN_RP, COEX_CU_UNASSOC_MANUAL_SCAN_WP,
	 0, COEX_UNASSOC_MANUAL_SCAN_FLAGS},
	{COEX_CU_UNASSOC_AUTO_SCAN_RP, COEX_CU_UNASSOC_AUTO_SCAN_WP,
	 0, COEX_UNASSOC_AUTO_SCAN_FLAGS},
	{COEX_CU_CALIBRATION_RP, COEX_CU_CALIBRATION_WP,
	 0, COEX_CALIBRATION_FLAGS},
	{COEX_CU_PERIODIC_CALIBRATION_RP, COEX_CU_PERIODIC_CALIBRATION_WP,
	 0, COEX_PERIODIC_CALIBRATION_FLAGS},
	{COEX_CU_CONNECTION_ESTAB_RP, COEX_CU_CONNECTION_ESTAB_WP,
	 0, COEX_CONNECTION_ESTAB_FLAGS},
	{COEX_CU_ASSOCIATED_IDLE_RP, COEX_CU_ASSOCIATED_IDLE_WP,
	 0, COEX_ASSOCIATED_IDLE_FLAGS},
	{COEX_CU_ASSOC_MANUAL_SCAN_RP, COEX_CU_ASSOC_MANUAL_SCAN_WP,
	 0, COEX_ASSOC_MANUAL_SCAN_FLAGS},
	{COEX_CU_ASSOC_AUTO_SCAN_RP, COEX_CU_ASSOC_AUTO_SCAN_WP,
	 0, COEX_ASSOC_AUTO_SCAN_FLAGS},
	{COEX_CU_ASSOC_ACTIVE_LEVEL_RP, COEX_CU_ASSOC_ACTIVE_LEVEL_WP,
	 0, COEX_ASSOC_ACTIVE_LEVEL_FLAGS},
	{COEX_CU_RF_ON_RP, COEX_CU_RF_ON_WP, 0, COEX_CU_RF_ON_FLAGS},
	{COEX_CU_RF_OFF_RP, COEX_CU_RF_OFF_WP, 0, COEX_RF_OFF_FLAGS},
	{COEX_CU_STAND_ALONE_DEBUG_RP, COEX_CU_STAND_ALONE_DEBUG_WP,
	 0, COEX_STAND_ALONE_DEBUG_FLAGS},
	{COEX_CU_IPAN_ASSOC_LEVEL_RP, COEX_CU_IPAN_ASSOC_LEVEL_WP,
	 0, COEX_IPAN_ASSOC_LEVEL_FLAGS},
	{COEX_CU_RSRVD1_RP, COEX_CU_RSRVD1_WP, 0, COEX_RSRVD1_FLAGS},
	{COEX_CU_RSRVD2_RP, COEX_CU_RSRVD2_WP, 0, COEX_RSRVD2_FLAGS}
};

/******************************************************************************
 *
 * uCode download functions
 *
 ******************************************************************************/

static inline struct fw_img *iwl_get_ucode_image(struct iwl_nic *nic,
					enum iwl_ucode_type ucode_type)
{
	switch (ucode_type) {
	case IWL_UCODE_INIT:
		return &nic->fw.ucode_init;
	case IWL_UCODE_WOWLAN:
		return &nic->fw.ucode_wowlan;
	case IWL_UCODE_REGULAR:
		return &nic->fw.ucode_rt;
	case IWL_UCODE_NONE:
		break;
	}
	return NULL;
}

/*
 *  Calibration
 */
static int iwl_set_Xtal_calib(struct iwl_trans *trans)
{
	struct iwl_calib_xtal_freq_cmd cmd;
	__le16 *xtal_calib =
		(__le16 *)iwl_eeprom_query_addr(trans->shrd, EEPROM_XTAL);

	iwl_set_calib_hdr(&cmd.hdr, IWL_PHY_CALIBRATE_CRYSTAL_FRQ_CMD);
	cmd.cap_pin1 = le16_to_cpu(xtal_calib[0]);
	cmd.cap_pin2 = le16_to_cpu(xtal_calib[1]);
	return iwl_calib_set(trans, (void *)&cmd, sizeof(cmd));
}

static int iwl_set_temperature_offset_calib(struct iwl_trans *trans)
{
	struct iwl_calib_temperature_offset_cmd cmd;
	__le16 *offset_calib =
		(__le16 *)iwl_eeprom_query_addr(trans->shrd,
						EEPROM_RAW_TEMPERATURE);

	memset(&cmd, 0, sizeof(cmd));
	iwl_set_calib_hdr(&cmd.hdr, IWL_PHY_CALIBRATE_TEMP_OFFSET_CMD);
	memcpy(&cmd.radio_sensor_offset, offset_calib, sizeof(*offset_calib));
	if (!(cmd.radio_sensor_offset))
		cmd.radio_sensor_offset = DEFAULT_RADIO_SENSOR_OFFSET;

	IWL_DEBUG_CALIB(trans, "Radio sensor offset: %d\n",
			le16_to_cpu(cmd.radio_sensor_offset));
	return iwl_calib_set(trans, (void *)&cmd, sizeof(cmd));
}

static int iwl_set_temperature_offset_calib_v2(struct iwl_trans *trans)
{
	struct iwl_calib_temperature_offset_v2_cmd cmd;
	__le16 *offset_calib_high = (__le16 *)iwl_eeprom_query_addr(trans->shrd,
				     EEPROM_KELVIN_TEMPERATURE);
	__le16 *offset_calib_low =
		(__le16 *)iwl_eeprom_query_addr(trans->shrd,
						EEPROM_RAW_TEMPERATURE);
	struct iwl_eeprom_calib_hdr *hdr;

	memset(&cmd, 0, sizeof(cmd));
	iwl_set_calib_hdr(&cmd.hdr, IWL_PHY_CALIBRATE_TEMP_OFFSET_CMD);
	hdr = (struct iwl_eeprom_calib_hdr *)iwl_eeprom_query_addr(trans->shrd,
							EEPROM_CALIB_ALL);
	memcpy(&cmd.radio_sensor_offset_high, offset_calib_high,
		sizeof(*offset_calib_high));
	memcpy(&cmd.radio_sensor_offset_low, offset_calib_low,
		sizeof(*offset_calib_low));
	if (!(cmd.radio_sensor_offset_low)) {
		IWL_DEBUG_CALIB(trans, "no info in EEPROM, use default\n");
		cmd.radio_sensor_offset_low = DEFAULT_RADIO_SENSOR_OFFSET;
		cmd.radio_sensor_offset_high = DEFAULT_RADIO_SENSOR_OFFSET;
	}
	memcpy(&cmd.burntVoltageRef, &hdr->voltage,
		sizeof(hdr->voltage));

	IWL_DEBUG_CALIB(trans, "Radio sensor offset high: %d\n",
			le16_to_cpu(cmd.radio_sensor_offset_high));
	IWL_DEBUG_CALIB(trans, "Radio sensor offset low: %d\n",
			le16_to_cpu(cmd.radio_sensor_offset_low));
	IWL_DEBUG_CALIB(trans, "Voltage Ref: %d\n",
			le16_to_cpu(cmd.burntVoltageRef));

	return iwl_calib_set(trans, (void *)&cmd, sizeof(cmd));
}

static int iwl_send_calib_cfg(struct iwl_trans *trans)
{
	struct iwl_calib_cfg_cmd calib_cfg_cmd;
	struct iwl_host_cmd cmd = {
		.id = CALIBRATION_CFG_CMD,
		.len = { sizeof(struct iwl_calib_cfg_cmd), },
		.data = { &calib_cfg_cmd, },
	};

	memset(&calib_cfg_cmd, 0, sizeof(calib_cfg_cmd));
	calib_cfg_cmd.ucd_calib_cfg.once.is_enable = IWL_CALIB_INIT_CFG_ALL;
	calib_cfg_cmd.ucd_calib_cfg.once.start = IWL_CALIB_INIT_CFG_ALL;
	calib_cfg_cmd.ucd_calib_cfg.once.send_res = IWL_CALIB_INIT_CFG_ALL;
	calib_cfg_cmd.ucd_calib_cfg.flags =
		IWL_CALIB_CFG_FLAG_SEND_COMPLETE_NTFY_MSK;

	return iwl_trans_send_cmd(trans, &cmd);
}

int iwlagn_rx_calib_result(struct iwl_priv *priv,
			    struct iwl_rx_cmd_buffer *rxb,
			    struct iwl_device_cmd *cmd)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_calib_hdr *hdr = (struct iwl_calib_hdr *)pkt->u.raw;
	int len = le32_to_cpu(pkt->len_n_flags) & FH_RSCSR_FRAME_SIZE_MSK;

	/* reduce the size of the length field itself */
	len -= 4;

	if (iwl_calib_set(trans(priv), hdr, len))
		IWL_ERR(priv, "Failed to record calibration data %d\n",
			hdr->op_code);

	return 0;
}

int iwl_init_alive_start(struct iwl_trans *trans)
{
	int ret;

	if (cfg(trans)->bt_params &&
	    cfg(trans)->bt_params->advanced_bt_coexist) {
		/*
		 * Tell uCode we are ready to perform calibration
		 * need to perform this before any calibration
		 * no need to close the envlope since we are going
		 * to load the runtime uCode later.
		 */
		ret = iwl_send_bt_env(trans, IWL_BT_COEX_ENV_OPEN,
			BT_COEX_PRIO_TBL_EVT_INIT_CALIB2);
		if (ret)
			return ret;

	}

	ret = iwl_send_calib_cfg(trans);
	if (ret)
		return ret;

	/**
	 * temperature offset calibration is only needed for runtime ucode,
	 * so prepare the value now.
	 */
	if (cfg(trans)->need_temp_offset_calib) {
		if (cfg(trans)->temp_offset_v2)
			return iwl_set_temperature_offset_calib_v2(trans);
		else
			return iwl_set_temperature_offset_calib(trans);
	}

	return 0;
}

static int iwl_send_wimax_coex(struct iwl_trans *trans)
{
	struct iwl_wimax_coex_cmd coex_cmd;

	if (cfg(trans)->base_params->support_wimax_coexist) {
		/* UnMask wake up src at associated sleep */
		coex_cmd.flags = COEX_FLAGS_ASSOC_WA_UNMASK_MSK;

		/* UnMask wake up src at unassociated sleep */
		coex_cmd.flags |= COEX_FLAGS_UNASSOC_WA_UNMASK_MSK;
		memcpy(coex_cmd.sta_prio, cu_priorities,
			sizeof(struct iwl_wimax_coex_event_entry) *
			 COEX_NUM_OF_EVENTS);

		/* enabling the coexistence feature */
		coex_cmd.flags |= COEX_FLAGS_COEX_ENABLE_MSK;

		/* enabling the priorities tables */
		coex_cmd.flags |= COEX_FLAGS_STA_TABLE_VALID_MSK;
	} else {
		/* coexistence is disabled */
		memset(&coex_cmd, 0, sizeof(coex_cmd));
	}
	return iwl_trans_send_cmd_pdu(trans,
				COEX_PRIORITY_TABLE_CMD, CMD_SYNC,
				sizeof(coex_cmd), &coex_cmd);
}

static const u8 iwl_bt_prio_tbl[BT_COEX_PRIO_TBL_EVT_MAX] = {
	((BT_COEX_PRIO_TBL_PRIO_BYPASS << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(0 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_BYPASS << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(1 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_LOW << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(0 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_LOW << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(1 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_HIGH << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(0 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_HIGH << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(1 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_BYPASS << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(0 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_COEX_OFF << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(0 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	((BT_COEX_PRIO_TBL_PRIO_COEX_ON << IWL_BT_COEX_PRIO_TBL_PRIO_POS) |
		(0 << IWL_BT_COEX_PRIO_TBL_SHARED_ANTENNA_POS)),
	0, 0, 0, 0, 0, 0, 0
};

void iwl_send_prio_tbl(struct iwl_trans *trans)
{
	struct iwl_bt_coex_prio_table_cmd prio_tbl_cmd;

	memcpy(prio_tbl_cmd.prio_tbl, iwl_bt_prio_tbl,
		sizeof(iwl_bt_prio_tbl));
	if (iwl_trans_send_cmd_pdu(trans,
				REPLY_BT_COEX_PRIO_TABLE, CMD_SYNC,
				sizeof(prio_tbl_cmd), &prio_tbl_cmd))
		IWL_ERR(trans, "failed to send BT prio tbl command\n");
}

int iwl_send_bt_env(struct iwl_trans *trans, u8 action, u8 type)
{
	struct iwl_bt_coex_prot_env_cmd env_cmd;
	int ret;

	env_cmd.action = action;
	env_cmd.type = type;
	ret = iwl_trans_send_cmd_pdu(trans,
			       REPLY_BT_COEX_PROT_ENV, CMD_SYNC,
			       sizeof(env_cmd), &env_cmd);
	if (ret)
		IWL_ERR(trans, "failed to send BT env command\n");
	return ret;
}


static int iwl_alive_notify(struct iwl_trans *trans)
{
	struct iwl_priv *priv = priv(trans);
	struct iwl_rxon_context *ctx;
	int ret;

	if (!priv->tx_cmd_pool)
		priv->tx_cmd_pool =
			kmem_cache_create("iwl_dev_cmd",
					  sizeof(struct iwl_device_cmd),
					  sizeof(void *), 0, NULL);

	if (!priv->tx_cmd_pool)
		return -ENOMEM;

	iwl_trans_fw_alive(trans);
	for_each_context(priv, ctx)
		ctx->last_tx_rejected = false;

	ret = iwl_send_wimax_coex(trans);
	if (ret)
		return ret;

	if (!cfg(priv)->no_xtal_calib) {
		ret = iwl_set_Xtal_calib(trans);
		if (ret)
			return ret;
	}

	return iwl_send_calib_results(trans);
}


/**
 * iwl_verify_inst_sparse - verify runtime uCode image in card vs. host,
 *   using sample data 100 bytes apart.  If these sample points are good,
 *   it's a pretty good bet that everything between them is good, too.
 */
static int iwl_verify_inst_sparse(struct iwl_nic *nic,
				      struct fw_desc *fw_desc)
{
	struct iwl_trans *trans = trans(nic);
	__le32 *image = (__le32 *)fw_desc->v_addr;
	u32 len = fw_desc->len;
	u32 val;
	u32 i;

	IWL_DEBUG_FW(nic, "ucode inst image size is %u\n", len);

	for (i = 0; i < len; i += 100, image += 100/sizeof(u32)) {
		/* read data comes through single port, auto-incr addr */
		/* NOTE: Use the debugless read so we don't flood kernel log
		 * if IWL_DL_IO is set */
		iwl_write_direct32(trans, HBUS_TARG_MEM_RADDR,
			i + IWLAGN_RTC_INST_LOWER_BOUND);
		val = iwl_read32(trans, HBUS_TARG_MEM_RDAT);
		if (val != le32_to_cpu(*image))
			return -EIO;
	}

	return 0;
}

static void iwl_print_mismatch_inst(struct iwl_nic *nic,
				    struct fw_desc *fw_desc)
{
	struct iwl_trans *trans = trans(nic);
	__le32 *image = (__le32 *)fw_desc->v_addr;
	u32 len = fw_desc->len;
	u32 val;
	u32 offs;
	int errors = 0;

	IWL_DEBUG_FW(nic, "ucode inst image size is %u\n", len);

	iwl_write_direct32(trans, HBUS_TARG_MEM_RADDR,
			   IWLAGN_RTC_INST_LOWER_BOUND);

	for (offs = 0;
	     offs < len && errors < 20;
	     offs += sizeof(u32), image++) {
		/* read data comes through single port, auto-incr addr */
		val = iwl_read32(trans, HBUS_TARG_MEM_RDAT);
		if (val != le32_to_cpu(*image)) {
			IWL_ERR(nic, "uCode INST section at "
				"offset 0x%x, is 0x%x, s/b 0x%x\n",
				offs, val, le32_to_cpu(*image));
			errors++;
		}
	}
}

/**
 * iwl_verify_ucode - determine which instruction image is in SRAM,
 *    and verify its contents
 */
static int iwl_verify_ucode(struct iwl_nic *nic,
			    enum iwl_ucode_type ucode_type)
{
	struct fw_img *img = iwl_get_ucode_image(nic, ucode_type);

	if (!img) {
		IWL_ERR(nic, "Invalid ucode requested (%d)\n", ucode_type);
		return -EINVAL;
	}

	if (!iwl_verify_inst_sparse(nic, &img->code)) {
		IWL_DEBUG_FW(nic, "uCode is good in inst SRAM\n");
		return 0;
	}

	IWL_ERR(nic, "UCODE IMAGE IN INSTRUCTION SRAM NOT VALID!!\n");

	iwl_print_mismatch_inst(nic, &img->code);
	return -EIO;
}

struct iwl_alive_data {
	bool valid;
	u8 subtype;
};

static void iwl_alive_fn(struct iwl_trans *trans,
			    struct iwl_rx_packet *pkt,
			    void *data)
{
	struct iwl_alive_data *alive_data = data;
	struct iwl_alive_resp *palive;

	palive = &pkt->u.alive_frame;

	IWL_DEBUG_FW(trans, "Alive ucode status 0x%08X revision "
		       "0x%01X 0x%01X\n",
		       palive->is_valid, palive->ver_type,
		       palive->ver_subtype);

	trans->shrd->device_pointers.error_event_table =
		le32_to_cpu(palive->error_event_table_ptr);
	trans->shrd->device_pointers.log_event_table =
		le32_to_cpu(palive->log_event_table_ptr);

	alive_data->subtype = palive->ver_subtype;
	alive_data->valid = palive->is_valid == UCODE_VALID_OK;
}

/* notification wait support */
void iwl_init_notification_wait(struct iwl_shared *shrd,
				   struct iwl_notification_wait *wait_entry,
				   u8 cmd,
				   void (*fn)(struct iwl_trans *trans,
					      struct iwl_rx_packet *pkt,
					      void *data),
				   void *fn_data)
{
	wait_entry->fn = fn;
	wait_entry->fn_data = fn_data;
	wait_entry->cmd = cmd;
	wait_entry->triggered = false;
	wait_entry->aborted = false;

	spin_lock_bh(&shrd->notif_wait_lock);
	list_add(&wait_entry->list, &shrd->notif_waits);
	spin_unlock_bh(&shrd->notif_wait_lock);
}

int iwl_wait_notification(struct iwl_shared *shrd,
			     struct iwl_notification_wait *wait_entry,
			     unsigned long timeout)
{
	int ret;

	ret = wait_event_timeout(shrd->notif_waitq,
				 wait_entry->triggered || wait_entry->aborted,
				 timeout);

	spin_lock_bh(&shrd->notif_wait_lock);
	list_del(&wait_entry->list);
	spin_unlock_bh(&shrd->notif_wait_lock);

	if (wait_entry->aborted)
		return -EIO;

	/* return value is always >= 0 */
	if (ret <= 0)
		return -ETIMEDOUT;
	return 0;
}

void iwl_remove_notification(struct iwl_shared *shrd,
				struct iwl_notification_wait *wait_entry)
{
	spin_lock_bh(&shrd->notif_wait_lock);
	list_del(&wait_entry->list);
	spin_unlock_bh(&shrd->notif_wait_lock);
}

void iwl_abort_notification_waits(struct iwl_shared *shrd)
{
	unsigned long flags;
	struct iwl_notification_wait *wait_entry;

	spin_lock_irqsave(&shrd->notif_wait_lock, flags);
	list_for_each_entry(wait_entry, &shrd->notif_waits, list)
		wait_entry->aborted = true;
	spin_unlock_irqrestore(&shrd->notif_wait_lock, flags);

	wake_up_all(&shrd->notif_waitq);
}

#define UCODE_ALIVE_TIMEOUT	HZ
#define UCODE_CALIB_TIMEOUT	(2*HZ)

int iwl_load_ucode_wait_alive(struct iwl_trans *trans,
				 enum iwl_ucode_type ucode_type)
{
	struct iwl_notification_wait alive_wait;
	struct iwl_alive_data alive_data;
	struct fw_img *fw;
	int ret;
	enum iwl_ucode_type old_type;

	iwl_init_notification_wait(trans->shrd, &alive_wait, REPLY_ALIVE,
				      iwl_alive_fn, &alive_data);

	old_type = trans->shrd->ucode_type;
	trans->shrd->ucode_type = ucode_type;
	fw = iwl_get_ucode_image(nic(trans), ucode_type);

	if (!fw)
		return -EINVAL;

	ret = iwl_trans_start_fw(trans, fw);
	if (ret) {
		trans->shrd->ucode_type = old_type;
		iwl_remove_notification(trans->shrd, &alive_wait);
		return ret;
	}

	/*
	 * Some things may run in the background now, but we
	 * just wait for the ALIVE notification here.
	 */
	ret = iwl_wait_notification(trans->shrd, &alive_wait,
					UCODE_ALIVE_TIMEOUT);
	if (ret) {
		trans->shrd->ucode_type = old_type;
		return ret;
	}

	if (!alive_data.valid) {
		IWL_ERR(trans, "Loaded ucode is not valid!\n");
		trans->shrd->ucode_type = old_type;
		return -EIO;
	}

	/*
	 * This step takes a long time (60-80ms!!) and
	 * WoWLAN image should be loaded quickly, so
	 * skip it for WoWLAN.
	 */
	if (ucode_type != IWL_UCODE_WOWLAN) {
		ret = iwl_verify_ucode(nic(trans), ucode_type);
		if (ret) {
			trans->shrd->ucode_type = old_type;
			return ret;
		}

		/* delay a bit to give rfkill time to run */
		msleep(5);
	}

	ret = iwl_alive_notify(trans);
	if (ret) {
		IWL_WARN(trans,
			"Could not complete ALIVE transition: %d\n", ret);
		trans->shrd->ucode_type = old_type;
		return ret;
	}

	return 0;
}

int iwl_run_init_ucode(struct iwl_trans *trans)
{
	struct iwl_notification_wait calib_wait;
	int ret;

	lockdep_assert_held(&trans->shrd->mutex);

	/* No init ucode required? Curious, but maybe ok */
	if (!nic(trans)->fw.ucode_init.code.len)
		return 0;

	if (trans->shrd->ucode_type != IWL_UCODE_NONE)
		return 0;

	iwl_init_notification_wait(trans->shrd, &calib_wait,
				      CALIBRATION_COMPLETE_NOTIFICATION,
				      NULL, NULL);

	/* Will also start the device */
	ret = iwl_load_ucode_wait_alive(trans, IWL_UCODE_INIT);
	if (ret)
		goto error;

	ret = iwl_init_alive_start(trans);
	if (ret)
		goto error;

	/*
	 * Some things may run in the background now, but we
	 * just wait for the calibration complete notification.
	 */
	ret = iwl_wait_notification(trans->shrd, &calib_wait,
					UCODE_CALIB_TIMEOUT);

	goto out;

 error:
	iwl_remove_notification(trans->shrd, &calib_wait);
 out:
	/* Whatever happened, stop the device */
	iwl_trans_stop_device(trans);
	return ret;
}
