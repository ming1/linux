/******************************************************************************
 *
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2012 - 2013 Intel Corporation. All rights reserved.
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
 * BSD LICENSE
 *
 * Copyright(c) 2012 - 2013 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *  * Neither the name Intel Corporation nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

#include <linux/jiffies.h>
#include <net/mac80211.h>

#include "iwl-notif-wait.h"
#include "iwl-trans.h"
#include "fw-api.h"
#include "time-event.h"
#include "mvm.h"
#include "iwl-io.h"
#include "iwl-prph.h"

/* A TimeUnit is 1024 microsecond */
#define TU_TO_JIFFIES(_tu)	(usecs_to_jiffies((_tu) * 1024))
#define MSEC_TO_TU(_msec)	(_msec*1000/1024)

void iwl_mvm_te_clear_data(struct iwl_mvm *mvm,
			   struct iwl_mvm_time_event_data *te_data)
{
	lockdep_assert_held(&mvm->time_event_lock);

	if (te_data->id == TE_MAX)
		return;

	list_del(&te_data->list);
	te_data->running = false;
	te_data->uid = 0;
	te_data->id = TE_MAX;
	te_data->vif = NULL;
}

void iwl_mvm_roc_done_wk(struct work_struct *wk)
{
	struct iwl_mvm *mvm = container_of(wk, struct iwl_mvm, roc_done_wk);

	synchronize_net();

	/*
	 * Flush the offchannel queue -- this is called when the time
	 * event finishes or is cancelled, so that frames queued for it
	 * won't get stuck on the queue and be transmitted in the next
	 * time event.
	 * We have to send the command asynchronously since this cannot
	 * be under the mutex for locking reasons, but that's not an
	 * issue as it will have to complete before the next command is
	 * executed, and a new time event means a new command.
	 */
	iwl_mvm_flush_tx_path(mvm, BIT(IWL_OFFCHANNEL_QUEUE), false);
}

static void iwl_mvm_roc_finished(struct iwl_mvm *mvm)
{
	/*
	 * First, clear the ROC_RUNNING status bit. This will cause the TX
	 * path to drop offchannel transmissions. That would also be done
	 * by mac80211, but it is racy, in particular in the case that the
	 * time event actually completed in the firmware (which is handled
	 * in iwl_mvm_te_handle_notif).
	 */
	clear_bit(IWL_MVM_STATUS_ROC_RUNNING, &mvm->status);

	/*
	 * Of course, our status bit is just as racy as mac80211, so in
	 * addition, fire off the work struct which will drop all frames
	 * from the hardware queues that made it through the race. First
	 * it will of course synchronize the TX path to make sure that
	 * any *new* TX will be rejected.
	 */
	schedule_work(&mvm->roc_done_wk);
}

/*
 * Handles a FW notification for an event that is known to the driver.
 *
 * @mvm: the mvm component
 * @te_data: the time event data
 * @notif: the notification data corresponding the time event data.
 */
static void iwl_mvm_te_handle_notif(struct iwl_mvm *mvm,
				    struct iwl_mvm_time_event_data *te_data,
				    struct iwl_time_event_notif *notif)
{
	lockdep_assert_held(&mvm->time_event_lock);

	IWL_DEBUG_TE(mvm, "Handle time event notif - UID = 0x%x action %d\n",
		     le32_to_cpu(notif->unique_id),
		     le32_to_cpu(notif->action));

	/*
	 * The FW sends the start/end time event notifications even for events
	 * that it fails to schedule. This is indicated in the status field of
	 * the notification. This happens in cases that the scheduler cannot
	 * find a schedule that can handle the event (for example requesting a
	 * P2P Device discoveribility, while there are other higher priority
	 * events in the system).
	 */
	WARN_ONCE(!le32_to_cpu(notif->status),
		  "Failed to schedule time event\n");

	if (le32_to_cpu(notif->action) == TE_NOTIF_HOST_END) {
		IWL_DEBUG_TE(mvm,
			     "TE ended - current time %lu, estimated end %lu\n",
			     jiffies, te_data->end_jiffies);

		if (te_data->vif->type == NL80211_IFTYPE_P2P_DEVICE) {
			ieee80211_remain_on_channel_expired(mvm->hw);
			iwl_mvm_roc_finished(mvm);
		}

		/*
		 * By now, we should have finished association
		 * and know the dtim period.
		 */
		if (te_data->vif->type == NL80211_IFTYPE_STATION &&
		    (!te_data->vif->bss_conf.assoc ||
		     !te_data->vif->bss_conf.dtim_period))
			IWL_ERR(mvm,
				"No assocation and the time event is over already...\n");

		iwl_mvm_te_clear_data(mvm, te_data);
	} else if (le32_to_cpu(notif->action) == TE_NOTIF_HOST_START) {
		te_data->running = true;
		te_data->end_jiffies = jiffies +
			TU_TO_JIFFIES(te_data->duration);

		if (te_data->vif->type == NL80211_IFTYPE_P2P_DEVICE) {
			set_bit(IWL_MVM_STATUS_ROC_RUNNING, &mvm->status);
			ieee80211_ready_on_channel(mvm->hw);
		}
	} else {
		IWL_WARN(mvm, "Got TE with unknown action\n");
	}
}

/*
 * The Rx handler for time event notifications
 */
int iwl_mvm_rx_time_event_notif(struct iwl_mvm *mvm,
				struct iwl_rx_cmd_buffer *rxb,
				struct iwl_device_cmd *cmd)
{
	struct iwl_rx_packet *pkt = rxb_addr(rxb);
	struct iwl_time_event_notif *notif = (void *)pkt->data;
	struct iwl_mvm_time_event_data *te_data, *tmp;

	IWL_DEBUG_TE(mvm, "Time event notification - UID = 0x%x action %d\n",
		     le32_to_cpu(notif->unique_id),
		     le32_to_cpu(notif->action));

	spin_lock_bh(&mvm->time_event_lock);
	list_for_each_entry_safe(te_data, tmp, &mvm->time_event_list, list) {
		if (le32_to_cpu(notif->unique_id) == te_data->uid)
			iwl_mvm_te_handle_notif(mvm, te_data, notif);
	}
	spin_unlock_bh(&mvm->time_event_lock);

	return 0;
}

static bool iwl_mvm_time_event_notif(struct iwl_notif_wait_data *notif_wait,
				     struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_mvm *mvm =
		container_of(notif_wait, struct iwl_mvm, notif_wait);
	struct iwl_mvm_time_event_data *te_data = data;
	struct ieee80211_vif *vif = te_data->vif;
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);
	struct iwl_time_event_notif *notif;
	struct iwl_time_event_resp *resp;

	u32 mac_id_n_color = FW_CMD_ID_AND_COLOR(mvmvif->id, mvmvif->color);

	/* until we do something else */
	WARN_ON(te_data->id != TE_BSS_STA_AGGRESSIVE_ASSOC);

	switch (pkt->hdr.cmd) {
	case TIME_EVENT_CMD:
		resp = (void *)pkt->data;
		/* TODO: I can't check that since the fw is buggy - it doesn't
		 * put the right values when we remove a TE. We can be here
		 * when we remove a TE because the remove TE command is sent in
		 * ASYNC...
		 * WARN_ON(mac_id_n_color != le32_to_cpu(resp->id_and_color));
		 */
		te_data->uid = le32_to_cpu(resp->unique_id);
		IWL_DEBUG_TE(mvm, "Got response - UID = 0x%x\n", te_data->uid);
		return false;

	case TIME_EVENT_NOTIFICATION:
		notif = (void *)pkt->data;
		WARN_ON(le32_to_cpu(notif->status) != 1);
		WARN_ON(mac_id_n_color != le32_to_cpu(notif->id_and_color));
		/* check if this is our Time Event that is starting */
		if (le32_to_cpu(notif->unique_id) != te_data->uid)
			return false;
		IWL_DEBUG_TE(mvm, "Event %d is starting - time is %d\n",
			     te_data->uid, le32_to_cpu(notif->timestamp));

		WARN_ONCE(!le32_to_cpu(notif->status),
			  "Failed to schedule protected session TE\n");

		te_data->running = true;
		te_data->end_jiffies = jiffies +
				       TU_TO_JIFFIES(te_data->duration);
		return true;

	default:
		WARN_ON(1);
		return false;
	};
}

void iwl_mvm_protect_session(struct iwl_mvm *mvm,
			     struct ieee80211_vif *vif,
			     u32 duration, u32 min_duration)
{
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);
	struct iwl_mvm_time_event_data *te_data = &mvmvif->time_event_data;
	static const u8 time_event_notif[] = { TIME_EVENT_CMD,
					       TIME_EVENT_NOTIFICATION };
	struct iwl_notification_wait wait_time_event;
	struct iwl_time_event_cmd time_cmd = {};
	int ret;

	lockdep_assert_held(&mvm->mutex);

	if (te_data->running &&
	    time_after(te_data->end_jiffies,
		       jiffies + TU_TO_JIFFIES(min_duration))) {
		IWL_DEBUG_TE(mvm, "We have enough time in the current TE: %u\n",
			     jiffies_to_msecs(te_data->end_jiffies - jiffies));
		return;
	}

	if (te_data->running) {
		IWL_DEBUG_TE(mvm, "extend 0x%x: only %u ms left\n",
			     te_data->uid,
			     jiffies_to_msecs(te_data->end_jiffies - jiffies));
		/*
		 * we don't have enough time
		 * cancel the current TE and issue a new one
		 * Of course it would be better to remove the old one only
		 * when the new one is added, but we don't care if we are off
		 * channel for a bit. All we need to do, is not to return
		 * before we actually begin to be on the channel.
		 */
		iwl_mvm_stop_session_protection(mvm, vif);
	}

	iwl_init_notification_wait(&mvm->notif_wait, &wait_time_event,
				   time_event_notif,
				   ARRAY_SIZE(time_event_notif),
				   iwl_mvm_time_event_notif,
				   &mvmvif->time_event_data);

	time_cmd.action = cpu_to_le32(FW_CTXT_ACTION_ADD);
	time_cmd.id_and_color =
		cpu_to_le32(FW_CMD_ID_AND_COLOR(mvmvif->id, mvmvif->color));
	time_cmd.id = cpu_to_le32(TE_BSS_STA_AGGRESSIVE_ASSOC);

	time_cmd.apply_time =
		cpu_to_le32(iwl_read_prph(mvm->trans, DEVICE_SYSTEM_TIME_REG));
	time_cmd.dep_policy = TE_INDEPENDENT;
	time_cmd.is_present = cpu_to_le32(1);
	time_cmd.max_frags = cpu_to_le32(TE_FRAG_NONE);
	time_cmd.max_delay = cpu_to_le32(500);
	/* TODO: why do we need to interval = bi if it is not periodic? */
	time_cmd.interval = cpu_to_le32(1);
	time_cmd.interval_reciprocal = cpu_to_le32(iwl_mvm_reciprocal(1));
	time_cmd.duration = cpu_to_le32(duration);
	time_cmd.repeat = cpu_to_le32(1);
	time_cmd.notify = cpu_to_le32(TE_NOTIF_HOST_START | TE_NOTIF_HOST_END);

	te_data->vif = vif;
	te_data->duration = duration;

	spin_lock_bh(&mvm->time_event_lock);
	te_data->id = le32_to_cpu(time_cmd.id);
	list_add_tail(&te_data->list, &mvm->time_event_list);
	spin_unlock_bh(&mvm->time_event_lock);

	ret = iwl_mvm_send_cmd_pdu(mvm, TIME_EVENT_CMD, CMD_SYNC,
				   sizeof(time_cmd), &time_cmd);
	if (ret) {
		IWL_ERR(mvm, "Couldn't send TIME_EVENT_CMD: %d\n", ret);
		goto out_remove_notif;
	}

	ret = iwl_wait_notification(&mvm->notif_wait, &wait_time_event, 1 * HZ);
	if (ret) {
		IWL_ERR(mvm, "%s - failed on timeout\n", __func__);
		spin_lock_bh(&mvm->time_event_lock);
		iwl_mvm_te_clear_data(mvm, te_data);
		spin_unlock_bh(&mvm->time_event_lock);
	}

	return;

out_remove_notif:
	iwl_remove_notification(&mvm->notif_wait, &wait_time_event);
}

/*
 * Explicit request to remove a time event. The removal of a time event needs to
 * be synchronized with the flow of a time event's end notification, which also
 * removes the time event from the op mode data structures.
 */
void iwl_mvm_remove_time_event(struct iwl_mvm *mvm,
			       struct iwl_mvm_vif *mvmvif,
			       struct iwl_mvm_time_event_data *te_data)
{
	struct iwl_time_event_cmd time_cmd = {};
	u32 id, uid;
	int ret;

	/*
	 * It is possible that by the time we got to this point the time
	 * event was already removed.
	 */
	spin_lock_bh(&mvm->time_event_lock);

	/* Save time event uid before clearing its data */
	uid = te_data->uid;
	id = te_data->id;

	/*
	 * The clear_data function handles time events that were already removed
	 */
	iwl_mvm_te_clear_data(mvm, te_data);
	spin_unlock_bh(&mvm->time_event_lock);

	/*
	 * It is possible that by the time we try to remove it, the time event
	 * has already ended and removed. In such a case there is no need to
	 * send a removal command.
	 */
	if (id == TE_MAX) {
		IWL_DEBUG_TE(mvm, "TE 0x%x has already ended\n", uid);
		return;
	}

	/* When we remove a TE, the UID is to be set in the id field */
	time_cmd.id = cpu_to_le32(uid);
	time_cmd.action = cpu_to_le32(FW_CTXT_ACTION_REMOVE);
	time_cmd.id_and_color =
		cpu_to_le32(FW_CMD_ID_AND_COLOR(mvmvif->id, mvmvif->color));

	IWL_DEBUG_TE(mvm, "Removing TE 0x%x\n", le32_to_cpu(time_cmd.id));
	ret = iwl_mvm_send_cmd_pdu(mvm, TIME_EVENT_CMD, CMD_ASYNC,
				   sizeof(time_cmd), &time_cmd);
	if (WARN_ON(ret))
		return;
}

void iwl_mvm_stop_session_protection(struct iwl_mvm *mvm,
				     struct ieee80211_vif *vif)
{
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);
	struct iwl_mvm_time_event_data *te_data = &mvmvif->time_event_data;

	lockdep_assert_held(&mvm->mutex);
	iwl_mvm_remove_time_event(mvm, mvmvif, te_data);
}

static bool iwl_mvm_roc_te_notif(struct iwl_notif_wait_data *notif_wait,
				 struct iwl_rx_packet *pkt, void *data)
{
	struct iwl_mvm *mvm =
		container_of(notif_wait, struct iwl_mvm, notif_wait);
	struct iwl_mvm_time_event_data *te_data = data;
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(te_data->vif);
	struct iwl_time_event_resp *resp;

	u32 mac_id_n_color = FW_CMD_ID_AND_COLOR(mvmvif->id, mvmvif->color);

	/* until we do something else */
	WARN_ON(te_data->id != TE_P2P_DEVICE_DISCOVERABLE);

	switch (pkt->hdr.cmd) {
	case TIME_EVENT_CMD:
		resp = (void *)pkt->data;
		WARN_ON(mac_id_n_color != le32_to_cpu(resp->id_and_color));
		te_data->uid = le32_to_cpu(resp->unique_id);
		IWL_DEBUG_TE(mvm, "Got response - UID = 0x%x\n", te_data->uid);
		return true;

	default:
		WARN_ON(1);
		return false;
	};
}

int iwl_mvm_start_p2p_roc(struct iwl_mvm *mvm, struct ieee80211_vif *vif,
			  int duration)
{
	struct iwl_mvm_vif *mvmvif = iwl_mvm_vif_from_mac80211(vif);
	struct iwl_mvm_time_event_data *te_data = &mvmvif->time_event_data;
	static const u8 roc_te_notif[] = { TIME_EVENT_CMD };
	struct iwl_notification_wait wait_time_event;
	struct iwl_time_event_cmd time_cmd = {};
	int ret;

	lockdep_assert_held(&mvm->mutex);
	if (te_data->running) {
		IWL_WARN(mvm, "P2P_DEVICE remain on channel already running\n");
		return -EBUSY;
	}

	/*
	 * Flush the done work, just in case it's still pending, so that
	 * the work it does can complete and we can accept new frames.
	 */
	flush_work(&mvm->roc_done_wk);

	iwl_init_notification_wait(&mvm->notif_wait, &wait_time_event,
				   roc_te_notif,
				   ARRAY_SIZE(roc_te_notif),
				   iwl_mvm_roc_te_notif,
				   &mvmvif->time_event_data);

	time_cmd.action = cpu_to_le32(FW_CTXT_ACTION_ADD);
	time_cmd.id_and_color =
		cpu_to_le32(FW_CMD_ID_AND_COLOR(mvmvif->id, mvmvif->color));
	time_cmd.id = cpu_to_le32(TE_P2P_DEVICE_DISCOVERABLE);

	time_cmd.apply_time = cpu_to_le32(0);
	time_cmd.dep_policy = cpu_to_le32(TE_INDEPENDENT);
	time_cmd.is_present = cpu_to_le32(1);

	time_cmd.interval = cpu_to_le32(1);

	/*
	 * TE_P2P_DEVICE_DISCOVERABLE can have lower priority than other events
	 * that are being scheduled by the driver/fw, and thus it might not be
	 * scheduled. To improve the chances of it being scheduled, allow it to
	 * be fragmented.
	 * In addition, for the same reasons, allow to delay the scheduling of
	 * the time event.
	 */
	time_cmd.max_frags = cpu_to_le32(MSEC_TO_TU(duration)/20);
	time_cmd.max_delay = cpu_to_le32(MSEC_TO_TU(duration/2));
	time_cmd.duration = cpu_to_le32(MSEC_TO_TU(duration));
	time_cmd.repeat = cpu_to_le32(1);
	time_cmd.notify = cpu_to_le32(TE_NOTIF_HOST_START | TE_NOTIF_HOST_END);

	/* Push the te data to the tracked te list */
	te_data->vif = vif;
	te_data->duration = MSEC_TO_TU(duration);

	spin_lock_bh(&mvm->time_event_lock);
	te_data->id = le32_to_cpu(time_cmd.id);
	list_add_tail(&te_data->list, &mvm->time_event_list);
	spin_unlock_bh(&mvm->time_event_lock);

	ret = iwl_mvm_send_cmd_pdu(mvm, TIME_EVENT_CMD, CMD_SYNC,
				   sizeof(time_cmd), &time_cmd);
	if (ret) {
		IWL_ERR(mvm, "Couldn't send TIME_EVENT_CMD: %d\n", ret);
		goto out_remove_notif;
	}

	ret = iwl_wait_notification(&mvm->notif_wait, &wait_time_event, 1 * HZ);
	if (ret) {
		IWL_ERR(mvm, "%s - failed on timeout\n", __func__);
		iwl_mvm_te_clear_data(mvm, te_data);
	}

	return ret;

out_remove_notif:
	iwl_remove_notification(&mvm->notif_wait, &wait_time_event);
	return ret;
}

void iwl_mvm_stop_p2p_roc(struct iwl_mvm *mvm)
{
	struct iwl_mvm_vif *mvmvif;
	struct iwl_mvm_time_event_data *te_data;

	lockdep_assert_held(&mvm->mutex);

	/*
	 * Iterate over the list of time events and find the time event that is
	 * associated with a P2P_DEVICE interface.
	 * This assumes that a P2P_DEVICE interface can have only a single time
	 * event at any given time and this time event coresponds to a ROC
	 * request
	 */
	mvmvif = NULL;
	spin_lock_bh(&mvm->time_event_lock);
	list_for_each_entry(te_data, &mvm->time_event_list, list) {
		if (te_data->vif->type == NL80211_IFTYPE_P2P_DEVICE) {
			mvmvif = iwl_mvm_vif_from_mac80211(te_data->vif);
			break;
		}
	}
	spin_unlock_bh(&mvm->time_event_lock);

	if (!mvmvif) {
		IWL_WARN(mvm, "P2P_DEVICE no remain on channel event\n");
		return;
	}

	iwl_mvm_remove_time_event(mvm, mvmvif, te_data);

	iwl_mvm_roc_finished(mvm);
}
