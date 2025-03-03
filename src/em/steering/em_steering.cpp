/**
 * Copyright 2023 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/filter.h>
#include <netinet/ether.h>
#include <netpacket/packet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rand.h>
#include "em.h"
#include "em_msg.h"
#include "em_cmd.h"
#include "em_cmd_exec.h"

int em_steering_t::send_client_assoc_ctrl_req_msg()
{
    em_cmd_t *pcmd;
    em_disassoc_params_t *disassoc_param;
    unsigned int i, j;
    unsigned int num = 0;
    dm_easy_mesh_t *dm;
    dm_bss_t *bss;
    em_client_assoc_ctrl_req_t assoc_ctrl[MAX_EM_BUFF_SZ];

    dm = get_data_model();

    pcmd = get_current_cmd();
    for (i = 0; i < pcmd->m_param.u.disassoc_params.num; i++) {
        disassoc_param = &pcmd->m_param.u.disassoc_params.params[i];
        for (j = 0; j < dm->m_num_bss; j++) {
            if ((memcmp(disassoc_param->bssid, dm->m_bss[j].m_bss_info.bssid.mac, sizeof(bssid_t)) == 0) &&
                (memcmp(dm->m_bss[j].m_bss_info.ruid.mac, get_radio_interface_mac(), sizeof(mac_address_t)) == 0)) {
                memcpy(assoc_ctrl[num].bssid, disassoc_param->bssid, sizeof(mac_address_t));
                if (disassoc_param->disassoc_time == 0) {
                    assoc_ctrl[num].assoc_control = 0x03;
                } else {
                    assoc_ctrl[num].assoc_control = 0x02;
                    assoc_ctrl[num].validity_period = disassoc_param->disassoc_time;
                }
                assoc_ctrl[num].count = 1;
                memcpy(assoc_ctrl[num].sta_mac, disassoc_param->sta_mac, sizeof(mac_address_t));
                send_client_assoc_ctrl_req_msg(&assoc_ctrl[num]);
                num++;
            }
        }
    }

    set_state(em_state_ctrl_configured);
}

int em_steering_t::send_client_assoc_ctrl_req_msg(em_client_assoc_ctrl_req_t *assoc_ctrl)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_client_assoc_ctrl_req;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm;

    dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_client_assoc_ctrl_req;
    memcpy(tlv->value, assoc_ctrl, sizeof(em_client_assoc_ctrl_req_t));
    tlv->len = htons(sizeof(em_client_assoc_ctrl_req_t));

    tmp += (sizeof (em_tlv_t) + sizeof(em_client_assoc_ctrl_req_t));
    len += (sizeof (em_tlv_t) + sizeof(em_client_assoc_ctrl_req_t));

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_assoc_ctrl_req, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("Client Assoc Control Request msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Client Assoc Control Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_client_assoc_ctrl_req_tx_cnt++;
    printf("%s:%d: Client Assoc Control Request (%d) Send Successful\n", __func__, __LINE__, m_client_assoc_ctrl_req_tx_cnt);

    return len;
}

int em_steering_t::send_client_steering_req_msg()
{
    em_cmd_t *pcmd;
    em_steer_params_t *steer_param;
    em_steering_req_t agile_req, non_agile_req, *req_ptr;
    int agile_sta_cnt = 0, non_agile_sta_cnt = 0;
    short len = 0;
    dm_sta_t *sta;
    dm_easy_mesh_t *dm = get_data_model();
    em_cmd_steer_params_t *params = &get_current_cmd()->m_param.u.steer_params;

    pcmd = get_current_cmd();
    for (int i = 0; i < params->num; i++) {
        steer_param = &params->params[i];
        sta = dm->find_sta(steer_param->sta_mac, steer_param->source);

        if(sta != NULL) {
            req_ptr = (sta->m_sta_info.multi_band_cap) ? &agile_req : &non_agile_req;
            if (sta->m_sta_info.multi_band_cap == true) {
                agile_sta_cnt++;
            } else {
                non_agile_sta_cnt++;
            }

            memcpy(&req_ptr->bssid, get_data_model()->m_bss[0].m_bss_info.bssid.mac, sizeof(bssid_t));
            req_ptr->req_mode                            = steer_param->request_mode;
            req_ptr->btm_dissoc_imminent                 = steer_param->disassoc_imminent;
            req_ptr->btm_abridged                        = steer_param->btm_abridged;
            //ignore this if its a mandate req
            req_ptr->steering_opportunity_window         = htons((steer_param->request_mode == 1) ? 0 : steer_param->steer_opportunity_win);
            req_ptr->btm_dissoc_timer                    = htons(steer_param->btm_disassociation_timer);
            req_ptr->target_bssid_list_count             = 1;
            req_ptr->bss_list                            = (em_steering_req_bss_list_t *)calloc(0, sizeof(em_steering_req_bss_list_t) * req_ptr->target_bssid_list_count);
            memcpy(req_ptr->bss_list->target_bssids, steer_param->target, sizeof(mac_addr_t));
            req_ptr->bss_list->target_bss_op_class       = steer_param->target_op_class;
            req_ptr->bss_list->target_bss_channel_num    = steer_param->target_channel;
        }
    }

    agile_req.sta_list_count = agile_sta_cnt;
    non_agile_req.sta_list_count = non_agile_sta_cnt;
    agile_req.sta_mac_addr = (mac_address_t *)calloc(0, sizeof(mac_address_t) * agile_req.sta_list_count);
    non_agile_req.sta_mac_addr = (mac_address_t *)calloc(0, sizeof(mac_address_t) * non_agile_req.sta_list_count);

    agile_sta_cnt = non_agile_sta_cnt = 0;
    for (int i = 0; i < params->num; i++) {
        steer_param = &params->params[i];
        sta = dm->find_sta(steer_param->sta_mac, steer_param->source);
        if (sta == NULL) {
            continue;
        }

        req_ptr = (sta->m_sta_info.multi_band_cap) ? &agile_req : &non_agile_req;
        int index = (sta->m_sta_info.multi_band_cap) ? agile_sta_cnt++ : non_agile_sta_cnt++;
        memcpy(&req_ptr->sta_mac_addr[index], steer_param->sta_mac, sizeof(mac_address_t));
    }

    if (agile_req.sta_list_count > 0) {
        len = sizeof(em_steering_req_t) + (agile_sta_cnt * sizeof(mac_addr_t)) + (agile_req.target_bssid_list_count * sizeof(em_steering_req_bss_list_t));
        printf("%s:%d: Sending agile multiband request for sta entries %d of len %d\n", __func__, __LINE__, agile_req.sta_list_count, len);
        send_client_steering_req_msg(&agile_req, len, true);
    }

    if (non_agile_req.sta_list_count > 0) {
        len = sizeof(em_steering_req_t) + (non_agile_sta_cnt * sizeof(mac_addr_t)) + sizeof(em_steering_req_bss_list_t);
        printf("%s:%d: Sending non agile multiband request for sta entries %d of len %d\n", __func__, __LINE__, non_agile_req.sta_list_count, len);
        send_client_steering_req_msg(&non_agile_req, len, false);
    }

    free(agile_req.sta_mac_addr);
    free(non_agile_req.sta_mac_addr);
    //free(agile_req.bss_list);
    //free(non_agile_req.bss_list);

    return len;
}

int em_steering_t::send_client_steering_req_msg(em_steering_req_t *req, int length, bool if_multiband)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_id = em_msg_type_client_steering_req;
    short sz = 0;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_id);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;
    cmdu->relay_ind = 0;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // 17.2.29 Steering Request TLV/ Profile-2 Steering Request TLV 17.2.57
    tlv = (em_tlv_t *)tmp;
    if (if_multiband == true) {
        tlv->type = em_tlv_type_profile2_steering_request;
    } else {
        tlv->type = em_tlv_type_steering_request;
    }
    sz = create_btm_request_tlv(tlv->value, req, length, if_multiband);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t((em_msg_type_t)msg_id, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("Client Steering Request msg validation failed\n");
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Client Steering Request msg send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    m_client_steering_req_tx_cnt++;
    printf("%s:%d: Client Steering Request (%d) Send Successful\n", __func__, __LINE__, m_client_steering_req_tx_cnt);

    return len;
}

int em_steering_t::send_btm_report_msg(mac_address_t sta, bssid_t bss)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_client_steering_btm_rprt;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    short msg_id = em_msg_type_client_steering_btm_rprt;
    dm_easy_mesh_t *dm = get_data_model();

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    // 17.2.30 Steering BTM Report TLV format
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_steering_btm_rprt;
    sz = create_btm_report_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_client_steering_btm_rprt, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: Steering BTM report validation failed\n", __func__, __LINE__);
        return -1;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: Steering BTM report send failed, error:%d\n", __func__, __LINE__, errno);
        return -1;
    }

    printf("%s:%d: Steering BTM report send success:%d\n", __func__, __LINE__);
    set_state(em_state_agent_configured);

    return len;
}

int em_steering_t::send_1905_ack_message(mac_addr_t sta_mac)
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short  msg_type = em_msg_type_1905_ack;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);
    short msg_id = em_msg_type_1905_ack;
    dm_easy_mesh_t *dm = get_data_model();

    em_cmd_t *pcmd = get_current_cmd();
    em_cmd_params_t *evt_param = &pcmd->m_param;

    memcpy(tmp, dm->get_ctrl_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, (unsigned char *)&type, sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    len += sizeof(unsigned short);

    cmdu = (em_cmdu_t *)tmp;

    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(msg_id);
    cmdu->last_frag_ind = 1;

    tmp += sizeof(em_cmdu_t);
    len += sizeof(em_cmdu_t);

    //17.2.36 Error Code TLV format
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value, 0, sta_mac);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));

    if (em_msg_t(em_msg_type_1905_ack, em_profile_type_3, buff, len).validate(errors) == 0) {
        printf("%s:%d: 1905 ACK validation failed\n", __func__, __LINE__);
        return 0;
    }

    if (send_frame(buff, len)  < 0) {
        printf("%s:%d: 1905 ACK send failed, error:%d\n", __func__, __LINE__, errno);
        return 0;
    }
    printf("%s:%d: 1905 ACK send success\n", __func__, __LINE__);

    return len;
}

short em_steering_t::create_btm_request_tlv(unsigned char *buff, em_steering_req_t *req, int length, bool if_multiband)
{
    short len = 0;
    em_profile2_steering_req_t *preq = (em_profile2_steering_req_t *)buff;
    unsigned char *tmp = buff;
    mac_addr_str_t mac_str;

    // Calculate the offset for sta_mac_addr
    size_t offset_sta_mac_addr = sizeof(bssid_t) + (sizeof(unsigned char) * 2) + (sizeof(unsigned short) * 2);
    // Calculate the offset for bss_list (assuming it follows sta_mac_addr)
    size_t offset_bss_list = offset_sta_mac_addr + (sizeof(mac_address_t) * req->sta_list_count);
/*     memcpy(&req->bssid, get_data_model()->m_bss[0].m_bss_info.bssid.mac, sizeof(bssid_t));
    req->req_mode                           = params->request_mode;
    req->btm_dissoc_imminent                = params->disassoc_imminent;
    req->btm_abridged                       = params->btm_abridged;
    req->btm_link_removal_imminent = params->link_removal_imminent;
    if(params->request_mode == 1)
    {
        //ignore this
    req->steering_opportunity_window        = 0;
    } else {
        req->steering_opportunity_window    = params->steer_opportunity_win;
    }
    req->btm_dissoc_timer                   = htons(params->btm_disassociation_timer);
    req->sta_list_count                     = 1;
    memcpy(req->sta_mac_addr, params->sta_mac, sizeof(mac_addr_t));
    req->target_bssid_list_count            = 1;
    memcpy(req->target_bssids, params->target, sizeof(mac_addr_t));
    req->target_bss_op_class                = params->target_op_class;;
    req->target_bss_channel_num             = params->target_channel; */

    memcpy(&preq->agile_multiband, req, length);
    tmp += offset_sta_mac_addr;
    len += offset_sta_mac_addr;

    // Copy the MAC addresses to the buffer
    for (int i = 0; i < req->sta_list_count; i++) {
        memcpy(tmp, req->sta_mac_addr[i], sizeof(mac_address_t));
        tmp += sizeof(mac_address_t);
        len += sizeof(mac_address_t);
    }

    memcpy(tmp, &req->target_bssid_list_count, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    for (int i = 0; i < req->target_bssid_list_count; i++) {
        memcpy(tmp, &req->bss_list[i], sizeof(em_steering_req_bss_list_t));
        tmp += sizeof(em_steering_req_bss_list_t);
        len += sizeof(em_steering_req_bss_list_t);
    }

    if (if_multiband == true) {
        preq->reason_code = 1;
        tmp += sizeof(preq->reason_code);
        len += sizeof(preq->reason_code);
    }

    return len;
}

short em_steering_t::create_btm_report_tlv(unsigned char *buff)
{
    short len = 0;
    unsigned char *tmp = buff;
    em_cmd_t *pcmd = get_current_cmd();
    em_cmd_btm_report_params_t  *btm_report_param = &pcmd->m_param.u.btm_report_params;

    memcpy(tmp, &btm_report_param->source, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, &btm_report_param->sta_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, &btm_report_param->status_code, sizeof(char));
    tmp += sizeof(char);
    len += sizeof(char);

    //todo: create bss list dynamically
    /*memcpy(tmp, btm_report_param->target, sizeof(mac_address_t));
    tmp += (sizeof(em_tlv_t) + sizeof(mac_address_t));
    len += (sizeof(em_tlv_t) + sizeof(mac_address_t));*/

    return len;
}

short em_steering_t::create_error_code_tlv(unsigned char *buff, int val, mac_addr_t sta_mac)
{
    short len = 0;
    unsigned char *tmp = buff;
    unsigned char reason = 0;

    em_cmd_t *pcmd = get_current_cmd();
    em_cmd_btm_report_params_t *btm_param = &pcmd->m_param.u.btm_report_params;

    memcpy(tmp, &val, sizeof(unsigned char));
    tmp += sizeof(unsigned char);
    len += sizeof(unsigned char);

    memcpy(tmp, sta_mac, sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    return len;
}

int em_steering_t::handle_client_steering_req(unsigned char *buff, unsigned int len, unsigned int type)
{
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_steering_req_t *steer_req;
    mac_addr_str_t mac_str;
    int tlv_len = 0;
    unsigned char *tmp;

    if (em_msg_t((em_msg_type_t)type, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Steering Request message validation failed\n");
        return -1;
    }

    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    tlv_len = ntohs(tlv->len);
    steer_req =  (em_steering_req_t *)&tlv->value;
    tmp = (unsigned char *)&tlv->value;

    size_t offset_sta_mac_addr = sizeof(bssid_t) + (sizeof(unsigned char) * 2) + (sizeof(unsigned short) * 2);

    for (int i = 0; i < steer_req->sta_list_count; i++) {
        dm_easy_mesh_t::macbytes_to_string(&tmp[offset_sta_mac_addr + i], mac_str);
        printf("%s:%d Recived steer req for sta=%s\n", __func__, __LINE__, mac_str);
        offset_sta_mac_addr += sizeof(mac_address_t);
    }

    get_mgr()->io_process(em_bus_event_type_bss_tm_req, (unsigned char *)tmp, tlv_len);

    send_1905_ack_message(&tmp[offset_sta_mac_addr]);

    return 0;
}

int em_steering_t::handle_client_steering_report(unsigned char *buff, unsigned int len)
{
    mac_address_t sta;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    em_raw_hdr_t *hdr = (em_raw_hdr_t *)buff;
    em_steering_btm_rprt_t *btm_rprt;

    if (em_msg_t(em_msg_type_client_steering_btm_rprt, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("%s:%d:Client Steering Request message validation failed\n");
        return -1;
    }

    cmdu = (em_cmdu_t *)(buff + sizeof(em_raw_hdr_t));
    tlv = (em_tlv_t *)(buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    btm_rprt =  (em_steering_btm_rprt_t *)&tlv->value;

    mac_addr_str_t mac_str;
    dm_easy_mesh_t::macbytes_to_string(btm_rprt->sta_mac_addr, mac_str);
    printf("%s:%d Client BTM Report for sta %s, status %d\n", __func__, __LINE__, mac_str, btm_rprt->btm_status_code);

    set_state(em_state_ctrl_configured);

    //send ack for report rcvd
    //send_1905_ack_message(btm_rprt->sta_mac_addr);

    return 0;
}

int em_steering_t::handle_ack_msg(unsigned char *buff, unsigned int len)
{
    set_state(em_state_ctrl_steer_btm_req_ack_rcvd);
    return 0;
}

void em_steering_t::process_ctrl_state()
{
    switch (get_state()) {
        case em_state_ctrl_sta_steer_pending:
            send_client_steering_req_msg();
            break;

        case em_state_ctrl_sta_disassoc_pending:
            send_client_assoc_ctrl_req_msg();
            break;
    }
}

void em_steering_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_steer_btm_res_pending:
            send_btm_report_msg(get_radio_interface_mac(), get_radio_interface_mac());
            break;

        default:
            break;
    }
}

void em_steering_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    tlvs = data + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t);
    tlvs_len = len - (sizeof(em_raw_hdr_t) - sizeof(em_cmdu_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_client_steering_req:
            handle_client_steering_req(data, len, htons(cmdu->type));
            break;

        case em_msg_type_client_steering_btm_rprt:
            handle_client_steering_report(data, len);
            break;

        case em_msg_type_1905_ack:
            handle_ack_msg(data, len);

        default:
            break;
    }
}

em_steering_t::em_steering_t()
{
    m_client_steering_req_tx_cnt = 0;
    m_client_assoc_ctrl_req_tx_cnt = 0;
}

em_steering_t::~em_steering_t()
{

}
