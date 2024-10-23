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
#include "em_cmd_exec.h"

int em_metrics_t::handle_assoc_sta_link_metrics_cquery(unsigned char* buff, unsigned int len)
{
    em_tlv_t *tlv;
    em_raw_hdr_t *hdr;
    int tmp_len, ret = 0;
    char assoc_sta_link_metrics_json[EM_SUBDOC_BUFF_SZ];
    mac_address_t sta_mac_id;
    mac_addr_str_t      sta_mac_str;
    char* errors[EM_MAX_TLV_MEMBERS];
    em_bus_event_t *bevt;
    em_subdoc_info_t *info;
    em_event_t evt;
    em_service_type_t to_svc;
    em_long_string_t res;

    /*if (em_msg_t(em_msg_type_assoc_sta_link_metrics_query, em_profile_type_2, buff, len).validate(errors) == 0) {
        printf("assoc link metrics query validation failed\n");
        return -1;
    }*/

    hdr = (em_raw_hdr_t *)buff;
    if (em_msg_t(buff + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
        len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_client_mac_info(&sta_mac_id) == true) {
        dm_easy_mesh_t::macbytes_to_string(sta_mac_id, sta_mac_str);
        printf("assoc sta mac = %s\n",sta_mac_str);
    }

    evt.type = em_event_type_bus;
    bevt = &evt.u.bevt;
    to_svc = em_service_type_agent;
    bevt->type = em_bus_event_type_assoc_sta_link_metrics_query;
    info = &bevt->u.subdoc;

    //dm_easy_mesh_t::create_assoc_sta_link_metrics_json_cmd(sta_mac_str, assoc_sta_link_metrics_json);
    dm_easy_mesh_t::create_assoc_sta_link_metrics_json_cmd(sta_mac_str, info->buff);

    to_svc = em_service_type_agent;
    //info->sz = strlen(assoc_sta_link_metrics_json);
    info->sz = sizeof(em_subdoc_data_buff_t);
    //strncpy(info->buff,assoc_sta_link_metrics_json,strlen(assoc_sta_link_metrics_json)+1);
    em_cmd_exec_t::send_cmd(to_svc, (unsigned char *)&evt, sizeof(em_event_t));
    return 0;
}

void em_metrics_t::process_msg(unsigned char *data, unsigned int len)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    unsigned char *tlvs;
    unsigned int tlvs_len;

    hdr = (em_raw_hdr_t *)data;
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    //TODO: Test code
   //handle_assoc_sta_link_metrics_cquery(data, len);

    switch (htons(cmdu->type)) {
        case em_msg_type_assoc_sta_link_metrics_query:
            handle_assoc_sta_link_metrics_cquery(data, len);
            break;

        default:
            break;
    }
}

void em_metrics_t::handle_state_assoc_sta_link_metrics_resp()
{
    unsigned char buff[MAX_EM_BUFF_SZ];
    unsigned int sz;

    memset(&buff, 0, sizeof(MAX_EM_BUFF_SZ));
    sz = create_assoc_sta_link_metrics_resp(buff);

    printf("%s:%d:Creation of assoc sta link metrics message  sz=%d successful\n", __func__, __LINE__,sz);
    // em_msg_t validateObj(em_msg_type_autoconf_search,em_profile_type_3,buff,sz); TODO

    //if (validateObj.validate(Errors)) TODO
    if(1)
    {
        if (send_frame(buff, sz)  < 0) {
            printf("%s:%d: failed, err:%d\n", __func__, __LINE__, errno);
            return;
        }
        printf("%s:%d: Assoc STA link metrics send successful\n", __func__, __LINE__);
        set_state(em_state_agent_config_complete);
    }
}

int em_metrics_t::create_assoc_sta_link_metrics_resp(unsigned char *buff)
{
    unsigned short  msg_type = em_msg_type_assoc_sta_link_metrics_rsp;
    int len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = buff;
    unsigned short sz = 0;
    unsigned short type = htons(ETH_P_1905);

    short msg_id = 1; // TODO

    memcpy(tmp, (unsigned char *)get_peer_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    len += sizeof(mac_address_t);

    memcpy(tmp, get_al_interface_mac(), sizeof(mac_address_t));
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

    //assoc sta link metrics 17.2.24
    //assoc sta link metrics 17.2.24
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_link_metric;
    sz = create_assoc_sta_link_metrics_tlv(tlv->value);
    tlv->len =  htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //Error code  TLV 17.2.36
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_error_code;
    sz = create_error_code_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);

    //assoc ext link metrics 17.2.62
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_assoc_sta_ext_link_metric;
    sz = create_assoc_ext_sta_link_metrics_tlv(tlv->value);
    tlv->len = htons(sz);

    tmp += (sizeof(em_tlv_t) + sz);
    len += (sizeof(em_tlv_t) + sz);


    // End of message
    tlv = (em_tlv_t *)tmp;
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;

    tmp += (sizeof (em_tlv_t));
    len += (sizeof (em_tlv_t));
    return len;
}

short em_metrics_t::create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff)
{
    //TODO: Cleanup hard-code data
    short len = 0;
    dm_sta_t *sta, *active_sta;
    hash_map_t **assocclt = (hash_map_t **) get_current_cmd()->get_data_model()->get_sta_map();
    hash_map_t **em_m_sta_map = get_data_model()->get_sta_map();
    em_assoc_sta_ext_link_metrics_t *assoc_sta_ext_link_metrics = (em_assoc_sta_ext_link_metrics_t*) buff;
    sta = (dm_sta_t *)hash_map_get_first(*assocclt);
    if ((*assocclt != NULL) &&  (assocclt != NULL) && (*em_m_sta_map != NULL) && (em_m_sta_map != NULL) && (sta != NULL)) {
        active_sta = (dm_sta_t *)hash_map_get_first(*em_m_sta_map);
        while (active_sta != NULL) {
            if (strncmp((char *)active_sta->get_sta_info()->id,(char *)sta->get_sta_info()->id,sizeof(mac_address_t)) == 0) {
                memcpy(&assoc_sta_ext_link_metrics->sta_mac_addr,&active_sta->get_sta_info()->id,sizeof(assoc_sta_ext_link_metrics->sta_mac_addr));

                len += sizeof(assoc_sta_ext_link_metrics->sta_mac_addr);
                assoc_sta_ext_link_metrics->num_bssids = 1;

                len += sizeof(assoc_sta_ext_link_metrics->num_bssids);
                memcpy(&assoc_sta_ext_link_metrics->bssid,&active_sta->get_sta_info()->bssid,sizeof(assoc_sta_ext_link_metrics->bssid));

                len += sizeof(assoc_sta_ext_link_metrics->bssid);
                assoc_sta_ext_link_metrics->last_data_dl_rate = active_sta->get_sta_info()->last_dl_rate;

                len += sizeof(assoc_sta_ext_link_metrics->last_data_dl_rate);
                assoc_sta_ext_link_metrics->last_data_ul_rate = active_sta->get_sta_info()->last_ul_rate;

                len += sizeof(assoc_sta_ext_link_metrics->last_data_ul_rate);
                assoc_sta_ext_link_metrics->util_receive = active_sta->get_sta_info()->util_rx;

                len += sizeof(assoc_sta_ext_link_metrics->util_receive);
                assoc_sta_ext_link_metrics->util_transmit = active_sta->get_sta_info()->util_tx;

                len += sizeof(assoc_sta_ext_link_metrics->util_transmit);
                return len;
            }
             //active_sta = (dm_sta_t *)hash_map_get_next(*em_m_sta_map, sta);
             active_sta = (dm_sta_t *)hash_map_get_next(*em_m_sta_map, active_sta);
        }
    }
    return 0;
}

short em_metrics_t::create_assoc_sta_link_metrics_tlv(unsigned char *buff)
{
    //TODO: Cleanup hard-coded data
    short len = 0;
    dm_sta_t *sta, *active_sta = NULL;
    mac_addr_str_t dst;
    mac_addr_str_t dst_mac_str;
    em_sta_info_t *em_sta_dev_info = NULL;
    hash_map_t **assocclt = (hash_map_t **) get_current_cmd()->get_data_model()->get_sta_map();
    hash_map_t **em_m_sta_map = get_data_model()->get_sta_map();
    em_assoc_sta_link_metrics_t *assoc_sta_link_metrics = (em_assoc_sta_link_metrics_t*) buff;

    sta = (dm_sta_t *)hash_map_get_first(*assocclt);
    if ((*assocclt != NULL) &&  (assocclt != NULL) && (*em_m_sta_map != NULL) && (em_m_sta_map != NULL) && (sta != NULL)) {
        active_sta = (dm_sta_t *)hash_map_get_first(*em_m_sta_map);
        while (active_sta != NULL) {
            dm_easy_mesh_t::macbytes_to_string(active_sta->get_sta_info()->id, dst);
            printf("\n%s:%d:[DEBUG] EM active sta client id %s\n", __func__, __LINE__, dst);
            dm_easy_mesh_t::macbytes_to_string(sta->get_sta_info()->id, dst);
            printf("%s:%d:[DEBUG] DM sta client id %s\n", __func__, __LINE__, dst);

            if (strncmp((char *)active_sta->get_sta_info()->id,(char *)sta->get_sta_info()->id,sizeof(mac_address_t)) == 0) {
                memcpy(&assoc_sta_link_metrics->sta_mac_addr,&active_sta->get_sta_info()->id,sizeof(assoc_sta_link_metrics->sta_mac_addr));

                dm_easy_mesh_t::macbytes_to_string(assoc_sta_link_metrics->sta_mac_addr, dst_mac_str);
                printf("%s:%d:[DEBUG] Client MAC=%s\n", __func__, __LINE__,dst_mac_str);

			    em_sta_dev_info = active_sta->get_sta_info();
                printf("%s:%d:[DEBUG] signal_strength %d\n", __func__, __LINE__,em_sta_dev_info->signal_strength);

                len += sizeof(assoc_sta_link_metrics->sta_mac_addr);
                assoc_sta_link_metrics->num_bssids = 1;
                printf("%s:%d:[DEBUG] num_bssids=%d\n", __func__, __LINE__,assoc_sta_link_metrics->num_bssids);

                len += sizeof(assoc_sta_link_metrics->num_bssids);
                memcpy(&assoc_sta_link_metrics->bssid,&active_sta->get_sta_info()->bssid,sizeof(assoc_sta_link_metrics->bssid));
                dm_easy_mesh_t::macbytes_to_string(assoc_sta_link_metrics->bssid, dst_mac_str);
                printf("%s:%d:[DEBUG] bssids=%s\n", __func__, __LINE__,dst_mac_str);

                len += sizeof(assoc_sta_link_metrics->bssid);
                assoc_sta_link_metrics->time_delta_ms = 1;
                printf("%s:%d:[DEBUG] time_delta_ms=%d\n", __func__, __LINE__,assoc_sta_link_metrics->time_delta_ms);

                len += sizeof(assoc_sta_link_metrics->time_delta_ms);
                assoc_sta_link_metrics->est_mac_data_rate_dl = active_sta->get_sta_info()->est_dl_rate;
                printf("%s:%d:[DEBUG] est_mac_data_rate_dl=%d\n", __func__, __LINE__,assoc_sta_link_metrics->est_mac_data_rate_dl);

                len += sizeof(assoc_sta_link_metrics->est_mac_data_rate_dl);
                assoc_sta_link_metrics->est_mac_data_rate_ul = active_sta->get_sta_info()->est_ul_rate;
                printf("%s:%d:[DEBUG] est_mac_data_rate_ul=%d\n", __func__, __LINE__,assoc_sta_link_metrics->est_mac_data_rate_ul);

                len += sizeof(assoc_sta_link_metrics->est_mac_data_rate_ul);
                assoc_sta_link_metrics->rcpi = 1;
                printf("%s:%d:[DEBUG] rcpi=%d\n", __func__, __LINE__,assoc_sta_link_metrics->rcpi);

                len += sizeof(assoc_sta_link_metrics->rcpi);
                return len;

            }
             //active_sta = (dm_sta_t *)hash_map_get_next(*em_m_sta_map, sta);
             active_sta = (dm_sta_t *)hash_map_get_next(*em_m_sta_map, active_sta);
        }
    }
    return 0;
}

short em_metrics_t::create_error_code_tlv(unsigned char *buff)
{
    short len = 0, found = 0;
    em_error_code_t *err = (em_error_code_t*)buff;
    dm_sta_t *sta, *active_sta;
    hash_map_t **assocclt = (hash_map_t **) get_current_cmd()->get_data_model()->get_assoc_sta_map();
    hash_map_t **em_m_sta_map = get_data_model()->get_sta_map();

    sta = (dm_sta_t *)hash_map_get_first(*assocclt);
    if ((*assocclt != NULL) &&  (assocclt != NULL) && (*em_m_sta_map != NULL) && (em_m_sta_map != NULL) && (sta != NULL)) {
        active_sta = (dm_sta_t *)hash_map_get_first(*em_m_sta_map);
        while (active_sta != NULL) {
            if (strncmp((char *)active_sta->get_sta_info()->id,(char *)sta->get_sta_info()->id,sizeof(mac_address_t)) == 0) {
                err->reason_code = 0x01; // STA associated with any BSS operated
                len += 1;
                memcpy(&err->sta_mac_addr,&active_sta->get_sta_info()->id,sizeof(err->sta_mac_addr));
                len += sizeof(err->sta_mac_addr);
                found ++;
            }
            active_sta = (dm_sta_t *)hash_map_get_next(*em_m_sta_map, sta);
        }
    } else {
        err->reason_code = 0x02; // STA not associated with any BSS operated
        len += 1;
        if (sta != NULL) {
            memcpy(&err->sta_mac_addr,&sta->get_sta_info()->id,sizeof(err->sta_mac_addr));
            len += sizeof(err->sta_mac_addr);
        }
    }
    if ( found == 0 ) {
        err->reason_code = 0x03; //STA associated but report cannot be retrived
        len += 1;
        if (sta != NULL) {
            memcpy(&err->sta_mac_addr,&sta->get_sta_info()->id,sizeof(err->sta_mac_addr));
            len += sizeof(err->sta_mac_addr);
        }
    }
    return len;
}

void em_metrics_t::process_state()
{
    switch (get_state()) {

        case em_state_agent_assoc_sta_link_metrics:
            handle_state_assoc_sta_link_metrics_resp();
            break;
        default:
            break;
    }
}

em_metrics_t::em_metrics_t()
{

}

em_metrics_t::~em_metrics_t()
{

}

