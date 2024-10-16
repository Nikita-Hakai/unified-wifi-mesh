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
#include <signal.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <pthread.h>
#include "em_agent.h"
#include "em_msg.h"
#include "ieee80211.h"
#include "em_cmd_agent.h"
#include "em_orch_agent.h"
#include "util.h"

em_agent_t g_agent;
const char *global_netid = "OneWifiMesh";

void em_agent_t::handle_sta_list(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_sta_list(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        //m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        //m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

    //Empty the m_assoc_map
    hash_map_t **ptr_sta_map = m_data_model.get_assoc_sta_map();
    hash_map_cleanup(*ptr_sta_map);
}

void em_agent_t::handle_ap_cap_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_ap_cap_query(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}


void em_agent_t::handle_client_cap_query(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_client_cap_query(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_radio_config(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_radio_config(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_vap_config(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_vap_config(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_dev_init(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_dev_init(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_onewifi_private_subdoc(em_bus_event_t *evt)
{
    unsigned int num;
    wifi_bus_desc_t *desc;
    raw_data_t l_bus_data;

    if((desc = get_bus_descriptor()) == NULL) {
       printf("descriptor is null");
    }

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_onewifi_private_subdoc(evt, desc, &m_bus_hdl)) == 0) {
        //m_agent_cmd->send_result(em_cmd_out_status_no_change);
	printf("analyze_onewifi_private_subdoc complete");
    }
}

void em_agent_t::handle_assoc_sta_link_metrics(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_assoc_sta_link_metrics(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        /*m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);*/
    }
}

void em_agent_t::handle_vendor_public_action_frame(struct ieee80211_mgmt *frame)
{

}

void em_agent_t::handle_public_action_frame(struct ieee80211_mgmt *frame)
{

    switch (frame->u.action.u.vs_public_action.action) {
        case WLAN_PA_VENDOR_SPECIFIC:
            handle_vendor_public_action_frame(frame);
            break;

        default:
            break;

    }

}

void em_agent_t::handle_action_frame(struct ieee80211_mgmt *frame)
{
    switch (frame->u.action.category) {
        case WLAN_ACTION_PUBLIC:
            handle_public_action_frame(frame);
            break;

        default:
            break;

    }
}

void em_agent_t::handle_frame_event(em_frame_event_t *evt)
{
    struct ieee80211_frame *frame;

    frame = (struct ieee80211_frame *)evt->frame;
    assert(IEEE80211_IS_MGMT(frame));
    
    // handle action frames only 
    if ((frame->i_fc[0] & 0x0f) == IEEE80211_FC0_SUBTYPE_ACTION) {
        handle_action_frame((struct ieee80211_mgmt *)frame);        
    }
}

void em_agent_t::handle_autoconfig_renew(em_bus_event_t *evt)
{
    em_cmd_t *pcmd[EM_MAX_CMD] = {NULL};
    unsigned int num;

    if (m_orch->is_cmd_type_in_progress(evt->type) == true) {
        m_agent_cmd->send_result(em_cmd_out_status_prev_cmd_in_progress);
    } else if ((num = m_data_model.analyze_autoconfig_renew(evt, pcmd)) == 0) {
        m_agent_cmd->send_result(em_cmd_out_status_no_change);
    } else if (m_orch->submit_commands(pcmd, num) > 0) {
        m_agent_cmd->send_result(em_cmd_out_status_success);
    } else {
        m_agent_cmd->send_result(em_cmd_out_status_not_ready);
    }

}

void em_agent_t::handle_bus_event(em_bus_event_t *evt)
{   
    
    switch (evt->type) {
        case em_bus_event_type_dev_init:
            handle_dev_init(evt);
            break;
        case em_bus_event_type_cfg_renew:
            handle_autoconfig_renew(evt);
            break;
        case em_bus_event_type_radio_config:
            handle_radio_config(evt);
            break;

        case em_bus_event_type_vap_config:
            handle_vap_config(evt);
            break;

        case em_bus_event_type_sta_list:
            handle_sta_list(evt);
            break;

        case em_bus_event_type_ap_cap_query:
            handle_ap_cap_query(evt);
            break;

        case em_bus_event_type_client_cap_query:
	        handle_client_cap_query(evt);
	        break;

        case em_bus_event_type_onewifi_private_subdoc:
			handle_onewifi_private_subdoc(evt);
			break;

        case em_bus_event_type_assoc_sta_link_metrics:
            handle_assoc_sta_link_metrics(evt);
            break;

        default:
            break;
    }    
}

void em_agent_t::handle_event(em_event_t *evt)
{
    switch(evt->type) {
        case em_event_type_frame:
            handle_frame_event(&evt->u.fevt);
            break;

        case em_event_type_bus:
            handle_bus_event(&evt->u.bevt);
            break;

        default:
            break;
    }

}

void em_agent_t::handle_timeout()
{
    m_orch->handle_timeout();
}

//TODO: Remove below test code later
char *assoc_clients = "{\n"
"  \"Version\": \"1.0\",\n"
"  \"SubDocName\": \"associated clients\",\n"
"  \"WiFiAssociatedClients\": [\n"
"    {\n"
"      \"VapName\": \"private_ssid_2g\",\n"
"      \"associatedClients\": [\n"
"        {\n"
"          \"MACAddress\": \"16:24:75:c1:79:0f\",\n"
"          \"WpaKeyMgmt\": \"\",\n"
"          \"PairwiseCipher\": \"\",\n"
"          \"AuthenticationState\": true,\n"
"          \"LastDataDownlinkRate\": 780,\n"
"          \"LastDataUplinkRate\": 6,\n"
"          \"SignalStrength\": -46,\n"
"          \"Retransmissions\": 13,\n"
"          \"Active\": true,\n"
"          \"OperatingStandard\": \"ac\",\n"
"          \"OperatingChannelBandwidth\": \"80\",\n"
"          \"SNR\": 45,\n"
"          \"InterferenceSources\": \"\",\n"
"          \"DataFramesSentAck\": 411,\n"
"          \"DataFramesSentNoAck\": 0,\n"
"          \"BytesSent\": 240132,\n"
"          \"BytesReceived\": 121062,\n"
"          \"RSSI\": -46,\n"
"          \"MinRSSI\": 0,\n"
"          \"MaxRSSI\": 0,\n"
"          \"Disassociations\": 0,\n"
"          \"AuthenticationFailures\": 0,\n"
"          \"PacketsSent\": 411,\n"
"          \"PacketsReceived\": 818,\n"
"          \"ErrorsSent\": 0,\n"
"          \"RetransCount\": 13,\n"
"          \"FailedRetransCount\": 0,\n"
"          \"RetryCount\": 5,\n"
"          \"MultipleRetryCount\": 0\n"
"        }\n"
"      ]\n"
"    }\n"
"  ]\n"
"}";

void em_agent_t::input_listener()
{
    wifi_bus_desc_t *desc;
    dm_easy_mesh_t dm;
    em_event_t evt;
    em_bus_event_t *bevt;
    raw_data_t data;

    bus_init(&m_bus_hdl);

    if((desc = get_bus_descriptor()) == NULL) {
        printf("%s:%d descriptor is null\n", __func__, __LINE__);
    }

    if (desc->bus_open_fn(&m_bus_hdl, "EasyMesh_service") != 0) {
        printf("%s:%d bus open failed\n",__func__, __LINE__);
        return;
    }

    printf("%s:%d he_bus open success\n", __func__, __LINE__);

    memset(&data, 0, sizeof(raw_data_t));

    if (desc->bus_get_fn(&m_bus_hdl, WIFI_WEBCONFIG_INIT_DML_DATA, &data) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    } else {
        printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data.raw_data.bytes);
    }

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_dev_init;
    memcpy(bevt->u.raw_buff, data.raw_data.bytes, data.raw_data_len);

    g_agent.agent_input(&evt);

    printf("%s:%d: Enter\n", __func__, __LINE__);
    if (desc->bus_event_subs_fn(&m_bus_hdl, WIFI_WEBCONFIG_GET_ASSOC, (void *)&em_agent_t::sta_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    if (desc->bus_event_subs_fn(&m_bus_hdl, WIFI_COLLECT_STATS_ASSOC_DEVICE_STATS, (void *)&em_agent_t::assoc_stats_cb, NULL, 0) != 0) {
        printf("%s:%d bus get failed\n", __func__, __LINE__);
        return;
    }

    //TODO: Remove below test code later
    pthread_t t_assoc_clients;

    // Create a new thread that will run the delayed_function
    if (pthread_create(&t_assoc_clients, NULL,em_agent_t::assoc_clients_f, NULL) != 0) {
        fprintf(stderr, "Error creating thread\n");
        return ;
    }

    pthread_detach(t_assoc_clients);

    io(NULL);
}

int em_agent_t::sta_cb(char *event_name, raw_data_t *data)
{
    printf("%s:%d Recv data from onewifi:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    em_event_t evt;
    em_bus_event_t *bevt;

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_sta_list;
    memcpy(bevt->u.raw_buff, data->raw_data.bytes, data->raw_data_len);

    g_agent.agent_input(&evt);

}

//TODO: Remove below test code later
void* em_agent_t::assoc_clients_f(void* arg) {
    sleep(10);
    printf("\n[DEBUG]: Function called after 10 seconds- aSSOC CLIENTS\n");

    em_event_t evt;
    em_bus_event_t *bevt;

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_sta_list;
    memcpy(bevt->u.raw_buff, assoc_clients, strlen(assoc_clients)+1);

    g_agent.agent_input(&evt);

    //START assoc dev stats
    pthread_t t_assoc_stats;

    // Create a new thread that will run the delayed_function
    if (pthread_create(&t_assoc_stats, NULL, em_agent_t::assoc_stats, NULL) != 0) {
        fprintf(stderr, "Error creating thread\n");
    }

    pthread_detach(t_assoc_stats);
}

//TODO: Remove below test code later
void* em_agent_t::assoc_stats(void* arg) {
    sleep(15);
    printf("\n[DEBUG]: Function called after 15 seconds\n");
    const char* jsonString = "{\n"
"    \"Version\": \"1.0\",\n"
"    \"SubDocName\": \"Associated_Device_Stats\",\n"
"    \"VapIndex\": 1,\n"
"    \"AssociatedDeviceStats\": [\n"
"        {\n"
"            \"cli_MACAddress\": \"16:24:75:c1:79:0f\",\n"
"            \"cli_IPAddress\": \"192.168.1.20\",\n"
"            \"cli_AuthenticationState\": true,\n"
"            \"cli_LastDataDownlinkRate\": 72,\n"
"            \"cli_LastDataUplinkRate\": 72,\n"
"            \"cli_SignalStrength\": -13,\n"
"            \"cli_Retransmissions\": 0,\n"
"            \"cli_Active\": true,\n"
"            \"cli_OperatingStandard\": \"n\",\n"
"            \"cli_OperatingChannelBandwidth\": \"20\",\n"
"            \"cli_SNR\": 79,\n"
"            \"cli_InterferenceSources\": \"xyz\",\n"
"            \"cli_DataFramesSentAck\": 24,\n"
"            \"cli_DataFramesSentNoAck\": 0,\n"
"            \"cli_BytesSent\": 32902,\n"
"            \"cli_BytesReceived\": 33620,\n"
"            \"cli_RSSI\": -13,\n"
"            \"cli_MinRSSI\": 0,\n"
"            \"cli_MaxRSSI\": 0,\n"
"            \"cli_Disassociations\": 0,\n"
"            \"cli_AuthenticationFailures\": 0,\n"
"            \"cli_Associations\": 1,\n"
"            \"cli_PacketsSent\": 24,\n"
"            \"cli_PacketsReceived\": 215,\n"
"            \"cli_ErrorsSent\": 0,\n"
"            \"cli_RetransCount\": 0,\n"
"            \"cli_FailedRetransCount\": 0,\n"
"            \"cli_RetryCount\": 0,\n"
"            \"cli_MultipleRetryCount\": 0,\n"
"            \"cli_MaxDownlinkRate\": 72,\n"
"            \"cli_MaxUplinkRate\": 72,\n"
"            \"cli_activeNumSpatialStreams\": 1,\n"
"            \"cli_TxFrames\": 254,\n"
"            \"cli_RxRetries\": 1,\n"
"            \"cli_RxErrors\": 0\n"
"        }\n"
"    ]\n"
"}";

    cJSON *json_test = cJSON_Parse(jsonString);
    char *formattedJson = cJSON_Print(json_test);

    printf("\n%s:%d ASSOC STATS data:\r\n%s\r\n", __func__, __LINE__, (char *)jsonString);

    em_event_t evt;
    em_bus_event_t *bevt;

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_assoc_sta_link_metrics;
    memcpy(bevt->u.raw_buff, jsonString, strlen(jsonString)+1);

    g_agent.agent_input(&evt);
}

int em_agent_t::assoc_stats_cb(char *event_name, raw_data_t *data)
{
    printf("%s:%d recv data:\r\n%s\r\n", __func__, __LINE__, (char *)data->raw_data.bytes);
    em_event_t evt;
    em_bus_event_t *bevt;

    bevt = &evt.u.bevt;
    bevt->type = em_bus_event_type_sta_list;
    memcpy(bevt->u.raw_buff, data->raw_data.bytes, data->raw_data_len);

    g_agent.agent_input(&evt);

    return 1;
}


int em_agent_t::data_model_init(const char *data_model_path)
{
    if (data_model_path != NULL) {
        snprintf(m_data_model_path, sizeof(m_data_model_path), "%s", data_model_path);
    } else {
        m_data_model_path[0] = 0;
    }

    if (m_data_model.init() != 0) {
        printf("%s:%d: data model init failed\n", __func__, __LINE__);
        return -1;
    }

    m_agent_cmd = new em_cmd_agent_t();

    return 0;
}

int em_agent_t::orch_init()
{
    m_orch = new em_orch_agent_t(this);
    return 0;
}

em_t *em_agent_t::find_em_for_msg_type(unsigned char *data, unsigned int len, em_t *al_em)
{
    em_raw_hdr_t *hdr;
    em_cmdu_t *cmdu;
    em_interface_t intf;
    em_freq_band_t band;
    dm_easy_mesh_t *dm;
    em_t *em = NULL;
    em_radio_id_t ruid;
    em_profile_type_t profile;
    mac_addr_str_t mac_str1, mac_str2;
	bool found = false;

    assert(len > ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))));
    if (len < ((sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)))) {
        return NULL;
    }
   
    hdr = (em_raw_hdr_t *)data;

    if (hdr->type != htons(ETH_P_1905)) {
        return NULL;
    }
   
    cmdu = (em_cmdu_t *)(data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
		case em_msg_type_autoconf_resp:
		case em_msg_type_autoconf_renew:
			if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                    len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_freq_band(&band) == false) {
            	printf("%s:%d: Could not find frequency band\n", __func__, __LINE__);
            	return NULL;
        	}
			
			em = (em_t *)hash_map_get_first(m_em_map);
        	while (em != NULL) {
            	if (em->is_matching_freq_band(&band) == true) {
                	found = true;
                	break;
            	}
            	em = (em_t *)hash_map_get_next(m_em_map, em);
        	}  

        	if (found == false) {
            	printf("%s:%d: Could not find em with matching band%d\n", __func__, __LINE__, band);
            	return NULL;
        	}

			break;

		case em_msg_type_autoconf_wsc:
			if (em_msg_t(data + (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t)),
                len - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t))).get_radio_id(&ruid) == false) {
				return NULL;
			}

			dm_easy_mesh_t::macbytes_to_string(ruid, mac_str1);
        	if ((em = (em_t *)hash_map_get(m_em_map, mac_str1)) != NULL) {
            	printf("%s:%d: Found existing radio:%s\n", __func__, __LINE__, mac_str1);
            	em->set_state(em_state_ctrl_wsc_m1_pending);
        	} else {
				return NULL;
			}
			break;

        case em_msg_type_autoconf_search:
        case em_msg_type_topo_query:
            break;

		default:
            printf("%s:%d: Frame: %d not handled in agent\n", __func__, __LINE__, htons(cmdu->type));
            assert(0);
            break;	
	}

	return em;
}

em_agent_t::em_agent_t()
{

}

em_agent_t::~em_agent_t()
{

}

int main(int argc, const char *argv[])
{
    if (g_agent.init(argv[1]) == 0) {
        g_agent.start();
    }

    return 0;
}

