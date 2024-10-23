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
#include <unordered_map>
#include <string>
#include "em_cmd_dev_init.h"
#include "dm_easy_mesh_agent.h"
#include <cjson/cJSON.h>
#include "em_cmd_sta_list.h"
#include "em_cmd_assoc_sta_link_metrics.h"
#include "em_cmd_onewifi_cb.h"

int dm_easy_mesh_agent_t::analyze_dev_init(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int index = 0;
    unsigned int num = 0, i, j = 0, num_radios = 0;
    em_orch_desc_t desc;
    dm_easy_mesh_agent_t  dm;
    dm_device_t *dev, *tgt_dev;
    dm_radio_t *rd, *tgt_rd;
    em_cmd_t *tmp;
    dm.translate_onewifi_dml_data(evt->u.raw_buff);

    num_radios = dm.get_num_radios();
    printf("%s:%d: Number of radios: %d\n", __func__, __LINE__, num_radios);
    pcmd[num] = new em_cmd_dev_init_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    return num;

}

int dm_easy_mesh_agent_t::analyze_sta_list(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    unsigned int index = 0;
    em_orch_desc_t desc;
    //put hash_map for dm_pcmd from this object
    mac_address_t radio_macaddr, temp_rmacaddr;
    dm_sta_t *get_sta = NULL;
    //To map radio MAC addresses to pcmd instances
    std::unordered_map<std::string, int> mac_to_index_map;
    int count = 0;

    printf("%s:%d:Enter str=%s\n", __func__, __LINE__,evt->u.raw_buff);

    translate_onewifi_stats_data(evt->u.raw_buff);

#if 0
    desc.op = dm_orch_type_sta_update;
    //pcmd[0] =  new em_cmd_sta_list_t(evt->params,dm);
    pcmd[0] =  new em_cmd_sta_list_t(evt->params,*this);
    pcmd[0]->override_op(0, &desc);
#endif
    desc.op = dm_orch_type_sta_update;

    dm_easy_mesh_agent_t  *dm = this;
    dm_easy_mesh_agent_t* dm_pcmd = new dm_easy_mesh_agent_t[2];

    hash_map_t **ptr_sta_map = dm->get_assoc_sta_map();

    if ((ptr_sta_map != NULL) && (*ptr_sta_map != NULL)) {

        get_sta = (dm_sta_t *)hash_map_get_first(*ptr_sta_map);

        while (get_sta != NULL) {
            dm_sta_t put_sta;

            memcpy(&temp_rmacaddr, put_sta.get_sta_info()->radiomac, 6);
    	    memcpy(&radio_macaddr, get_sta->get_sta_info()->radiomac, sizeof(mac_address_t));
            std::string mac_str(reinterpret_cast<char*>(&radio_macaddr), sizeof(mac_address_t));
            if ((mac_to_index_map.find(mac_str) == mac_to_index_map.end()) == true)
            {
                //returned true, means its a new rmac and was not processed earlier
                //so use a new dm object, as in new hash_map.
                mac_addr_str_t dst_mac_str;
                dm_easy_mesh_t::macbytes_to_string(radio_macaddr, dst_mac_str);
                printf("%s:%d radio_macaddr MAC=%s\n", __func__, __LINE__,dst_mac_str);
                dm_easy_mesh_t::macbytes_to_string(temp_rmacaddr, dst_mac_str);
                printf("%s:%d temp_rmacaddr MAC=%s\n", __func__, __LINE__,dst_mac_str);
                if (memcmp(&radio_macaddr, &temp_rmacaddr, sizeof(mac_address_t)) == 0) {
                    index = index + 1;
                    mac_to_index_map[mac_str] = index; // Map the MAC address to the index
                    count = mac_to_index_map[mac_str];
                } else {
                    mac_to_index_map[mac_str] = index; // Map the MAC address to the index
                    count = mac_to_index_map[mac_str];
                }
                hash_map_t **put_hm = dm_pcmd[count].get_assoc_sta_map();
                if (*put_hm == NULL)
                {
                    *put_hm = hash_map_create();
                }
                em_sta_info_t *em_sta;
                em_sta = get_sta->get_sta_info();
                hash_map_put(*put_hm, strdup(put_sta.get_sta_info()->m_sta_key), new dm_sta_t(em_sta));
            }
            else
            {
                // Use the existing index for this MAC address
                // since it already has an index, get the index based on rmac to push to same hash_map
                count = mac_to_index_map[mac_str];
                hash_map_t **put_hm = dm_pcmd[count].get_assoc_sta_map();
                if(*put_hm == NULL)
                {
                    *put_hm = hash_map_create();
                }
                em_sta_info_t *em_sta;
                em_sta = get_sta->get_sta_info();
                hash_map_put(*put_hm, strdup(put_sta.get_sta_info()->m_sta_key), new dm_sta_t(em_sta));
            }
            mac_addr_str_t  rad_str_mac;
            macbytes_to_string(radio_macaddr, rad_str_mac);

            get_sta = (dm_sta_t *)hash_map_get_next(*ptr_sta_map, get_sta);
        }
        printf("%s:%d:[DEBUG] DM objects created\n", __func__, __LINE__);
    }

    //pcmd cmd create code
    for (int i = 0; i <= count; i++)
    {
        hash_map_t **test_map = dm_pcmd[i].get_assoc_sta_map();
        //push all in a loop now for the number of indexes
        pcmd[i] = new em_cmd_sta_list_t(evt->params, dm_pcmd[i]);
        pcmd[i]->override_op(0, &desc);
        printf("%s:%d:[DEBUG] Pushed to PCMD for index %d\n",__func__, __LINE__, i);
    }

    return 1;
}

int dm_easy_mesh_agent_t::analyze_assoc_sta_link_metrics(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    printf("%s:%d Enter func\n", __func__, __LINE__);
    em_orch_desc_t desc;

    webconfig_t config;
    webconfig_external_easymesh_t extdata = {0};
    webconfig_subdoc_type_t type = webconfig_subdoc_type_assocdev_stats;

    webconfig_proto_easymesh_init(&extdata, this, get_num_radios, set_num_radios,\
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,\
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,\
            get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);


    printf("[DEBUG]: addr of this %p\n", *this);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    if ((webconfig_easymesh_decode(&config, evt->u.raw_buff, &extdata, &type)) == webconfig_error_none) {
        printf("%s:%d assoc sta Link metrics decode success:\n%s\n",__func__, __LINE__, evt->u.raw_buff);
    } else {
        printf("%s:%d assoc sta link metrics decode fail\n",__func__, __LINE__);
    }

    /*desc.op = dm_orch_type_assoc_sta_link_metrics_report;
    desc.submit = true;
    //dm.decode_assoc_sta_metrics(subdoc, 0);
    //dm_easy_mesh_agent_t  *dm = this;
    pcmd[0] = new em_cmd_assoc_sta_link_metrics_t(evt->params, *this);
    //pcmd[0] = new em_cmd_assoc_sta_link_metrics_t(evt->params, *dm);
    pcmd[0]->override_op(0, &desc);*/

    return 1;
}

int dm_easy_mesh_agent_t::analyze_assoc_sta_link_metrics_query(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    printf("%s:%d:{DEBUG} START\n", __func__, __LINE__);
    dm_easy_mesh_t  dm;
    em_orch_desc_t desc;
    em_subdoc_info_t *subdoc;
    mac_addr_str_t cli_macstr, radio_str_mac;
    mac_address_t cli_mac, radio_mac;
    mac_address_t test = {0x16,0x24,0x75,0xc1,0x79,0x0f};
    mac_addr_str_t mac_str;

    desc.op = dm_orch_type_assoc_sta_link_metrics_report;
    desc.submit = true;

    subdoc = &evt->u.subdoc;

    dm_sta_t *sta = new dm_sta_t();;
    hash_map_t **m_sta_map = (hash_map_t **)dm.get_sta_map();

    *m_sta_map = hash_map_create();

    dm.decode_assoc_sta_metrics_query(subdoc, "AssocLinkMetrics", cli_macstr);
        printf("%s:%d:{DEBUG} here\n", __func__, __LINE__);
    string_to_macbytes(cli_macstr, cli_mac);
    //string_to_macbytes(cli_macstr, cli_mac);
    //string_to_macbytes(radio_str_mac, radio_mac);
    printf("%s:%d: StaList msg id %d\n", __func__, __LINE__,dm.msg_id);
    printf("%s:%d: client mac %s\n", __func__, __LINE__,cli_macstr);
    //printf("%s:%d: Radio mac %s\n", __func__, __LINE__,radio_str_mac);

    memcpy(sta->get_sta_info()->id, &cli_mac, sizeof(mac_address_t));
    //memcpy(sta->get_sta_info()->bssid,&bss_mac,sizeof(mac_address_t)); TODO once cache is available
    hash_map_put(*m_sta_map, strdup(cli_macstr), sta);
    //memcpy(dm.m_radio[0].get_radio_info()->id.mac,&radio_mac,sizeof(mac_address_t));
    dm.m_num_radios = 1;

    //dm_easy_mesh_t::macbytes_to_string(dm.m_radio[0].get_radio_info()->id.mac,mac_str);//TODO: DEBUG

    pcmd[0] = new em_cmd_assoc_sta_link_metrics_t(evt->params, dm);
    pcmd[0]->override_op(0, &desc);
        printf("%s:%d:{DEBUG} here end\n", __func__, __LINE__);
    return 1;
}


void dm_easy_mesh_agent_t::translate_onewifi_dml_data (char *str)
{           
    webconfig_t config;
    webconfig_external_easymesh_t ext;
    webconfig_subdoc_type_t type;
    int num_radios,num_op,num_bss;
    unsigned int i = 0;
                
    webconfig_proto_easymesh_init(&ext, this, get_num_radios, set_num_radios, 
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);
    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply; 
                
    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return ;
                
    }           
                
    if ((webconfig_easymesh_decode(&config, str, &ext, &type)) == webconfig_error_none) {
        printf("%s:%d Dev-Init decode success\n",__func__, __LINE__);
    } else {       
        printf("%s:%d Dev-Init decode fail\n",__func__, __LINE__);
    }       
        
}
    
int dm_easy_mesh_agent_t::analyze_onewifi_private_subdoc(em_bus_event_t *evt, wifi_bus_desc_t *desc,bus_handle_t *bus_hdl)
{
    dm_orch_type_t op;
    em_subdoc_info_t *subdoc;
    unsigned int num_radios;
    subdoc = &evt->u.subdoc;
    em_event_t bus;
    webconfig_external_easymesh_t dev_data;
    webconfig_subdoc_type_t type = webconfig_subdoc_type_private;
    webconfig_apply_data_t temp;
    webconfig_t config;
    static char *webconfig_easymesh_raw_data_ptr;
    dm_easy_mesh_agent_t  dm;
    raw_data_t l_bus_data;
    unsigned int index = 0;
    raw_data_t data;

    printf("%s:%d: Enter\n", __func__, __LINE__);
    if ( dm.decode_config(subdoc, "dm_cache") == -1) {
        printf("%s:%d: Failed to decode\n", __func__, __LINE__);
        return 0;
    }
    num_radios = dm.get_num_radios();
    printf("%s:%d: Number of radios: %d\n", __func__, __LINE__, num_radios);
    memset(&data, 0, sizeof(raw_data_t));

    webconfig_proto_easymesh_init(&dev_data, &dm, get_num_radios, set_num_radios, 
				get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
				get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
				get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    printf("%s:%d New configuration SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,
	    dm.get_bss(index)->get_bss_info()->ssid,dm.get_bss(index)->get_bss_info()->sec_mode,dm.get_bss(index)->get_bss_info()->passphrase);

    if ((webconfig_easymesh_encode(&config, &dev_data, type, &webconfig_easymesh_raw_data_ptr )) == webconfig_error_none) {
        printf("%s:%d Private subdoc encode success %s\n",__func__, __LINE__,webconfig_easymesh_raw_data_ptr);
    } else {
        printf("%s:%d Private subdoc encode fail\n",__func__, __LINE__);
        return 0;
    }
    memset(&l_bus_data, 0, sizeof(raw_data_t));

    l_bus_data.data_type    = bus_data_type_string;
    l_bus_data.raw_data.bytes   = webconfig_easymesh_raw_data_ptr;
    l_bus_data.raw_data_len = strlen(webconfig_easymesh_raw_data_ptr);
    if (desc->bus_set_fn(bus_hdl, "Device.WiFi.WebConfig.Data.Subdoc.South", &l_bus_data)== 0) {
	printf("%s:%d private subdoc send successfull\n",__func__, __LINE__);
	printf("%s:%d Before commit config SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,
		get_bss(index)->get_bss_info()->ssid,get_bss(index)->get_bss_info()->sec_mode,get_bss(index)->get_bss_info()->passphrase);
    commit_config(dm,index,index,dm.m_num_radios,dm.m_num_bss);
	printf("%s:%d After commit SSID=%s Security mode=%d  passphrase=%s \n",__func__,__LINE__,get_bss(index)->get_bss_info()->ssid,
		get_bss(index)->get_bss_info()->sec_mode,get_bss(index)->get_bss_info()->passphrase);
    }
    else {
	printf("%s:%d private subdoc send fail\n",__func__, __LINE__);
	return -1;
    }
    return 1;
}

int dm_easy_mesh_agent_t::analyze_onewifi_cb(em_bus_event_t *evt, em_cmd_t *pcmd[])
{
    webconfig_t config;
    webconfig_external_easymesh_t ext;
    webconfig_subdoc_type_t type;
    int num = 0;
    unsigned int i = 0, j = 0;
    dm_easy_mesh_agent_t  dm;
    em_cmd_t *tmp;
    webconfig_proto_easymesh_init(&ext, &dm, get_num_radios, set_num_radios,
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info, get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);
    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;
    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return 0;
    }

    if ((webconfig_easymesh_decode(&config, evt->u.raw_buff, &ext, &type)) == webconfig_error_none) {
        printf("%s:%d Private subdoc decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d Private subdoc decode fail\n",__func__, __LINE__);
    }

    for (i = 0; i < m_num_bss; i++) {
        for (j = 0; j < dm.m_num_bss; j++) {
           if (memcmp(get_bss(i)->get_bss_info()->ruid.mac, dm.get_bss(j)->get_bss_info()->ruid.mac, sizeof(mac_address_t)) == 0) {
               if (memcmp(get_bss(i)->get_bss_info()->bssid.mac, dm.get_bss(j)->get_bss_info()->bssid.mac, sizeof(mac_address_t)) == 0) {
                   commit_bss_config(dm, j);
               }
           }
       }
    }

    pcmd[num] = new em_cmd_ow_cb_t(evt->params, dm);
    tmp = pcmd[num];
    num++;

    while ((pcmd[num] = tmp->clone_for_next()) != NULL) {
        tmp = pcmd[num];
        num++;
    }
    return num;
}
        
void dm_easy_mesh_agent_t::translate_onewifi_sta_data(char *str)
{               
                
}               
                    
void dm_easy_mesh_agent_t::translate_onewifi_stats_data(char *str)
{
    printf("%s:%d: Enter\n", __func__, __LINE__);

    webconfig_t config;
    webconfig_external_easymesh_t extdata = {0};
    webconfig_subdoc_type_t type;

    webconfig_proto_easymesh_init(&extdata, this, get_num_radios, set_num_radios, 
            get_num_op_class, set_num_op_class, get_num_bss, set_num_bss,
            get_device_info, get_network_info, get_radio_info, get_ieee_1905_security_info, get_bss_info, get_op_class_info,
			get_first_sta_info, get_next_sta_info, get_sta_info, put_sta_info);

    config.initializer = webconfig_initializer_onewifi;
    config.apply_data =  webconfig_dummy_apply;

    if (webconfig_init(&config) != webconfig_error_none) {
        printf( "[%s]:%d Init WiFi Web Config  fail\n",__func__,__LINE__);
        return ;

    }

    if ((webconfig_easymesh_decode(&config, str, &extdata, &type)) == webconfig_error_none) {
        printf("%s:%d Assoc clients decode success\n",__func__, __LINE__);
    } else {
        printf("%s:%d Assoc clients decode fail\n",__func__, __LINE__);
    }
}

webconfig_error_t dm_easy_mesh_agent_t::webconfig_dummy_apply(webconfig_subdoc_t *doc, webconfig_subdoc_data_t *data)
{       
    return webconfig_error_none;
}   

dm_easy_mesh_agent_t::dm_easy_mesh_agent_t()
{

}

dm_easy_mesh_agent_t::~dm_easy_mesh_agent_t()
{

}
