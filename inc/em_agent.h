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

#ifndef EMAGNT_H
#define EMAGNT_H

#include "em.h"
#include "em_mgr.h"
#include "ieee80211.h"
#include "dm_easy_mesh_agent.h"
#include "em_crypto.h"
#include "em_orch_agent.h"
#include "bus.h"
#include "bus_common.h"

class em_cmd_agent_t;

class em_agent_t : public em_mgr_t {

    em_orch_agent_t *m_orch;
    dm_easy_mesh_agent_t m_data_model;
    em_short_string_t   m_data_model_path;
    em_cmd_agent_t  *m_agent_cmd;

    void io_run(char *buff);

    void handle_bus_event(em_bus_event_t *evt);
    void handle_action_frame(struct ieee80211_mgmt *frame);
    void handle_public_action_frame(struct ieee80211_mgmt *frame);
    void handle_vendor_public_action_frame(struct ieee80211_mgmt *frame);

public:

    bus_handle_t m_bus_hdl;

    void input_listener();

    int data_model_init(const char *data_model_path);
    bool    is_data_model_initialized() { return true; }

    int orch_init();

    void handle_timeout();
    void handle_event(em_event_t *evt);
    void handle_frame_event(em_frame_event_t *evt);

    void handle_dev_init(em_bus_event_t *evt);  
    void handle_radio_config(em_bus_event_t *evt);  
    void handle_vap_config(em_bus_event_t *evt);    
    void handle_sta_list(em_bus_event_t *evt);
    void handle_ap_cap_query(em_bus_event_t *evt);
    void handle_autoconfig_renew(em_bus_event_t *evt);
    void handle_client_cap_query(em_bus_event_t *evt);
    void handle_onewifi_private_subdoc(em_bus_event_t *evt);

    em_cmd_t& get_command(char *in);
    
    dm_easy_mesh_t *get_data_model(const char *net_id, const unsigned char *al_mac = NULL) { return &m_data_model; }
    dm_easy_mesh_t *create_data_model(const char *net_id, const unsigned char *al_mac, em_profile_type_t profile = em_profile_type_3) { return NULL; }
    void delete_data_model(const char *net_id, const unsigned char *al_mac) { }
    void delete_all_data_models() { }
    int update_tables(dm_easy_mesh_t *dm) { return 0; }
    int load_net_ssid_table() { return 0; }
    void debug_probe();

    em_service_type_t get_service_type() { return em_service_type_agent; }
    static bus_error_t bus_listener(bus_handle_t *handle, bus_event_sub_action_t action, char const* eventName, bus_filter_t filter, int32_t interval, bool* autoPublish);    
    //void io(char *buff);
    static int sta_cb(char *event_name, raw_data_t *data);
    void *get_assoc(void*);
    void io(void *data, bool input = true);
    bool agent_input(void *data);
    bool agent_output(void *data);
    
    em_agent_t();
    ~em_agent_t();

};

#endif
