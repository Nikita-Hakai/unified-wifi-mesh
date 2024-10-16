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

#ifndef EM_METRICS_H
#define EM_METRICS_H

#include "em_base.h"

class em_metrics_t {

    virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;

public:
    void process_msg(unsigned char *data, unsigned int len);
    void process_state();

    virtual void set_state(em_state_t state) = 0;
    virtual em_state_t get_state() = 0;
    virtual unsigned char *get_peer_mac() = 0;
    virtual unsigned char *get_al_interface_mac() = 0;
    virtual em_cmd_t *get_current_cmd() = 0;
    virtual dm_easy_mesh_t *get_data_model() = 0;

    int handle_assoc_sta_link_metrics_query(unsigned char* buff, unsigned int len);
    void handle_state_assoc_sta_link_metrics_resp();

    int create_assoc_sta_link_metrics_resp(unsigned char *buff);
    short create_error_code_tlv(unsigned char *buff);
    short create_assoc_sta_link_metrics_tlv(unsigned char *buff);
    short create_assoc_ext_sta_link_metrics_tlv(unsigned char *buff);

    em_metrics_t();
    ~em_metrics_t();

};

#endif
