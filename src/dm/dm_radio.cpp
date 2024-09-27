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
#include "dm_radio.h"
#include "dm_easy_mesh.h"
#include "dm_easy_mesh_ctrl.h"



int dm_radio_t::decode(const cJSON *obj, void *parent_id)
{
    cJSON *tmp;
    mac_addr_str_t  mac_str = {0};

    mac_address_t *dev_id = (mac_address_t *)parent_id;

    memset(&m_radio_info, 0, sizeof(em_radio_info_t));

    if ((tmp = cJSON_GetObjectItem(obj, "ID")) != NULL) {
        snprintf(mac_str, sizeof(mac_str), "%s", cJSON_GetStringValue(tmp));
        dm_easy_mesh_t::string_to_macbytes(mac_str, m_radio_info.id.mac);
        dm_easy_mesh_t::name_from_mac_address(&m_radio_info.id.mac, m_radio_info.id.name);
    }

    printf("%s:%d: Radio: %s\n", __func__, __LINE__, mac_str);

    //memcpy(&m_radio_info.dev_id.mac, dev_id, sizeof(mac_address_t));

    if ((tmp = cJSON_GetObjectItem(obj, "Enabled")) != NULL) {
        m_radio_info.enabled = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfBSS")) != NULL) {
        m_radio_info.number_of_bss = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfUnassocSta")) != NULL) {
        m_radio_info.number_of_unassoc_sta = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Noise")) != NULL) {
        m_radio_info.noise = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "Utilization")) != NULL) {
        m_radio_info.utilization = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "NumberOfCurrOpClass")) != NULL) {
        m_radio_info.number_of_curr_op_classes = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TrafficSeparationCombinedFronthaul")) != NULL) {
        m_radio_info.traffic_sep_combined_fronthaul = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "TrafficSeparationCombinedBackhaul")) != NULL) {
        m_radio_info.traffic_sep_combined_backhaul = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "SteeringPolicy")) != NULL) {
        m_radio_info.steering_policy = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ChannelUtilizationThreshold")) != NULL) {
        m_radio_info.channel_util_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "RCPISteeringThreshold")) != NULL) {
        m_radio_info.rcpi_steering_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "STAReportingRCPIThreshold")) != NULL) {
        m_radio_info.sta_reporting_rcpi_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "STAReportingRCPIHysteresisMarginOverride")) != NULL) {
        m_radio_info.sta_reporting_hysteresis_margin_override = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ChannelUtilizationReportingThreshold")) != NULL) {
        m_radio_info.channel_utilization_reporting_threshold = tmp->valuedouble;
    }

    if ((tmp = cJSON_GetObjectItem(obj, "AssociatedSTATrafficStatsInclusionPolicy")) != NULL) {
        m_radio_info.associated_sta_traffic_stats_inclusion_policy = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "AssociatedSTALinkMetricsInclusionPolicy")) != NULL) {
        m_radio_info.associated_sta_link_mterics_inclusion_policy = cJSON_IsTrue(tmp);
    }

    if ((tmp = cJSON_GetObjectItem(obj, "ChipsetVendor")) != NULL) {
        snprintf(m_radio_info.chip_vendor, sizeof(m_radio_info.chip_vendor), "%s", cJSON_GetStringValue(tmp));
    }

    if ((tmp = cJSON_GetObjectItem(obj, "APMetricsWiFi6")) != NULL) {
        m_radio_info.ap_metrics_wifi6 = cJSON_IsTrue(tmp);
    }

    return 0;
}

void dm_radio_t::encode(cJSON *obj)
{
    mac_addr_str_t  mac_str;

    dm_easy_mesh_t::macbytes_to_string(m_radio_info.id.mac, mac_str);
    cJSON_AddStringToObject(obj, "ID", mac_str);

    cJSON_AddBoolToObject(obj, "Enabled", m_radio_info.enabled);
    cJSON_AddNumberToObject(obj, "NumberOfBSS", m_radio_info.number_of_bss);
    cJSON_AddNumberToObject(obj, "NumberOfUnassocSta", m_radio_info.number_of_unassoc_sta);
    cJSON_AddNumberToObject(obj, "Noise", m_radio_info.noise);
    cJSON_AddNumberToObject(obj, "Utilization", m_radio_info.utilization);
    cJSON_AddNumberToObject(obj, "NumberOfCurrOpClass", m_radio_info.number_of_curr_op_classes);
    cJSON_AddBoolToObject(obj, "TrafficSeparationCombinedFronthaul", m_radio_info.traffic_sep_combined_fronthaul);
    cJSON_AddBoolToObject(obj, "TrafficSeparationCombinedBackhaul", m_radio_info.traffic_sep_combined_backhaul);
    cJSON_AddNumberToObject(obj, "SteeringPolicy", m_radio_info.steering_policy);
    cJSON_AddNumberToObject(obj, "ChannelUtilizationThreshold", m_radio_info.channel_util_threshold);
    cJSON_AddNumberToObject(obj, "RCPISteeringThreshold", m_radio_info.rcpi_steering_threshold);
    cJSON_AddNumberToObject(obj, "STAReportingRCPIThreshold", m_radio_info.sta_reporting_rcpi_threshold);
    cJSON_AddNumberToObject(obj, "STAReportingRCPIHysteresisMarginOverride", m_radio_info.sta_reporting_hysteresis_margin_override);
    cJSON_AddNumberToObject(obj, "ChannelUtilizationReportingThreshold", m_radio_info.channel_utilization_reporting_threshold);
    cJSON_AddBoolToObject(obj, "AssociatedSTATrafficStatsInclusionPolicy", m_radio_info.associated_sta_traffic_stats_inclusion_policy);
    cJSON_AddBoolToObject(obj, "AssociatedSTALinkMetricsInclusionPolicy", m_radio_info.associated_sta_link_mterics_inclusion_policy);
    cJSON_AddStringToObject(obj, "ChipsetVendor", m_radio_info.chip_vendor);
    cJSON_AddBoolToObject(obj, "APMetricsWiFi6", m_radio_info.ap_metrics_wifi6);
}

dm_orch_type_t dm_radio_t::get_dm_orch_type(const dm_radio_t& radio)
{
    if ( this == &radio) {
        dm_orch_type_none;
    } else {
        return dm_orch_type_rd_update;
    }
    return dm_orch_type_rd_insert;
}

bool dm_radio_t::operator == (const dm_radio_t& obj) {   

    int ret = 0;
    ret += (memcmp(&this->m_radio_info.id.mac ,&obj.m_radio_info.id.mac,sizeof(mac_address_t)) != 0);
    ret += (memcmp(&this->m_radio_info.id.name,&obj.m_radio_info.id.name,sizeof(em_interface_name_t)) != 0);
    ret += !(this->m_radio_info.enabled == obj.m_radio_info.enabled);
    ret += !(this->m_radio_info.number_of_bss == obj.m_radio_info.number_of_bss);
    ret += !(this->m_radio_info.number_of_unassoc_sta == obj.m_radio_info.number_of_unassoc_sta);
    ret += !(this->m_radio_info.noise == obj.m_radio_info.noise);
    ret += !(this->m_radio_info.utilization == obj.m_radio_info.utilization);
    ret += !(this->m_radio_info.number_of_curr_op_classes == obj.m_radio_info.number_of_curr_op_classes);
    ret += !(this->m_radio_info.traffic_sep_combined_fronthaul == obj.m_radio_info.traffic_sep_combined_fronthaul);
    ret += !(this->m_radio_info.traffic_sep_combined_backhaul == obj.m_radio_info.traffic_sep_combined_backhaul);
    ret += !(this->m_radio_info.steering_policy == obj.m_radio_info.steering_policy);
    ret += !(this->m_radio_info.channel_util_threshold == obj.m_radio_info.channel_util_threshold);
    ret += !(this->m_radio_info.rcpi_steering_threshold == obj.m_radio_info.rcpi_steering_threshold);
    ret += !(this->m_radio_info.sta_reporting_rcpi_threshold == obj.m_radio_info.sta_reporting_rcpi_threshold);
    ret += !(this->m_radio_info.sta_reporting_hysteresis_margin_override  == obj.m_radio_info.sta_reporting_hysteresis_margin_override);
    ret += !(this->m_radio_info.channel_utilization_reporting_threshold  == obj.m_radio_info.channel_utilization_reporting_threshold);
    ret += !(this->m_radio_info.associated_sta_traffic_stats_inclusion_policy == obj.m_radio_info.associated_sta_traffic_stats_inclusion_policy);
    ret += !(this->m_radio_info.associated_sta_link_mterics_inclusion_policy == obj.m_radio_info.associated_sta_link_mterics_inclusion_policy);
    ret += (memcmp(&this->m_radio_info.chip_vendor,&obj.m_radio_info.chip_vendor,sizeof(em_long_string_t)) != 0);
    //ret += !(this->m_radio_info.ap_metrics_wifi6 == obj.m_radio_info.ap_metrics_wifi6);

    if (ret > 0)
        return false;
    else
        return true;
}

void dm_radio_t::operator = (const dm_radio_t& obj)
{
    memcpy(&this->m_radio_info.id.mac ,&obj.m_radio_info.id.mac,sizeof(mac_address_t));
    memcpy(&this->m_radio_info.id.name,&obj.m_radio_info.id.name,sizeof(em_interface_name_t));
    this->m_radio_info.enabled = obj.m_radio_info.enabled;
    this->m_radio_info.number_of_bss = obj.m_radio_info.number_of_bss;
    this->m_radio_info.number_of_unassoc_sta = obj.m_radio_info.number_of_unassoc_sta;
    this->m_radio_info.noise = obj.m_radio_info.noise;
    this->m_radio_info.utilization = obj.m_radio_info.utilization;
    this->m_radio_info.number_of_curr_op_classes = obj.m_radio_info.number_of_curr_op_classes;
    this->m_radio_info.traffic_sep_combined_fronthaul = obj.m_radio_info.traffic_sep_combined_fronthaul;
    this->m_radio_info.traffic_sep_combined_backhaul = obj.m_radio_info.traffic_sep_combined_backhaul;
    this->m_radio_info.steering_policy = obj.m_radio_info.steering_policy;
    this->m_radio_info.channel_util_threshold = obj.m_radio_info.channel_util_threshold;
    this->m_radio_info.rcpi_steering_threshold = obj.m_radio_info.rcpi_steering_threshold;
    this->m_radio_info.sta_reporting_rcpi_threshold = obj.m_radio_info.sta_reporting_rcpi_threshold;
    this->m_radio_info.sta_reporting_hysteresis_margin_override  = obj.m_radio_info.sta_reporting_hysteresis_margin_override;
    this->m_radio_info.channel_utilization_reporting_threshold  = obj.m_radio_info.channel_utilization_reporting_threshold;
    this->m_radio_info.associated_sta_traffic_stats_inclusion_policy = obj.m_radio_info.associated_sta_traffic_stats_inclusion_policy;
    this->m_radio_info.associated_sta_link_mterics_inclusion_policy = obj.m_radio_info.associated_sta_link_mterics_inclusion_policy;
    memcpy(&this->m_radio_info.chip_vendor,&obj.m_radio_info.chip_vendor,sizeof(em_long_string_t));
    //this->m_radio_info.ap_metrics_wifi6 = obj.m_radio_info.ap_metrics_wifi6;
}

dm_radio_t::dm_radio_t(em_radio_info_t *radio)
{
    memcpy(&m_radio_info, radio, sizeof(em_radio_info_t));
}

dm_radio_t::dm_radio_t(const dm_radio_t& radio)
{
    memcpy(&m_radio_info, &radio.m_radio_info, sizeof(em_radio_info_t));
}

dm_radio_t::dm_radio_t()
{

}

dm_radio_t::~dm_radio_t()
{

}
