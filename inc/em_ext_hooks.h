/**
 * Copyright 2026 Comcast Cable Communications Management, LLC
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

#ifndef EM_EXT_HOOKS_H
#define EM_EXT_HOOKS_H

#include "em_base.h"

class em_t;

/**
 * Extension point that lets an out-of-tree component hook into the
 * controller and agent, without UWM knowing what that component does.
 * Every default keeps the stock behaviour, so UWM is unchanged unless an
 * extension registers itself with em_register_ext_hooks().
 */
class em_ext_hooks_t {
public:
    virtual ~em_ext_hooks_t() = default;

    // Controller: offered the whole command line before UWM reads it. The extension may remove
    // the arguments it consumed by shifting the rest down (argv[0] stays, argv[*argc] must stay
    // NULL) and lowering *argc. Return false to abort startup.
    virtual bool process_cli_args(int *argc, const char *argv[]) { return true; }

    // Appends extra TLVs to the outgoing message of type msg_type at buff, right before
    // the end of message TLV. Returns the number of bytes written (0 if nothing appended).
    virtual unsigned int append_tlvs(em_msg_type_t msg_type, unsigned char *buff) { return 0; }
    // Offered every TLV (type, value, value length) of an incoming message of type msg_type.
    virtual void handle_tlv(em_msg_type_t msg_type, unsigned char tlv_type, const unsigned char *val, unsigned short len) {}

    // Agent: offered every event bound for OneWifi before the caller sends it.
    // Return true if the extension handled it; the caller then does nothing further.
    virtual bool intercept_agent_event(em_t *em, em_bus_event_type_t type, unsigned char *data, unsigned int len) { return false; }
    // Agent: lowest em state from which a radio counts as configured.
    virtual em_state_t agent_configured_state() { return em_state_agent_onewifi_bssconfig_ind; }
    // Controller: final say on whether a BSS SSID reported by an agent is accepted.
    virtual bool accept_bss_ssid(bool matches_network) { return matches_network; }

    // Controller: true means the topology is published right after the topology sync of an
    // em_config command, instead of at the end of it.
    virtual bool publish_topology_early() { return false; }
};

inline em_ext_hooks_t *&em_ext_hooks_slot()
{
    static em_ext_hooks_t default_hooks;
    static em_ext_hooks_t *current = &default_hooks;
    return current;
}

inline em_ext_hooks_t *em_get_ext_hooks()
{
    return em_ext_hooks_slot();
}

inline void em_register_ext_hooks(em_ext_hooks_t *hooks)
{
    if (hooks != NULL) {
        em_ext_hooks_slot() = hooks;
    }
}

#endif
