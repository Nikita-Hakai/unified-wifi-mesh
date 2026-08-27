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

#include <string.h>
#include "dm_sta.h"
#include "dm_easy_mesh.h"
#include "em_vendor.h"
#include "lq_socket.h"

class em_vendor_ctrl_t : public em_vendor_ext_interface_t {
public:
    int handle_vendor_tlv_ext(const unsigned char *tlv_value,
                               unsigned int         tlv_len,
                               dm_easy_mesh_t      *dm) override;

private:
    void publish_wei_app(wei_data_t wei_data);
    // static void wei_app_cb();
};