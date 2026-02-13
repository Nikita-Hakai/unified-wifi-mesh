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
#include "em_logger.h"
#include "em_msg.h"
#include "dm_easy_mesh.h"
#include "em_cmd.h"
#include "util.h"
#include "em.h"
#include "em_cmd_exec.h"

static const unsigned char em_vendor_oui[EM_VENDOR_OUI_SIZE] = {0xd8, 0x9c, 0x8e};
// static const size_t EM_VENDOR_CHUNK_SIZE = 65535;  // Max chunk size per TLV
#define MAX_TLV_VALUE_SIZE 65535

static const size_t EM_VENDOR_CHUNK_SIZE =
    MAX_TLV_VALUE_SIZE
    - EM_VENDOR_OUI_SIZE
    - sizeof(uint8_t)              // vendor_data->num
    - sizeof(uint16_t)             // attr_id
    - sizeof(vendor_chunk_header_t);


// short em_logger_t::create_vendor_msg(uint8_t seq_num, uint8_t total_chunks, 
//                                             const unsigned char *chunk_data, size_t chunk_len)
short em_logger_t::create_vendor_msg(uint32_t transfer_id,
                                       uint16_t seq_num,
                                       uint16_t total_chunks,
                                       uint32_t offset,
                                       uint32_t total_size,
                                       const unsigned char *chunk_data,
                                       size_t chunk_len)
{
    size_t len = 0;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    unsigned short msg_type = em_msg_type_topo_vendor;
    size_t msg_len = 0;
    em_cmdu_t *cmdu;
    em_tlv_t *tlv;
    unsigned char *tmp = NULL;
    unsigned short type = htons(ETH_P_1905);
    dm_easy_mesh_t *dm = get_data_model();
    // Allocate buffer for entire message (tar + headers + overhead)
    size_t buf_size = chunk_len + 2048;
    unsigned char *buff = (unsigned char *)malloc(buf_size);
    if (!buff) {
        em_printfout("Failed to allocate buffer for vendor message: %zu bytes", buf_size);
        return 0;
    }
    memset(buff, 0, buf_size);
    tmp = buff;

    // Fill in header
    memcpy(tmp, dm->get_ctl_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    msg_len += sizeof(mac_address_t);

    memcpy(tmp, dm->get_agent_al_interface_mac(), sizeof(mac_address_t));
    tmp += sizeof(mac_address_t);
    msg_len += sizeof(mac_address_t);

    memcpy(tmp, reinterpret_cast<unsigned char *> (&type), sizeof(unsigned short));
    tmp += sizeof(unsigned short);
    msg_len += sizeof(unsigned short);

    cmdu = reinterpret_cast<em_cmdu_t *> (tmp);
    memset(tmp, 0, sizeof(em_cmdu_t));
    cmdu->type = htons(msg_type);
    cmdu->id = htons(get_mgr()->get_next_msg_id());
    cmdu->last_frag_ind = 1;
    tmp += sizeof(em_cmdu_t);
    msg_len += sizeof(em_cmdu_t);


    // Create vendor TLV for this chunk
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_vendor_specific;

    em_vendor_specific_t *vendor_data = reinterpret_cast<em_vendor_specific_t *> (tlv->value);
    memcpy(reinterpret_cast<char *> (vendor_data->vendor_oui), em_vendor_oui, EM_VENDOR_OUI_SIZE);

    em_printfout("vendor oui [%x, %x, %x], chunk %u of %u", 
                 vendor_data->vendor_oui[0], vendor_data->vendor_oui[1], vendor_data->vendor_oui[2],
                 seq_num, total_chunks);
    
    vendor_data->num = 1;

    em_vendor_data_t *data = reinterpret_cast<em_vendor_data_t *> (vendor_data->data);
    data->attr_id = vendor_ext_attr_id_ap_log;

    // msg_len += sizeof(data->attr_id);

    // vendor_chunk_header_t *chunks = reinterpret_cast<vendor_chunk_header_t *> (data->vendor_data);
    // chunks->seq_num = seq_num;
    // chunks->total_chunks = total_chunks;

    // // Add chunk data
    // if ((chunk_data != NULL) && (chunk_len > 0)) {
    //     memcpy(chunks->payload, chunk_data, chunk_len);
    //     len += static_cast<size_t> (chunk_len);
    //     em_printfout("Added chunk(seq) %u: %zu bytes and total len: %zu", seq_num, chunk_len, len);
    // } else {
    //     em_printfout("No chunk data to add for chunk_len:%zu", chunk_len);
     
    // }

    // tlv->len = htons(static_cast<unsigned short> (len));


    vendor_chunk_header_t *chunks =
        reinterpret_cast<vendor_chunk_header_t *>(data->vendor_data);

    chunks->transfer_id  = htonl(transfer_id);
    chunks->offset       = htonl(offset);
    chunks->total_chunks = htons(total_chunks);
    chunks->seq_num      = htons(seq_num);
    chunks->total_size   = htonl(total_size);

    if (chunk_data && chunk_len > 0) {
        memcpy(chunks->payload, chunk_data, chunk_len);
    }

    size_t vendor_payload_len =
        EM_VENDOR_OUI_SIZE +
        sizeof(vendor_data->num) +
        sizeof(data->attr_id) +
        sizeof(vendor_chunk_header_t) +
        chunk_len;

    tlv->len = htons((uint16_t)vendor_payload_len);

    len = vendor_payload_len;

    em_printfout(" tlv len: %u", ntohs(tlv->len));
    tmp += (sizeof(em_tlv_t) + static_cast<size_t> (len));
    msg_len += (sizeof(em_tlv_t) + static_cast<size_t> (len));



    // End of message TLV
    tlv = reinterpret_cast<em_tlv_t *> (tmp);
    tlv->type = em_tlv_type_eom;
    tlv->len = 0;
    tmp += sizeof(em_tlv_t);
    msg_len += sizeof(em_tlv_t);

    // Validate and send message
    if (em_msg_t(em_msg_type_topo_vendor, em_profile_type_2, buff, static_cast<unsigned int> (msg_len)).validate(errors) == 0) {
        printf("%s:%d: Topo Vendor Message validation failed\n", __func__, __LINE__);
        free(buff);
        return -1;
    }

    if (send_frame(buff, static_cast<unsigned int> (msg_len)) < 0) {
        printf("%s:%d: Topo Vendor Message send failed, error:%d\n", __func__, __LINE__, errno);
        free(buff);
        return -1;
    }

    em_printfout("Topo Vendor Message sent - chunk %u, chunk len:%zu and total len %zu", seq_num, len, msg_len);

    free(buff);
    return static_cast<short> (msg_len);
}

void em_logger_t::send_logs_msg()
{
    em_printfout("Sending vendor logs message with chunks...\n");

    // Determine tar file size and calculate chunks needed
    FILE *fp = fopen("/tmp/wifi_logs.tar.bz2", "rb");
    if (!fp) {
        em_printfout("Failed to open tar.bz2 file for reading");
        return;
    }
    
    fseek(fp, 0, SEEK_END);
    size_t tar_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (tar_size == 0) {
        em_printfout("tar.bz2 file is empty");
        fclose(fp);
        return;
    }

    // Calculate number of chunks
    // uint8_t total_chunks = (uint8_t)((tar_size) / EM_VENDOR_CHUNK_SIZE);
    // if (tar_size % EM_VENDOR_CHUNK_SIZE > 0) {
    //     total_chunks++;
    // }

    uint16_t total_chunks = (tar_size / EM_VENDOR_CHUNK_SIZE);
    if (tar_size % EM_VENDOR_CHUNK_SIZE)
        total_chunks++;

    if (total_chunks > UINT16_MAX) {
        em_printfout("Too many chunks required");
        fclose(fp);
        return;
    }
    em_printfout("tar.bz2 file size: %zu bytes, chunks needed: %u", tar_size, total_chunks);

    // Allocate buffer for chunk data
    unsigned char *chunk_buf = (unsigned char *)malloc(EM_VENDOR_CHUNK_SIZE);
    if (!chunk_buf) {
        em_printfout("Failed to allocate chunk buffer");
        fclose(fp);
        return;
    }

    uint32_t transfer_id = (uint32_t)time(NULL);

    // Create vendor msg for each chunk
    for (uint16_t i = 0; i < total_chunks; i++) {
        em_printfout("\n");
        memset(chunk_buf, 0, EM_VENDOR_CHUNK_SIZE);
        size_t offset = i * EM_VENDOR_CHUNK_SIZE;
        
        // Read chunk from tar file
        size_t to_read = (i == total_chunks - 1) ? 
                        (tar_size - (i * EM_VENDOR_CHUNK_SIZE)) : 
                        EM_VENDOR_CHUNK_SIZE;
        
        size_t bytes_read = fread(chunk_buf, 1, to_read, fp);
        if (bytes_read != to_read) {
            em_printfout("Failed to read chunk %u: expected %zu, got %zu", i, to_read, bytes_read);
            break;
        }

        em_printfout("bytes_read %zu, offset %zu", bytes_read, offset);

        // size_t sz = create_vendor_msg(i, total_chunks, chunk_buf, bytes_read);
        size_t sz = create_vendor_msg(
                 transfer_id,
                 i,
                 total_chunks,
                 offset,
                 tar_size,
                 chunk_buf,
                 bytes_read);
        if (sz <= 0) {
            em_printfout("Failed to create vendor chunk TLV for chunk %u: %zu", i, sz);
            break;
        }
    }

    em_printfout("%s:%d: Log upload success (%u chunks)\n", __func__, __LINE__, total_chunks);

    set_state(em_state_agent_configured);

    free(chunk_buf);
    fclose(fp);
}
#define MAX_VENDOR_CHUNKS 1024
int em_logger_t::handle_vendor_msg(unsigned char *buff, unsigned int len)
{
    em_tlv_t *tlv, *tlv_start;
    size_t tmp_len, base_len;
    dm_easy_mesh_t *dm;
    char *errors[EM_MAX_TLV_MEMBERS] = {0};
    static size_t total_received = 0;

    dm = get_data_model();

    em_printfout("===>>> handle vendor msg rcvd: %zu", total_received);

    if (em_msg_t(em_msg_type_topo_vendor, get_profile_type(), buff, len).validate(errors) == 0) {
        printf("%s:%d: Vendor msg validation failed\n", __func__, __LINE__);
        return -1;
    }

    tlv_start = reinterpret_cast<em_tlv_t *> (buff + sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));
    base_len = static_cast<size_t> (len) - (sizeof(em_raw_hdr_t) + sizeof(em_cmdu_t));

    tlv = tlv_start;
    tmp_len = base_len;

    // Collect all chunks
    // FILE *fp = fopen("/tmp/agent_1_wifi_logs.tar.bz2", "wb");
    // if (!fp) {
    //     em_printfout("Failed to open output tar file for writing: %s", strerror(errno));
    //     return -1;
    // }

    // uint8_t expected_chunk = 0;
    // uint8_t total_chunks = 0;
    size_t total_written = 0;

    static FILE *fp = NULL;
static uint16_t total_chunks = 0;
static uint16_t received_count = 0;
static bool received[MAX_VENDOR_CHUNKS] = {0};
static bool transfer_active = false;


    while ((tlv->type != em_tlv_type_eom) && (tmp_len > 0)) {
        if (tlv->type == em_tlv_type_vendor_specific) {
            // em_vendor_specific_t *vendor_data = reinterpret_cast<em_vendor_specific_t *> (tlv->value);
            // em_printfout("\t\t===>>> Received vendor chunks cnt:%d", vendor_data->num);

            // em_vendor_data_t *data = reinterpret_cast<em_vendor_data_t *> (vendor_data->data);
            // vendor_chunk_header_t *chunk = reinterpret_cast<vendor_chunk_header_t *> (data->vendor_data);
            
            // em_printfout("\t\t===>>> vendor attribute:%d", data->attr_id);

            // uint8_t seq_num = chunk->seq_num;
            // total_chunks = chunk->total_chunks;
            // size_t chunk_data_len = ntohs(tlv->len) - EM_VENDOR_OUI_SIZE - sizeof(vendor_chunk_header_t);

            // em_printfout("Received vendor chunk %u of %u, size: %zu bytes", seq_num, total_chunks, chunk_data_len);

            // if (seq_num != expected_chunk) {
            //     em_printfout("Chunk sequence error: expected %u, got %u", expected_chunk, seq_num);
            // }

            // unsigned char *chunk_data = reinterpret_cast<unsigned char *> (chunk) + sizeof(vendor_chunk_header_t);
            // size_t bytes_written = fwrite(chunk_data, 1, chunk_data_len, fp);
            // if (bytes_written != chunk_data_len) {
            //     em_printfout("Failed to write chunk %u: expected %zu, got %zu", seq_num, chunk_data_len, bytes_written);
            //     fclose(fp);
            //     return -1;
            // }

            // total_written += bytes_written;
            // expected_chunk++;

            // total_received++;

            // if (total_received >= total_chunks) {
            //     em_printfout("All chunks received");
            //     total_received = 0;
            //     break;
            // }


            // if (tlv->type == em_tlv_type_vendor_specific) {

                em_vendor_specific_t *vendor_data =
                    reinterpret_cast<em_vendor_specific_t *>(tlv->value);

                em_vendor_data_t *data =
                    reinterpret_cast<em_vendor_data_t *>(vendor_data->data);

                vendor_chunk_header_t *chunk =
                    reinterpret_cast<vendor_chunk_header_t *>(data->vendor_data);

                uint16_t seq_num = ntohs(chunk->seq_num);
                uint16_t total = ntohs(chunk->total_chunks);

                size_t tlv_len = ntohs(tlv->len);

                size_t chunk_data_len =
                    tlv_len
                    - EM_VENDOR_OUI_SIZE
                    - sizeof(vendor_data->num)
                    - sizeof(data->attr_id)
                    - sizeof(vendor_chunk_header_t);

                unsigned char *chunk_data =
                    reinterpret_cast<unsigned char *>(chunk)
                    + sizeof(vendor_chunk_header_t);

                em_printfout("RX chunk %u/%u size %zu",
                            seq_num, total, chunk_data_len);

                /* ---------- First Chunk Initialization ---------- */

                if (!transfer_active) {

                    if (total > MAX_VENDOR_CHUNKS) {
                        em_printfout("Too many chunks");
                        return -1;
                    }

                    memset(received, 0, sizeof(received));
                    total_chunks = total;
                    received_count = 0;

                    fp = fopen("/tmp/agent_1_wifi_logs.tar.bz2", "wb+");
                    if (!fp) {
                        em_printfout("File open failed");
                        return -1;
                    }

                    transfer_active = true;
                }

                /* ---------- Validation ---------- */

                if (seq_num >= total_chunks) {
                    em_printfout("Invalid seq %u", seq_num);
                    return -1;
                }

                if (received[seq_num]) {
                    em_printfout("Duplicate chunk %u ignored", seq_num);
                    break;
                }

                /* ---------- Calculate Offset ---------- */

                size_t offset = seq_num * EM_VENDOR_CHUNK_SIZE;

                fseek(fp, offset, SEEK_SET);

                size_t written =
                    fwrite(chunk_data, 1, chunk_data_len, fp);

                if (written != chunk_data_len) {
                    em_printfout("Write failed");
                    return -1;
                }

                received[seq_num] = true;
                received_count++;

                /* ---------- Completion Check ---------- */
                em_printfout("recvd cnt:%u vs total chunks:%u", received_count, total_chunks);
                if (received_count == total_chunks) {

                    em_printfout("Transfer complete (%u chunks)",
                                total_chunks);

                    fclose(fp);
                    fp = NULL;

                    transfer_active = false;
                    total_chunks = 0;
                    received_count = 0;
                    memset(received, 0, sizeof(received));
                }
            // }

        }
        
        tmp_len -= (sizeof(em_tlv_t) + static_cast<size_t> (ntohs(tlv->len)));
        tlv = reinterpret_cast<em_tlv_t *> (reinterpret_cast<unsigned char *> (tlv) + sizeof(em_tlv_t) + ntohs(tlv->len));
    }

    // fclose(fp);

    if (total_received == total_chunks) {
        em_printfout("Successfully assembled tar.bz2 file: %zu bytes from %u chunks", total_written, total_chunks);
    } else {
        em_printfout("Incomplete reassembly: got %u of %u chunks", total_received, total_chunks);
    }

    return 0;
}

void em_logger_t::process_msg(unsigned char *data, unsigned int len)
{
    em_cmdu_t *cmdu = reinterpret_cast<em_cmdu_t *> (data + sizeof(em_raw_hdr_t));

    switch (htons(cmdu->type)) {
        case em_msg_type_topo_vendor:
            handle_vendor_msg(data, len);
            break;

        default:
            break;
    }
}

void em_logger_t::process_ctrl_state()
{
    switch (get_state()) {

        default:
            printf("%s:%d: unhandled case %s\n", __func__, __LINE__, em_t::state_2_str(get_state()));
            break;
    }
}

void em_logger_t::process_agent_state()
{
    switch (get_state()) {
        case em_state_agent_logger_report_pending:
            send_logs_msg();
            break;

        default:
            break;
    }
}

em_logger_t::em_logger_t()
{

}

em_logger_t::~em_logger_t()
{

}
