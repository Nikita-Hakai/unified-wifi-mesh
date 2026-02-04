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

#ifndef EM_LOGGER_H
#define EM_LOGGER_H

#include "em_base.h"
#include "dm_easy_mesh.h"

class em_mgr_t;
class em_logger_t {


	/**!
	 * @brief Retrieves the data model instance.
	 *
	 * This function provides access to the data model used within the system.
	 *
	 * @returns A pointer to the data model instance of type `dm_easy_mesh_t`.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual dm_easy_mesh_t *get_data_model() = 0;
    
	/**!
	 * @brief Retrieves the current state.
	 *
	 * @returns The current state as an em_state_t.
	 *
	 * @note This is a pure virtual function that must be implemented by derived classes.
	 */
	virtual em_state_t get_state() = 0;
    
	/**!
	 * @brief Sets the state of the EM.
	 *
	 * This function sets the current state of the EM to the specified state.
	 *
	 * @param[in] state The state to set, represented by em_state_t.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual void set_state(em_state_t state) = 0;
    
	/**!
	 * @brief Sends a frame of data.
	 *
	 * This function is responsible for sending a frame of data, which can be multicast or unicast.
	 *
	 * @param[in] buff Pointer to the buffer containing the data to be sent.
	 * @param[in] len Length of the data in the buffer.
	 * @param[in] multicast Flag indicating whether the data should be sent as multicast.
	 *
	 * @returns int
	 * @retval 0 on success
	 * @retval -1 on failure
	 *
	 * @note Ensure the buffer is properly allocated and the length is correctly specified.
	 */
	virtual int send_frame(unsigned char *buff, unsigned int len, bool multicast = false) = 0;
    
	/**!
	 * @brief Retrieves the profile type.
	 *
	 * This function returns the current profile type of the entity.
	 *
	 * @returns The profile type as an em_profile_type_t.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_profile_type_t get_profile_type() = 0;
    
	/**!
	 * @brief Retrieves the current command.
	 *
	 * This function returns a pointer to the current command being processed.
	 *
	 * @returns A pointer to the current command of type em_cmd_t.
	 * @retval nullptr If there is no current command.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_cmd_t *get_current_cmd() = 0;
    

public:
	short create_vendor_msg(uint32_t transfer_id,
                                       uint16_t seq_num,
                                       uint16_t total_chunks,
                                       uint32_t offset,
                                       uint32_t total_size,
                                       const unsigned char *chunk_data,
                                       size_t chunk_len);
	void send_logs_msg();
	int handle_vendor_msg(unsigned char *buff, unsigned int len);

	/**!
	 * @brief Retrieves the manager instance.
	 *
	 * This function returns a pointer to the manager instance associated with the steering module.
	 *
	 * @returns A pointer to the manager instance of type `em_mgr_t`.
	 *
	 * @note This is a pure virtual function and must be implemented by derived classes.
	 */
	virtual em_mgr_t *get_mgr() = 0;
    
	/**!
	 * @brief Processes a message.
	 *
	 * This function takes a data buffer and its length, processing the message contained within.
	 *
	 * @param[in] data Pointer to the data buffer containing the message.
	 * @param[in] len Length of the data buffer.
	 *
	 * @note Ensure that the data buffer is valid and the length is correct to avoid undefined behavior.
	 */
	void process_msg(unsigned char *data, unsigned int len);
    
	/**!
	 * @brief Processes the control state.
	 *
	 * This function is responsible for handling the control state of the system.
	 *
	 * @note Ensure that the system is initialized before calling this function.
	 */
	void process_ctrl_state();
    
	/**!
	 * @brief Processes the state of the agent.
	 *
	 * This function is responsible for handling the current state of the agent and performing necessary actions based on that state.
	 *
	 * @note This function does not take any parameters and does not return any value.
	 */
	void process_agent_state();

    
	/**!
	 * @brief Constructor for the em_logger_t class.
	 *
	 * Initializes a new instance of the em_logger_t class.
	 *
	 * @note This constructor does not take any parameters.
	 */
	em_logger_t();
    
	/**!
	 * @brief Destructor for the em_logger_t class.
	 *
	 * This function cleans up any resources used by the em_logger_t instance.
	 *
	 * @note This is a virtual destructor, allowing for proper cleanup of derived class objects.
	 */
	virtual ~em_logger_t();
};

#endif
