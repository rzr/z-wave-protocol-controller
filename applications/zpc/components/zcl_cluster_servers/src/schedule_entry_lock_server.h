/******************************************************************************
 * # License
 * <b>Copyright 2024 Silicon Laboratories Inc. www.silabs.com</b>
 ******************************************************************************
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 *****************************************************************************/

#ifndef SCHEDULE_ENTRY_LOCK_SERVER_H
#define SCHEDULE_ENTRY_LOCK_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the schedule entry lock cluster server
 *
 * @returns true on success
 * @returns false on failure
 *
 */
sl_status_t schedule_entry_lock_cluster_server_init(void);

#ifdef __cplusplus
}
#endif

#endif  //SCHEDULE_ENTRY_LOCK_SERVER_H
/** @} end schedule_entry_lock_server */
