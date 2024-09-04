/******************************************************************************
 * # License
 * <b>Copyright 2021 Silicon Laboratories Inc. www.silabs.com</b>
 ******************************************************************************
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 *****************************************************************************/

/**
 * @defgroup switch_color_command_class Switch Color Command Class
 * @ingroup command_classes
 * @brief Switch Color Command Class handlers and control functions
 *
 * This module implement functions for generating and parsing the Z-Wave frames
 * for controlling the Switch Color Command Class.
 *
 * The data model used for this command class is tailored to be mapped to the
 * ZCL Level cluster.
 *
 * The State attribute is a hook for the Set / Get rule registrations. The
 * actual values being set and resolved are the duration and the value.
 * If the duration and/or the value needs a resolution, the Command Class
 * handler adjusts the state in order to trigger the resolver:
 *
 * - state = reported [] for a get resolution
 * - state = desired [1] reported [0] for a set resolution
 * - state = desired [0] reported [0] for a no resolution
 *
@startuml{attribute_store_switch_color_command_class.png} "Switch Color data model" width=10cm
title Switch Color data model
allow_mixing
skinparam objectBorderColor black

legend top
<font color=#FEFEFE>ATTRIBUTE(type)</font> : ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_type
endlegend

package "Attribute Store" <<Database>> {
  object "NodeID" as node #f2ffe6
  node : Attribute Type = ATTRIBUTE_NODE_ID
  node : value = Desired: [], Reported: [03]

  object "Endpoint Attribute" as endpoint #e6fff7
  endpoint : Attribute Type = ATTRIBUTE_ENDPOINT_ID
  endpoint : value = Desired: [] - Reported: [04]

  object "Version" as version #FEFEFE
  version : Attribute Type = ATTRIBUTE(VERSION)
  version : value = Desired: [] - Reported: [2]

  object "State" as state #FFFFFF
  state : Attribute Type = ATTRIBUTE(STATE)
  state : value = Desired: [1] - Reported: [0]

  object "Value" as value #FFFFFF
  value : Attribute Type = ATTRIBUTE(VALUE)
  value : value = Desired: [0x00], Reported: [0xFF]

  object "Duration" as duration #FFFFFF
  duration : Attribute Type = ATTRIBUTE(DURATION)
  duration : value = Desired: [10], Reported: [10]
}

node *-- endpoint
endpoint *-- version
endpoint *-- state
state *-- value
state *-- duration

@enduml
 *
 * @{
*/

#ifndef ZWAVE_COMMAND_CLASS_SWITCH_COLOR_H
#define ZWAVE_COMMAND_CLASS_SWITCH_COLOR_H

#include "sl_status.h"
#include "attribute_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Runs a functions for all chidren with a certain type for all color
 * component IDs in the Color Switch Command Class
 *
 * @param state_node         Attribute Store node for the Color Switch State
 * @param child_node_type    Type of children to run the function on
 * @param function           Function to run on all children
 */
void zwave_command_class_switch_color_invoke_on_all_attributes(
  attribute_store_node_t state_node,
  attribute_store_type_t child_node_type,
  void (*function)(attribute_store_node_t));

/**
 * @brief Runs a functions for all chidren with a certain type for all color
 * component IDs in the Color Switch Command Class
 *
 * @param state_node         Attribute Store node for the Color Switch State
 * @param child_node_type    Type of children to run the function on
 * @param function           Function to run on all children
 */
void zwave_command_class_switch_color_invoke_on_all_attributes_with_return_value(
  attribute_store_node_t state_node,
  attribute_store_type_t child_node_type,
  sl_status_t (*function)(attribute_store_node_t));

/**
 * @brief This function initialize the Switch Color Command Class handler
 *
 * @return SL_STATUS_OK on success, any other error code for an error.
 */
sl_status_t zwave_command_class_switch_color_init();

#ifdef __cplusplus
}
#endif

#endif  //ZWAVE_COMMAND_CLASS_SWITCH_COLOR_H
/** @} end switch_color_command_class */
