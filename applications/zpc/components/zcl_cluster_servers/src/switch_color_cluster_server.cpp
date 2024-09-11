
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
// Includes from this component
#include "switch_color_cluster_server.h"

// Includes from Unify
#include "sl_log.h"
#include "sl_status.h"
#include "attribute_store_helper.h"
#include "attribute_store.h"
#include "zpc_attribute_store_network_helper.h"
#include "zwave_command_class_color_switch_types.h"

#include "attribute_store_defined_attribute_types.h"
#include "unify_dotdot_defined_attribute_types.h"
#include "unify_dotdot_attribute_store.h"
#include "unify_dotdot_attribute_store_node_state.h"
#include "unify_dotdot_attribute_store_helpers.h"

// Includes from auto-generated files
#include "dotdot_mqtt.h"

// Cpp include
#include "attribute.hpp"

// Setup Log ID
#define LOG_TAG "switch_color_cluster_server"

// Attribute macro, shortening those long defines for attribute types:
#define ATTRIBUTE(type) ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_##type

////////////////////////////////////////////////////////////////////////////////
// Private helper functions
////////////////////////////////////////////////////////////////////////////////
attribute_store_node_t
  get_state_node_by_unid_endpoint(dotdot_unid_t unid,
                                  attribute_store_node_t endpoint)
{
  attribute_store::attribute endpoint_node
    = attribute_store_network_helper_get_endpoint_node(unid, endpoint);
  return endpoint_node.child_by_type(ATTRIBUTE(STATE));
}

attribute_store_node_t
  get_duration_node_by_unid_endpoint(dotdot_unid_t unid,
                                     attribute_store_node_t endpoint)
{
  attribute_store::attribute state_node
    = get_state_node_by_unid_endpoint(unid, endpoint);
  attribute_store::attribute duration_node
    = state_node.child_by_type(ATTRIBUTE(DURATION));

  return duration_node;
}

attribute_store_node_t
  get_up_down_node_by_unid_endpoint(dotdot_unid_t unid,
                                    attribute_store_node_t endpoint)
{
  attribute_store::attribute state_node
    = get_state_node_by_unid_endpoint(unid, endpoint);
  attribute_store::attribute up_down
    = state_node.child_by_type(ATTRIBUTE(UP_DOWN));

  return up_down;
}

attribute_store_node_t
  get_ignore_start_level_node_by_unid_endpoint(dotdot_unid_t unid,
                                               attribute_store_node_t endpoint)
{
  attribute_store::attribute state_node
    = get_state_node_by_unid_endpoint(unid, endpoint);
  attribute_store::attribute ignore_start_level_node
    = state_node.child_by_type(ATTRIBUTE(IGNORE_START_LEVEL));

  return ignore_start_level_node;
}

attribute_store_node_t
  get_start_level_node_by_unid_endpoint(dotdot_unid_t unid,
                                        attribute_store_node_t endpoint)
{
  attribute_store::attribute state_node
    = get_state_node_by_unid_endpoint(unid, endpoint);
  attribute_store::attribute start_level_node
    = state_node.child_by_type(ATTRIBUTE(START_LEVEL));

  return start_level_node;
}

attribute_store_node_t
  get_start_change_node_by_unid_endpoint_color_component_id(
    dotdot_unid_t unid,
    attribute_store_node_t endpoint,
    uint8_t color_component_id)
{
  attribute_store::attribute state_node
    = get_state_node_by_unid_endpoint(unid, endpoint);
  attribute_store::attribute color_component_id_node
    = state_node.child_by_type_and_value(ATTRIBUTE(COLOR_COMPONENT_ID),
                                         color_component_id);

  attribute_store::attribute start_change_node
    = color_component_id_node.child_by_type(ATTRIBUTE(START_CHANGE));

  return start_change_node;
}

attribute_store_node_t get_stop_change_node_by_unid_endpoint_color_component_id(
  dotdot_unid_t unid,
  attribute_store_node_t endpoint,
  uint8_t color_component_id)
{
  attribute_store::attribute state_node
    = get_state_node_by_unid_endpoint(unid, endpoint);
  attribute_store::attribute color_component_id_node
    = state_node.child_by_type_and_value(ATTRIBUTE(COLOR_COMPONENT_ID),
                                         color_component_id);

  attribute_store::attribute stop_change_node
    = color_component_id_node.child_by_type(ATTRIBUTE(STOP_CHANGE));

  return stop_change_node;
}

sl_status_t unify_switch_color_cluster_set_color_command(
  const dotdot_unid_t unid,
  const dotdot_endpoint_id_t endpoint,
  uic_mqtt_dotdot_callback_call_type_t callback_type,
  uint8_t color_component_id,
  uint8_t value,
  uint32_t duration)
{
  try {
    if (callback_type == UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK) {
      return dotdot_is_any_unify_switch_color_attribute_supported(unid,
                                                                  endpoint)
               ? SL_STATUS_OK
               : SL_STATUS_FAIL;
    }

    sl_log_debug(LOG_TAG,
                 "Updating ZCL desired values after Unify_SwitchColor::Set "
                 "command. color_component_id: %d, value :%d, duration : %d",
                 color_component_id,
                 value,
                 duration);

    sl_status_t result = SL_STATUS_FAIL;

    //Set value for attribute by color component id
    switch (color_component_id) {
      case WARM_WHITE:
        result = dotdot_set_unify_switch_color_warm_white(unid,
                                                          endpoint,
                                                          DESIRED_ATTRIBUTE,
                                                          value);
        break;
      case COLD_WHITE:
        result = dotdot_set_unify_switch_color_cold_white(unid,
                                                          endpoint,
                                                          DESIRED_ATTRIBUTE,
                                                          value);
        break;
      case RED:
        result = dotdot_set_unify_switch_color_red(unid,
                                                   endpoint,
                                                   DESIRED_ATTRIBUTE,
                                                   value);
        break;
      case GREEN:
        result = dotdot_set_unify_switch_color_green(unid,
                                                     endpoint,
                                                     DESIRED_ATTRIBUTE,
                                                     value);
        break;
      case BLUE:
        result = dotdot_set_unify_switch_color_blue(unid,
                                                    endpoint,
                                                    DESIRED_ATTRIBUTE,
                                                    value);
        break;
      case AMBER:
        result = dotdot_set_unify_switch_color_amber(unid,
                                                     endpoint,
                                                     DESIRED_ATTRIBUTE,
                                                     value);
        break;
      case CYAN:
        result = dotdot_set_unify_switch_color_cyan(unid,
                                                    endpoint,
                                                    DESIRED_ATTRIBUTE,
                                                    value);
        break;
      case PURPLE:
        result = dotdot_set_unify_switch_color_purple(unid,
                                                      endpoint,
                                                      DESIRED_ATTRIBUTE,
                                                      value);
        break;
      default:
        sl_log_debug(
          LOG_TAG,
          "Invalid Colol Component ID  Unify_SwitchColor::Set command");
        break;
    }

    if (result != SL_STATUS_OK) {
      sl_log_warning(LOG_TAG, "Can't set value for Unify Switch Color cluster");
      return SL_STATUS_FAIL;
    }
    // Find duration node and set desired value
    attribute_store::attribute duration_node
      = get_duration_node_by_unid_endpoint(unid, endpoint);
    if (duration_node.is_valid()) {
      duration_node.set_desired<uint32_t>(duration);
    }
  } catch (const std::exception &e) {
    sl_log_error(
      LOG_TAG,
      "Error while handle unify_switch_color_cluster_set_color_command : %s",
      e.what());
    return SL_STATUS_FAIL;
  }
  return SL_STATUS_OK;
}

sl_status_t unify_switch_color_cluster_start_stop_change_command(
  const dotdot_unid_t unid,
  const dotdot_endpoint_id_t endpoint,
  uic_mqtt_dotdot_callback_call_type_t callback_type,
  bool start_stop,
  bool up_down,
  bool ignor_start_level,
  uint8_t color_component_id,
  uint8_t start_level,
  uint32_t duration)
{
  try {
    if (callback_type == UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK) {
      return dotdot_is_any_unify_switch_color_attribute_supported(unid,
                                                                  endpoint)
               ? SL_STATUS_OK
               : SL_STATUS_FAIL;
    }

    sl_log_debug(LOG_TAG,
                 "Updating ZCL desired values after Unify_SwitchColor::Start "
                 "Stop Change command");

    // Find duration node and set desired value
    attribute_store::attribute duration_node
      = get_duration_node_by_unid_endpoint(unid, endpoint);
    if (duration_node.is_valid()) {
      duration_node.set_desired<uint32_t>(duration);
    }

    // Find up down node and set desired value
    attribute_store::attribute up_down_node
      = get_up_down_node_by_unid_endpoint(unid, endpoint);
    up_down_node.set_desired<uint8_t>(up_down);

    // Find irnore start level node and set desired value
    attribute_store::attribute ignore_start_level_node
      = get_ignore_start_level_node_by_unid_endpoint(unid, endpoint);
    ignore_start_level_node.set_desired<uint8_t>(ignor_start_level);

    // Find start level node and set desired value
    attribute_store::attribute start_level_node
      = get_start_level_node_by_unid_endpoint(unid, endpoint);
    start_level_node.set_desired<uint8_t>(start_level);

    if (start_stop) {
      attribute_store::attribute start_change_node
        = get_start_change_node_by_unid_endpoint_color_component_id(
          unid,
          endpoint,
          color_component_id);
      start_change_node.set_desired<uint8_t>(start_stop);
    } else {
      attribute_store::attribute stop_change_node
        = get_stop_change_node_by_unid_endpoint_color_component_id(
          unid,
          endpoint,
          color_component_id);
      stop_change_node.set_desired<uint8_t>(!start_stop);
    }
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while handle "
                 "unify_switch_color_cluster_start_stop_change_command : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }
  return SL_STATUS_OK;
}

///////////////////////////////////////////////////////////////////////////////
// Init and teardown functions
///////////////////////////////////////////////////////////////////////////////
sl_status_t switch_color_cluster_server_init()
{
  sl_log_debug(LOG_TAG, "SwitchColor cluster (ZWave) server initialization");

  uic_mqtt_dotdot_unify_switch_color_set_color_callback_set(
    &unify_switch_color_cluster_set_color_command);
  uic_mqtt_dotdot_unify_switch_color_start_stop_change_callback_set(
    &unify_switch_color_cluster_start_stop_change_command);
  return SL_STATUS_OK;
}
