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
// Includes from this component
#include "zwave_command_class_switch_color.h"
#include "zwave_command_classes_utils.h"

// Generic includes
#include <stdlib.h>
#include <assert.h>

// Includes from other ZPC Components
#include "zwave_command_class_indices.h"
#include "zwave_command_handler.h"
#include "zpc_attribute_store_network_helper.h"
#include "attribute_store_defined_attribute_types.h"
#include "ZW_classcmd.h"
#include "zpc_attribute_resolver.h"

// Includes from other Unify Components
#include "dotdot_mqtt.h"
#include "dotdot_mqtt_generated_commands.h"
#include "attribute_store_helper.h"
#include "attribute_resolver.h"
#include "attribute_timeouts.h"
#include "sl_log.h"

// Cpp include
#include "attribute.hpp"
#include "zwave_frame_generator.hpp"
#include "zwave_frame_parser.hpp"

// Interfaces
#include "zwave_command_class_color_switch_types.h"

// Attribute macro, shortening those long defines for attribute types:
#define ATTRIBUTE(type) ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_##type

// Max component ID color supported
constexpr uint8_t MAX_SUPPORTED_COLOR_COMPONENT = 9;

// Index of obsoleted component ID
constexpr uint8_t COMPONENT_ID_INDEXED_COLOR = 8;

// Define initial state of attribute
constexpr uint8_t INITIAL_STATE = 0;

// Log tag
constexpr char LOG_TAG[] = "zwave_command_class_switch_color";

namespace
{
zwave_frame_generator frame_generator(COMMAND_CLASS_SWITCH_COLOR);
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions
///////////////////////////////////////////////////////////////////////////////
zwave_cc_version_t get_current_switch_color_version(attribute_store_node_t node)
{
  zwave_cc_version_t version
    = zwave_command_class_get_version_from_node(node,
                                                COMMAND_CLASS_SWITCH_COLOR);

  if (version == 0) {
    sl_log_error(LOG_TAG, "Switch_color Command Class Version not found");
  }

  return version;
}

///////////////////////////////////////////////////////////////////////////////
// Validation function
///////////////////////////////////////////////////////////////////////////////
bool zwave_command_class_switch_color_validate_value(uint8_t value)
{
  return (value >= 0x00 && value <= 0xFF);
}

///////////////////////////////////////////////////////////////////////////////
// Resolution functions
///////////////////////////////////////////////////////////////////////////////
static sl_status_t zwave_command_class_switch_color_supported_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  return frame_generator.generate_no_args_frame(SWITCH_COLOR_SUPPORTED_GET,
                                                frame,
                                                frame_length);
}

static sl_status_t zwave_command_class_switch_color_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Switch Color Get");
  try {
    attribute_store::attribute value_node(node);
    assert(value_node.is_valid() && value_node.type() == ATTRIBUTE(VALUE));

    // Compute expected size for set frame
    const uint8_t expected_frame_size = sizeof(ZW_SWITCH_COLOR_GET_FRAME);

    // Creating the frame
    frame_generator.initialize_frame(SWITCH_COLOR_GET,
                                     frame,
                                     expected_frame_size);

    auto component_id_node
      = value_node.first_parent(ATTRIBUTE(COLOR_COMPONENT_ID));
    // Add Color Component ID field to the frame
    frame_generator.add_value(component_id_node, DESIRED_OR_REPORTED_ATTRIBUTE);

    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating Switch Color get frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_switch_color_set(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Switch Color Set");
  try {
    attribute_store::attribute value_node(node);
    assert(value_node.is_valid() && value_node.type() == ATTRIBUTE(VALUE));

    auto current_version = get_current_switch_color_version(node);

    constexpr uint8_t ZWAVE_CC_HEADER_SIZE = 2;

    attribute_store::attribute state_node
      = value_node.first_parent(ATTRIBUTE(STATE));
    //Get number of COLOR_COMPONENT_ID
    auto supported_color_component_count
      = state_node.children(ATTRIBUTE(COLOR_COMPONENT_ID)).size();

    // Compute expected size for set frame
    auto expected_frame_size
      = ZWAVE_CC_HEADER_SIZE + supported_color_component_count * 2;
    if (current_version >= 2) {
      // V2 have color component count + duration size
      expected_frame_size += 2;
    }

    // Creating the frame
    frame_generator.initialize_frame(SWITCH_COLOR_SET,
                                     frame,
                                     expected_frame_size);

    if (current_version >= 2) {
      //Set Color Component Count in frame
      frame_generator.add_raw_byte(supported_color_component_count);
    }

    // Iterate on all color count
    for (auto color_component_id_node:
         state_node.children(ATTRIBUTE(COLOR_COMPONENT_ID))) {
      // Set Color Component ID in frame
      frame_generator.add_value(color_component_id_node,
                                DESIRED_OR_REPORTED_ATTRIBUTE);
      // Set Value in frame
      auto value_node = color_component_id_node.child_by_type(ATTRIBUTE(VALUE));
      // Can't set value directly since attribute store uses uint32_t and we only want to set 1 byte (uint8_t)
      auto value = value_node.desired_or_reported<uint32_t>();
      frame_generator.add_raw_byte(static_cast<uint8_t>(value));
    }

    if (current_version >= 2) {
      auto duration_node = state_node.child_by_type(ATTRIBUTE(DURATION));
      // Can't set value directly since attribute store uses uint32_t and we only want to set 1 byte (uint8_t)
      auto duration = duration_node.desired_or_reported<uint32_t>();
      frame_generator.add_raw_byte(static_cast<uint8_t>(duration));
    }

    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating Switch Color Set frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_switch_color_start_level_change(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Switch Color Start Level Change");
  try {
    attribute_store::attribute start_change_node(node);
    assert(start_change_node.is_valid()
           && start_change_node.type() == ATTRIBUTE(START_CHANGE));

    uint8_t start_change = start_change_node.desired_or_reported<uint8_t>();
    sl_log_debug(LOG_TAG, "start_change: %d", start_change);

    //Set start change = 0 to be able to handle the next command
    start_change_node.set_desired<uint8_t>(INITIAL_STATE);

    //We only handle if Start Change is 1
    if (start_change != 1) {
      sl_log_error(LOG_TAG,
                   "Start Change have invalid value: %d",
                   start_change);
      return SL_STATUS_FAIL;
    }

    auto current_version = get_current_switch_color_version(node);

    // Compute expected size for set frame
    const uint8_t expected_frame_size
      = current_version >= 3
          ? sizeof(ZW_SWITCH_COLOR_START_LEVEL_CHANGE_V3_FRAME)
          : sizeof(ZW_SWITCH_COLOR_START_LEVEL_CHANGE_FRAME);

    // Creating the frame
    frame_generator.initialize_frame(SWITCH_COLOR_START_LEVEL_CHANGE,
                                     frame,
                                     expected_frame_size);

    //Get color component id node
    auto color_component_id_node = start_change_node.parent();

    //Get state node
    attribute_store::attribute state_node
      = start_change_node.first_parent(ATTRIBUTE(STATE));

    //Get start level node
    attribute_store::attribute start_level_node(
      state_node.child_by_type(ATTRIBUTE(START_LEVEL)));
    uint8_t start_level = start_level_node.desired_or_reported<uint8_t>();
    if (!zwave_command_class_switch_color_validate_value(start_level)) {
      sl_log_error(
        LOG_TAG,
        "Start Level have invalid value: %d, it should in range <0 - 255>",
        start_level);
      return SL_STATUS_FAIL;
    }

    //Get up down node and value
    attribute_store::attribute up_down_node(
      state_node.child_by_type(ATTRIBUTE(UP_DOWN)));
    uint8_t up_down = up_down_node.desired_or_reported<uint8_t>();
    if ((up_down != 0) && (up_down != 1)) {
      sl_log_error(LOG_TAG,
                   "Up/Down have invalid value: %d, it should be 0 or 1",
                   up_down);
      return SL_STATUS_FAIL;
    }

    //Get ignore start level node and value
    attribute_store::attribute ignore_start_level_node(
      state_node.child_by_type(ATTRIBUTE(IGNORE_START_LEVEL)));
    uint8_t ignore_start_level
      = ignore_start_level_node.desired_or_reported<uint8_t>();
    if ((ignore_start_level != 0) && (ignore_start_level != 1)) {
      sl_log_error(
        LOG_TAG,
        "Ignore Start Level have invalid value: %d, it should be 0 or 1",
        ignore_start_level);
      return SL_STATUS_FAIL;
    }

    uint8_t properties1 = ((up_down << 6) | (ignore_start_level << 5));

    //Add data to frame
    frame_generator.add_raw_byte(properties1);
    frame_generator.add_value(color_component_id_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_raw_byte(start_level);

    if (current_version >= 3) {
      auto duration_node = state_node.child_by_type(ATTRIBUTE(DURATION));
      auto duration      = duration_node.desired_or_reported<uint32_t>();
      frame_generator.add_raw_byte(static_cast<uint8_t>(duration));
    }

    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(
      LOG_TAG,
      "Error while generating Switch Color Start Level Change frame : %s",
      e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_switch_color_stop_level_change(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Switch Color Stop Level Change");
  try {
    attribute_store::attribute stop_change_node(node);
    assert(stop_change_node.is_valid()
           && stop_change_node.type() == ATTRIBUTE(STOP_CHANGE));

    uint8_t stop_change = stop_change_node.desired_or_reported<uint8_t>();
    sl_log_debug(LOG_TAG, "stop_change: %d", stop_change);

    //Set start change = 0 to be able to handle the next command
    stop_change_node.set_desired<uint8_t>(INITIAL_STATE);

    //We only handle if Stop Change is 1
    if (stop_change != 1) {
      sl_log_error(LOG_TAG, "Start Change have invalid value: %d", stop_change);
      return SL_STATUS_FAIL;
    }

    // Compute expected size for set frame
    const uint8_t expected_frame_size
      = sizeof(ZW_SWITCH_COLOR_STOP_LEVEL_CHANGE_V3_FRAME);

    // Creating the frame
    frame_generator.initialize_frame(SWITCH_COLOR_STOP_LEVEL_CHANGE,
                                     frame,
                                     expected_frame_size);

    //Get color component id node
    auto color_component_id_node = stop_change_node.parent();

    //Add data to frame
    frame_generator.add_value(color_component_id_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);

    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(
      LOG_TAG,
      "Error while generating Switch Color Stop Level Change frame : %s",
      e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

///////////////////////////////////////////////////////////////////////////////
// Frame parsing functions
///////////////////////////////////////////////////////////////////////////////
static sl_status_t zwave_command_class_switch_color_handle_supported_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  // Setup
  attribute_store::attribute endpoint_node(
    zwave_command_class_get_endpoint_node(connection_info));

  sl_log_debug(LOG_TAG, "Switch_color Supported Report frame received");

  // Compute expected size for report frame
  const uint8_t expected_size = sizeof(ZW_SWITCH_COLOR_SUPPORTED_REPORT_FRAME);

  // Parse the frame
  try {
    zwave_frame_parser parser(frame_data, frame_length);

    if (!parser.is_frame_size_valid(expected_size)) {
      sl_log_error(LOG_TAG, "Invalid frame size for Switch_color Report frame");
      return SL_STATUS_FAIL;
    }

    const uint8_t bitmask_1           = parser.read_byte();
    const uint8_t bitmask_2           = parser.read_byte();
    color_component_bitmask_t bitmask = (bitmask_2 << 8) | bitmask_1;
    sl_log_debug(LOG_TAG,
                 "Switch Color Report Color Component Mask  : %d",
                 bitmask);

    //Get mask node
    attribute_store::attribute mask_node
      = endpoint_node.child_by_type(ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK));
    //Set reported mask node
    mask_node.set_reported<uint16_t>(bitmask);

    //Get state node
    attribute_store::attribute state_node(
      endpoint_node.child_by_type(ATTRIBUTE(STATE)));

    // Create the color component ID attributes
    color_component_bitmask_t current_bit;
    for (uint8_t i = 0; i < MAX_SUPPORTED_COLOR_COMPONENT; i++) {
      current_bit = 1 << i;
      current_bit &= bitmask;

      // Marked as not supported, we check the next one
      if (current_bit == 0) {
        continue;
      }

      // Ignore special case
      if (i == COMPONENT_ID_INDEXED_COLOR) {
        sl_log_warning(LOG_TAG,
                       "Component ID 8 is obsoleted, not creating attribute\n");
        continue;
      }

      // Create component ID
      color_component_id_t component_id = i;
      auto color_component_node
        = state_node.emplace_node(ATTRIBUTE(COLOR_COMPONENT_ID), component_id);

      // New we associate a value to it so the controller can get it's values
      color_component_node.emplace_node(ATTRIBUTE(VALUE));

      // Create Start and Stop Level change
      auto start_node
        = color_component_node.emplace_node(ATTRIBUTE(START_CHANGE));
      start_node.set_reported<uint8_t>(INITIAL_STATE);

      auto stop_node
        = color_component_node.emplace_node(ATTRIBUTE(STOP_CHANGE));
      stop_node.set_reported<uint8_t>(INITIAL_STATE);
    }

  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while parsing Switch_color Supported Report frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }
  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_switch_color_handle_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  // Setup
  attribute_store::attribute endpoint_node(
    zwave_command_class_get_endpoint_node(connection_info));
  auto current_version = get_current_switch_color_version(endpoint_node);

  sl_log_debug(LOG_TAG, "Switch_color Report frame received");

  // Compute expected size for report frame
  const uint8_t expected_size = (current_version >= 3)
                                  ? sizeof(ZW_SWITCH_COLOR_REPORT_V3_FRAME)
                                  : sizeof(ZW_SWITCH_COLOR_REPORT_FRAME);

  attribute_store::attribute state_node
    = endpoint_node.child_by_type(ATTRIBUTE(STATE));

  if (!state_node.is_valid()) {
    sl_log_error(
      LOG_TAG,
      "Can't find state node when parsing Switch Color Report frame");
    return SL_STATUS_FAIL;
  }

  // Parse the frame
  try {
    zwave_frame_parser parser(frame_data, frame_length);

    if (!parser.is_frame_size_valid(expected_size)) {
      sl_log_error(LOG_TAG, "Invalid frame size for Switch_color Report frame");
      return SL_STATUS_FAIL;
    }

    //Get Color Component ID
    uint8_t component_id = parser.read_byte();

    //Get Color Current Value
    uint32_t current_value = parser.read_byte();

    attribute_store::attribute component_id_node
      = state_node.child_by_type_and_value(ATTRIBUTE(COLOR_COMPONENT_ID),
                                           component_id);

    attribute_store::attribute value_node
      = component_id_node.child_by_type(ATTRIBUTE(VALUE));

    value_node.set_reported<uint32_t>(current_value);

    if (current_version >= 3) {
      //Get Target Value

      uint32_t target_value = parser.read_byte();
      sl_log_debug(LOG_TAG,
                   "Switch Color Report Target Value : %d",
                   target_value);

      //Get Duration from frame and Set value
      auto duration_node  = state_node.child_by_type(ATTRIBUTE(DURATION));
      auto duration_value = parser.read_byte();
      duration_node.set_reported<uint32_t>(duration_value);
    }

  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while parsing Switch_color Report frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }
  return SL_STATUS_OK;
}

///////////////////////////////////////////////////////////////////////////////
// Incoming commands handler
///////////////////////////////////////////////////////////////////////////////
sl_status_t zwave_command_class_switch_color_control_handler(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  // Frame too short, it should have not come here.
  if (frame_length <= COMMAND_INDEX) {
    return SL_STATUS_NOT_SUPPORTED;
  }

  switch (frame_data[COMMAND_INDEX]) {
    case SWITCH_COLOR_SUPPORTED_REPORT:
      return zwave_command_class_switch_color_handle_supported_report(
        connection_info,
        frame_data,
        frame_length);
    case SWITCH_COLOR_REPORT:
      return zwave_command_class_switch_color_handle_report(connection_info,
                                                            frame_data,
                                                            frame_length);
    default:
      return SL_STATUS_NOT_SUPPORTED;
  }
}

///////////////////////////////////////////////////////////////////////////////
// Attribute Store callback functions
///////////////////////////////////////////////////////////////////////////////
static void zwave_command_class_switch_color_on_version_attribute_update(
  attribute_store_node_t updated_node, attribute_store_change_t change)
{
  if (change == ATTRIBUTE_DELETED) {
    return;
  }

  // Confirm that we have a version attribute update
  assert(ATTRIBUTE(VERSION) == attribute_store_get_node_type(updated_node));

  attribute_store::attribute version_node(updated_node);
  // Do not create the attributes until we are sure of the version
  zwave_cc_version_t supporting_node_version = 0;

  // Wait for the version
  if (!version_node.reported_exists()) {
    return;
  }

  sl_log_debug(LOG_TAG, "Switch Color version attribute update received");

  supporting_node_version = version_node.reported<uint8_t>();

  // Now we know we have a switch_color supporting endpoint.
  attribute_store::attribute endpoint_node
    = version_node.first_parent(ATTRIBUTE_ENDPOINT_ID);

  // Emplace supported color mask
  endpoint_node.emplace_node(ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK));
  // Emplace state
  auto state_node = endpoint_node.emplace_node(ATTRIBUTE(STATE));

  // Set Reported state
  state_node.set_reported<uint32_t>(FINAL_STATE);

  // Emplace color start level change
  std::vector<attribute_store_node_t> switch_color_start_change_attributes;
  switch_color_start_change_attributes.push_back(ATTRIBUTE(UP_DOWN));
  switch_color_start_change_attributes.push_back(ATTRIBUTE(IGNORE_START_LEVEL));
  switch_color_start_change_attributes.push_back(ATTRIBUTE(START_LEVEL));

  for (auto attribute: switch_color_start_change_attributes) {
    state_node.emplace_node(attribute);
  }

  // Emplace duration
  if (supporting_node_version >= 2) {
    state_node.emplace_node(ATTRIBUTE(DURATION));
  }
}

///////////////////////////////////////////////////////////////////////////////
// Public interface functions
///////////////////////////////////////////////////////////////////////////////
sl_status_t zwave_command_class_switch_color_init()
{
  // Attribute store callbacks
  attribute_store_register_callback_by_type(
    zwave_command_class_switch_color_on_version_attribute_update,
    ATTRIBUTE(VERSION));

  // Attribute resolver rules
  attribute_resolver_register_rule(
    ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK),
    NULL,
    &zwave_command_class_switch_color_supported_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(START_CHANGE),
    &zwave_command_class_switch_color_start_level_change,
    NULL);

  attribute_resolver_register_rule(
    ATTRIBUTE(STOP_CHANGE),
    &zwave_command_class_switch_color_stop_level_change,
    NULL);

  attribute_resolver_register_rule(ATTRIBUTE(VALUE),
                                   &zwave_command_class_switch_color_set,
                                   &zwave_command_class_switch_color_get);

  // The support side of things: Register our handler to the Z-Wave CC framework:
  zwave_command_handler_t handler = {};
  handler.support_handler         = NULL;
  handler.control_handler = &zwave_command_class_switch_color_control_handler;
  // Not supported, so this does not really matter
  handler.minimal_scheme = ZWAVE_CONTROLLER_ENCAPSULATION_NETWORK_SCHEME;
  handler.manual_security_validation = false;
  handler.command_class              = COMMAND_CLASS_SWITCH_COLOR;
  handler.version                    = SWITCH_COLOR_VERSION_V3;
  handler.command_class_name         = "Switch_color";
  handler.comments                   = "";

  zwave_command_handler_register_handler(handler);

  return SL_STATUS_OK;
}

void zwave_command_class_switch_color_invoke_on_all_attributes(
  attribute_store_node_t state_node,
  attribute_store_type_t child_node_type,
  void (*function)(attribute_store_node_t))
{
  uint32_t index = 0;
  attribute_store_node_t component_node
    = attribute_store_get_first_child_by_type(
      state_node,
      ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_COLOR_COMPONENT_ID);
  while (component_node != ATTRIBUTE_STORE_INVALID_NODE) {
    index += 1;
    attribute_store_node_t child_node
      = attribute_store_get_first_child_by_type(component_node,
                                                child_node_type);

    function(child_node);
    component_node = attribute_store_get_node_child_by_type(
      state_node,
      ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_COLOR_COMPONENT_ID,
      index);
  }
}

void zwave_command_class_switch_color_invoke_on_all_attributes_with_return_value(
  attribute_store_node_t state_node,
  attribute_store_type_t child_node_type,
  sl_status_t (*function)(attribute_store_node_t))
{
  uint32_t index = 0;
  attribute_store_node_t component_node
    = attribute_store_get_first_child_by_type(
      state_node,
      ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_COLOR_COMPONENT_ID);
  while (component_node != ATTRIBUTE_STORE_INVALID_NODE) {
    index += 1;
    attribute_store_node_t child_node
      = attribute_store_get_first_child_by_type(component_node,
                                                child_node_type);

    function(child_node);
    component_node = attribute_store_get_node_child_by_type(
      state_node,
      ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_COLOR_COMPONENT_ID,
      index);
  }
}