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
#include "zwave_command_class_switch_all.h"
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

// Attribute macro, shortening those long defines for attribute types:
#define ATTRIBUTE(type) ATTRIBUTE_COMMAND_CLASS_SWITCH_ALL_##type

// Log tag
constexpr char LOG_TAG[] = "zwave_command_class_switch_all";


namespace
{
zwave_frame_generator frame_generator(COMMAND_CLASS_SWITCH_ALL);
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions
///////////////////////////////////////////////////////////////////////////////
zwave_cc_version_t get_current_switch_all_version(attribute_store_node_t node)
{
  zwave_cc_version_t version
    = zwave_command_class_get_version_from_node(node, COMMAND_CLASS_SWITCH_ALL);

  if (version == 0) {
    sl_log_error(LOG_TAG, "switch_all Command Class Version not found");
  }

  return version;
}
///////////////////////////////////////////////////////////////////////////////
// Resolution functions
///////////////////////////////////////////////////////////////////////////////
//static sl_status_t zwave_command_class_switch_all_get(
//  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
//{
//   return frame_generator.generate_no_args_frame(switch_all_GET,
//                                                 frame,
//                                                 frame_length);
//}

// static sl_status_t zwave_command_class_switch_all_set(
//  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
// {
//  try {
//    attribute_store::attribute value_node(node);
//    auto current_version = get_current_switch_all_version(node);
//
//    // Compute expected size for set frame
//    const uint8_t expected_frame_size = 12;
//
//    // Creating the frame
//     frame_generator.initialize_frame(switch_all_SET,
//                                      frame,
//                                      expected_frame_size);
//     frame_generator.add_value(value_node, DESIRED_OR_REPORTED_ATTRIBUTE);
//     frame_generator.validate_frame(frame_length);
//  } catch (const std::exception &e) {
//    sl_log_error(LOG_TAG,
//                 "Error while generating switch_all Set frame : %s",
//                 e.what());
//    return SL_STATUS_FAIL;
//  }
//
//  return SL_STATUS_OK;
//}

///////////////////////////////////////////////////////////////////////////////
// Frame parsing functions
///////////////////////////////////////////////////////////////////////////////
//static sl_status_t zwave_command_class_switch_all_handle_report(
//  const zwave_controller_connection_info_t *connection_info,
//  const uint8_t *frame_data,
//  uint16_t frame_length)
//{
//  // Setup
//  attribute_store::attribute endpoint_node(
//    zwave_command_class_get_endpoint_node(connection_info));
//  auto current_version = get_current_switch_all_version(endpoint_node);
//
//  sl_log_debug(LOG_TAG, "switch_all Report frame received");
//
//  // Compute expected size for report frame
//  const uint8_t expected_size = 12;

//  // Parse the frame
//  try {
//   zwave_frame_parser parser(frame_data, frame_length);

//   if (!parser.is_frame_size_valid(expected_size)) {
//     sl_log_error(LOG_TAG,
//                  "Invalid frame size for switch_all Report frame");
//     return SL_STATUS_FAIL;
//   }

//  } catch (const std::exception &e) {
//   sl_log_error(LOG_TAG,
//                "Error while parsing switch_all Report frame : %s",
//                e.what());
//   return SL_STATUS_FAIL;
//  }
//  return SL_STATUS_OK;
//}

///////////////////////////////////////////////////////////////////////////////
// Incoming commands handler
///////////////////////////////////////////////////////////////////////////////
sl_status_t zwave_command_class_switch_all_control_handler(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  // Frame too short, it should have not come here.
  if (frame_length <= COMMAND_INDEX) {
    return SL_STATUS_NOT_SUPPORTED;
  }

  switch (frame_data[COMMAND_INDEX]) {
    // case switch_all_REPORT:
    //   return zwave_command_class_switch_all_handle_report(connection_info,
    //                                                    frame_data,
    //                                                    frame_length);
    default:
      return SL_STATUS_NOT_SUPPORTED;
  }
}

///////////////////////////////////////////////////////////////////////////////
// Attribute Store callback functions
///////////////////////////////////////////////////////////////////////////////
static void zwave_command_class_switch_all_on_version_attribute_update(
  attribute_store_node_t updated_node, attribute_store_change_t change)
{
  if (change == ATTRIBUTE_DELETED) {
    return;
  }

  // Confirm that we have a version attribute update
  assert(ATTRIBUTE(VERSION) == attribute_store_get_node_type(updated_node));

  attribute_store::attribute version_node(updated_node);
  // Do not create the attributes until we are sure of the version
  //zwave_cc_version_t supporting_node_version = 0;

  // Wait for the version
  if (!version_node.reported_exists()) {
    return;
  }
  //supporting_node_version = version_node.reported<uint8_t>();

  // Now we know we have a switch_all supporting endpoint.
  attribute_store::attribute endpoint_node
   = version_node.first_parent(ATTRIBUTE_ENDPOINT_ID);

  // Create the switch_all attributes
  endpoint_node.emplace_node(ATTRIBUTE(MODE));

  endpoint_node.first_parent(ATTRIBUTE_HOME_ID).emplace_node(ATTRIBUTE(ON_OFF));

}

///////////////////////////////////////////////////////////////////////////////
// Public interface functions
///////////////////////////////////////////////////////////////////////////////
sl_status_t zwave_command_class_switch_all_init()
{
  // Attribute store callbacks
  attribute_store_register_callback_by_type(
    zwave_command_class_switch_all_on_version_attribute_update,
    ATTRIBUTE(VERSION));

  // Attribute resolver rules
  // attribute_resolver_register_rule(ATTRIBUTE(MODE),
  //                                  zwave_command_class_switch_all_set,
  //                                  zwave_command_class_switch_all_get);
  //   attribute_resolver_register_rule(ATTRIBUTE(ON_OFF),
  //                                  zwave_command_class_switch_all_set,
  //                                  nullptr);

  // The support side of things: Register our handler to the Z-Wave CC framework:
  zwave_command_handler_t handler = {};
  handler.support_handler         = NULL;
  handler.control_handler = &zwave_command_class_switch_all_control_handler;
  // Not supported, so this does not really matter
  handler.minimal_scheme             = ZWAVE_CONTROLLER_ENCAPSULATION_NETWORK_SCHEME;
  handler.manual_security_validation = false;
  handler.command_class              = COMMAND_CLASS_SWITCH_ALL;
  handler.version                    = SWITCH_ALL_VERSION;
  handler.command_class_name         = "switch_all";
  handler.comments                   = "";

  zwave_command_handler_register_handler(handler);

  return SL_STATUS_OK;
}
