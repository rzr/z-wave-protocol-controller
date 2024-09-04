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
// Base class
#include "zwave_command_class_switch_color.h"
#include "zwave_command_class_color_switch_types.h"
#include "zwave_command_class_generic_types.h"
#include "zwave_command_classes_utils.h"
#include "unity.h"

// Generic includes
#include <string.h>

// Unify
#include "datastore.h"
#include "attribute_store.h"
#include "attribute_store_fixt.h"

// Interface includes
#include "ZW_classcmd.h"
#include "sl_log.h"

// ZPC includes
#include "attribute_store_defined_attribute_types.h"
#include "zpc_attribute_store_type_registration.h"

// Test helpers
#include "zwave_command_class_test_helper.hpp"

// Attribute macro, shortening those long defines for attribute types:
#define ATTRIBUTE(type) ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_##type

// Max component ID color supported
#define MAX_SUPPORTED_COLOR_COMPONENT 9
// Index of obsoleted component ID
#define COMPONENT_ID_INDEXED_COLOR 8

// Log tag
constexpr char LOG_TAG[] = "zwave_command_class_switch_color_test";

using namespace zwave_command_class_test_helper;

extern "C" {

/// Setup the test suite (called once before all test_xxx functions are called)
void suiteSetUp()
{
  datastore_init(":memory:");
  attribute_store_init();
  zpc_attribute_store_register_known_attribute_types();
}

/// Teardown the test suite (called once after all test_xxx functions are called)
int suiteTearDown(int num_failures)
{
  attribute_store_teardown();
  datastore_teardown();
  return num_failures;
}

// Tested command class handler
const zwave_struct_handler_args command_class_handler
  = {.command_class_id  = COMMAND_CLASS_SWITCH_COLOR,
     .supported_version = 3,
     .scheme            = ZWAVE_CONTROLLER_ENCAPSULATION_NETWORK_SCHEME};
// Get Set function map
const resolver_function_map attribute_bindings = {
  {ATTRIBUTE(VALUE), {SWITCH_COLOR_GET, SWITCH_COLOR_SET}},
  {ATTRIBUTE(STOP_CHANGE), {0, SWITCH_COLOR_STOP_LEVEL_CHANGE}},
  {ATTRIBUTE(START_CHANGE), {0, SWITCH_COLOR_START_LEVEL_CHANGE}},
  {ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK), {SWITCH_COLOR_SUPPORTED_GET, 0}},
};

/// Called before each and every test
void setUp()
{
  zwave_setUp(command_class_handler,
              &zwave_command_class_switch_color_init,
              attribute_bindings);
}

///////////////////////////////////////////////////////////////////////////////
// Internal helpers
///////////////////////////////////////////////////////////////////////////////
attribute_store::attribute helper_get_component_maks_node()
{
  return helper_test_and_get_node(ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK));
}

attribute_store::attribute helper_get_state_node()
{
  return helper_test_and_get_node(ATTRIBUTE(STATE));
}

attribute_store::attribute helper_get_component_id_node()
{
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  return helper_test_and_get_node(ATTRIBUTE(COLOR_COMPONENT_ID), state_node);
}

attribute_store::attribute helper_get_duration_node()
{
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  return helper_test_and_get_node(ATTRIBUTE(DURATION), state_node);
}

attribute_store::attribute helper_get_up_down_node()
{
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  return helper_test_and_get_node(ATTRIBUTE(UP_DOWN), state_node);
}

attribute_store::attribute helper_get_ignore_start_level_node()
{
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  return helper_test_and_get_node(ATTRIBUTE(IGNORE_START_LEVEL), state_node);
}

attribute_store::attribute helper_get_start_level_node()
{
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  return helper_test_and_get_node(ATTRIBUTE(START_LEVEL), state_node);
}

attribute_store::attribute helper_get_value_node_from_color_component_id_node(attribute_store_node_t color_component_id_node)
{
  return helper_test_and_get_node(ATTRIBUTE(VALUE), color_component_id_node);
}

attribute_store::attribute helper_get_start_change_node_from_color_component_id_node(attribute_store_node_t color_component_id_node)
{
  return helper_test_and_get_node(ATTRIBUTE(START_CHANGE), color_component_id_node);
}

attribute_store::attribute helper_get_stop_change_node_from_color_component_id_node(attribute_store_node_t color_component_id_node)
{
  return helper_test_and_get_node(ATTRIBUTE(STOP_CHANGE), color_component_id_node);
}

std::vector<attribute_store::attribute> get_supported_color_component_id_node(uint16_t bitmask_tested) 
{
  std::vector<attribute_store::attribute> supported_colors_node;
  uint8_t current_bit;

  //Get state node form endpoint node
  auto vector_state_node = cpp_endpoint_id_node.children(ATTRIBUTE(STATE));
  attribute_store::attribute state_node(vector_state_node.front());

  for (uint8_t i = 0; i < MAX_SUPPORTED_COLOR_COMPONENT; i++) {
    current_bit = 1 << i;
    current_bit &= bitmask_tested;

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

    // Get color component id node
    color_component_id_t component_id = i;
     supported_colors_node.push_back(state_node.child_by_type_and_value(ATTRIBUTE(COLOR_COMPONENT_ID), component_id));
  }

  return supported_colors_node;
}

///////////////////////////////////////////////////////////////////////////////
// Test cases
///////////////////////////////////////////////////////////////////////////////

void test_switch_color_interview_v1_happy_case()
{
  helper_set_version(1);

  helper_test_and_get_node(ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK));
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  // Verify that we have the correct node(s)
  helper_test_node_exists(ATTRIBUTE(UP_DOWN), state_node);
  helper_test_node_exists(ATTRIBUTE(IGNORE_START_LEVEL), state_node);
  helper_test_node_exists(ATTRIBUTE(START_LEVEL), state_node);
  
  helper_test_node_does_not_exists(ATTRIBUTE(DURATION), state_node);
}

void test_switch_color_interview_v2_happy_case()
{
  helper_set_version(2);

  helper_test_and_get_node(ATTRIBUTE(SUPPORTED_COLOR_COMPONENT_MASK));
  auto state_node = helper_test_and_get_node(ATTRIBUTE(STATE));

  // Verify that we have the correct node(s)
  helper_test_node_exists(ATTRIBUTE(UP_DOWN), state_node);
  helper_test_node_exists(ATTRIBUTE(IGNORE_START_LEVEL), state_node);
  helper_test_node_exists(ATTRIBUTE(START_LEVEL), state_node);
  helper_test_node_exists(ATTRIBUTE(DURATION), state_node);
}

void test_switch_color_supported_get_happy_case()
{
  helper_test_get_set_frame_happy_case(SWITCH_COLOR_SUPPORTED_GET);
}

void test_switch_color_supported_report_happy_case()
{
  
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  //Get state node form endpoint node
  auto vector_state_node = cpp_endpoint_id_node.children(ATTRIBUTE(STATE));
  attribute_store::attribute state_node(vector_state_node.front());


  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);


  for (auto color_component_id_node : vector_supported_node_id) { 
    // Verify that color component id node exist
    uint8_t component_id_not_expect_tested = ATTRIBUTE_STORE_INVALID_NODE;
    TEST_ASSERT_NOT_EQUAL_MESSAGE(component_id_not_expect_tested,
                                  color_component_id_node,
                                  "Can not find attribute");

    // Verify that we value note exist
    helper_get_value_node_from_color_component_id_node(color_component_id_node);

    // Verify that we start change note exist and have correct value
    auto start_change_node = helper_get_start_change_node_from_color_component_id_node(color_component_id_node);
    uint8_t start_change_value_tested = 0;
    TEST_ASSERT_EQUAL_MESSAGE(start_change_value_tested,
                              start_change_node.reported<uint8_t>(),
                              "Start change node isn't have correct value");

    // Verify that we stop change note exist and have correct value
    auto stop_change_node =  helper_get_stop_change_node_from_color_component_id_node(color_component_id_node);
    uint8_t stop_change_value_tested = 0;
    TEST_ASSERT_EQUAL_MESSAGE(stop_change_value_tested,
                              stop_change_node.reported<uint8_t>(),
                              "Stop change node isn't have correct value");    
  }
  
  // Test number of Color Component ID
  auto supported_color_component_count = attribute_store_get_node_child_count_by_type(state_node, 
                                                                                      ATTRIBUTE(COLOR_COMPONENT_ID));

  TEST_ASSERT_EQUAL_MESSAGE(vector_supported_node_id.size(),
                            supported_color_component_count,
                            "Number of Color Component ID attribute is not correct");
}

void test_switch_color_get_happy_case()
{
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  
  //Send Color Switch Supported Report frame to create necessary attributes.
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // attribute_store_log();

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto element : vector_supported_node_id) { 
    //Get value node
    attribute_store::attribute color_component_id_node(element);
    auto value_node = color_component_id_node.child_by_type(ATTRIBUTE(VALUE));
    //Test switch color get frame
    helper_test_get_set_frame_happy_case(SWITCH_COLOR_GET, value_node, {color_component_id_node.reported<uint8_t>()});
  }
}

void test_switch_color_report_v1_happy_case()
{
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t value_tested = 0xAB;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 

    // Verify that we value note exist
    auto value_node = helper_get_value_node_from_color_component_id_node(color_component_id_node);

    helper_test_report_frame(SWITCH_COLOR_REPORT, {color_component_id_node.reported<uint8_t>(), value_tested});
    // attribute_store_log();
    // Verify that the value is updated correct
    TEST_ASSERT_EQUAL_MESSAGE(value_tested,
                              value_node.reported<uint32_t>(),
                              "Value of isn't updated correct after swich color report");
  }
}

void test_switch_color_report_v3_happy_case()
{
  helper_set_version(3);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t current_value_tested = 0xAB;
  uint8_t target_value_tested = 0xAB;
  uint8_t duration_tested = 10;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 
    // Verify that we value note exist
    auto value_node = helper_get_value_node_from_color_component_id_node(color_component_id_node);

    //Verify that we duration note exist
    auto duration_node = helper_get_duration_node();

    helper_test_report_frame(SWITCH_COLOR_REPORT, {color_component_id_node.reported<uint8_t>(), current_value_tested, target_value_tested, duration_tested});

    // attribute_store_log();

    // Verify that the value is updated correct
    TEST_ASSERT_EQUAL_MESSAGE(current_value_tested,
                              value_node.reported<uint32_t>(),
                              "Value of value node isn't updated correct after swich color report");
   
    // Verify that the duration is updated correct
    TEST_ASSERT_EQUAL_MESSAGE(duration_tested,
                              duration_node.reported<uint32_t>(),
                              "Value of duration node isn't updated correct after swich color report");                           
  }
}

void test_switch_color_report_v1_invalid_color_component_id()
{
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t value_tested = 0xAB;
  uint8_t color_component_id_invalid_tested = 5;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 
    // Verify that we value note exist
    helper_get_value_node_from_color_component_id_node(color_component_id_node);

    helper_test_report_frame(SWITCH_COLOR_REPORT, {color_component_id_invalid_tested, value_tested}, SL_STATUS_FAIL);
  }
}

void test_switch_color_start_level_change_v1_happy_case()
{
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t start_change_node_tested = 1;
  uint8_t start_change_node_finnal_state = FINAL_STATE;
  uint8_t up_down_tested = 1;
  uint8_t ignore_start_level_tested = 1;
  uint8_t start_level_tested = 0xAB;
  uint8_t start_level_change_properties1_tested = ((up_down_tested << 6) | (ignore_start_level_tested << 5));

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 
    // Get color start change node and set desired value
    auto start_change_node = helper_get_start_change_node_from_color_component_id_node(color_component_id_node);
    start_change_node.set_desired(start_change_node_tested);

    // Get color start change node and set desired value
    auto up_down_node = helper_get_up_down_node();
    up_down_node.set_desired(up_down_tested);

    // Get color start change node and set desired value
    auto ignore_start_level_node = helper_get_ignore_start_level_node();
    ignore_start_level_node.set_desired(ignore_start_level_tested);

    // Get color start change node and set desired value
    auto start_level_node = helper_get_start_level_node();
    start_level_node.set_desired(start_level_tested);

    // attribute_store_log();
    helper_test_get_set_frame_happy_case(SWITCH_COLOR_START_LEVEL_CHANGE,
                                         start_change_node,
                                         {start_level_change_properties1_tested, color_component_id_node.reported<uint8_t>(), start_level_tested});

    //Verify start leve change = 0 after send frame 
    TEST_ASSERT_EQUAL_MESSAGE(start_change_node_finnal_state,
                              start_change_node.reported<uint8_t>(),
                              "Value of start change isn't updated correct after send frame");
  }
}

void test_switch_color_start_level_change_v3_happy_case()
{
  helper_set_version(3);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t start_change_node_tested = 1;
  uint8_t start_change_node_finnal_state = FINAL_STATE;
  uint8_t up_down_tested = 1;
  uint8_t ignore_start_level_tested = 1;
  uint8_t start_level_tested = 0xAB;
  uint8_t duration_tested = 10;
  uint8_t start_level_change_properties1_tested = ((up_down_tested << 6) | (ignore_start_level_tested << 5));

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 
    // Get color start change node and set desired value
    auto start_change_node = helper_get_start_change_node_from_color_component_id_node(color_component_id_node);
    start_change_node.set_desired(start_change_node_tested);

    // Get up down node and set desired value
    auto up_down_node = helper_get_up_down_node();
    up_down_node.set_desired(up_down_tested);

    // Get ignore start level node and set desired value
    auto ignore_start_level_node = helper_get_ignore_start_level_node();
    ignore_start_level_node.set_desired(ignore_start_level_tested);

    // Get start level node and set desired value
    auto start_level_node = helper_get_start_level_node();
    start_level_node.set_desired(start_level_tested);

    // Get duration node and set desired value
    auto duration_node = helper_get_duration_node();
    duration_node.set_desired(duration_tested);

    // attribute_store_log();
    helper_test_get_set_frame_happy_case(SWITCH_COLOR_START_LEVEL_CHANGE_V3,
                                         start_change_node,
                                         {start_level_change_properties1_tested, color_component_id_node.reported<uint8_t>(), start_level_tested, duration_tested});

    //Verify start leve change = 0 after send frame 
    TEST_ASSERT_EQUAL_MESSAGE(start_change_node_finnal_state,
                              start_change_node.reported<uint8_t>(),
                              "Value of start change isn't updated correct after send frame");
  }
}

void test_switch_color_start_level_change_invalid_start_change_value()
{
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t start_change_node_tested = 2;
  uint8_t start_change_node_finnal_state = FINAL_STATE;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 
    // Get color start change node and set desired value
    auto start_change_node = helper_get_start_change_node_from_color_component_id_node(color_component_id_node);
    start_change_node.set_desired(start_change_node_tested);

    // attribute_store_log();

    helper_test_get_set_fail_case(SWITCH_COLOR_START_LEVEL_CHANGE,
                                  SL_STATUS_FAIL,
                                  start_change_node);

    //Verify start leve change = 0 after send frame 
    TEST_ASSERT_EQUAL_MESSAGE(start_change_node_finnal_state,
                              start_change_node.reported<uint8_t>(),
                              "Value of start change isn't updated correct after send frame");
  }
}

void test_switch_color_stop_level_change_happy_case()
{
  helper_set_version(3);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t stop_change_node_tested = 1;
  uint8_t stop_change_node_finnal_state = FINAL_STATE;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 

    // Get color start change node and set desired value
    auto stop_change_node = helper_get_stop_change_node_from_color_component_id_node(color_component_id_node);
    stop_change_node.set_desired(stop_change_node_tested);

    // attribute_store_log();
    helper_test_get_set_frame_happy_case(SWITCH_COLOR_STOP_LEVEL_CHANGE,
                                         stop_change_node,
                                         {color_component_id_node.reported<uint8_t>()});

    //Verify start leve change = 0 after send frame 
    TEST_ASSERT_EQUAL_MESSAGE(stop_change_node_finnal_state,
                              stop_change_node.reported<uint8_t>(),
                              "Value of stop change isn't updated correct after send frame");
  }
}

void test_switch_color_stop_level_change_invalid_stop_change_value()
{
  helper_set_version(3);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t stop_change_node_tested = 2;
  uint8_t stop_change_node_finnal_state = FINAL_STATE;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 

    // Get color start change node and set desired value
    auto stop_change_node = helper_get_stop_change_node_from_color_component_id_node(color_component_id_node);
    stop_change_node.set_desired(stop_change_node_tested);

    // attribute_store_log();

    helper_test_get_set_fail_case(SWITCH_COLOR_STOP_LEVEL_CHANGE,
                                  SL_STATUS_FAIL,
                                  stop_change_node);

    //Verify start leve change = 0 after send frame 
    TEST_ASSERT_EQUAL_MESSAGE(stop_change_node_finnal_state,
                              stop_change_node.reported<uint8_t>(),
                              "Value of stop change isn't updated correct after send frame");
  }
}

void test_switch_color_set_v1_happy_case()
{
  helper_set_version(1);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t value_reported_tested = 0xAB;
  uint8_t value_desired_tested = 0xCD;
  attribute_store::attribute value_node_tested;

  std::vector<uint8_t> arg_tested_frame;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 

    //Send report frame to initialize the value
    helper_test_report_frame(SWITCH_COLOR_REPORT, {color_component_id_node.reported<uint8_t>(), value_reported_tested});

    attribute_store::attribute value_node = helper_get_value_node_from_color_component_id_node(color_component_id_node);
    value_node.set_desired(value_desired_tested);

    arg_tested_frame.push_back(color_component_id_node.reported<uint8_t>()); 
    arg_tested_frame.push_back(value_desired_tested);

    value_node_tested = value_node;
  }

  // attribute_store_log();

  helper_test_get_set_frame_happy_case(SWITCH_COLOR_SET,
                                       value_node_tested,
                                       arg_tested_frame);
}



void test_switch_color_set_v2_happy_case()
{
  helper_set_version(2);

  uint8_t mask_1 = 0x1C;
  uint8_t mask_2 = 0x00;
  uint16_t bitmask_tested = (mask_2 << 8) | mask_1; // 0000 0000 0001 1100
  uint8_t value_reported_tested = 0xAB;
  uint8_t value_desired_tested = 0xCD;
  uint8_t value_duration_tested = 100;
  attribute_store::attribute value_node_tested;

  std::vector<uint8_t> arg_tested_frame;

  auto component_mask_node = helper_get_component_maks_node();
  helper_test_report_frame(SWITCH_COLOR_SUPPORTED_REPORT, {mask_1, mask_2});

  // Verify that the value of color component mask is updated
  TEST_ASSERT_EQUAL_MESSAGE(bitmask_tested,
                            component_mask_node.reported<uint16_t>(),
                            "Value of color component mask isn't updated after report");

  //Get state node form endpoint node
  auto vector_state_node = cpp_endpoint_id_node.children(ATTRIBUTE(STATE));
  attribute_store::attribute state_node(vector_state_node.front());

  auto vector_supported_node_id = get_supported_color_component_id_node(bitmask_tested);

  for (auto color_component_id_node : vector_supported_node_id) { 

    //Send report frame to initialize the value
    helper_test_report_frame(SWITCH_COLOR_REPORT, {color_component_id_node.reported<uint8_t>(), value_reported_tested});

    attribute_store::attribute value_node = helper_get_value_node_from_color_component_id_node(color_component_id_node);
    value_node.set_desired(value_desired_tested);

    arg_tested_frame.push_back(color_component_id_node.reported<uint8_t>()); 
    arg_tested_frame.push_back(value_desired_tested);

    value_node_tested = value_node;
  }

  // attribute_store_log();

  attribute_store::attribute duration_node = helper_get_duration_node();
  duration_node.set_desired(value_duration_tested);

  arg_tested_frame.push_back(value_duration_tested);

  auto supported_color_component_count = attribute_store_get_node_child_count_by_type(state_node, 
                                                                                      ATTRIBUTE(COLOR_COMPONENT_ID));
  arg_tested_frame.insert(arg_tested_frame.begin(), (uint8_t)supported_color_component_count);

  helper_test_get_set_frame_happy_case(SWITCH_COLOR_SET_V2,
                                       value_node_tested,
                                       arg_tested_frame);
}

}