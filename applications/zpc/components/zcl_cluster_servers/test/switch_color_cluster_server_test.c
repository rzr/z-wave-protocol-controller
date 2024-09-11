/******************************************************************************
 * # License
 * <b>Copyright 2022 Silicon Laboratories Inc. www.silabs.com</b>
 ******************************************************************************
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 *****************************************************************************/
#include "switch_color_cluster_server.h"
#include "unify_dotdot_attribute_store.h"
#include "unity.h"

// Unify components
#include "datastore.h"
#include "attribute_store_fixt.h"
#include "attribute_store_helper.h"
#include "unify_dotdot_defined_attribute_types.h"
#include "dotdot_mqtt_mock.h"

// ZPC Components
#include "zwave_unid.h"
#include "zwave_command_class_thermostat_fan_types.h"

// Test helpers
#include "zpc_attribute_store_test_helper.h"
#include "attribute_store_defined_attribute_types.h"

#define ATTRIBUTE(type) ATTRIBUTE_COMMAND_CLASS_SWITCH_COLOR_##type

static uic_mqtt_dotdot_unify_switch_color_set_color_callback_t                 set_color_command = NULL;
static uic_mqtt_dotdot_unify_switch_color_start_stop_change_callback_t         start_stop_change_command = NULL;

void uic_mqtt_dotdot_unify_switch_color_set_color_callback_set_stub(
  const uic_mqtt_dotdot_unify_switch_color_set_color_callback_t callback,
  int cmock_num_calls)
{
  set_color_command = callback;
}

void uic_mqtt_dotdot_unify_switch_color_start_stop_change_callback_set_stub(
  const uic_mqtt_dotdot_unify_switch_color_start_stop_change_callback_t callback,
  int cmock_num_calls)
{
  start_stop_change_command = callback;
}

/// Setup the test suite (called once before all test_xxx functions are called)
void suiteSetUp()
{
  datastore_init(":memory:");
  attribute_store_init();
}

/// Teardown the test suite (called once after all test_xxx functions are called)
int suiteTearDown(int num_failures)
{
  attribute_store_teardown();
  datastore_teardown();
  return num_failures;
}

/// Called before each and every test
void setUp()
{
  zpc_attribute_store_test_helper_create_network();

  set_color_command = NULL;
  start_stop_change_command = NULL;

  uic_mqtt_dotdot_unify_switch_color_set_color_callback_set_Stub(&uic_mqtt_dotdot_unify_switch_color_set_color_callback_set_stub);
  uic_mqtt_dotdot_unify_switch_color_start_stop_change_callback_set_Stub(&uic_mqtt_dotdot_unify_switch_color_start_stop_change_callback_set_stub);

  // Call init
  TEST_ASSERT_EQUAL(SL_STATUS_OK, switch_color_cluster_server_init());
}

/// Called after each and every test
void tearDown()
{
  attribute_store_delete_node(attribute_store_get_root());
}

void test_color_set_command_v1_happy_case()
{
  TEST_ASSERT_NOT_NULL(set_color_command);

  const uint8_t color_component_id_tested = 3; //Green Color
  const uint8_t value_tested = 0xAB;
  const uint16_t duration_tested = 100;

  // It should not work since we don't have the attribute yet
  TEST_ASSERT_EQUAL(SL_STATUS_FAIL,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  // Simulate that the nodes is created by an another function
  attribute_store_node_t green_node = attribute_store_add_node(DOTDOT_ATTRIBUTE_ID_UNIFY_SWITCH_COLOR_GREEN,
                                                               endpoint_id_node);

  // Test support
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  // Test callback
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_NORMAL,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  uint8_t color_value = 0;

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(green_node, &color_value, sizeof(color_value)),
    "Can't get color value");
    
  // Test value
  TEST_ASSERT_EQUAL(value_tested, color_value);
}

void test_color_set_command_v2_happy_case()
{
  TEST_ASSERT_NOT_NULL(set_color_command);

  const uint8_t color_component_id_tested = 3; //Green Color
  const uint8_t value_tested = 0xAB;
  const uint16_t duration_tested = 100;

  // It should not work since we don't have the attribute yet
  TEST_ASSERT_EQUAL(SL_STATUS_FAIL,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  // Simulate that the nodes is created by an another function
  attribute_store_node_t green_node = attribute_store_add_node(DOTDOT_ATTRIBUTE_ID_UNIFY_SWITCH_COLOR_GREEN,
                                                               endpoint_id_node);

  attribute_store_node_t state_node = attribute_store_add_node(ATTRIBUTE(STATE),
                                                               endpoint_id_node);                                                             

  attribute_store_node_t duration_node = attribute_store_add_node(ATTRIBUTE(DURATION),
                                                                  state_node);

  // Test support
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  // Test callback
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_NORMAL,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  uint8_t color_value = 0;
  uint32_t duration_value = 0;

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(green_node, &color_value, sizeof(color_value)),
    "Can't get color value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(duration_node, &duration_value, sizeof(duration_value)),
    "Can't get duration value");
    
  // Test value
  TEST_ASSERT_EQUAL(value_tested, color_value);
  TEST_ASSERT_EQUAL(duration_tested, duration_value);
}

void test_color_set_command_v1_invalid_color_component_id()
{
  TEST_ASSERT_NOT_NULL(set_color_command);

  const uint8_t color_component_id_tested = 10; //Green Color
  const uint8_t value_tested = 0xAB;
  const uint16_t duration_tested = 100;

  // It should not work since we don't have the attribute yet
  TEST_ASSERT_EQUAL(SL_STATUS_FAIL,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  // Simulate that the nodes is created by an another function
  attribute_store_add_node(DOTDOT_ATTRIBUTE_ID_UNIFY_SWITCH_COLOR_GREEN,
                                                               endpoint_id_node);

  // Test support
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));

  // Test callback
  TEST_ASSERT_EQUAL(SL_STATUS_FAIL,
                    set_color_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_NORMAL,
                                      color_component_id_tested,
                                      value_tested,
                                      duration_tested));
}

void test_start_stop_change_command_start_change_happy_case()
{
  TEST_ASSERT_NOT_NULL(set_color_command);

  const bool start_stop_tested = 1; //Start change
  const uint8_t start_change_value_tested = 1;
  const bool up_down_tested = 1;
  const bool ignor_start_level_tested = 1;
  const uint8_t color_component_id_tested = 3; //Green Color;
  const uint8_t start_level_tested = 0xAB;
  const uint32_t duration_tested = 100;

  // It should not work since we don't have the attribute yet
  TEST_ASSERT_EQUAL(SL_STATUS_FAIL,
                    start_stop_change_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      start_stop_tested,
                                      up_down_tested,
                                      ignor_start_level_tested,
                                      color_component_id_tested,
                                      start_level_tested,
                                      duration_tested));

  // Simulate that the nodes is created by an another function
  attribute_store_add_node(DOTDOT_ATTRIBUTE_ID_UNIFY_SWITCH_COLOR_GREEN,
                           endpoint_id_node);

  attribute_store_node_t state_node = attribute_store_add_node(ATTRIBUTE(STATE),
                                                               endpoint_id_node);
  attribute_store_node_t color_component_id_node = attribute_store_add_node(ATTRIBUTE(COLOR_COMPONENT_ID),
                                                                            state_node);

  attribute_store_set_node_attribute_value(color_component_id_node,
                                           REPORTED_ATTRIBUTE,
                                           (uint8_t*)&color_component_id_tested,
                                           sizeof(color_component_id_tested));     

  attribute_store_node_t start_change_node = attribute_store_add_node(ATTRIBUTE(START_CHANGE),
                                                                      color_component_id_node);                                                                 

  attribute_store_node_t duration_node = attribute_store_add_node(ATTRIBUTE(DURATION),
                                                                  state_node);

  attribute_store_node_t up_down_node = attribute_store_add_node(ATTRIBUTE(UP_DOWN),
                                                                 state_node);

  attribute_store_node_t ignore_start_level_node = attribute_store_add_node(ATTRIBUTE(IGNORE_START_LEVEL),
                                                                            state_node);

  attribute_store_node_t start_level_node = attribute_store_add_node(ATTRIBUTE(START_LEVEL),
                                                                     state_node);

  // Test support
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    start_stop_change_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      start_stop_tested,
                                      up_down_tested,
                                      ignor_start_level_tested,
                                      color_component_id_tested,
                                      start_level_tested,
                                      duration_tested));

  // Test callback  
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    start_stop_change_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_NORMAL,
                                      start_stop_tested,
                                      up_down_tested,
                                      ignor_start_level_tested,
                                      color_component_id_tested,
                                      start_level_tested,
                                      duration_tested));

  uint8_t start_change_value = 0;
  uint8_t up_down_value = 0;
  uint8_t ignor_start_level_value = 0;
  uint8_t start_level_value = 0;
  uint32_t duration_value = 0;

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(start_change_node, &start_change_value, sizeof(start_change_value)),
    "Can't get start change value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(up_down_node, &up_down_value, sizeof(up_down_value)),
    "Can't get up down value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(ignore_start_level_node, &ignor_start_level_value, sizeof(ignor_start_level_value)),
    "Can't get ignore start level value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(start_level_node, &start_level_value, sizeof(start_level_value)),
    "Can't get tart level value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(duration_node, &duration_value, sizeof(duration_value)),
    "Can't get duration value");
    
  // Test value
  TEST_ASSERT_EQUAL(start_change_value_tested, start_change_value);
  TEST_ASSERT_EQUAL(up_down_tested, up_down_value);
  TEST_ASSERT_EQUAL(ignor_start_level_tested, ignor_start_level_value);
  TEST_ASSERT_EQUAL(start_level_tested, start_level_value);
  TEST_ASSERT_EQUAL(duration_tested, duration_value);
}

void test_start_stop_change_command_stop_change_happy_case()
{
  TEST_ASSERT_NOT_NULL(set_color_command);

  const bool start_stop_tested = 0; //Stop change
  const uint8_t stop_change_value_tested = 1;
  const bool up_down_tested = 1;
  const bool ignor_start_level_tested = 1;
  const uint8_t color_component_id_tested = 3; //Green Color;
  const uint8_t start_level_tested = 0xAB;
  const uint32_t duration_tested = 100;

  // It should not work since we don't have the attribute yet
  TEST_ASSERT_EQUAL(SL_STATUS_FAIL,
                    start_stop_change_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      start_stop_tested,
                                      up_down_tested,
                                      ignor_start_level_tested,
                                      color_component_id_tested,
                                      start_level_tested,
                                      duration_tested));

  // Simulate that the nodes is created by an another function
  attribute_store_add_node(DOTDOT_ATTRIBUTE_ID_UNIFY_SWITCH_COLOR_GREEN,
                           endpoint_id_node);

  attribute_store_node_t state_node = attribute_store_add_node(ATTRIBUTE(STATE),
                                                               endpoint_id_node);
  attribute_store_node_t color_component_id_node = attribute_store_add_node(ATTRIBUTE(COLOR_COMPONENT_ID),
                                                                            state_node);

  attribute_store_set_node_attribute_value(color_component_id_node,
                                           REPORTED_ATTRIBUTE,
                                           (uint8_t*)&color_component_id_tested,
                                           sizeof(color_component_id_tested));     

  attribute_store_node_t stop_change_node = attribute_store_add_node(ATTRIBUTE(STOP_CHANGE),
                                                                      color_component_id_node);                                                                 

  attribute_store_node_t duration_node = attribute_store_add_node(ATTRIBUTE(DURATION),
                                                                  state_node);

  attribute_store_node_t up_down_node = attribute_store_add_node(ATTRIBUTE(UP_DOWN),
                                                                 state_node);

  attribute_store_node_t ignore_start_level_node = attribute_store_add_node(ATTRIBUTE(IGNORE_START_LEVEL),
                                                                            state_node);

  attribute_store_node_t start_level_node = attribute_store_add_node(ATTRIBUTE(START_LEVEL),
                                                                     state_node);

  // Test support
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    start_stop_change_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_SUPPORT_CHECK,
                                      start_stop_tested,
                                      up_down_tested,
                                      ignor_start_level_tested,
                                      color_component_id_tested,
                                      start_level_tested,
                                      duration_tested));

  // Test callback  
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    start_stop_change_command(supporting_node_unid,
                                      endpoint_id,
                                      UIC_MQTT_DOTDOT_CALLBACK_TYPE_NORMAL,
                                      start_stop_tested,
                                      up_down_tested,
                                      ignor_start_level_tested,
                                      color_component_id_tested,
                                      start_level_tested,
                                      duration_tested));

  uint8_t stop_change_value = 0;
  uint8_t up_down_value = 0;
  uint8_t ignor_start_level_value = 0;
  uint8_t start_level_value = 0;
  uint32_t duration_value = 0;

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(stop_change_node, &stop_change_value, sizeof(stop_change_value)),
    "Can't get stop change value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(up_down_node, &up_down_value, sizeof(up_down_value)),
    "Can't get up down value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(ignore_start_level_node, &ignor_start_level_value, sizeof(ignor_start_level_value)),
    "Can't get ignore start level value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(start_level_node, &start_level_value, sizeof(start_level_value)),
    "Can't get tart level value");

  TEST_ASSERT_EQUAL_MESSAGE(
    SL_STATUS_OK,
    attribute_store_get_desired(duration_node, &duration_value, sizeof(duration_value)),
    "Can't get duration value");
    
  // Test value
  TEST_ASSERT_EQUAL(stop_change_value_tested, stop_change_value);
  TEST_ASSERT_EQUAL(up_down_tested, up_down_value);
  TEST_ASSERT_EQUAL(ignor_start_level_tested, ignor_start_level_value);
  TEST_ASSERT_EQUAL(start_level_tested, start_level_value);
  TEST_ASSERT_EQUAL(duration_tested, duration_value);
}