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
#include "zwave_controller_utils.h"
#include "zwave_command_class_indices.h"

// Includes from other components
#include "unity.h"
#include "sl_log.h"

// Mock includes
#include "zwave_tx_mock.h"

// Generic includes
#include <assert.h>
#include <stdbool.h>

// Test constant
static uint8_t test_super_tricky_nif[] = {
  0xD2,
  0x09,
  0xFB,
  COMMAND_CLASS_CONTROL_MARK,  // This one will be ignored, as it is part of an extended CC
  0xBD,
  0xCB,
  0x92,
  0xA7,
  0xFF,
  0x01,
  0xEA,
  0xF9,
  0xFF,
  0x66,
  COMMAND_CLASS_CONTROL_MARK,
  0x9F,
  0x44,
  0x28,
  0x00,
  0xF2,
  0x4E,
  0xF6};  // Erroneous ending, in the middle of an Extended CC
static uint8_t test_super_tricky_nif_length = sizeof(test_super_tricky_nif);

/// Setup the test suite (called once before all test_xxx functions are called)
void suiteSetUp() {}

/// Teardown the test suite (called once after all test_xxx functions are called)
int suiteTearDown(int num_failures)
{
  return num_failures;
}

void setUp() {}

void test_zwave_parse_nif()
{
  zwave_command_class_t supported_command_classes[ZWAVE_MAX_NIF_SIZE];
  zwave_command_class_t controlled_command_classes[ZWAVE_MAX_NIF_SIZE];
  size_t supported_command_classes_length  = 0;
  size_t controlled_command_classes_length = 0;

  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    zwave_parse_nif(test_super_tricky_nif,
                                    test_super_tricky_nif_length,
                                    supported_command_classes,
                                    &supported_command_classes_length,
                                    controlled_command_classes,
                                    &controlled_command_classes_length));

  // Check the supported CCs
  TEST_ASSERT_EQUAL(11, supported_command_classes_length);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[0], supported_command_classes[0]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[1], supported_command_classes[1]);
  TEST_ASSERT_EQUAL(
    ((test_super_tricky_nif[2] << 8) | test_super_tricky_nif[3]),
    supported_command_classes[2]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[4], supported_command_classes[3]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[5], supported_command_classes[4]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[6], supported_command_classes[5]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[6], supported_command_classes[5]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[7], supported_command_classes[6]);
  TEST_ASSERT_EQUAL(
    ((test_super_tricky_nif[8] << 8) | test_super_tricky_nif[9]),
    supported_command_classes[7]);

  TEST_ASSERT_EQUAL(test_super_tricky_nif[10], supported_command_classes[8]);
  TEST_ASSERT_EQUAL(
    ((test_super_tricky_nif[11] << 8) | test_super_tricky_nif[12]),
    supported_command_classes[9]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[13], supported_command_classes[10]);

  // Now check the controlled CCs
  TEST_ASSERT_EQUAL(5, controlled_command_classes_length);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[15], controlled_command_classes[0]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[16], controlled_command_classes[1]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[17], controlled_command_classes[2]);
  TEST_ASSERT_EQUAL(test_super_tricky_nif[18], controlled_command_classes[3]);
  TEST_ASSERT_EQUAL(
    ((test_super_tricky_nif[19] << 8) | test_super_tricky_nif[20]),
    controlled_command_classes[4]);
}

void test_zwave_parse_nif_null_pointers()
{
  TEST_ASSERT_EQUAL(SL_STATUS_OK,
                    zwave_parse_nif(test_super_tricky_nif,
                                    test_super_tricky_nif_length,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL));
}

void test_zwave_network_scheme_str()
{
  // clang-format off
  TEST_ASSERT_EQUAL_STRING("Network Scheme", zwave_network_scheme_str(ZWAVE_CONTROLLER_ENCAPSULATION_NETWORK_SCHEME));
  TEST_ASSERT_EQUAL_STRING("Unencrypted", zwave_network_scheme_str(ZWAVE_CONTROLLER_ENCAPSULATION_NONE));
  TEST_ASSERT_EQUAL_STRING("Security Scheme 0", zwave_network_scheme_str(ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_0));
  TEST_ASSERT_EQUAL_STRING("Security 2, unauthenticated", zwave_network_scheme_str(ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_2_UNAUTHENTICATED));
  TEST_ASSERT_EQUAL_STRING("Security 2, authenticated", zwave_network_scheme_str(ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_2_AUTHENTICATED));
  TEST_ASSERT_EQUAL_STRING("Security 2, access", zwave_network_scheme_str(ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_2_ACCESS));
  TEST_ASSERT_EQUAL_STRING("Unknown", zwave_network_scheme_str(42));
  // clang-format on
}

void test_is_command_class_in_supported_list()
{
  // Test constant
  static uint8_t test_nif[]      = {0xD2,
                               0x09,
                               0xFB,
                               0x01,
                               0xBD,
                               0xCB,
                               0x92,
                               0xA7,
                               0xCA,
                               0x1A,
                               0xEA,
                               0x99,
                               0xC6,
                               0x66,
                               0x9F,
                               0xFF};
  static uint8_t test_nif_length = sizeof(test_nif);

  TEST_ASSERT_TRUE(
    is_command_class_in_supported_list(0x09, test_nif, test_nif_length));
}

void test_send_nop_to_node()
{
  const zwave_node_id_t test_node_id     = 12;
  const uint32_t test_qos_priority       = 3485;
  const uint32_t test_discard_timeout_ms = 1;
  void *test_user                        = (void *)0x1233654;
  on_zwave_tx_send_data_complete_t test_callback
    = (on_zwave_tx_send_data_complete_t)23;

  zwave_tx_send_data_ExpectAndReturn(NULL,
                                     1,
                                     NULL,
                                     0,
                                     test_callback,
                                     test_user,
                                     0,
                                     SL_STATUS_FULL);
  zwave_tx_send_data_IgnoreArg_connection();
  zwave_tx_send_data_IgnoreArg_tx_options();
  zwave_tx_send_data_IgnoreArg_data();

  TEST_ASSERT_EQUAL(SL_STATUS_FULL,
                    zwave_send_nop_to_node(test_node_id,
                                           test_qos_priority,
                                           test_discard_timeout_ms,
                                           test_callback,
                                           test_user));
}

void test_zwave_command_class_list_pack_empty()
{
  zwave_node_info_t node_info = {.listening_protocol        = 2,
                                 .optional_protocol         = 3,
                                 .basic_device_class        = 4,
                                 .generic_device_class      = 5,
                                 .specific_device_class     = 6,
                                 .command_class_list_length = 0,
                                 .command_class_list        = {0}};

  uint8_t nif[ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH * 2] = {0};
  uint8_t nif_length                                                  = 0;

  zwave_command_class_list_pack(&node_info, nif, &nif_length);
  TEST_ASSERT_EQUAL(0, nif_length);
  zwave_command_class_list_unpack(&node_info, nif, nif_length);
  TEST_ASSERT_EQUAL(0, node_info.command_class_list_length);
}

void test_zwave_command_class_list_pack()
{
  zwave_node_info_t node_info = {.listening_protocol        = 2,
                                 .optional_protocol         = 3,
                                 .basic_device_class        = 4,
                                 .generic_device_class      = 5,
                                 .specific_device_class     = 6,
                                 .command_class_list_length = 3,
                                 .command_class_list = {0x01, 0xF0, 0xFF}};

  uint8_t nif[ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH] = {0};
  uint8_t nif_length                                              = 0;

  zwave_command_class_list_pack(&node_info, nif, &nif_length);

  TEST_ASSERT_EQUAL(node_info.command_class_list_length, nif_length);
  TEST_ASSERT_EQUAL(node_info.command_class_list[0], nif[0]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[1], nif[1]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[2], nif[2]);
}

void test_zwave_command_class_list_pack_extended()
{
  zwave_node_info_t node_info = {
    .listening_protocol        = 2,
    .optional_protocol         = 3,
    .basic_device_class        = 4,
    .generic_device_class      = 5,
    .specific_device_class     = 6,
    .command_class_list_length = 3 + 3,
    .command_class_list = {0x20, 0xEF, 0xF0, 0xF100, 0xF101, 0xFFFF}
  };

  uint8_t nif[ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH * 2] = {0};
  uint8_t nif_length                                                  = 0;

  zwave_command_class_list_pack(&node_info, nif, &nif_length);

  TEST_ASSERT_EQUAL(3 + 3 * 2, nif_length);

  TEST_ASSERT_EQUAL(node_info.command_class_list[0], nif[0]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[1], nif[1]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[2], nif[2]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[3], (nif[3] << 8) | nif[4]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[4], (nif[5] << 8) | nif[6]);
  TEST_ASSERT_EQUAL(node_info.command_class_list[5], (nif[7] << 8) | nif[8]);
  zwave_command_class_list_unpack(&node_info, nif, nif_length);
  TEST_ASSERT_EQUAL(3 + 3, node_info.command_class_list_length);
}

void test_zwave_command_class_list_pack_extended_full()
{
  zwave_node_info_t node_info = {
    .listening_protocol    = 2,
    .optional_protocol     = 3,
    .basic_device_class    = 4,
    .generic_device_class  = 5,
    .specific_device_class = 6,
    .command_class_list_length
    = ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH,
  };

  for (int i = 0; i < ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH; i++) {
    node_info.command_class_list[i] = 0xFFFF;
  }
  uint8_t nif[ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH * 2] = {0};
  uint8_t nif_length                                                  = 0;

  zwave_command_class_list_pack(&node_info, nif, &nif_length);
  TEST_ASSERT_EQUAL(ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH * 2,
                    nif_length);

  zwave_command_class_list_unpack(&node_info, nif, nif_length);
  TEST_ASSERT_EQUAL(ZWAVE_CONTROLLER_MAXIMUM_COMMAND_CLASS_LIST_LENGTH,
                    node_info.command_class_list_length);
}
