
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

// System
#include <cstdlib>

#include "zwave_command_class_user_credential.h"
#include "zwave_command_classes_utils.h"
#include "ZW_classcmd.h"


// Includes from other ZPC Components
#include "zwave_command_class_indices.h"
#include "zwave_command_handler.h"
#include "zwave_command_class_version_types.h"
#include "attribute_store_defined_attribute_types.h"
#include "zpc_attribute_store.h"
#include "zwave_controller_crc16.h"

// Unify
#include "attribute_resolver.h"
#include "attribute_store.h"
#include "attribute_store_helper.h"
#include "attribute_store_type_registration.h"
#include "sl_log.h"

// DotDot
#include "unify_dotdot_attribute_store_node_state.h"

// Cpp related
#include <vector>
#include <string>
#include <map>
#include <boost/format.hpp>

// Cpp Attribute store
#include "attribute.hpp"
#include "zwave_frame_generator.hpp"
#include "zwave_frame_parser.hpp"

// UTF16 conversion (deprecated in C++17)
// Needed for credential data (password) per specification
#include <locale>
#include <codecvt>

// Macro
#define ATTRIBUTE(type) ATTRIBUTE_COMMAND_CLASS_USER_CREDENTIAL_##type

// Constexpr
constexpr char LOG_TAG[] = "zwave_command_class_user_credential";
// Used to get user names
// If the user name has a size > to this number, we will truncate it
// Specification says that payload data should not exceeded 64 bytes.
constexpr uint8_t MAX_CHAR_SIZE = 64;
// Used to compute checksums
constexpr uint16_t CRC_INITIALIZATION_VALUE = 0x1D0F;

// Using
using attribute_callback = std::function<void(attribute_store::attribute&)>;

/**
 * @brief Implementation notes
 * 
 * 1. Perform mandatory interview with User and Credentials Capabilities
 * 2. Once interview is finished we retrieve all Users/Credentials (see zwave_network_status_changed)
 *    > To get all Users and Credential we create a new node with a desired value. 
 *    > The lack of reported value will trigger a GET
 *    > GET will set the reported value so we can get a report for this USER/CREDENTIAL
 * 
 */

namespace
{
zwave_frame_generator frame_generator(COMMAND_CLASS_USER_CREDENTIAL);
}

/////////////////////////////////////////////////////////////////////////////
// Preemptive declarations
/////////////////////////////////////////////////////////////////////////////
/**
 * @brief Trigger an User Get for given user_id
 * 
 * @param endpoint_node Endpoint node
 * @param user_id       User ID. Can be set to 0 to discover users
*/
void trigger_get_user(attribute_store_node_t endpoint_node,
                      user_credential_user_unique_id_t user_id);

/////////////////////////////////////////////////////////////////////////////
// Data struct
/////////////////////////////////////////////////////////////////////////////

struct uint16_exploded {
  uint8_t msb;  // Most Significant Bit
  uint8_t lsb;  // Less Significant Bit
};

// Used to define reported values
struct user_field_data {
  attribute_store_type_t node_type;
  uint8_t report_index;
  uint8_t bitmask     = 0;
  uint8_t shift_right = 0;
};

// Used to create command frame
struct attribute_command_data {
  // Attribute type that will be fetched from the base_node
  attribute_store_type_t attribute_type;
  // Attribute value state (reported, desired,...)
  attribute_store_node_value_state_t attribute_state;
  // If not ATTRIBUTE_STORE_INVALID_NODE, the function will not fetch attribute_type
  // but will use this node directly
  attribute_store_node_t node = ATTRIBUTE_STORE_INVALID_NODE;
};

struct credential_id_nodes {
  attribute_store::attribute slot_node;
  attribute_store::attribute type_node;
  attribute_store::attribute user_unique_id_node;
};

/////////////////////////////////////////////////////////////////////////////
// Capabilites Data Structs
/////////////////////////////////////////////////////////////////////////////
// User capabilities
struct user_capabilities {
  // Maximum number of users that can be stored in the device
  uint16_t max_user_count = 0;
  // Credential rules supported
  uint8_t supported_credential_rules_bitmask = 0;
  // User types supported
  uint32_t supported_user_types_bitmask = 0;
  // Max length for the user names
  uint8_t max_user_name_length = 0;
  // Device support for scheduling users
  uint8_t support_user_schedule = 0;
  // Device support for getting the checksum of all users
  uint8_t support_all_user_checksum = 0;
  // Device support for getting the checksum of a specific user
  uint8_t support_by_user_checksum = 0;

  // True if the data is valid inside this struct
  bool is_data_valid = false;

  /**
   * @brief Check if the user proprieties are valid
   * 
   * @note Will return false if is_data_valid is false
   * 
   * @param user_id          User ID
   * @param user_type        User type
   * @param credential_rule  Credential rule
   * @param user_name        User name
   * 
   * @return true  User is valid
   * @return false User is not valid
  */
  bool is_user_valid(user_credential_user_unique_id_t user_id,
                     user_credential_type_t user_type,
                     user_credential_rule_t credential_rule,
                     const char *user_name)
  {
    if (!is_data_valid) {
      sl_log_error(
        LOG_TAG,
        "User capabilities are not valid. Try restarting the device.");
      return false;
    }

    if (!is_user_id_valid(user_id)) {
      sl_log_error(LOG_TAG, "User ID is not valid.");
      return false;
    }

    if (!is_user_type_supported(user_type)) {
      sl_log_error(LOG_TAG, "User type is not supported.");
      return false;
    }

    if (!is_credential_rule_supported(credential_rule)) {
      sl_log_error(LOG_TAG, "Credential rule is not supported.");
      return false;
    }

    if (!is_user_name_valid(user_name)) {
      sl_log_error(LOG_TAG, "User name is not valid.");
      return false;
    }
    return true;
  }

  /**
   * @brief Checks if the given user name is valid.
   * @param user_name The user name to be validated.
   * @return true User name is valid
   * @return false User name is not valid
   */
  bool is_user_name_valid(const char *user_name) const
  {
    std::string str_user_name(user_name);
    return str_user_name.length() <= max_user_name_length;
  }

  /**
   * @brief Check if a user id is valid
   * @param user_id User ID to check
   * @return true User ID is valid
   * @return false User ID is not valid
  */
  bool is_user_id_valid(user_credential_user_unique_id_t user_id)
  {
    return user_id <= max_user_count;
  }
  /** 
   * @brief Check if a user type is supported
   * @param user_type User type to check
   * @return true User type is supported
   * @return false User type is not supported
  */
  bool is_user_type_supported(user_credential_type_t user_type) const
  {
    return (supported_user_types_bitmask & (1 << user_type));
  }

  /**
   * @brief Check if a credential rule is supported
   * @param credential_rule Credential rule to check
   * @return true Credential rule is supported
   * @return false Credential rule is not supported
  */
  bool
    is_credential_rule_supported(user_credential_rule_t credential_rule) const
  {
    return (supported_credential_rules_bitmask & (1 << credential_rule));
  }
};

// Associated with a Credential type
struct credential_capabilities {
  user_credential_type_t credential_type = 0;
  uint16_t max_slot_count                = 0;
  uint8_t learn_support                  = 0;
  uint8_t min_credential_length          = 0;
  uint8_t max_credential_length          = 0;
  uint8_t learn_recommended_timeout      = 0;
  uint8_t learn_number_of_steps          = 0;

  bool is_data_valid = false;

  bool is_learn_supported() const
  {
    return is_data_valid && learn_support > 0;
  }

  bool is_credential_valid(user_credential_type_t credential_type,
                           user_credential_slot_t credential_slot,
                           const std::vector<uint8_t> &credential_data)
  {
    if (!is_data_valid) {
      sl_log_error(
        LOG_TAG,
        "Credential capabilities are not valid. Try restarting the device.");
      return false;
    }

    if (credential_type != this->credential_type) {
      sl_log_error(LOG_TAG, "Credential type mismatch.");
      return false;
    }

    if (!is_slot_valid(credential_slot)) {
      sl_log_error(
        LOG_TAG,
        "Slot ID is not valid. Given : %d, Max Supported Slot count : %d",
        credential_slot,
        max_slot_count);
      return false;
    }

    if (!is_credential_data_valid(credential_data)) {
      sl_log_error(LOG_TAG,
                   "Credential data size is not valid. Should be between %d "
                   "and %d, given : %d",
                   min_credential_length,
                   max_credential_length,
                   credential_data.size());
      return false;
    }

    return true;
  }

  bool is_slot_valid(user_credential_slot_t credential_slot) const
  {
    return credential_slot <= max_slot_count;
  }

  bool
    is_credential_data_valid(const std::vector<uint8_t> &credential_data) const
  {
    return (credential_data.size() >= min_credential_length
            && credential_data.size() <= max_credential_length);
  }
};

/////////////////////////////////////////////////////////////////////////////
// Capabilites Helpers
/////////////////////////////////////////////////////////////////////////////
/**
 * @brief Get the attributes of a node
 * 
 * @param parent_node Parent node of the attributes
 * @param attributes  Fill the attribute_store_type_t with the corresponding value inside the pointer
 * 
 * @return sl_status_t SL_STATUS_OK if everything was fine ; otherwise an error code
*/
sl_status_t get_attributes(attribute_store_node_t parent_node,
                           std::map<attribute_store_type_t, void *> attributes)
{
  sl_status_t status = SL_STATUS_OK;
  for (auto &attribute: attributes) {
    size_t attribute_size = 0;
    switch (attribute_store_get_storage_type(attribute.first)) {
      case U8_STORAGE_TYPE:
        attribute_size = sizeof(uint8_t);
        break;
      case U16_STORAGE_TYPE:
        attribute_size = sizeof(uint16_t);
        break;
      case U32_STORAGE_TYPE:
        attribute_size = sizeof(uint32_t);
        break;
      default:
        sl_log_error(
          LOG_TAG,
          "Unsupported storage type for attribute %d. Can't get capabilities.",
          attribute.first);
        return SL_STATUS_FAIL;
    }

    sl_status_t current_status
      = attribute_store_get_child_reported(parent_node,
                                           attribute.first,
                                           attribute.second,
                                           attribute_size);
    if (status != SL_STATUS_OK) {
      sl_log_error(LOG_TAG,
                   "Can't get value for attribute %s",
                   attribute_store_get_type_name(attribute.first));
    }

    status |= current_status;
  }
  return status;
}

/**
 * @brief Get the user capabilities of a node
 * 
 * @param endpoint_node Endpoint node
 * 
 * @return user_capabilities User capabilities. is_data_valid will be false if an error occurred
*/
user_capabilities get_user_capabilities(attribute_store_node_t endpoint_node)
{
  user_capabilities capabilities;

  std::map<attribute_store_type_t, void *> attributes = {
    {ATTRIBUTE(NUMBER_OF_USERS), &capabilities.max_user_count},
    {ATTRIBUTE(SUPPORTED_CREDENTIAL_RULES),
     &capabilities.supported_credential_rules_bitmask},
    {ATTRIBUTE(SUPPORTED_USER_TYPES),
     &capabilities.supported_user_types_bitmask},
    {ATTRIBUTE(MAX_USERNAME_LENGTH), &capabilities.max_user_name_length},
    {ATTRIBUTE(SUPPORT_USER_SCHEDULE), &capabilities.support_user_schedule},
    {ATTRIBUTE(SUPPORT_ALL_USERS_CHECKSUM),
     &capabilities.support_all_user_checksum},
    {ATTRIBUTE(SUPPORT_USER_CHECKSUM), &capabilities.support_by_user_checksum}};

  sl_status_t status = get_attributes(endpoint_node, attributes);

  capabilities.is_data_valid = (status == SL_STATUS_OK);

  return capabilities;
}

/**
 * @brief Get the credential capabilities of a node for given credential type
 * 
 * @param endpoint_node   Endpoint node
 * @param credential_type Credential type
 * 
 * @return credential_capabilities Credential capabilities. is_data_valid will be false if an error occurred
*/
credential_capabilities
  get_credential_capabilities(attribute_store_node_t endpoint_node,
                              user_credential_type_t credential_type)
{
  credential_capabilities capabilities;

  attribute_store_node_t supported_credential_type_node
    = attribute_store_get_node_child_by_value(
      endpoint_node,
      ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE),
      REPORTED_ATTRIBUTE,
      (uint8_t *)&credential_type,
      sizeof(credential_type),
      0);

  if (!attribute_store_node_exists(supported_credential_type_node)) {
    sl_log_error(LOG_TAG,
                 "Credential type %d not supported. Can't get capabilities",
                 credential_type);
    return capabilities;
  }

  std::map<attribute_store_type_t, void *> attributes = {
    {ATTRIBUTE(CREDENTIAL_SUPPORTED_SLOT_COUNT), &capabilities.max_slot_count},
    {ATTRIBUTE(CREDENTIAL_LEARN_SUPPORT), &capabilities.learn_support},
    {ATTRIBUTE(CREDENTIAL_MIN_LENGTH), &capabilities.min_credential_length},
    {ATTRIBUTE(CREDENTIAL_MAX_LENGTH), &capabilities.max_credential_length},
    {ATTRIBUTE(CREDENTIAL_LEARN_RECOMMENDED_TIMEOUT),
     &capabilities.learn_recommended_timeout},
    {ATTRIBUTE(CREDENTIAL_LEARN_NUMBER_OF_STEPS),
     &capabilities.learn_number_of_steps}};

  sl_status_t status
    = get_attributes(supported_credential_type_node, attributes);
  capabilities.credential_type = credential_type;
  capabilities.is_data_valid   = (status == SL_STATUS_OK);

  return capabilities;
}

/////////////////////////////////////////////////////////////////////////////
// Type Helpers
/////////////////////////////////////////////////////////////////////////////
uint16_t get_uint16_value(const uint8_t *frame, uint16_t start_index)
{
  uint16_t extracted_value = 0;
  for (int i = 0; i < 2; i++) {
    extracted_value = (extracted_value << 8) | frame[start_index + i];
  }

  return extracted_value;
}

///////////////////////////////////////////////////////////////////////
// Mics helpers
///////////////////////////////////////////////////////////////////////
std::u16string utf8_to_utf16(const std::string &utf8)
{
  std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> cnv;
  std::u16string s = cnv.from_bytes(utf8);
  if (cnv.converted() < utf8.size())
    throw std::runtime_error("incomplete conversion");
  return s;
}

/////////////////////////////////////////////////////////////////////////////
// Command Class Helper
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief Update desired value if found, or create the node otherwise
 * 
 * Check for the value in the desired value of attribute_type (with parent base_node).
 * If we found it, we update the reported value and clear the desired value.
 * Otherwise we create the node with the given value and set it to reported.
 * 
 * @tparam T Type of the value to set
 * 
 * @param base_node Base node to search for the attribute
 * @param attribute_type Type of the attribute to search for
 * @param value Value to search/set
 * 
 * @return attribute_store::attribute Node that was created/updated
 */
template<typename T> attribute_store::attribute
  create_or_update_desired_value(attribute_store::attribute base_node,
                                 attribute_store_type_t attribute_type,
                                 T value)
{
  auto node = base_node.child_by_type_and_value(attribute_type,
                                                value,
                                                DESIRED_ATTRIBUTE);
  if (!node.is_valid()) {
    node = base_node.emplace_node(attribute_type, value);
  } else {
    node.set_reported(value);
    node.clear_desired();
  }

  return node;
}

void set_operation_type(attribute_store_node_t node,
                        attribute_store_type_t operation_type_node_type,
                        user_credential_operation_type_t operation_type)
{
  auto operation_type_node
    = attribute_store_get_node_child_by_type(node, operation_type_node_type, 0);

  if (!attribute_store_node_exists(operation_type_node)) {
    operation_type_node
      = attribute_store_add_node(operation_type_node_type, node);
  }
  // Undefine reported to be sure that we can so the same operation twice in a row
  attribute_store_undefine_reported(operation_type_node);
  attribute_store_set_desired(operation_type_node,
                              &operation_type,
                              sizeof(operation_type));
}
void set_user_operation_type(attribute_store_node_t user_node,
                             user_credential_operation_type_t operation_type)
{
  set_operation_type(user_node, ATTRIBUTE(USER_OPERATION_TYPE), operation_type);
}

void set_credential_operation_type(
  attribute_store_node_t slot_node,
  user_credential_operation_type_t operation_type)
{
  set_operation_type(slot_node,
                     ATTRIBUTE(CREDENTIAL_OPERATION_TYPE),
                     operation_type);
}

void set_credential_learn_operation_type(
  attribute_store_node_t slot_node,
  user_credential_operation_type_t operation_type)
{
  set_operation_type(slot_node,
                     ATTRIBUTE(CREDENTIAL_LEARN_OPERATION_TYPE),
                     operation_type);
}

/**
 * @brief Get user id node 
 * 
 * @deprecated
 * 
 * @warning state can't be DESIRED_OR_REPORTED_ATTRIBUTE or it will not work
 * 
 * @param endpoint_node  Endpoint point node
 * @param user_id        User ID to find 
 * @param state          Check reported or desired value. 
 * @param user_id_node   User id node will be stored here if found
 * 
 * @return true  User id exists
 * @return false User id doesn't exists
 */
bool get_user_id_node(attribute_store_node_t endpoint_node,
                      user_credential_user_unique_id_t user_id,
                      attribute_store_node_value_state_t state,
                      attribute_store_node_t &user_id_node)
{
  user_id_node
    = attribute_store_get_node_child_by_value(endpoint_node,
                                              ATTRIBUTE(USER_UNIQUE_ID),
                                              state,
                                              (uint8_t *)&user_id,
                                              sizeof(user_id),
                                              0);

  return attribute_store_node_exists(user_id_node);
}

/**
 * @brief Get node associated with user ID (reported)
 * 
 * @deprecated
 * 
 * @warning This function only checks the reported User Unique
 * 
 * @param endpoint_node  Current endpoint node 
 * @param user_id        User ID  
 * 
 * @return attribute_store_node_t If User ID exists
 * @return INVALID_ATTRIBUTE_STORE_NODE If User ID does not exist
 */
attribute_store_node_t
  get_reported_user_id_node(attribute_store_node_t endpoint_node,
                            user_credential_user_unique_id_t user_id)
{
  attribute_store_node_t user_id_node;
  get_user_id_node(endpoint_node, user_id, REPORTED_ATTRIBUTE, user_id_node);
  return user_id_node;
}

/**
 * @brief Get node associated with user ID (desired)
 * 
 * @warning This function only checks the reported User Unique
 * 
 * @deprecated
 * 
 * @param endpoint_node  Current endpoint node 
 * @param user_id        User ID  
 * 
 * @return attribute_store_node_t If User ID exists
 * @return INVALID_ATTRIBUTE_STORE_NODE If User ID does not exist
 */
attribute_store_node_t
  get_desired_user_id_node(attribute_store_node_t endpoint_node,
                           user_credential_user_unique_id_t user_id)
{
  attribute_store_node_t user_id_node;
  get_user_id_node(endpoint_node, user_id, DESIRED_ATTRIBUTE, user_id_node);
  return user_id_node;
}

/**
 * @brief Get node associated with user ID (desired or reported)
 * 
 * @param endpoint_node  Current endpoint node
 * @param user_id        User ID
 * 
 * @return True is user exists, false otherwise
 */
bool user_exists(attribute_store::attribute endpoint_node,
                 user_credential_user_unique_id_t user_id)
{
  return endpoint_node
    .child_by_type_and_value(ATTRIBUTE(USER_UNIQUE_ID),
                             user_id,
                             REPORTED_ATTRIBUTE)
    .is_valid();
}

/**
 * @brief Get node associated with user ID (desired or reported)
 * 
 * @param endpoint_node  Current endpoint node
 * @param user_id        User ID
 * @param state          Check reported or desired value (or desired else reported)
 * 
 * @throws std::runtime_error If User ID does not exist with given state
 * 
 * @return User ID Node
 */
attribute_store::attribute
  get_user_unique_id_node(attribute_store::attribute endpoint_node,
                          user_credential_user_unique_id_t user_id,
                          attribute_store_node_value_state_t state)
{
  attribute_store::attribute user_id_node
    = endpoint_node.child_by_type_and_value(ATTRIBUTE(USER_UNIQUE_ID),
                                            user_id,
                                            state);

  if (!user_id_node.is_valid()) {
    throw std::runtime_error(
      (boost::format("User ID %1% not found (state : %2%).") % user_id % state)
        .str());
  }

  return user_id_node;
}

/**
 * @brief Get credential type node associated with user ID
 * 
 * @param user_id_node  User ID node
 * @param cred_type     Credential type
 * @param state         Check reported or desired value (or desired else reported)
 * 
 * @throws std::runtime_error If Credential type for given user_id_node does not exist with given state
 * 
 * @return Credential type node
 */
attribute_store::attribute
  get_credential_type_node(attribute_store::attribute user_id_node,
                           user_credential_type_t cred_type,
                           attribute_store_node_value_state_t state)
{
  if (!user_id_node.is_valid()) {
    throw std::runtime_error(
      "get_credential_type_node: User ID node is not valid.");
  }

  attribute_store::attribute cred_type_node
    = user_id_node.child_by_type_and_value(ATTRIBUTE(CREDENTIAL_TYPE),
                                           cred_type,
                                           state);

  if (!cred_type_node.is_valid()) {
    throw std::runtime_error(
      (boost::format("Credential type  %1% (state : %2%) not found for %3%.")
       % cred_type % state % user_id_node.value_to_string())
        .str());
  }

  return cred_type_node;
}

/**
 * @brief Get credential slot node associated with credential type
 * 
 * @param cred_type_node  Credential type node
 * @param cred_slot       Credential slot
 * @param state           Check reported or desired value (or desired else reported)
 * 
 * @throws std::runtime_error If Credential slot for given cred_type_node does not exist with given state
 * 
 * @return Credential slot node
 */
attribute_store::attribute
  get_credential_slot_node(attribute_store::attribute cred_type_node,
                           user_credential_slot_t cred_slot,
                           attribute_store_node_value_state_t state)
{
  if (!cred_type_node.is_valid()) {
    throw std::runtime_error(
      "get_credential_slot_node: Credential Type node is not valid.");
  }

  attribute_store::attribute cred_slot_node
    = cred_type_node.child_by_type_and_value(ATTRIBUTE(CREDENTIAL_SLOT),
                                             cred_slot,
                                             state);

  if (!cred_slot_node.is_valid()) {
    throw std::runtime_error(
      (boost::format(
         "Credential type  %1% (state : %2%) not found for %3% / %4%.")
       % cred_slot % state % cred_type_node.value_to_string())
        .str());
  }

  return cred_slot_node;
}

/**
 * @brief Get credential node associated with credential_type and user_id.
 * 
 * @deprecated
 * 
 * @param endpoint_node         Current endpoint node
 * @param user_id               User ID
 * @param credential_type       Credential type
 * @param state                 Check reported or desired value. 
 * @param credential_type_node  Credential node will be stored here if found
 * 
 * @return true  Credential Type exists
 * @return false Credential Type doesn't exists
   */
bool get_credential_type_node(attribute_store_node_t endpoint_node,
                              user_credential_user_unique_id_t user_id,
                              user_credential_type_t credential_type,
                              attribute_store_node_value_state_t state,
                              attribute_store_node_t &credential_type_node)
{
  attribute_store_node_t user_id_node
    = get_reported_user_id_node(endpoint_node, user_id);

  credential_type_node
    = attribute_store_get_node_child_by_value(user_id_node,
                                              ATTRIBUTE(CREDENTIAL_TYPE),
                                              state,
                                              (uint8_t *)&credential_type,
                                              sizeof(credential_type),
                                              0);

  return attribute_store_node_exists(credential_type_node);
}

/**
 * @brief Get ALL the credential type nodes.
 * 
 * By default it will return all the credential type nodes, but you can narrow
 *  to a specific credential type with the credential_type parameter
 * 
 * @deprecated Use for_each_credential_type_nodes instead
 * 
 * @param endpoint_node     Endpoint point node
 * @param credential_type   Credential type to find. If 0, will return all credential types
 * 
 * @return std::vector<attribute_store_node_t> List of credential type nodes
*/
std::vector<attribute_store_node_t>
  get_all_credential_type_nodes(attribute_store_node_t endpoint_node,
                                user_credential_type_t credential_type = 0)
{
  std::vector<attribute_store_node_t> credential_type_nodes;

  // Delete all user nodes
  auto user_node_count
    = attribute_store_get_node_child_count_by_type(endpoint_node,
                                                   ATTRIBUTE(USER_UNIQUE_ID));

  for (size_t user_id_index = 0; user_id_index < user_node_count;
       user_id_index++) {
    attribute_store_node_t user_node
      = attribute_store_get_node_child_by_type(endpoint_node,
                                               ATTRIBUTE(USER_UNIQUE_ID),
                                               user_id_index);

    auto credential_type_node_count
      = attribute_store_get_node_child_count_by_type(
        user_node,
        ATTRIBUTE(CREDENTIAL_TYPE));

    for (size_t credential_index = 0;
         credential_index < credential_type_node_count;
         credential_index++) {
      attribute_store_node_t credential_type_node
        = attribute_store_get_node_child_by_type(user_node,
                                                 ATTRIBUTE(CREDENTIAL_TYPE),
                                                 credential_index);
      if (credential_type == 0) {
        // If we haven't specify a node type we take them all
        credential_type_nodes.push_back(credential_type_node);
      } else {
        // Otherwise we only take the ones that match
        user_credential_type_t current_credential_type;
        attribute_store_read_value(credential_type_node,
                                   REPORTED_ATTRIBUTE,
                                   &current_credential_type,
                                   sizeof(current_credential_type));

        if (current_credential_type == credential_type) {
          credential_type_nodes.push_back(credential_type_node);
        }
      }
    }
  }

  return credential_type_nodes;
}

/**
 * @brief Iterate on each credential type nodes for a given user
 * 
 * @param user_id_node      User ID node
 * @param callback          Callback function to call for each credential type node
 * @param credential_type   Credential type to find. If 0, process all credential types
 */
void for_each_credential_type_nodes_for_user(
  attribute_store::attribute user_id_node,
  const attribute_callback &callback,
  user_credential_type_t credential_type = 0)
{
  auto credential_type_nodes = user_id_node.children(ATTRIBUTE(CREDENTIAL_TYPE));
  for (auto &credential_type_node: credential_type_nodes) {
    // Call
    if (credential_type == 0
        || (credential_type_node.reported_exists()
            && credential_type_node.reported<user_credential_type_t>()
                 == credential_type)) {
      callback(credential_type_node);
    }
  }
}

/**
 * @brief Iterate on each credential type nodes
 * 
 * @param endpoint_node     Endpoint point node
 * @param callback          Callback function to call for each credential type node
 * @param credential_type   Credential type to find. If 0, process all credential types
 */
void for_each_credential_type_nodes(attribute_store::attribute endpoint_node,
                                    const attribute_callback &callback,
                                    user_credential_type_t credential_type = 0)
{
  auto user_nodes = endpoint_node.children(ATTRIBUTE(USER_UNIQUE_ID));
  for (auto &user_node: user_nodes) {
    for_each_credential_type_nodes_for_user(user_node,
                                            callback,
                                            credential_type);
  }
}



/**
 * @brief Get credential slot node
 * 
 * @warning state can't be DESIRED_OR_REPORTED_ATTRIBUTE or it will not work
 * 
 * @param credential_type_node  Endpoint point node
 * @param credential_slot       Credential Slot to find 
 * @param state                 Check reported or desired value. 
 * @param credential_slot_node  Credential Slot node will be stored here if found
 * 
 * @return true  Credential Slot exists
 * @return false Credential Slot doesn't exists
 */
bool get_credential_slot_node(attribute_store_node_t credential_type_node,
                              user_credential_slot_t credential_slot,
                              attribute_store_node_value_state_t state,
                              attribute_store_node_t &credential_slot_node)
{
  credential_slot_node
    = attribute_store_get_node_child_by_value(credential_type_node,
                                              ATTRIBUTE(CREDENTIAL_SLOT),
                                              state,
                                              (uint8_t *)&credential_slot,
                                              sizeof(credential_slot),
                                              0);

  return attribute_store_node_exists(credential_slot_node);
}

/**
 * @brief Checks if given credential ID (credential type, credential slot) is available
 * 
 * @param endpoint_node     Endpoint node
 * @param credential_type   Credential type
 * @param credential_slot   Credential slot
 * 
 * @return true  Credential is available
 * @return false Credential is not available : if an user already have the combination of given credential type and slot.
*/
bool is_credential_available(attribute_store_node_t endpoint_node,
                             user_credential_type_t credential_type,
                             user_credential_slot_t credential_slot)
{
  auto credential_type_nodes
    = get_all_credential_type_nodes(endpoint_node, credential_type);

  // Credential type, Credential Node pair is Unique
  for (auto &credential_type_node: credential_type_nodes) {
    user_credential_type_t current_type;
    attribute_store_get_reported(credential_type_node,
                                 &current_type,
                                 sizeof(current_type));
    user_credential_slot_t current_slot;
    attribute_store_get_child_reported(credential_type_node,
                                       ATTRIBUTE(CREDENTIAL_SLOT),
                                       &current_slot,
                                       sizeof(current_slot));
    if (current_slot == credential_slot && current_type == credential_type) {
      return false;
    }
  }

  return true;
}

/**
 * @brief Add credential type node to given user if it doesn't exists.
 * 
 * @param endpoint_node     Endpoint node
 * @param user_id           User ID. Must exists.
 * @param credential_type   Credential type
 * 
 * @return attribute_store_node_t Credential type node (with desired value if it doesn't exists, or the existant one)
 * @return ATTRIBUTE_STORE_INVALID_NODE If an error occurred 
 **/
attribute_store_node_t
  add_credential_type_node_if_missing(attribute_store_node_t endpoint_node,
                                      user_credential_user_unique_id_t user_id,
                                      user_credential_type_t credential_type)
{
  attribute_store_node_t credential_type_node = ATTRIBUTE_STORE_INVALID_NODE;

  attribute_store_node_t user_id_node
    = get_reported_user_id_node(endpoint_node, user_id);

  if (!attribute_store_node_exists(user_id_node)) {
    sl_log_error(LOG_TAG, "User ID %d doesn't exists", user_id);
    return credential_type_node;
  }

  // First check Credential Type existence
  get_credential_type_node(endpoint_node,
                           user_id,
                           credential_type,
                           REPORTED_ATTRIBUTE,
                           credential_type_node);
  if (!attribute_store_node_exists(credential_type_node)) {
    // Create Credential Type if it doesn't exists
    credential_type_node
      = attribute_store_emplace_desired(user_id_node,
                                        ATTRIBUTE(CREDENTIAL_TYPE),
                                        &credential_type,
                                        sizeof(credential_type));
  }

  return credential_type_node;
}

/**
 * @brief Get associated credential identifier nodes 
 * 
 * @param child_node Not that have a CREDENTIAL_SLOT, CREDENTIAL_TYPE and USER_UNIQUE_ID as respective parents
 * 
 * @throws std::runtime_error If one of the nodes is not found
 * 
 * @return credential_id_nodes Credential identifier nodes
 */
credential_id_nodes
  get_credential_identifier_nodes(attribute_store_node_t child_node)
{
  attribute_store::attribute slot_node(child_node);
  slot_node = slot_node.first_parent_or_self(ATTRIBUTE(CREDENTIAL_SLOT));
  attribute_store::attribute type_node
    = slot_node.first_parent(ATTRIBUTE(CREDENTIAL_TYPE));
  attribute_store::attribute user_unique_id_node
    = type_node.first_parent(ATTRIBUTE(USER_UNIQUE_ID));

  if (!slot_node.is_valid()) {
    throw std::runtime_error(
      "get_credential_identifier_nodes: Can't get credential slot node.");
  }

  if (!type_node.is_valid()) {
    throw std::runtime_error(
      "get_credential_identifier_nodes: Can't get credential type node.");
  }

  if (!user_unique_id_node.is_valid()) {
    throw std::runtime_error(
      "get_credential_identifier_nodes: Can't get user unique ID node.");
  }

  return {.slot_node           = slot_node,
          .type_node           = type_node,
          .user_unique_id_node = user_unique_id_node};
}

template<typename T> struct identifier_state {
  T value;
  attribute_store_node_value_state_t state;
};
/**
 * @brief Get associated credential identifier nodes
 * 
 * @param endpoint_node Endpoint node
 * @param user_id       User ID with given state
 * @param credential_type Credential type with given state
 * @param credential_slot Credential slot with given state
 * 
 * @throws std::runtime_error If one of the nodes is not found
 * 
 * @return credential_id_nodes Credential identifier nodes
 */
credential_id_nodes get_credential_identifier_nodes(
  const attribute_store::attribute &endpoint_node,
  identifier_state<user_credential_user_unique_id_t> user_id,
  identifier_state<user_credential_type_t> credential_type,
  identifier_state<user_credential_slot_t> credential_slot)
{
  credential_id_nodes nodes;

  nodes.user_unique_id_node
    = get_user_unique_id_node(endpoint_node, user_id.value, user_id.state);

  if (!nodes.user_unique_id_node.is_valid()) {
    throw std::runtime_error(
      "get_credential_identifier_nodes: Can't get user unique ID "
      + std::to_string(user_id.value));
  }

  nodes.type_node = get_credential_type_node(nodes.user_unique_id_node,
                                             credential_type.value,
                                             credential_type.state);

  if (!nodes.type_node.is_valid()) {
    throw std::runtime_error(
      (boost::format("get_credential_identifier_nodes: Can't get credential "
                     "type %1% for user %2%")
       % credential_type.value % user_id.value)
        .str());
  }

  nodes.slot_node = get_credential_slot_node(nodes.type_node,
                                             credential_slot.value,
                                             credential_slot.state);

  if (!nodes.slot_node.is_valid()) {
    throw std::runtime_error(
      (boost::format("get_credential_identifier_nodes: Can't get credential "
                     "slot %1% for credential type %2% / user %3%")
       % credential_slot.value % credential_type.value % user_id.value)
        .str());
  }
  return nodes;
}

/////////////////////////////////////////////////////////////////////////////
// Attributes helpers
/////////////////////////////////////////////////////////////////////////////

/** @brief Set reported attributes based on user_data
 * 
 * @note This function also undefine all desired values
 * 
 * @param base_node  Parent node of the newly created attributes
 * @param frame_data Frame data to interpret
 * @param user_data  User data to interpret frame_data
 * 
 * @return sl_status_t SL_STATUS_OK if everything was fine
*/
sl_status_t
  set_reported_attributes(attribute_store_node_t base_node,
                          const uint8_t *frame_data,
                          const std::vector<user_field_data> &user_data)
{
  sl_status_t status = SL_STATUS_OK;

  for (const auto &field: user_data) {
    attribute_store_storage_type_t storage_type
      = attribute_store_get_storage_type(field.node_type);

    switch (storage_type) {
      case U8_STORAGE_TYPE: {
        uint8_t uint8_value = frame_data[field.report_index];
        if (field.bitmask != 0) {
          uint8_value = (uint8_value & field.bitmask) >> field.shift_right;
        }
        status |= attribute_store_set_child_reported(base_node,
                                                     field.node_type,
                                                     &uint8_value,
                                                     sizeof(uint8_value));
      } break;
      // Unsigned 16-bit integers are used for this attribute
      case U16_STORAGE_TYPE: {
        uint16_t uint16_value
          = get_uint16_value(frame_data, field.report_index);
        status |= attribute_store_set_child_reported(base_node,
                                                     field.node_type,
                                                     &uint16_value,
                                                     sizeof(uint16_value));

        break;
      }
      default:
        sl_log_error(LOG_TAG,
                     "Internal error : unsupported storage_type in "
                     "set_reported_attributes");
        return SL_STATUS_NOT_SUPPORTED;
    }

    // Undefined desired value
    status
      |= attribute_store_set_child_desired(base_node, field.node_type, NULL, 0);
  }

  return status;
}

/**
 * @brief Get value inside the node and store it in a uint8_t vector
 * 
 * @param node Node to get the value from
 * @param data Vector to store the value (output). It will be cleared before any data is stored in it
 * @param value_state Value state (reported, desired,...). Default to Reported
 * 
 * @return sl_status_t SL_STATUS_OK if everything was fine
 * @return SL_STATUS_NOT_SUPPORTED If the storage type is not supported or other errors
*/
sl_status_t node_to_uint8_vector(attribute_store_node_t node,
                                 std::vector<uint8_t> &data,
                                 attribute_store_node_value_state_t value_state
                                 = REPORTED_ATTRIBUTE)
{
  data.clear();

  auto node_type             = attribute_store_get_node_type(node);
  auto node_storage_type     = attribute_store_get_storage_type(node_type);
  auto attribute_description = attribute_store_get_type_name(node_type);

  sl_status_t status;
  switch (node_storage_type) {
    case U8_STORAGE_TYPE: {
      uint8_t uint8_value;
      status = attribute_store_read_value(node,
                                          value_state,
                                          &uint8_value,
                                          sizeof(uint8_value));
      data.push_back(uint8_value);
    } break;
    case U16_STORAGE_TYPE: {
      uint16_t uint16_value;
      status = attribute_store_read_value(node,
                                          value_state,
                                          &uint16_value,
                                          sizeof(uint16_value));
      data.push_back((uint16_value & 0xFF00) >> 8);
      data.push_back((uint16_value & 0x00FF));
    } break;
    // Variable length field
    case BYTE_ARRAY_STORAGE_TYPE: {
      // First get the length
      auto credential_data_length
        = attribute_store_get_node_value_size(node, value_state);

      // + 1 for the length
      data.resize(credential_data_length + 1);
      data[0] = credential_data_length;
      status
        = attribute_store_read_value(node,
                                     value_state,
                                     data.data() + 1,  // Offset for the length
                                     credential_data_length);
    } break;

    case C_STRING_STORAGE_TYPE: {
      char c_user_name[MAX_CHAR_SIZE];
      // Unfortunately attribute_store_get_string is not exposed so we need to do this
      switch (value_state) {
        case DESIRED_OR_REPORTED_ATTRIBUTE:
          status
            = attribute_store_get_desired_else_reported_string(node,
                                                               c_user_name,
                                                               MAX_CHAR_SIZE);
          break;
        case DESIRED_ATTRIBUTE:
          status = attribute_store_get_desired_string(node,
                                                      c_user_name,
                                                      MAX_CHAR_SIZE);
          break;
        case REPORTED_ATTRIBUTE:
          status = attribute_store_get_reported_string(node,
                                                       c_user_name,
                                                       MAX_CHAR_SIZE);
          break;
      }

      std::string user_name = c_user_name;
      data.push_back(user_name.length());
      for (const char &c: user_name) {
        data.push_back(c);
      }
    } break;
    default:
      sl_log_critical(LOG_TAG,
                      "Not supported type for %s",
                      attribute_description);
      return SL_STATUS_FAIL;
  }

  if (status != SL_STATUS_OK) {
    sl_log_error(LOG_TAG,
                 "Can't get value of Attribute %s",
                 attribute_description);
    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

/**
 * @brief Compute a node value and add it to the current checksum
 * 
 * @param current_checksum Current checksum (can be empty)
 * @param node             Node to compute the checksum from
 * 
 * @return true  If the node was added to the checksum
 * @return false If the node was not added to the checksum
*/
bool add_node_to_checksum(std::vector<uint8_t> &current_checksum,
                          attribute_store_node_t node)
{
  if (!attribute_store_node_exists(node)) {
    sl_log_error(LOG_TAG, "Can't find node %d. Not adding to checksum.", node);
    return false;
  }
  std::vector<uint8_t> data;
  if (node_to_uint8_vector(node, data) != SL_STATUS_OK) {
    sl_log_error(
      LOG_TAG,
      "Can't convert node %d to uint8_t vector. Not adding to checksum.",
      node);
    return false;
  }
  current_checksum.insert(current_checksum.end(), data.begin(), data.end());

  return true;
};

/**
 * @brief Updates the desired values of attributes in the attribute store.
 *
 * This function takes a map of attribute values and their corresponding sizes, and updates the desired values
 * of the attributes in the attribute store. 
 * The attribute store is updated for the specified parent node.
 *
 * @param attribute_map_values A map containing the attribute values and their sizes.
 * @param parent_node The parent node of values that will be updated
 * 
 * @return SL_STATUS_OK if the desired values were updated successfully, an otherwise an error code.
 */
sl_status_t update_desired_values(
  attribute_store_node_t parent_node,
  std::map<attribute_store_type_t, std::pair<const void *, uint8_t>>
    attribute_map_values)
{
  sl_status_t status = SL_STATUS_OK;
  for (auto &attr: attribute_map_values) {
    auto value      = attr.second.first;
    auto value_size = attr.second.second;

    if (attribute_store_get_storage_type(attr.first) == C_STRING_STORAGE_TYPE) {
      auto str_attribute_node
        = attribute_store_get_node_child_by_type(parent_node, attr.first, 0);
      auto value_str = static_cast<const char *>(value);
      sl_log_debug(LOG_TAG,
                   "Update desired value of %s to %s",
                   attribute_store_get_type_name(attr.first),
                   value_str);
      status
        |= attribute_store_set_desired_string(str_attribute_node, value_str);
    } else {
      sl_log_debug(LOG_TAG,
                   "Update desired value of %s",
                   attribute_store_get_type_name(attr.first));
      status |= attribute_store_set_child_desired(parent_node,
                                                  attr.first,
                                                  value,
                                                  value_size);
    }

    if (status != SL_STATUS_OK) {
      sl_log_error(LOG_TAG,
                   "Error while setting desired value of %s",
                   attribute_store_get_type_name(attr.first));
    }
  }

  return status;
}

/////////////////////////////////////////////////////////////////////////////
// Version & Attribute Creation
/////////////////////////////////////////////////////////////////////////////
static void zwave_command_class_user_credential_on_version_attribute_update(
  attribute_store_node_t updated_node, attribute_store_change_t change)
{
  if (change == ATTRIBUTE_DELETED) {
    return;
  }

  zwave_cc_version_t version = 0;
  attribute_store_get_reported(updated_node, &version, sizeof(version));

  if (version == 0) {
    return;
  }

  sl_log_debug(LOG_TAG, "User Credential version %d", version);

  attribute_store_node_t endpoint_node
    = attribute_store_get_first_parent_with_type(updated_node,
                                                 ATTRIBUTE_ENDPOINT_ID);

  // The order of the attribute matter since it defines the order of the
  // Z-Wave get command order.
  const attribute_store_type_t attributes[] = {
    ATTRIBUTE(NUMBER_OF_USERS),
    ATTRIBUTE(SUPPORT_CREDENTIAL_CHECKSUM),
  };

  attribute_store_add_if_missing(endpoint_node,
                                 attributes,
                                 COUNT_OF(attributes));

  // Listen to
  // zwave_command_class_notification_register_event_callback(
  //   endpoint_node,
  //   &on_notification_event);
}

/////////////////////////////////////////////////////////////////////////////
// User Credential User Capabilities Get/Report
/////////////////////////////////////////////////////////////////////////////
static sl_status_t zwave_command_class_user_credential_user_capabilities_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "User Capabilities Get");

  return frame_generator.generate_no_args_frame(USER_CAPABILITIES_GET,
                                                frame,
                                                frame_length);
}

sl_status_t zwave_command_class_user_credential_user_capabilities_handle_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  attribute_store::attribute endpoint_node(
    zwave_command_class_get_endpoint_node(connection_info));

  sl_log_debug(LOG_TAG, "User Capabilities Report");
  const uint8_t expected_size = 9;

  try {
    zwave_frame_parser parser(frame_data, frame_length);

    if (!parser.is_frame_size_valid(expected_size, expected_size + 4)) {
      sl_log_error(LOG_TAG,
                   "Invalid frame size for User Capabilities Report frame");
      return SL_STATUS_FAIL;
    }

    parser.read_sequential<uint16_t>(
      2,
      endpoint_node.emplace_node(ATTRIBUTE(NUMBER_OF_USERS)));
    parser.read_byte(
      endpoint_node.emplace_node(ATTRIBUTE(SUPPORTED_CREDENTIAL_RULES)));
    parser.read_byte(
      endpoint_node.emplace_node(ATTRIBUTE(MAX_USERNAME_LENGTH)));

    constexpr uint8_t SUPPORT_ALL_USERS_CHECKSUM_BITMASK
      = USER_CAPABILITIES_REPORT_PROPERTIES1_ALL_USERS_CHECKSUM_SUPPORT_BIT_MASK;
    auto support_bits = parser.read_byte_with_bitmask(
      {{USER_CAPABILITIES_REPORT_PROPERTIES1_USER_SCHEDULE_SUPPORT_BIT_MASK,
        endpoint_node.emplace_node(ATTRIBUTE(SUPPORT_USER_SCHEDULE))},
       {SUPPORT_ALL_USERS_CHECKSUM_BITMASK,
        endpoint_node.emplace_node(ATTRIBUTE(SUPPORT_ALL_USERS_CHECKSUM))},
       {USER_CAPABILITIES_REPORT_PROPERTIES1_USER_CHECKSUM_SUPPORT_BIT_MASK,
        endpoint_node.emplace_node(ATTRIBUTE(SUPPORT_USER_CHECKSUM))}});

    // SUPPORT_ALL_USERS_CHECKSUM support
    if (support_bits[SUPPORT_ALL_USERS_CHECKSUM_BITMASK]) {
      sl_log_debug(LOG_TAG,
                   "SUPPORT_ALL_USERS_CHECKSUM is set, sending All Users "
                   "Checksum Get Command");
      endpoint_node.emplace_node(ATTRIBUTE(ALL_USERS_CHECKSUM));
    }

    parser.read_bitmask(
      endpoint_node.emplace_node(ATTRIBUTE(SUPPORTED_USER_TYPES)));

  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while parsing User Capabilities Report frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// User Credential Credential Capabilities Get/Report
/////////////////////////////////////////////////////////////////////////////
static sl_status_t
  zwave_command_class_user_credential_credential_capabilities_get(
    attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Capabilities Get");

  return frame_generator.generate_no_args_frame(CREDENTIAL_CAPABILITIES_GET,
                                                frame,
                                                frame_length);
  ;
}

sl_status_t
  zwave_command_class_user_credential_credential_capabilities_handle_report(
    const zwave_controller_connection_info_t *connection_info,
    const uint8_t *frame_data,
    uint16_t frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Capabilities Report");

  attribute_store::attribute endpoint_node(
    zwave_command_class_get_endpoint_node(connection_info));

  const uint8_t min_expected_size = 5;

  try {
    zwave_frame_parser parser(frame_data, frame_length);

    // We only needs to check the minimum size here
    if (!parser.is_frame_size_valid(min_expected_size, UINT8_MAX)) {
      sl_log_error(
        LOG_TAG,
        "Invalid frame size for Credential Capabilities Report frame");
      return SL_STATUS_FAIL;
    }

    // TODO: Add admin code support
    parser.read_byte_with_bitmask(
      {{CREDENTIAL_CAPABILITIES_REPORT_PROPERTIES1_CREDENTIAL_CHECKSUM_SUPPORT_BIT_MASK,
        endpoint_node.emplace_node(ATTRIBUTE(SUPPORT_CREDENTIAL_CHECKSUM))}});

    uint8_t supported_credential_types_count = parser.read_byte();

    // Remove all previous known SUPPORTED_CREDENTIAL_TYPE
    attribute_store::attribute type_node;
    do {
      // Take first supported credential type node
      endpoint_node.child_by_type(ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE))
        .delete_node();
    } while (endpoint_node.child_by_type(ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE))
               .is_valid());

    // Compute this value here since we need it for the exposure of the supported user credential types
    uint16_t ucl_credential_type_mask = 0;

    // Create each node with credential type
    std::vector<attribute_store::attribute> credential_type_nodes;
    for (uint8_t current_credential_type_index = 0;
         current_credential_type_index < supported_credential_types_count;
         current_credential_type_index++) {
      // Create new node
      auto current_credential_type_node
        = endpoint_node.add_node(ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE));
      // Read credential type and save into the node
      auto credential_type = parser.read_byte(current_credential_type_node);
      // Compute bitmask for MQTT
      ucl_credential_type_mask |= (1 << (credential_type - 1));
      // Save the credential type node for later
      credential_type_nodes.push_back(current_credential_type_node);
    }

    // CL Support
    for (uint8_t current_credential_type_index = 0;
         current_credential_type_index < supported_credential_types_count;
         current_credential_type_index++) {
      // Create new node
      auto credential_learn_support_node
        = credential_type_nodes[current_credential_type_index].add_node(
          ATTRIBUTE(CREDENTIAL_LEARN_SUPPORT));
      parser.read_byte_with_bitmask(
        {CREDENTIAL_CAPABILITIES_REPORT_PROPERTIES1_CREDENTIAL_CHECKSUM_SUPPORT_BIT_MASK,
         credential_learn_support_node});
    }

    // Number of Supported Credential Slots
    for (uint8_t current_credential_type_index = 0;
         current_credential_type_index < supported_credential_types_count;
         current_credential_type_index++) {
      auto credential_learn_support_node
        = credential_type_nodes[current_credential_type_index].add_node(
          ATTRIBUTE(CREDENTIAL_SUPPORTED_SLOT_COUNT));

      parser.read_sequential<uint16_t>(2, credential_learn_support_node);
    }

    auto create_and_store_uint8_value = [&](attribute_store_type_t type) {
      for (uint8_t current_credential_type_index = 0;
           current_credential_type_index < supported_credential_types_count;
           current_credential_type_index++) {
        auto node
          = credential_type_nodes[current_credential_type_index].add_node(type);
        parser.read_byte(node);
      }
    };

    create_and_store_uint8_value(ATTRIBUTE(CREDENTIAL_MIN_LENGTH));
    create_and_store_uint8_value(ATTRIBUTE(CREDENTIAL_MAX_LENGTH));
    create_and_store_uint8_value(
      ATTRIBUTE(CREDENTIAL_LEARN_RECOMMENDED_TIMEOUT));
    create_and_store_uint8_value(ATTRIBUTE(CREDENTIAL_LEARN_NUMBER_OF_STEPS));

    // Set UCL mask for supported user credential types
    endpoint_node
      .emplace_node(
        DOTDOT_ATTRIBUTE_ID_USER_CREDENTIAL_SUPPORTED_CREDENTIAL_TYPES)
      .set_reported(ucl_credential_type_mask);
  } catch (const std::exception &e) {
    sl_log_error(
      LOG_TAG,
      "Error while parsing Credential Capabilities Report frame : %s",
      e.what());
    return SL_STATUS_FAIL;
  }
  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// All User Checksum Get/Report
/////////////////////////////////////////////////////////////////////////////
static sl_status_t zwave_command_class_user_credential_all_user_checksum_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "All User Checksum Get");

  ZW_ALL_USERS_CHECKSUM_GET_FRAME *get_frame
    = (ZW_ALL_USERS_CHECKSUM_GET_FRAME *)frame;
  get_frame->cmdClass = COMMAND_CLASS_USER_CREDENTIAL;
  get_frame->cmd      = ALL_USERS_CHECKSUM_GET;
  *frame_length       = sizeof(ZW_ALL_USERS_CHECKSUM_GET_FRAME);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_all_user_checksum_handle_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  if (frame_length != 4) {
    return SL_STATUS_NOT_SUPPORTED;
  }

  sl_log_debug(LOG_TAG, "All User Checksum Report");

  attribute_store_node_t endpoint_node
    = zwave_command_class_get_endpoint_node(connection_info);

  user_credential_all_users_checksum_t all_users_checksum
    = get_uint16_value(frame_data, 2);

  attribute_store_set_child_reported(endpoint_node,
                                     ATTRIBUTE(ALL_USERS_CHECKSUM),
                                     &all_users_checksum,
                                     sizeof(all_users_checksum));

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Credential Set/Get/Report
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief Trigger a GET credential command
 * 
 * Create credential_type (reported) and credential_slot (desired) nodes if they don't exist
 * 
 * trigger_get_credential(user_node, 0, 0) will trigger a GET command for the first credential of user_node
 * 
 * @param user_unique_id_node User ID node
 * @param credential_type 0 to get the first credential; valid value otherwise
 * @param credential_slot 0 to get the first credential; valid value otherwise
 *
*/
void trigger_get_credential(
  attribute_store::attribute &user_unique_id_node,
  user_credential_type_t credential_type,
  user_credential_slot_t credential_slot)
{
  sl_log_debug(LOG_TAG,
               "Trigger GET credential for user %d : "
               "Credential type %d, credential slot %d",
               user_unique_id_node.reported<user_credential_user_unique_id_t>(),
               credential_type,
               credential_slot);
  user_unique_id_node
    .emplace_node(ATTRIBUTE(CREDENTIAL_TYPE),
                  credential_type,
                  REPORTED_ATTRIBUTE)
    .emplace_node(ATTRIBUTE(CREDENTIAL_SLOT),
                  credential_slot,
                  DESIRED_ATTRIBUTE);
}

sl_status_t zwave_command_class_user_credential_credential_set(
  attribute_store_node_t credential_operation_type_node,
  uint8_t *frame,
  uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Set");
  try {
    auto cred_nodes
      = get_credential_identifier_nodes(credential_operation_type_node);

    auto operation_type
      = cred_nodes.slot_node.child_by_type(ATTRIBUTE(CREDENTIAL_OPERATION_TYPE))
          .desired<user_credential_operation_type_t>();

    sl_log_debug(LOG_TAG, "Operation type : %d", operation_type);

    // Generate the frame
    const bool is_delete_operation
      = (operation_type == CREDENTIAL_SET_OPERATION_TYPE_DELETE);

    uint8_t expected_frame_size = 9;
    uint8_t credential_size     = 0;
    auto credential_data_node
      = cred_nodes.slot_node.child_by_type(ATTRIBUTE(CREDENTIAL_DATA));

    if (!is_delete_operation) {
      auto state = REPORTED_ATTRIBUTE;
      if (credential_data_node.desired_exists()) {
        state = DESIRED_ATTRIBUTE;
      }
      credential_size = static_cast<uint8_t>(
        credential_data_node.get<std::vector<uint8_t>>(state).size());
    }

    // Append the credential data
    expected_frame_size += credential_size;

    frame_generator.initialize_frame(CREDENTIAL_SET,
                                     frame,
                                     expected_frame_size);
    frame_generator.add_value(cred_nodes.user_unique_id_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_value(cred_nodes.type_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_value(cred_nodes.slot_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_raw_byte(operation_type);
    frame_generator.add_raw_byte(credential_size);
    if (!is_delete_operation) {
      frame_generator.add_value(credential_data_node,
                                DESIRED_OR_REPORTED_ATTRIBUTE);
    }

    frame_generator.validate_frame(frame_length);

  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating Credential Set frame : %s",
                 e.what());
    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_user_credential_credential_get(
  attribute_store_node_t credential_slot_node,
  uint8_t *frame,
  uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Get");

  // Generate the frame
  constexpr auto expected_frame_size
    = static_cast<uint8_t>(sizeof(ZW_CREDENTIAL_GET_FRAME));
  try {
    auto cred_nodes = get_credential_identifier_nodes(credential_slot_node);

    frame_generator.initialize_frame(CREDENTIAL_GET,
                                     frame,
                                     expected_frame_size);
    frame_generator.add_value(cred_nodes.user_unique_id_node,
                              REPORTED_ATTRIBUTE);
    frame_generator.add_value(cred_nodes.type_node, REPORTED_ATTRIBUTE);
    frame_generator.add_value(cred_nodes.slot_node, DESIRED_ATTRIBUTE);
    frame_generator.validate_frame(frame_length);

    // Delete special nodes (start interview of credentials)
    if (cred_nodes.type_node.reported<user_credential_type_t>() == 0
        && cred_nodes.slot_node.desired<user_credential_slot_t>() == 0) {
      cred_nodes.type_node.delete_node();
      cred_nodes.slot_node.delete_node();
    }
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating Credential Get frame : %s",
                 e.what());
    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

enum class credential_report_type_t : uint8_t {
  CREDENTIAL_ADDED                          = 0x00,
  CREDENTIAL_MODIFIED                       = 0x01,
  CREDENTIAL_DELETED                        = 0x02,
  CREDENTIAL_UNCHANGED                      = 0x03,
  RESPONSE_TO_GET                           = 0x04,
  CREDENTIAL_ADD_REJECTED_LOCATION_OCCUPIED = 0x05,
  CREDENTIAL_MODIFY_REJECTED_LOCATION_EMPTY = 0x06,
  CREDENTIAL_DUPLICATE_ERROR                = 0x07,
  CREDENTIAL_MANUFACTURER_SECURITY_RULE     = 0x08,
  CREDENTIAL_LOCATION_ALREADY_ASSIGNED      = 0x09,
  CREDENTIAL_DUPLICATE_ADMIN_CODE           = 0x0A
};

sl_status_t
  handle_credential_deletion(attribute_store::attribute &endpoint_node,
                             attribute_store::attribute &user_id_node,
                             user_credential_user_unique_id_t user_id,
                             user_credential_type_t credential_type,
                             user_credential_user_unique_id_t credential_slot)
{
  if (user_id != 0 && credential_type != 0 && credential_slot != 0) {
    sl_log_info(LOG_TAG,
                "Credential Deleted. Type %d, Slot %d (User %d)",
                credential_type,
                credential_slot,
                user_id);
    // Delete the credential slot node
    get_credential_identifier_nodes(endpoint_node,
                                    {user_id, REPORTED_ATTRIBUTE},
                                    {credential_type, REPORTED_ATTRIBUTE},
                                    {credential_slot, REPORTED_ATTRIBUTE})
      .slot_node.delete_node();
  } else if (user_id != 0 && credential_type != 0 && credential_slot == 0) {
    sl_log_info(LOG_TAG,
                "All credential type %d deleted for user %d.",
                credential_type,
                user_id);
    for_each_credential_type_nodes_for_user(
      user_id_node,
      [&](attribute_store::attribute &credential_type_node) {
        credential_type_node.delete_node();
      },
      credential_type);
  } else if (user_id != 0 && credential_type == 0 && credential_slot == 0) {
    sl_log_info(LOG_TAG, "All credentials for user %d deleted.", user_id);
    for_each_credential_type_nodes_for_user(
      user_id_node,
      [&](attribute_store::attribute &credential_type_node) {
        credential_type_node.delete_node();
      });
  } else if (user_id == 0 && credential_type == 0 && credential_slot == 0) {
    sl_log_info(LOG_TAG, "All credentials deleted.");
    for_each_credential_type_nodes(
      endpoint_node,
      [&](attribute_store::attribute &credential_type_node) {
        credential_type_node.delete_node();
      });
  } else if (user_id == 0 && credential_type != 0 && credential_slot == 0) {
    sl_log_info(LOG_TAG,
                "All credentials of type %d are deleted",
                credential_type);
    for_each_credential_type_nodes(
      endpoint_node,
      [&](attribute_store::attribute &credential_type_node) {
        credential_type_node.delete_node();
      },
      credential_type);
  } else {
    sl_log_critical(LOG_TAG,
                    "Invalid combination of user_id %d, credential_type %d and "
                    "credential_slot %d for credential deletion",
                    user_id,
                    credential_type,
                    credential_slot);
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}


sl_status_t zwave_command_class_user_credential_credential_handle_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Report");

  attribute_store::attribute endpoint_node(
    zwave_command_class_get_endpoint_node(connection_info));

  const uint8_t min_size = 15;

  try {
    zwave_frame_parser parser(frame_data, frame_length);

    if (!parser.is_frame_size_valid(min_size, UINT8_MAX)) {
      sl_log_error(LOG_TAG, "Invalid frame size for Credential Report frame");
      return SL_STATUS_FAIL;
    }

    credential_report_type_t credential_report_type
      = static_cast<credential_report_type_t>(parser.read_byte());
    auto user_id = parser.read_sequential<user_credential_user_unique_id_t>(2);
    user_credential_type_t credential_type = parser.read_byte();
    auto credential_slot = parser.read_sequential<user_credential_slot_t>(2);

    sl_log_debug(LOG_TAG,
                 "Credential Report (%d). Type %d, Slot %d (User %d)",
                 credential_report_type,
                 credential_type,
                 credential_slot,
                 user_id);

    // Helper function to clean up pending credentials slot nodes
    auto clean_up_pending_credentials_slot_nodes = [&]() {
      auto nodes = get_credential_identifier_nodes(
        endpoint_node,
        {user_id, REPORTED_ATTRIBUTE},
        {credential_type, DESIRED_OR_REPORTED_ATTRIBUTE},
        {credential_slot, DESIRED_ATTRIBUTE});

      nodes.slot_node.delete_node();
    };

    // We should have a valid user id if we receive this report
    auto user_id_node
      = get_user_unique_id_node(endpoint_node, user_id, REPORTED_ATTRIBUTE);

    attribute_store::attribute credential_type_node;
    attribute_store::attribute credential_slot_node;

    switch (credential_report_type) {
      case credential_report_type_t::CREDENTIAL_ADDED:
        if (!is_credential_available(endpoint_node,
                                     credential_type,
                                     credential_slot)) {
          sl_log_error(LOG_TAG,
                       "Credential already exists. Can't add credential Type "
                       "%d, Slot %d (User %d)",
                       credential_type,
                       credential_slot,
                       user_id);
          return SL_STATUS_FAIL;
        } else {
          credential_type_node
            = create_or_update_desired_value(user_id_node,
                                             ATTRIBUTE(CREDENTIAL_TYPE),
                                             credential_type);
          credential_slot_node
            = create_or_update_desired_value(credential_type_node,
                                           ATTRIBUTE(CREDENTIAL_SLOT),
                                           credential_slot);
        }
        break;
      case credential_report_type_t::CREDENTIAL_MODIFIED: {
        // Should throw an exception if the credential doesn't exists
        auto nodes = get_credential_identifier_nodes(
          endpoint_node,
          {user_id, REPORTED_ATTRIBUTE},
          {credential_type, REPORTED_ATTRIBUTE},
          {credential_slot, REPORTED_ATTRIBUTE});
        credential_type_node = nodes.type_node;
        credential_slot_node = nodes.slot_node;
        // Clear desired value
        credential_slot_node.clear_desired();
        credential_slot_node.set_reported(credential_slot);
      } break;
      case credential_report_type_t::CREDENTIAL_DELETED:
        return handle_credential_deletion(endpoint_node,
                                          user_id_node,
                                          user_id,
                                          credential_type,
                                          credential_slot);
      case credential_report_type_t::CREDENTIAL_UNCHANGED:
        sl_log_info(LOG_TAG,
                    "Credential Unchanged. Type %d, Slot %d (User %d)",
                    credential_type,
                    credential_slot,
                    user_id);
        return SL_STATUS_OK;
      // Update desired value if found, otherwise create the nodes
      case credential_report_type_t::RESPONSE_TO_GET:
        credential_type_node
          = create_or_update_desired_value(user_id_node,
                                           ATTRIBUTE(CREDENTIAL_TYPE),
                                           credential_type);
        credential_slot_node
          = create_or_update_desired_value(credential_type_node,
                                           ATTRIBUTE(CREDENTIAL_SLOT),
                                           credential_slot);
        break;
      case credential_report_type_t::CREDENTIAL_ADD_REJECTED_LOCATION_OCCUPIED:
        sl_log_error(LOG_TAG,
                     "Credential data rejected as it already exists : user %d, "
                     "credential type %d, credential slot %d",
                     user_id,
                     credential_type,
                     credential_slot);
        clean_up_pending_credentials_slot_nodes();
        return SL_STATUS_OK;
      case credential_report_type_t::CREDENTIAL_MODIFY_REJECTED_LOCATION_EMPTY:
        sl_log_error(
          LOG_TAG,
          "Credential data cannot be modified as it does not exists : user %d, "
          "credential type %d, credential slot %d",
          user_id,
          credential_type,
          credential_slot);

        credential_type_node
          = user_id_node.child_by_type_and_value(ATTRIBUTE(CREDENTIAL_TYPE),
                                                 credential_type,
                                                 DESIRED_OR_REPORTED_ATTRIBUTE);

        if (!credential_type_node.is_valid()) {
          sl_log_debug(
            LOG_TAG,
            "No credential type found for user %d, credential type %d",
            user_id,
            credential_type);
          return SL_STATUS_OK;
        }

        credential_slot_node = credential_type_node.child_by_type_and_value(
          ATTRIBUTE(CREDENTIAL_SLOT),
          credential_slot,
          DESIRED_ATTRIBUTE);

        credential_slot_node.delete_node();
        return SL_STATUS_OK;
      // Duplicate Credential : 0x02
      case credential_report_type_t::CREDENTIAL_DUPLICATE_ERROR:
        // Do nothing, the credential GET will clean up for us
        sl_log_warning(LOG_TAG,
                       "Duplicate Credential for user %d, credential type %d, "
                       "credential slot %d",
                       user_id,
                       credential_type,
                       credential_slot);

        // This should contains the duplicated credential
        clean_up_pending_credentials_slot_nodes();
        return SL_STATUS_OK;
      case credential_report_type_t::CREDENTIAL_MANUFACTURER_SECURITY_RULE:
        sl_log_warning(
          LOG_TAG,
          "Credential data rejected as it doesn't respect manufacturer "
          "security rules : user %d, credential type %d, "
          "credential slot %d",
          user_id,
          credential_type,
          credential_slot);
        // This should contains the faulty credential
        clean_up_pending_credentials_slot_nodes();
        return SL_STATUS_OK;
      case credential_report_type_t::CREDENTIAL_LOCATION_ALREADY_ASSIGNED:
        sl_log_warning(
          LOG_TAG,
          "Credential data rejected as location is already assigned : user %d, "
          "credential type %d, credential slot %d",
          user_id,
          credential_type,
          credential_slot);
        // This should contains the faulty credential
        clean_up_pending_credentials_slot_nodes();
        return SL_STATUS_OK;
      case credential_report_type_t::CREDENTIAL_DUPLICATE_ADMIN_CODE:
        // TODO : Handle this case
      default:
        sl_log_error(LOG_TAG,
                     "Invalid credential report type %d",
                     credential_report_type);
        return SL_STATUS_FAIL;
    }

    if (!credential_type_node.is_valid()) {
      sl_log_critical(LOG_TAG,
                      "Credential type is invalid when it should be. Can't "
                      "process credential report.");
      return SL_STATUS_FAIL;
    }

    if (!credential_slot_node.is_valid()) {
      sl_log_critical(LOG_TAG,
                      "Credential slot is invalid when it should be. Can't "
                      "process credential report.");
      return SL_STATUS_FAIL;
    }

    // If we are here it means that we have a valid credential type and slot node
    parser.read_byte_with_bitmask(
      {CREDENTIAL_REPORT_PROPERTIES1_CRB_BIT_MASK,
       credential_slot_node.emplace_node(ATTRIBUTE(CREDENTIAL_READ_BACK))});
    uint8_t cred_data_size = parser.read_byte();
    parser.read_sequential<std::vector<uint8_t>>(
      cred_data_size,
      credential_slot_node.emplace_node(ATTRIBUTE(CREDENTIAL_DATA)));
    parser.read_byte(
      credential_slot_node.emplace_node(ATTRIBUTE(CREDENTIAL_MODIFIER_TYPE)));
    parser.read_sequential<user_credential_modifier_node_id_t>(
      2,
      credential_slot_node.emplace_node(
        ATTRIBUTE(CREDENTIAL_MODIFIER_NODE_ID)));

    // Next
    user_credential_type_t next_credential_type = parser.read_byte();
    auto next_credential_slot
      = parser.read_sequential<user_credential_slot_t>(2);

    // Interview next credential is available
    if (next_credential_type != 0 && next_credential_slot != 0
        && credential_report_type
             == credential_report_type_t::RESPONSE_TO_GET) {
      trigger_get_credential(user_id_node,
                             next_credential_type,
                             next_credential_slot);
    }

  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while parsing Credential Report frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Credential Learn Start/Report/Stop
/////////////////////////////////////////////////////////////////////////////
static sl_status_t zwave_command_class_user_credential_credential_learn_start(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Learn Start");
  attribute_store::attribute credential_operation_type_node(node);

  try {
    frame_generator.initialize_frame(CREDENTIAL_LEARN_START,
                                     frame,
                                     sizeof(ZW_CREDENTIAL_LEARN_START_FRAME));
    auto nodes
      = get_credential_identifier_nodes(credential_operation_type_node);

    frame_generator.add_value(nodes.user_unique_id_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_value(nodes.type_node, DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_value(nodes.slot_node, DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.add_value(credential_operation_type_node,
                              DESIRED_ATTRIBUTE);
    frame_generator.add_value(
      nodes.slot_node.child_by_type(ATTRIBUTE(CREDENTIAL_LEARN_TIMEOUT)),
      DESIRED_OR_REPORTED_ATTRIBUTE);
    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating Credential Learn Start frame : %s",
                 e.what());
    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_user_credential_credential_learn_cancel(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Learn Cancel");
  attribute_store::attribute credential_learn_stop_node(node);

  credential_learn_stop_node.set_reported<uint8_t>(1);
  credential_learn_stop_node.clear_desired();

  return frame_generator.generate_no_args_frame(CREDENTIAL_LEARN_CANCEL,
                                                frame,
                                                frame_length);
}

sl_status_t zwave_command_class_user_credential_credential_learn_status_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  attribute_store::attribute endpoint_node
    = zwave_command_class_get_endpoint_node(connection_info);

  try {
    zwave_frame_parser parser(frame_data, frame_length);

    if (!parser.is_frame_size_valid(sizeof(ZW_CREDENTIAL_LEARN_REPORT_FRAME))) {
      sl_log_error(
        LOG_TAG,
        "Invalid frame size for Credential Learn Status Report frame");
      return SL_STATUS_NOT_SUPPORTED;
    }

    // Parse the frame
    const uint8_t learn_status = parser.read_byte();
    const auto user_id
      = parser.read_sequential<user_credential_user_unique_id_t>(2);
    const user_credential_type_t credential_type = parser.read_byte();
    const auto credential_slot
      = parser.read_sequential<user_credential_slot_t>(2);
    const uint8_t step_remaining = parser.read_byte();

    sl_log_debug(LOG_TAG,
                 "Credential Learn Status Report. Credential Type: %d / "
                 "Credential Slot: %d (User %d)",
                 credential_type,
                 credential_slot,
                 user_id);

    auto credential_id_nodes = get_credential_identifier_nodes(
      endpoint_node,
      {user_id, REPORTED_ATTRIBUTE},
      {credential_type, DESIRED_OR_REPORTED_ATTRIBUTE},
      {credential_slot, DESIRED_OR_REPORTED_ATTRIBUTE});

    // Get operation type so we can handle error cases
    auto operation_type
      = credential_id_nodes.slot_node
          .child_by_type(ATTRIBUTE(CREDENTIAL_LEARN_OPERATION_TYPE))
          .desired<user_credential_operation_type_t>();

    // Action based of current learn status
    std::string learn_status_str;
    bool need_deletion       = false;
    sl_log_level_t log_level = SL_LOG_INFO;

    switch (learn_status) {
      case CREDENTIAL_LEARN_REPORT_STARTED:
        learn_status_str = "Credential Learn Started";
        break;
      case CREDENTIAL_LEARN_REPORT_SUCCESS:
        learn_status_str = "Credential Learn Success";
        break;
      case CREDENTIAL_LEARN_REPORT_ALREADY_IN_PROGRESS:
        log_level        = SL_LOG_WARNING;
        learn_status_str = "Credential Learn already in progress";
        break;
      case CREDENTIAL_LEARN_REPORT_ENDED_NOT_DUE_TO_TIMEOUT:
        learn_status_str = "Credential Learn ended not due to timeout";
        need_deletion = (operation_type == USER_CREDENTIAL_OPERATION_TYPE_ADD);
        break;
      case CREDENTIAL_LEARN_REPORT_TIMEOUT:
        log_level        = SL_LOG_WARNING;
        learn_status_str = "Credential Learn Timeout";
        need_deletion = (operation_type == USER_CREDENTIAL_OPERATION_TYPE_ADD);
        break;
      case 0x05:  // Credential Learn Step Retry
        learn_status_str = "Credential Learn Step Needs a Retry";
        need_deletion = (operation_type == USER_CREDENTIAL_OPERATION_TYPE_ADD);
        break;
      case CREDENTIAL_LEARN_REPORT_INVALID_CREDENTIAL_LEARN_ADD_OPERATION_TYPE:
        log_level        = SL_LOG_ERROR;
        learn_status_str = "Invalid Add Operation Types";
        break;
      case CREDENTIAL_LEARN_REPORT_INVALID_CREDENTIAL_LEARN_MODIFY_OPERATION_TYPE:
        log_level        = SL_LOG_ERROR;
        learn_status_str = "Invalid Modify Operation Type";
        need_deletion = (operation_type == USER_CREDENTIAL_OPERATION_TYPE_ADD);
        break;
      default:
        learn_status_str
          = "Unknown Credential Learn Status " + std::to_string(learn_status);
        log_level = SL_LOG_CRITICAL;
    }

    sl_log(LOG_TAG,
           log_level,
           "%s for User %d, Credential Type %d, "
           "Credential Slot %d",
           learn_status_str.c_str(),
           user_id,
           credential_type,
           credential_slot);

    if (need_deletion) {
      credential_id_nodes.slot_node.delete_node();
    }

    // Update nodes
    credential_id_nodes.slot_node.emplace_node(
      ATTRIBUTE(CREDENTIAL_LEARN_STEPS_REMAINING),
      step_remaining);
    credential_id_nodes.slot_node.emplace_node(
      ATTRIBUTE(CREDENTIAL_LEARN_STATUS),
      learn_status);

  } catch (const std::exception &e) {
    sl_log_error(
      LOG_TAG,
      "Error while parsing Credential Learn Status Report frame : %s",
      e.what());

    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// User Unique Identifier Credential Association Set/Report
/////////////////////////////////////////////////////////////////////////////

static sl_status_t zwave_command_class_user_credential_uuic_association_set(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG,
               "User Unique Identifier Credential Association Set command");
  attribute_store::attribute destination_credential_slot_node(node);

  try {
    frame_generator.initialize_frame(
      USER_CREDENTIAL_ASSOCIATION_SET,
      frame,
      sizeof(ZW_USER_CREDENTIAL_ASSOCIATION_SET_FRAME));

    auto nodes
      = get_credential_identifier_nodes(destination_credential_slot_node);
    frame_generator.add_value(nodes.user_unique_id_node, REPORTED_ATTRIBUTE);
    frame_generator.add_value(nodes.type_node, REPORTED_ATTRIBUTE);
    frame_generator.add_value(nodes.slot_node, REPORTED_ATTRIBUTE);
    frame_generator.add_value(
      nodes.slot_node.child_by_type(ATTRIBUTE(ASSOCIATION_DESTINATION_USER_ID)),
      DESIRED_ATTRIBUTE);
    frame_generator.add_value(destination_credential_slot_node,
                              DESIRED_ATTRIBUTE);
    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating User Unique Identifier Credential "
                 "Association Set frame : %s",
                 e.what());
    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_uuic_association_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  constexpr uint8_t EXPECTED_FRAME_LENGTH = 12;
  if (frame_length != EXPECTED_FRAME_LENGTH) {
    sl_log_error(LOG_TAG,
                 "USER_CREDENTIAL_ASSOCIATION_REPORT frame length is not "
                 "valid. Expected %d, got %d",
                 EXPECTED_FRAME_LENGTH,
                 frame_length);
    return SL_STATUS_NOT_SUPPORTED;
  }

  constexpr uint8_t INDEX_SOURCE_USER_ID              = 2;
  constexpr uint8_t INDEX_SOURCE_CREDENTIAL_TYPE      = 4;
  constexpr uint8_t INDEX_SOURCE_CREDENTIAL_SLOT      = 5;
  constexpr uint8_t INDEX_DESTINATION_USER_ID         = 7;
  constexpr uint8_t INDEX_DESTINATION_CREDENTIAL_SLOT = 9;
  constexpr uint8_t INDEX_ASSOCIATION_STATUS          = 11;

  attribute_store_node_t endpoint_node
    = zwave_command_class_get_endpoint_node(connection_info);

  // Interpret frame
  const user_credential_user_unique_id_t source_user_id
    = get_uint16_value(frame_data, INDEX_SOURCE_USER_ID);
  const user_credential_type_t source_credential_type
    = frame_data[INDEX_SOURCE_CREDENTIAL_TYPE];
  const user_credential_slot_t source_credential_slot
    = get_uint16_value(frame_data, INDEX_SOURCE_CREDENTIAL_SLOT);
  const user_credential_user_unique_id_t destination_user_id
    = get_uint16_value(frame_data, INDEX_DESTINATION_USER_ID);
  const user_credential_slot_t destination_credential_slot
    = get_uint16_value(frame_data, INDEX_DESTINATION_CREDENTIAL_SLOT);
  const uint8_t association_status = frame_data[INDEX_ASSOCIATION_STATUS];

  sl_log_debug(LOG_TAG,
               "User Unique Identifier Credential Association Report. Source "
               "User ID: %d / "
               "Source Credential Type: %d / Source Credential Slot: %d / "
               "Destination User ID: %d / Destination Credential Slot: %d",
               source_user_id,
               source_credential_type,
               source_credential_slot,
               destination_user_id,
               destination_credential_slot);

  // Get nodes
  attribute_store_node_t source_credential_type_node;
  attribute_store_node_t source_credential_slot_node;
  get_credential_type_node(endpoint_node,
                           source_user_id,
                           source_credential_type,
                           REPORTED_ATTRIBUTE,
                           source_credential_type_node);
  get_credential_slot_node(source_credential_type_node,
                           source_credential_slot,
                           REPORTED_ATTRIBUTE,
                           source_credential_slot_node);

  if (!attribute_store_node_exists(source_credential_type_node)
      || !attribute_store_node_exists(source_credential_slot_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find User %d, Credential Type %d, "
                 "Credential Slot %d reported by User Unique Identifier "
                 "Credential Association Report",
                 source_user_id,
                 source_credential_type,
                 source_credential_slot);
    return SL_STATUS_NOT_SUPPORTED;
  }

  // Set association status
  attribute_store_set_child_reported(source_credential_slot_node,
                                     ATTRIBUTE(ASSOCIATION_STATUS),
                                     &association_status,
                                     sizeof(association_status));

  // Clean up association data so ZPC won't try to send the SET command again
  auto association_destination_user_id_node
    = attribute_store_get_first_child_by_type(
      source_credential_slot_node,
      ATTRIBUTE(ASSOCIATION_DESTINATION_USER_ID));
  auto association_destination_credential_slot_node
    = attribute_store_get_first_child_by_type(
      source_credential_slot_node,
      ATTRIBUTE(ASSOCIATION_DESTINATION_CREDENTIAL_SLOT));
  attribute_store_delete_node(association_destination_user_id_node);
  attribute_store_delete_node(association_destination_credential_slot_node);

  if (association_status != USER_CREDENTIAL_ASSOCIATION_REPORT_SUCCESS) {
    sl_log_error(LOG_TAG,
                 "User Unique Identifier Credential Association error. "
                 "Reported status code : %d",
                 association_status);
    return SL_STATUS_OK;
  }

  // Simple case : we only have to change the slot number
  if (destination_user_id == source_user_id) {
    sl_log_info(LOG_TAG,
                "Moving slot %d to slot %d (user %d)",
                source_credential_slot,
                destination_credential_slot,
                destination_user_id);

    return attribute_store_set_reported(source_credential_slot_node,
                                        &destination_credential_slot,
                                        sizeof(destination_credential_slot));
  }

  // Complex case : we have to move the slot to another user
  sl_log_info(LOG_TAG,
              "Moving slot %d (user %d) to slot %d (user %d)",
              source_credential_slot,
              source_user_id,
              destination_credential_slot,
              destination_user_id);

  // Get user node
  attribute_store_node_t destination_user_id_node;
  get_user_id_node(endpoint_node,
                   destination_user_id,
                   REPORTED_ATTRIBUTE,
                   destination_user_id_node);

  if (!attribute_store_node_exists(destination_user_id_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find User %d reported by User Unique Identifier "
                 "Credential Association Report",
                 destination_user_id);
    return SL_STATUS_NOT_SUPPORTED;
  }

  // Get destination type node
  attribute_store_node_t destination_credential_type_node;
  // Look for it if it exists
  get_credential_type_node(endpoint_node,
                           destination_user_id,
                           source_credential_type,
                           REPORTED_ATTRIBUTE,
                           destination_credential_type_node);
  // If it doesn't exists yet we create it
  if (!attribute_store_node_exists(destination_credential_type_node)) {
    destination_credential_type_node
      = attribute_store_emplace(destination_user_id_node,
                                ATTRIBUTE(CREDENTIAL_TYPE),
                                &source_credential_type,
                                sizeof(source_credential_type));
  }

  // Get destination slot node (if we are here we assume that it doesn't exists)
  attribute_store_node_t destination_credential_slot_node
    = attribute_store_emplace(destination_credential_type_node,
                              ATTRIBUTE(CREDENTIAL_SLOT),
                              &destination_credential_slot,
                              sizeof(destination_credential_slot));

  // Copy attribute tree
  attribute_store::attribute cpp_source_credential_slot_node(
    source_credential_slot_node);
  attribute_store::attribute cpp_destination_credential_slot_node(
    destination_credential_slot_node);

  // Can't use walk_tree here since we need a capturing lambda
  // Define the lambda explicitly since it is recursive https://stackoverflow.com/a/4081391
  std::function<void(attribute_store::attribute, attribute_store_type_t)>
    deep_copy_reported_attributes;
  deep_copy_reported_attributes
    = [&](attribute_store::attribute cpp_current_node,
          attribute_store::attribute cpp_parent_node) {
        // Ignore fields that doesn't have a reported value
        if (!cpp_current_node.reported_exists()) {
          return;
        }
        attribute_store_node_t destination_node;
        // If we are not at the root node, add new node
        if (cpp_current_node.type() != cpp_parent_node.type()) {
          destination_node = attribute_store_add_node(cpp_current_node.type(),
                                                      cpp_parent_node);

          attribute_store_copy_value(cpp_current_node,
                                     destination_node,
                                     REPORTED_ATTRIBUTE);
        }
        // Check node children
        for (auto child: cpp_current_node.children()) {
          // If we are not at the root, need to copy the child attribute
          if (cpp_current_node.type() != cpp_parent_node.type()) {
            cpp_parent_node = destination_node;
          }
          deep_copy_reported_attributes(child, cpp_parent_node);
        }
      };
  deep_copy_reported_attributes(cpp_source_credential_slot_node,
                                cpp_destination_credential_slot_node);

  // Then remove the old node
  attribute_store_delete_node(source_credential_slot_node);

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// User Set/Get/Report/Set Error Report
/////////////////////////////////////////////////////////////////////////////

// Start user interview process by starting a user get with ID 0
void trigger_get_user(attribute_store_node_t endpoint_node,
                      user_credential_user_unique_id_t user_id)
{
  // If we are not in the special case of user ID 0 we need to check if user is already here
  if (user_id != 0) {
    attribute_store_node_t user_node
      = attribute_store_get_node_child_by_value(endpoint_node,
                                                ATTRIBUTE(USER_UNIQUE_ID),
                                                REPORTED_ATTRIBUTE,
                                                (uint8_t *)&user_id,
                                                sizeof(user_id),
                                                0);
    // If it exists we interview it again
    if (attribute_store_node_exists(user_node)) {
      sl_log_debug(
        LOG_TAG,
        "User Unique ID %d found. Undefine its reported value to update it.",
        user_id);
      attribute_store_set_desired(user_node, &user_id, sizeof(user_id));
      attribute_store_undefine_reported(user_node);
      return;
    }
  }

  // If user id is 0 or not existant we create it
  sl_log_debug(LOG_TAG, "Creating User Unique ID node %d", user_id);
  attribute_store_emplace_desired(endpoint_node,
                                  ATTRIBUTE(USER_UNIQUE_ID),
                                  &user_id,
                                  sizeof(user_id));
}

static sl_status_t zwave_command_class_user_credential_user_set(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  try {
    // Node setup
    attribute_store::attribute user_operation_type_node(node);
    attribute_store::attribute user_unique_id_node
      = user_operation_type_node.first_parent(ATTRIBUTE(USER_UNIQUE_ID));

    // Get Values
    auto user_unique_id
      = user_unique_id_node
          .desired_or_reported<user_credential_user_unique_id_t>();
    auto user_operation_type
      = user_operation_type_node.desired<user_credential_operation_type_t>();

    const bool is_delete_operation
      = (user_operation_type == USER_SET_OPERATION_TYPE_DELETE);

    uint8_t expected_frame_size = (is_delete_operation) ? 5 : 12;
    uint8_t user_name_size      = 0;

    if (!is_delete_operation) {
      user_name_size = static_cast<uint8_t>(
        user_unique_id_node.child_by_type(ATTRIBUTE(USER_NAME))
          .reported<std::string>()
          .size());
    }

    // Append the user name size (will be 0 if is delete operation)
    expected_frame_size += user_name_size;

    sl_log_debug(LOG_TAG,
                 "User SET for user %d (operation type : %d)",
                 user_unique_id,
                 user_operation_type);

    // Creating the frame
    frame_generator.initialize_frame(USER_SET, frame, expected_frame_size);

    frame_generator.add_value(user_operation_type_node, DESIRED_ATTRIBUTE);
    frame_generator.add_value(user_unique_id_node,
                              DESIRED_OR_REPORTED_ATTRIBUTE);

    if (!is_delete_operation) {
      frame_generator.add_value(
        user_unique_id_node.child_by_type(ATTRIBUTE(USER_TYPE)),
        DESIRED_OR_REPORTED_ATTRIBUTE);
      frame_generator.add_value(
        user_unique_id_node.child_by_type(ATTRIBUTE(USER_ACTIVE_STATE)),
        DESIRED_OR_REPORTED_ATTRIBUTE);
      frame_generator.add_value(
        user_unique_id_node.child_by_type(ATTRIBUTE(CREDENTIAL_RULE)),
        DESIRED_OR_REPORTED_ATTRIBUTE);
      frame_generator.add_value(user_unique_id_node.child_by_type(
                                  ATTRIBUTE(USER_EXPIRING_TIMEOUT_MINUTES)),
                                DESIRED_OR_REPORTED_ATTRIBUTE);
      frame_generator.add_value(
        user_unique_id_node.child_by_type(ATTRIBUTE(USER_NAME_ENCODING)),
        DESIRED_OR_REPORTED_ATTRIBUTE);
      frame_generator.add_raw_byte(user_name_size);
      frame_generator.add_value(
        user_unique_id_node.child_by_type(ATTRIBUTE(USER_NAME)),
        DESIRED_OR_REPORTED_ATTRIBUTE);
    }

    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating User SET frame : %s",
                 e.what());
    return SL_STATUS_NOT_SUPPORTED;
  }
  return SL_STATUS_OK;
}

static sl_status_t zwave_command_class_user_credential_user_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  attribute_store::attribute user_unique_id_node(node);

  // If we enter this state it means that something went badly wrong or
  // user initiate the interview process again.
  // In both cases we want to invalidate the user database so that the device
  // can send us the correct user database.

  if (!user_unique_id_node.desired_exists()) {
    sl_log_warning(LOG_TAG,
                   "Can't get user unique id Desired value. Removing all users "
                   "to perform interview again.");
    attribute_store::attribute endpoint_node = user_unique_id_node.parent();

    // Get User node count
    for (auto user_node: endpoint_node.children(ATTRIBUTE(USER_UNIQUE_ID))) {
      attribute_store_delete_node(user_node);
    }

    // NOTE : In the case of user re-interviewing the device, it will be interviewed again when the node goes ONLINE.
    return SL_STATUS_NOT_SUPPORTED;
  }

  user_credential_user_unique_id_t user_id
    = user_unique_id_node.desired<user_credential_user_unique_id_t>();
  sl_log_debug(LOG_TAG, "User Get for user %d", user_id);

  // Generate the frame
  constexpr uint8_t expected_frame_size
    = static_cast<uint8_t>(sizeof(ZW_USER_GET_FRAME));
  try {
    frame_generator.initialize_frame(USER_GET, frame, expected_frame_size);
    frame_generator.add_value(user_unique_id_node, DESIRED_ATTRIBUTE);
    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating USER_GET frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }

  // This special user ID will contains the unaffected credentials.
  if (user_id == 0) {
    sl_log_debug(LOG_TAG, "Starting interview for all users on the device.");
    user_unique_id_node.clear_desired();
    user_unique_id_node.set_reported(user_id);
  }

  return SL_STATUS_OK;
}

// TODO : Update with values in ZW_cmdclass.h
enum class user_report_type_t : uint8_t {
  USER_ADDED                          = 0x00,
  USER_MODIFIED                       = 0x01,
  USER_DELETED                        = 0x02,
  USER_UNCHANGED                      = 0x03,
  RESPONSE_TO_GET                     = 0x04,
  USER_ADD_REJECTED_LOCATION_OCCUPIED = 0x05,
  USER_MODIFY_REJECTED_LOCATION_EMPTY = 0x06,
  NON_ZERO_EXPIRING_MINUTES_INVALID   = 0x07
};

sl_status_t zwave_command_class_user_credential_user_handle_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  sl_log_debug(LOG_TAG, "User Report");

  attribute_store::attribute endpoint_node(
    zwave_command_class_get_endpoint_node(connection_info));

  const uint8_t expected_min_size = 16;

  try {
    zwave_frame_parser parser(frame_data, frame_length);

    if (!parser.is_frame_size_valid(expected_min_size, UINT8_MAX)) {
      sl_log_error(LOG_TAG, "Invalid frame size for User Report frame");
      return SL_STATUS_FAIL;
    }

    auto user_report_type = static_cast<user_report_type_t>(parser.read_byte());

    auto next_user_id
      = parser.read_sequential<user_credential_user_unique_id_t>(2);

    user_credential_modifier_type_t user_modifier_type = parser.read_byte();
    auto user_modifier_id
      = parser.read_sequential<user_credential_modifier_node_id_t>(2);

    // Get User ID
    auto current_user_id
      = parser.read_sequential<user_credential_user_unique_id_t>(2);

    sl_log_debug(LOG_TAG,
                 "User report for user %d. User report type %d",
                 current_user_id,
                 user_report_type);

    // CC:0083.01.05.11.006: Zero is an invalid User Unique Identifier and MUST NOT be used by the node
    if (current_user_id == 0) {
      if (user_report_type == user_report_type_t::RESPONSE_TO_GET) {
        sl_log_info(LOG_TAG, "No users was found on the device.");
        return SL_STATUS_OK;
      } else if (user_report_type == user_report_type_t::USER_DELETED) {
        sl_log_info(LOG_TAG, "Request to delete all users");

        for (auto user_node:
             endpoint_node.children(ATTRIBUTE(USER_UNIQUE_ID))) {
          // Don't delete special user 0
          if (user_node.reported_exists()
              && user_node.reported<user_credential_user_unique_id_t>() == 0) {
            continue;
          }

          attribute_store_delete_node(user_node);
        }

        return SL_STATUS_OK;
      } else {
        sl_log_error(LOG_TAG,
                     "User report with ID 0 received. This is an invalid User "
                     "Unique Identifier and MUST NOT be used by the node.");
        return SL_STATUS_FAIL;
      }
    }

    // Lambda function to remove user node in an invalid state
    auto remove_current_user_node = [&]() {
      get_user_unique_id_node(endpoint_node, current_user_id, DESIRED_ATTRIBUTE)
        .delete_node();
    };

    // Current user id node that will be used later
    // Each report type has a different behavior
    attribute_store::attribute current_user_id_node;
    switch (user_report_type) {
      // Need to create new user node
      case user_report_type_t::USER_ADDED:
        current_user_id_node
          = endpoint_node.emplace_node(ATTRIBUTE(USER_UNIQUE_ID),
                                       current_user_id);
      // If this is the first user we get it might not exists yet so we create it.
      // Otherwise we just update the reported value
      case user_report_type_t::RESPONSE_TO_GET:
        current_user_id_node
          = create_or_update_desired_value(endpoint_node,
                                           ATTRIBUTE(USER_UNIQUE_ID),
                                           current_user_id);
        break;
      // We should have a record of given user ID
      case user_report_type_t::USER_MODIFIED:
      case user_report_type_t::USER_DELETED:
        current_user_id_node = get_user_unique_id_node(endpoint_node,
                                                       current_user_id,
                                                       REPORTED_ATTRIBUTE);
        break;
      // Special/Errors cases
      case user_report_type_t::USER_UNCHANGED:
        sl_log_info(LOG_TAG, "User %d is unchanged", current_user_id);
        return SL_STATUS_OK;
      case user_report_type_t::USER_ADD_REJECTED_LOCATION_OCCUPIED:
        sl_log_warning(LOG_TAG,
                       "User %d was not added since it already exists. Try to "
                       "modify it instead.",
                       current_user_id);
        remove_current_user_node();
        return SL_STATUS_OK;
      case user_report_type_t::USER_MODIFY_REJECTED_LOCATION_EMPTY:
        sl_log_warning(LOG_TAG,
                       "User %d was not modified since it doesn't exists. Try "
                       "to add it instead.",
                       current_user_id);
        remove_current_user_node();
        return SL_STATUS_OK;
      case user_report_type_t::NON_ZERO_EXPIRING_MINUTES_INVALID:
        sl_log_warning(LOG_TAG,
                       "User %d was not modified/added since the expiring "
                       "timeout minutes is invalid.",
                       current_user_id);
        return SL_STATUS_OK;
      default:
        sl_log_error(LOG_TAG, "Invalid value for user report type.");
        return SL_STATUS_FAIL;
    };

    // Deleted special case
    if (user_report_type == user_report_type_t::USER_DELETED) {
      // TODO : move all credential from this user to user 0
      // Maybe it is done automatically by the credential report
      sl_log_info(LOG_TAG, "User %d has been deleted", current_user_id);
      current_user_id_node.delete_node();
      return SL_STATUS_OK;
    }

    // Set already parsed values
    current_user_id_node.emplace_node(ATTRIBUTE(USER_MODIFIER_TYPE))
      .set_reported(user_modifier_type);
    current_user_id_node.emplace_node(ATTRIBUTE(USER_MODIFIER_NODE_ID))
      .set_reported(user_modifier_id);

    // Keep parsing the frame
    parser.read_byte(current_user_id_node.emplace_node(ATTRIBUTE(USER_TYPE)));
    parser.read_byte_with_bitmask(
      {USER_REPORT_PROPERTIES1_USER_ACTIVE_STATE_BIT_MASK,
       current_user_id_node.emplace_node(ATTRIBUTE(USER_ACTIVE_STATE))});
    parser.read_byte(
      current_user_id_node.emplace_node(ATTRIBUTE(CREDENTIAL_RULE)));
    parser.read_sequential<user_credential_expiring_timeout_minutes_t>(
      2,
      current_user_id_node.emplace_node(
        ATTRIBUTE(USER_EXPIRING_TIMEOUT_MINUTES)));
    parser.read_byte_with_bitmask(
      {USER_REPORT_PROPERTIES2_USER_NAME_ENCODING_MASK,
       current_user_id_node.emplace_node(ATTRIBUTE(USER_NAME_ENCODING))});
    parser.read_string(current_user_id_node.emplace_node(ATTRIBUTE(USER_NAME)));

    // Get credentials
    trigger_get_credential(current_user_id_node, 0, 0);

    if (next_user_id != 0
        && user_report_type == user_report_type_t::RESPONSE_TO_GET) {
      if (!user_exists(endpoint_node, next_user_id)) {
        sl_log_debug(LOG_TAG, "Trigger a get for next user (%d)", next_user_id);
        endpoint_node.add_node(ATTRIBUTE(USER_UNIQUE_ID))
          .set_desired(next_user_id);
      } else {
        sl_log_error(LOG_TAG,
                     "User %d already exists. Not discovering more users.",
                     next_user_id);
      }
    } else {
      sl_log_debug(LOG_TAG, "No more users to discover");
    }

  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while parsing User Report frame : %s",
                 e.what());
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Checksum helpers
/////////////////////////////////////////////////////////////////////////////

/**
 * @brief Compte the checksum and verify the checksum integrity. 
 * 
 * Compare crc16 of checksum_data and expected checksum and put it in the 
 * checksum_error_type if not matching.  
 * 
 * @param base_node The base node to put the error attribute
 * @param checksum_error_type The type of the error attribute
 * @param checksum_data The data to compute the checksum. Checksum will be 0 if empty.
 * @param expected_checksum The expected checksum
 * 
 * @return The computed checksum of checksum_data
*/
user_credential_checksum_t compute_checksum_and_verify_integrity(
  attribute_store_node_t base_node,
  attribute_store_type_t checksum_error_type,
  std::vector<uint8_t> checksum_data,
  user_credential_checksum_t expected_checksum)
{
  user_credential_checksum_t computed_checksum = 0;
  // If checksum data is empty, the checksum is 0. The guard is present to avoid
  // zwave_controller_crc16 to return CRC_INITIALIZATION_VALUE if checksum_data is empty.
  // See CC:0083.01.19.11.016 & CC:0083.01.17.11.013
  if (checksum_data.size() > 0) {
    computed_checksum = zwave_controller_crc16(CRC_INITIALIZATION_VALUE,
                                               checksum_data.data(),
                                               checksum_data.size());
  }

  if (computed_checksum != expected_checksum) {
    // Set checksum mismatch error
    attribute_store_set_child_reported(base_node,
                                       checksum_error_type,
                                       &computed_checksum,
                                       sizeof(computed_checksum));
  } else {
    // If we don't have any errors we remove the checksum_error_type node
    auto checksum_mismatch_node
      = attribute_store_get_first_child_by_type(base_node, checksum_error_type);
    attribute_store_delete_node(checksum_mismatch_node);
  }

  return computed_checksum;
}

/////////////////////////////////////////////////////////////////////////////
// User Checksum Get/Report
/////////////////////////////////////////////////////////////////////////////
static sl_status_t zwave_command_class_user_credential_user_checksum_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "User Checksum Get");
  attribute_store::attribute checksum_node(node);

  auto user_id_node = checksum_node.first_parent(ATTRIBUTE(USER_UNIQUE_ID));

  if (!user_id_node.is_valid()) {
    sl_log_error(
      LOG_TAG,
      "Can't find User Unique ID node. Not sending User Checksum Get.");
    return SL_STATUS_NOT_SUPPORTED;
  }

  constexpr uint8_t expected_frame_size
    = static_cast<uint8_t>(sizeof(ZW_USER_CHECKSUM_GET_FRAME));

  try {
    frame_generator.initialize_frame(USER_CHECKSUM_GET,
                                     frame,
                                     expected_frame_size);
    frame_generator.add_value(user_id_node);
    frame_generator.validate_frame(frame_length);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Error while generating User Checksum Get frame : %s",
                 e.what());
    return SL_STATUS_NOT_SUPPORTED;
  }

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_user_checksum_handle_report(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  constexpr uint8_t EXPECTED_FRAME_LENGTH = 6;
  if (frame_length != EXPECTED_FRAME_LENGTH) {
    sl_log_error(LOG_TAG,
                 "USER_CHECKSUM_REPORT  frame length is not "
                 "valid. Expected %d, got %d",
                 EXPECTED_FRAME_LENGTH,
                 frame_length);
    return SL_STATUS_NOT_SUPPORTED;
  }

  constexpr uint8_t INDEX_SOURCE_USER_ID = 2;
  constexpr uint8_t INDEX_USER_CHECKSUM  = 4;

  attribute_store_node_t endpoint_node
    = zwave_command_class_get_endpoint_node(connection_info);

  // Interpret frame
  const user_credential_user_unique_id_t user_id
    = get_uint16_value(frame_data, INDEX_SOURCE_USER_ID);
  const user_credential_checksum_t user_checksum
    = get_uint16_value(frame_data, INDEX_USER_CHECKSUM);

  sl_log_debug(LOG_TAG,
               "User Checksum Report. Source User ID: %d / "
               "Checksum: 0x%X",
               user_id,
               user_checksum);

  attribute_store_node_t user_id_node;
  if (!get_user_id_node(endpoint_node,
                        user_id,
                        REPORTED_ATTRIBUTE,
                        user_id_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find User %d reported by User Checksum Report",
                 user_id);
    return SL_STATUS_NOT_SUPPORTED;
  }

  // Set reported value
  attribute_store_set_child_reported(user_id_node,
                                     ATTRIBUTE(USER_CHECKSUM),
                                     &user_checksum,
                                     sizeof(user_checksum));

  // Compute checksum ourselves to see if it matches
  std::vector<uint8_t> checksum_data;

  // First gather all the User values
  const std::vector<attribute_store_type_t> user_attributes = {
    ATTRIBUTE(USER_TYPE),
    ATTRIBUTE(USER_ACTIVE_STATE),
    ATTRIBUTE(CREDENTIAL_RULE),
    ATTRIBUTE(USER_NAME_ENCODING),
    ATTRIBUTE(USER_NAME),
  };
  attribute_store::attribute cpp_user_id_node(user_id_node);
  for (auto attribute: user_attributes) {
    if (!add_node_to_checksum(checksum_data,
                              cpp_user_id_node.child_by_type(attribute))) {
      return SL_STATUS_FAIL;
    }
  }

  // The all credential data
  auto credential_type_node_count
    = attribute_store_get_node_child_count_by_type(user_id_node,
                                                   ATTRIBUTE(CREDENTIAL_TYPE));

  for (size_t credential_index = 0;
       credential_index < credential_type_node_count;
       credential_index++) {
    attribute_store_node_t credential_type_node
      = attribute_store_get_node_child_by_type(user_id_node,
                                               ATTRIBUTE(CREDENTIAL_TYPE),
                                               credential_index);
    auto credential_slot_node_count
      = attribute_store_get_node_child_count_by_type(
        credential_type_node,
        ATTRIBUTE(CREDENTIAL_SLOT));

    for (size_t slot_index = 0; slot_index < credential_slot_node_count;
         slot_index++) {
      attribute_store_node_t credential_slot_node
        = attribute_store_get_node_child_by_type(credential_type_node,
                                                 ATTRIBUTE(CREDENTIAL_SLOT),
                                                 slot_index);
      // We don't have all the data for this slot, skipping it.
      if (!attribute_store_is_reported_defined(credential_slot_node)) {
        sl_log_debug(
          LOG_TAG,
          "Credential Slot #%d is not defined. Not adding to checksum.",
          slot_index);
        continue;
      }

      // Add credential type to checksum
      if (!add_node_to_checksum(checksum_data, credential_type_node)) {
        return SL_STATUS_FAIL;
      }

      // Add credential slot to checksum
      if (!add_node_to_checksum(checksum_data, credential_slot_node)) {
        return SL_STATUS_FAIL;
      }

      auto credential_data_node
        = attribute_store_get_first_child_by_type(credential_slot_node,
                                                  ATTRIBUTE(CREDENTIAL_DATA));

      // Add credential data to checksum
      if (!add_node_to_checksum(checksum_data, credential_data_node)) {
        return SL_STATUS_FAIL;
      }
    }
  }

  user_credential_checksum_t computed_checksum
    = compute_checksum_and_verify_integrity(
      user_id_node,
      ATTRIBUTE(USER_CHECKSUM_MISMATCH_ERROR),
      checksum_data,
      user_checksum);

  if (computed_checksum != user_checksum) {
    sl_log_error(LOG_TAG,
                 "Checksum mismatch for user %d. Expected 0x%X, got 0x%X",
                 user_id,
                 user_checksum,
                 computed_checksum);
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Credential Checksum Get/Report
/////////////////////////////////////////////////////////////////////////////

static sl_status_t zwave_command_class_user_credential_credential_checksum_get(
  attribute_store_node_t node, uint8_t *frame, uint16_t *frame_length)
{
  sl_log_debug(LOG_TAG, "Credential Checksum Get");

  auto credential_type_node = attribute_store_get_first_parent_with_type(
    node,
    ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE));

  if (!attribute_store_node_exists(credential_type_node)) {
    sl_log_error(
      LOG_TAG,
      "Can't find Credential Type node. Not sending Credential Checksum Get.");
    return SL_STATUS_NOT_SUPPORTED;
  }

  user_credential_type_t credential_type = 0;
  sl_status_t status = attribute_store_get_reported(credential_type_node,
                                                    &credential_type,
                                                    sizeof(credential_type));

  if (status != SL_STATUS_OK) {
    sl_log_error(
      LOG_TAG,
      "Can't get credential type value. Not sending Credential Checksum Get.");
    return SL_STATUS_NOT_SUPPORTED;
  }

  ZW_CREDENTIAL_CHECKSUM_GET_FRAME *get_frame
    = (ZW_CREDENTIAL_CHECKSUM_GET_FRAME *)frame;
  get_frame->cmdClass       = COMMAND_CLASS_USER_CREDENTIAL;
  get_frame->cmd            = CREDENTIAL_CHECKSUM_GET;
  get_frame->credentialType = credential_type;

  *frame_length = sizeof(ZW_CREDENTIAL_CHECKSUM_GET_FRAME);

  return SL_STATUS_OK;
}

sl_status_t
  zwave_command_class_user_credential_credential_checksum_handle_report(
    const zwave_controller_connection_info_t *connection_info,
    const uint8_t *frame_data,
    uint16_t frame_length)
{
  constexpr uint8_t EXPECTED_FRAME_LENGTH = 5;
  if (frame_length != EXPECTED_FRAME_LENGTH) {
    sl_log_error(LOG_TAG,
                 "CREDENTIAL_CHECKSUM_REPORT frame length is not "
                 "valid. Expected %d, got %d",
                 EXPECTED_FRAME_LENGTH,
                 frame_length);
    return SL_STATUS_NOT_SUPPORTED;
  }

  constexpr uint8_t INDEX_CREDENTIAL_TYPE = 2;
  constexpr uint8_t INDEX_USER_CHECKSUM   = 3;

  attribute_store_node_t endpoint_node
    = zwave_command_class_get_endpoint_node(connection_info);

  // Interpret frame
  const user_credential_type_t credential_type
    = frame_data[INDEX_CREDENTIAL_TYPE];
  const user_credential_checksum_t credential_checksum
    = get_uint16_value(frame_data, INDEX_USER_CHECKSUM);

  sl_log_debug(LOG_TAG,
               "Credential Checksum Report. Credential type: %d / "
               "Checksum: 0x%X",
               credential_type,
               credential_checksum);

  attribute_store_node_t credential_type_node
    = attribute_store_get_node_child_by_value(
      endpoint_node,
      ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE),
      REPORTED_ATTRIBUTE,
      (uint8_t *)&credential_type,
      sizeof(credential_type),
      0);

  if (!attribute_store_node_exists(credential_type_node)) {
    sl_log_error(
      LOG_TAG,
      "Can't find Credential Type %d reported by Credential Checksum "
      "Report",
      credential_type);
    return SL_STATUS_NOT_SUPPORTED;
  }

  // Set reported value
  attribute_store_set_child_reported(credential_type_node,
                                     ATTRIBUTE(CREDENTIAL_CHECKSUM),
                                     &credential_checksum,
                                     sizeof(credential_checksum));

  // Compute checksum ourselves to see if it matches
  std::vector<uint8_t> checksum_data;

  auto credential_type_nodes
    = get_all_credential_type_nodes(endpoint_node, credential_type);
  for (auto credential_type_node: credential_type_nodes) {
    auto credential_slot_node_count
      = attribute_store_get_node_child_count_by_type(
        credential_type_node,
        ATTRIBUTE(CREDENTIAL_SLOT));

    for (size_t slot_index = 0; slot_index < credential_slot_node_count;
         slot_index++) {
      attribute_store_node_t credential_slot_node
        = attribute_store_get_node_child_by_type(credential_type_node,
                                                 ATTRIBUTE(CREDENTIAL_SLOT),
                                                 slot_index);
      // We don't have all the data for this slot, skipping it.
      if (!attribute_store_is_reported_defined(credential_slot_node)) {
        sl_log_debug(
          LOG_TAG,
          "Credential Slot #%d is not defined. Not adding to checksum.",
          slot_index);
        continue;
      }

      // Add credential slot to checksum
      if (!add_node_to_checksum(checksum_data, credential_slot_node)) {
        return SL_STATUS_FAIL;
      }

      auto credential_data_node
        = attribute_store_get_first_child_by_type(credential_slot_node,
                                                  ATTRIBUTE(CREDENTIAL_DATA));

      // Add credential data to checksum
      if (!add_node_to_checksum(checksum_data, credential_data_node)) {
        return SL_STATUS_FAIL;
      }
    }
  }

  user_credential_checksum_t computed_checksum
    = compute_checksum_and_verify_integrity(
      credential_type_node,
      ATTRIBUTE(CREDENTIAL_CHECKSUM_MISMATCH_ERROR),
      checksum_data,
      credential_checksum);

  if (computed_checksum != credential_checksum) {
    sl_log_error(
      LOG_TAG,
      "Checksum mismatch for credential type %d. Expected 0x%X, got 0x%X",
      credential_type,
      credential_checksum,
      computed_checksum);
    return SL_STATUS_FAIL;
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Post interview actions
/////////////////////////////////////////////////////////////////////////////
void zwave_network_status_changed(attribute_store_node_t updated_node,
                                  attribute_store_change_t change)
{
  attribute_store_node_t node_id_node
    = attribute_store_get_first_parent_with_type(updated_node,
                                                 ATTRIBUTE_NODE_ID);

  zwave_node_id_t node_id;
  attribute_store_get_reported(node_id_node, &node_id, sizeof(node_id));

  // If we are updating the zpc node or if we trying to delete the attribute we don't want to do anything
  if (change == ATTRIBUTE_DELETED || get_zpc_node_id_node() == node_id_node) {
    return;
  }

  NodeStateNetworkStatus network_status;
  sl_status_t reported_value_status
    = attribute_store_get_reported(updated_node,
                                   &network_status,
                                   sizeof(network_status));

  // If the endpoint report is marked as ONLINE_FUNCTIONAL
  if (reported_value_status == SL_STATUS_OK
      && network_status == ZCL_NODE_STATE_NETWORK_STATUS_ONLINE_FUNCTIONAL) {
    sl_log_debug(LOG_TAG,
                 "Node %d is now ONLINE_FUNCTIONAL : start the delayed "
                 "interview process",
                 node_id);
    // Perform action on each endpoint that supports User Credential Command class
    uint8_t endpoint_count
      = attribute_store_get_node_child_count_by_type(node_id_node,
                                                     ATTRIBUTE_ENDPOINT_ID);

    sl_log_debug(LOG_TAG, "Checking endpoints (total : %d)...", endpoint_count);

    for (uint8_t i = 0; i < endpoint_count; i++) {
      // Get current endpoint node
      attribute_store_node_t endpoint_node
        = attribute_store_get_node_child_by_type(node_id_node,
                                                 ATTRIBUTE_ENDPOINT_ID,
                                                 i);

      zwave_endpoint_id_t endpoint_id;
      attribute_store_get_reported(endpoint_node,
                                   &endpoint_id,
                                   sizeof(endpoint_id));
      // Check if the endpoint supports User Credential Command class
      if (zwave_node_supports_command_class(COMMAND_CLASS_USER_CREDENTIAL,
                                            node_id,
                                            endpoint_id)) {
        auto user_count = attribute_store_get_node_child_count_by_type(
          endpoint_node,
          ATTRIBUTE(USER_UNIQUE_ID));
        sl_log_debug(LOG_TAG,
                     "Endpoint %d supports User Credential.",
                     endpoint_id);
        if (user_count == 0) {
          sl_log_debug(LOG_TAG,
                       "No user found. Starting User and Credential interview");
          // Start the interview process with user ID = 0
          trigger_get_user(endpoint_node, 0);
        } else {
          sl_log_debug(LOG_TAG, "Users already discovered. No actions needed.");
        }
      }
    }
  }
}

/////////////////////////////////////////////////////////////////////////////
// Exposed class functions
/////////////////////////////////////////////////////////////////////////////

sl_status_t zwave_command_class_user_credential_add_new_user(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t user_type,
  user_credential_rule_t credential_rule,
  user_credential_user_active_state_t user_active_state,
  user_credential_expiring_timeout_minutes_t expiring_timeout,
  user_credential_user_name_encoding_t user_name_encoding,
  const char *user_name)
{
  // Check user id
  if (user_id == 0) {
    sl_log_error(LOG_TAG, "User ID 0 is reserved. Not adding user.");
    return SL_STATUS_FAIL;
  }

  // Check if the user already exists
  attribute_store_node_t user_id_node
    = get_reported_user_id_node(endpoint_node, user_id);

  // Node already exists, can't create user.
  if (attribute_store_node_exists(user_id_node)) {
    sl_log_error(LOG_TAG,
                 "User with ID %d already exists. Not adding user.",
                 user_id);
    return SL_STATUS_FAIL;
  }
  // Debug info
  sl_log_debug(
    LOG_TAG,
    "zwave_command_class_user_credential_add_new_user called with : ");
  sl_log_debug(LOG_TAG, "\tuser_id : %d", user_id);
  sl_log_debug(LOG_TAG, "\tuser_type : %d", user_type);
  sl_log_debug(LOG_TAG, "\tcredential_rule : %d", credential_rule);
  sl_log_debug(LOG_TAG, "\tuser_active_state : %d", user_active_state);
  sl_log_debug(LOG_TAG, "\texpiring_timeout : %d", expiring_timeout);
  sl_log_debug(LOG_TAG, "\tuser_name_encoding : %d", user_name_encoding);
  sl_log_debug(LOG_TAG, "\tuser_name : %s", user_name);

  // Check capabilites
  user_capabilities capabilites = get_user_capabilities(endpoint_node);
  if (!capabilites.is_user_valid(user_id,
                                 user_type,
                                 credential_rule,
                                 user_name)) {
    sl_log_error(LOG_TAG, "User capabilities are not valid. Not adding user.");
    return SL_STATUS_FAIL;
  }

  // Create the user node
  user_id_node = attribute_store_emplace_desired(endpoint_node,
                                                 ATTRIBUTE(USER_UNIQUE_ID),
                                                 &user_id,
                                                 sizeof(user_id));

  attribute_store_emplace_desired(user_id_node,
                                  ATTRIBUTE(USER_TYPE),
                                  &user_type,
                                  sizeof(user_type));

  attribute_store_emplace_desired(user_id_node,
                                  ATTRIBUTE(CREDENTIAL_RULE),
                                  &credential_rule,
                                  sizeof(credential_rule));

  attribute_store_emplace_desired(user_id_node,
                                  ATTRIBUTE(USER_ACTIVE_STATE),
                                  &user_active_state,
                                  sizeof(user_active_state));

  if (user_type != USER_CREDENTIAL_USER_TYPE_EXPIRING_USER) {
    if (expiring_timeout != 0) {
      sl_log_warning(
        LOG_TAG,
        "Expiring timeout set for non-expiring user, set value to 0.");
    }
    expiring_timeout = 0;
  }

  attribute_store_emplace_desired(user_id_node,
                                  ATTRIBUTE(USER_EXPIRING_TIMEOUT_MINUTES),
                                  &expiring_timeout,
                                  sizeof(expiring_timeout));

  attribute_store_emplace_desired(user_id_node,
                                  ATTRIBUTE(USER_NAME_ENCODING),
                                  &user_name_encoding,
                                  sizeof(user_name_encoding));
  // User name node
  auto user_name_node
    = attribute_store_add_node(ATTRIBUTE(USER_NAME), user_id_node);
  attribute_store_set_desired_string(user_name_node, user_name);

  // Finally set operation type add
  set_user_operation_type(user_id_node, USER_CREDENTIAL_OPERATION_TYPE_ADD);

  sl_log_debug(LOG_TAG, "Add user with ID %d", user_id);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_delete_user(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id)
{
  // Check if the user exists
  attribute_store_node_t user_id_node
    = get_reported_user_id_node(endpoint_node, user_id);

  // Node doesn't exists, can't delete user.
  if (!attribute_store_node_exists(user_id_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find user with ID %d. Not deleting user.",
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Finally set operation type delete
  set_user_operation_type(user_id_node, USER_CREDENTIAL_OPERATION_TYPE_DELETE);

  sl_log_debug(LOG_TAG, "Remove user with ID %d", user_id);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_modify_user(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t user_type,
  user_credential_rule_t credential_rule,
  user_credential_user_active_state_t user_active_state,
  user_credential_expiring_timeout_minutes_t expiring_timeout,
  user_credential_user_name_encoding_t user_name_encoding,
  const char *user_name)
{
  // Check user id
  if (user_id == 0) {
    sl_log_error(LOG_TAG, "User ID 0 is reserved. Can't modify user.");
    return SL_STATUS_FAIL;
  }

  // Check if the user already exists
  attribute_store_node_t user_id_node
    = get_reported_user_id_node(endpoint_node, user_id);

  // Node already exists, can't create user.
  if (!attribute_store_node_exists(user_id_node)) {
    sl_log_error(LOG_TAG,
                 "User with ID %d doesn't exists. Can't modify user.",
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Debug info
  sl_log_debug(
    LOG_TAG,
    "zwave_command_class_user_credential_modify_user called with : ");
  sl_log_debug(LOG_TAG, "\tuser_id : %d", user_id);
  sl_log_debug(LOG_TAG, "\tuser_type : %d", user_type);
  sl_log_debug(LOG_TAG, "\tcredential_rule : %d", credential_rule);
  sl_log_debug(LOG_TAG, "\tuser_active_state : %d", user_active_state);
  sl_log_debug(LOG_TAG, "\texpiring_timeout : %d", expiring_timeout);
  sl_log_debug(LOG_TAG, "\tuser_name_encoding : %d", user_name_encoding);
  sl_log_debug(LOG_TAG, "\tuser_name : %s", user_name);

  // Check capabilites
  user_capabilities capabilites = get_user_capabilities(endpoint_node);
  if (!capabilites.is_user_valid(user_id,
                                 user_type,
                                 credential_rule,
                                 user_name)) {
    sl_log_error(LOG_TAG, "User capabilities are not valid. Not adding user.");
    return SL_STATUS_FAIL;
  }

  std::map<attribute_store_type_t, std::pair<const void *, uint8_t>> values = {
    {ATTRIBUTE(USER_TYPE), {&user_type, sizeof(user_type)}},
    {ATTRIBUTE(CREDENTIAL_RULE), {&credential_rule, sizeof(credential_rule)}},
    {ATTRIBUTE(USER_ACTIVE_STATE),
     {&user_active_state, sizeof(user_active_state)}},
    {ATTRIBUTE(USER_NAME_ENCODING),
     {&user_name_encoding, sizeof(user_name_encoding)}},
    {ATTRIBUTE(USER_NAME), {user_name, sizeof(user_name)}},
  };

  // Only add expiring timeout if user is expiring
  if (user_type == USER_CREDENTIAL_USER_TYPE_EXPIRING_USER) {
    values.insert({ATTRIBUTE(USER_EXPIRING_TIMEOUT_MINUTES),
                   {&expiring_timeout, sizeof(expiring_timeout)}});
  }

  // Update values based on the map
  sl_status_t status = update_desired_values(user_id_node, values);
  // If everything went well set operation type to modify
  if (status == SL_STATUS_OK) {
    set_user_operation_type(user_id_node,
                            USER_CREDENTIAL_OPERATION_TYPE_MODIFY);
    sl_log_debug(LOG_TAG, "Modify user with ID %d", user_id);
  } else {
    sl_log_error(LOG_TAG, "Can't modify user with ID %d", user_id);
  }

  return status;
}

/**
 * @brief Convert credential data str to a vector of uint8_t
 * 
 * @note CC:0083.01.0A.11.021 Passwords MUST be transmitted in Unicode UTF-16 format, in big endian order
 * 
 * @param credential_data Credential data to convert
 * @param credential_type Credential type
 * @param credential_data_vector Vector to store the converted data
 * 
 * @return SL_STATUS_OK if the conversion was successful, SL_STATUS_FAIL otherwise
*/
sl_status_t get_credential_data(const char *credential_data,
                                user_credential_type_t credential_type,
                                std::vector<uint8_t> &credential_data_vector)
{
  std::string credential_data_str(credential_data);
  switch (credential_type) {
    case CREDENTIAL_REPORT_PASSWORD: {
      // CC:0083.01.0A.11.021 Passwords MUST be transmitted in Unicode UTF-16 format, in big endian order
      try {
        auto credential_data_utf16 = utf8_to_utf16(credential_data_str);
        for (const auto &c: credential_data_utf16) {
          credential_data_vector.push_back((uint8_t)(c >> 8));
          credential_data_vector.push_back((uint8_t)c);
        }
      } catch (const std::exception &e) {
        sl_log_error(LOG_TAG,
                     "Error while converting credential data to UTF16: %s",
                     e.what());
        return SL_STATUS_FAIL;
      }
    } break;
    case CREDENTIAL_REPORT_PIN_CODE:
      for (const auto &c: credential_data_str) {
        if (c < '0' || c > '9') {
          sl_log_error(LOG_TAG,
                       "Invalid character in PIN code: %c. Only digits are "
                       "allowed.",
                       c);
          return SL_STATUS_FAIL;
        }
        credential_data_vector.push_back(c);
      }
      break;
    default:
      for (const auto &c: credential_data_str) {
        credential_data_vector.push_back(c);
      }
  }

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_add_new_credential(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t credential_type,
  user_credential_slot_t credential_slot,
  const char *credential_data)
{
  // Check if parameters are ok
  if (credential_type == 0 || credential_slot == 0) {
    sl_log_error(
      LOG_TAG,
      "Credential Type and Slot 0 are reserved. Not adding credentials.");
    return SL_STATUS_FAIL;
  }

  auto capabilities
    = get_credential_capabilities(endpoint_node, credential_type);

  if (!capabilities.is_slot_valid(credential_slot)) {
    sl_log_error(LOG_TAG,
                 "Credential slot %d for Credential Type %d is not valid. "
                 "Not adding credentials.",
                 credential_slot,
                 credential_type);
    return SL_STATUS_FAIL;
  }

  // Create or update existing structure
  attribute_store_node_t credential_type_node = ATTRIBUTE_STORE_INVALID_NODE;
  attribute_store_node_t credential_slot_node = ATTRIBUTE_STORE_INVALID_NODE;

  if (!is_credential_available(endpoint_node,
                               credential_type,
                               credential_slot)) {
    sl_log_error(LOG_TAG,
                 "Credential slot %d for Credential Type %d already exists."
                 "Not adding credentials.",
                 credential_slot,
                 credential_type);
    return SL_STATUS_FAIL;
  }

  attribute_store::attribute user_id_node;
  try {
    user_id_node = get_reported_user_id_node(endpoint_node, user_id);
  } catch (const std::exception &e) {
    sl_log_error(LOG_TAG,
                 "Can't find User %d. Not adding credentials.",
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Get or create credential type node
  credential_type_node
    = user_id_node.emplace_node(ATTRIBUTE(CREDENTIAL_TYPE), credential_type);

  // Debug info
  sl_log_debug(
    LOG_TAG,
    "zwave_command_class_user_credential_add_new_credential called with : ");
  sl_log_debug(LOG_TAG, "\tuser_id : %d", user_id);
  sl_log_debug(LOG_TAG, "\tcredential_type : %d", credential_type);
  sl_log_debug(LOG_TAG, "\tcredential_slot : %d", credential_slot);
  sl_log_debug(LOG_TAG, "\tcredential_data : %s", credential_data);

  // Process credential data
  std::vector<uint8_t> credential_data_vector;
  sl_status_t credential_data_conversion_status
    = get_credential_data(credential_data,
                          credential_type,
                          credential_data_vector);
  // Something went wrong, we need to delete the slot
  if (credential_data_conversion_status == SL_STATUS_FAIL) {
    return SL_STATUS_FAIL;
  }

  if (!capabilities.is_credential_valid(credential_type,
                                        credential_slot,
                                        credential_data_vector)) {
    sl_log_error(
      LOG_TAG,
      "Credential capabilities are not valid. Not adding credential.");
    return SL_STATUS_FAIL;
  }

  // Create credential slot
  credential_slot_node
    = attribute_store_emplace_desired(credential_type_node,
                                      ATTRIBUTE(CREDENTIAL_SLOT),
                                      &credential_slot,
                                      sizeof(credential_slot));

  // Add data
  attribute_store_emplace_desired(credential_slot_node,
                                  ATTRIBUTE(CREDENTIAL_DATA),
                                  credential_data_vector.data(),
                                  credential_data_vector.size());

  // Finally set operation type add
  set_credential_operation_type(credential_slot_node,
                                USER_CREDENTIAL_OPERATION_TYPE_ADD);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_modify_credential(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t credential_type,
  user_credential_slot_t credential_slot,
  const char *credential_data)
{
  // Get credential structure
  attribute_store_node_t credential_type_node = ATTRIBUTE_STORE_INVALID_NODE;
  attribute_store_node_t credential_slot_node = ATTRIBUTE_STORE_INVALID_NODE;

  // First check Credential Type existence
  bool node_found = get_credential_type_node(endpoint_node,
                                             user_id,
                                             credential_type,
                                             REPORTED_ATTRIBUTE,
                                             credential_type_node);
  if (!node_found) {
    sl_log_error(
      LOG_TAG,
      "Can't find Credential Type %d for User %d. Not modifing credentials.",
      credential_type,
      user_id);
    return SL_STATUS_FAIL;
  }

  node_found = get_credential_slot_node(credential_type_node,
                                        credential_slot,
                                        REPORTED_ATTRIBUTE,
                                        credential_slot_node);

  if (!node_found) {
    sl_log_error(LOG_TAG,
                 "Can't find Credential Slot %d for Credential Type %d (User "
                 "%d). Not modifing credentials.",
                 credential_slot,
                 credential_type,
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Debug info
  sl_log_debug(
    LOG_TAG,
    "zwave_command_class_user_credential_modify_credential called with : ");
  sl_log_debug(LOG_TAG, "\tuser_id : %d", user_id);
  sl_log_debug(LOG_TAG, "\tcredential_type : %d", credential_type);
  sl_log_debug(LOG_TAG, "\tcredential_slot : %d", credential_slot);
  sl_log_debug(LOG_TAG, "\tcredential_data : %s", credential_data);

  // Process credential data
  std::vector<uint8_t> credential_data_vector;
  sl_status_t credential_data_conversion_status
    = get_credential_data(credential_data,
                          credential_type,
                          credential_data_vector);
  // Something went wrong, we don't modify
  if (credential_data_conversion_status == SL_STATUS_FAIL) {
    sl_log_error(LOG_TAG,
                 "Something went wrong while processing credential data. Not "
                 "modifying credentials.");
    return SL_STATUS_FAIL;
  }

  // Verify credential validity
  auto capabilities
    = get_credential_capabilities(endpoint_node, credential_type);
  if (!capabilities.is_credential_valid(credential_type,
                                        credential_slot,
                                        credential_data_vector)) {
    sl_log_error(
      LOG_TAG,
      "Credential capabilities are not valid. Not adding credential.");
    return SL_STATUS_FAIL;
  }

  // Add data
  sl_status_t status
    = attribute_store_set_child_desired(credential_slot_node,
                                        ATTRIBUTE(CREDENTIAL_DATA),
                                        credential_data_vector.data(),
                                        credential_data_vector.size());
  if (status != SL_STATUS_OK) {
    sl_log_error(LOG_TAG,
                 "Can't set CREDENTIAL_DATA in attribute store. Not modifying "
                 "credential.");
    return SL_STATUS_FAIL;
  }

  // Finally set operation type modify
  set_credential_operation_type(credential_slot_node,
                                USER_CREDENTIAL_OPERATION_TYPE_MODIFY);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_delete_credential(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t credential_type,
  user_credential_slot_t credential_slot)
{
  // First see if the user exists
  auto user_id_node = get_reported_user_id_node(endpoint_node, user_id);
  if (!attribute_store_node_exists(user_id_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find user with ID %d. Not adding credentials.",
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Get credential structure
  attribute_store_node_t credential_type_node = ATTRIBUTE_STORE_INVALID_NODE;
  attribute_store_node_t credential_slot_node = ATTRIBUTE_STORE_INVALID_NODE;

  // First check Credential Type existence
  bool node_found = get_credential_type_node(endpoint_node,
                                             user_id,
                                             credential_type,
                                             REPORTED_ATTRIBUTE,
                                             credential_type_node);
  if (!node_found) {
    sl_log_error(
      LOG_TAG,
      "Can't find Credential Type %d for User %d. Not deleting credentials.",
      credential_type,
      user_id);
    return SL_STATUS_FAIL;
  }

  node_found = get_credential_slot_node(credential_type_node,
                                        credential_slot,
                                        REPORTED_ATTRIBUTE,
                                        credential_slot_node);

  if (!node_found) {
    sl_log_error(LOG_TAG,
                 "Can't find Credential Slot %d for Credential Type %d (User "
                 "%d). Not deleting credentials.",
                 credential_slot,
                 credential_type,
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Finally set operation type delete
  set_credential_operation_type(credential_slot_node,
                                USER_CREDENTIAL_OPERATION_TYPE_DELETE);
  sl_log_debug(LOG_TAG,
               "Delete credential slot %d (credential type %d, user id %d)",
               credential_slot,
               credential_type,
               user_id);
  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_delete_all_users(
  attribute_store_node_t endpoint_node)
{
  // Send an User SET with user id = 0
  user_credential_user_unique_id_t user_id = 0;
  attribute_store_node_t user_id_node
    = attribute_store_emplace(endpoint_node,
                              ATTRIBUTE(USER_UNIQUE_ID),
                              &user_id,
                              sizeof(user_id));

  // Finally set operation type delete
  set_user_operation_type(user_id_node, USER_CREDENTIAL_OPERATION_TYPE_DELETE);

  sl_log_debug(LOG_TAG,
               "Delete all user operation received. Creating user with id %d "
               "to send a User SET.",
               user_id);
  return SL_STATUS_OK;
}

void trigger_credential_deletion(attribute_store_node_t endpoint_node,
                                 user_credential_user_unique_id_t user_id,
                                 user_credential_type_t credential_type,
                                 user_credential_slot_t credential_slot)
{
  attribute_store_node_t user_id_node
    = attribute_store_emplace(endpoint_node,
                              ATTRIBUTE(USER_UNIQUE_ID),
                              &user_id,
                              sizeof(user_id));
  attribute_store_node_t credential_type_node
    = attribute_store_emplace(user_id_node,
                              ATTRIBUTE(CREDENTIAL_TYPE),
                              &credential_type,
                              sizeof(credential_type));
  attribute_store_node_t credential_slot_node
    = attribute_store_emplace(credential_type_node,
                              ATTRIBUTE(CREDENTIAL_SLOT),
                              &credential_slot,
                              sizeof(credential_slot));

  // Finally set operation type delete
  set_credential_operation_type(credential_slot_node,
                                USER_CREDENTIAL_OPERATION_TYPE_DELETE);

  sl_log_debug(LOG_TAG,
               "Creating user with id %d, credential type %d and slot "
               "both to %d to send a Credential SET.",
               user_id,
               credential_type,
               credential_slot);
}

sl_status_t zwave_command_class_user_credential_delete_all_credentials(
  attribute_store_node_t endpoint_node)
{
  sl_log_debug(LOG_TAG, "Delete all credential operation received");

  trigger_credential_deletion(endpoint_node, 0, 0, 0);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_delete_all_credentials_by_type(
  attribute_store_node_t endpoint_node, user_credential_type_t credential_type)
{
  sl_log_debug(LOG_TAG,
               "Delete all credential of type %d operation received",
               credential_type);

  trigger_credential_deletion(endpoint_node, 0, credential_type, 0);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_delete_all_credentials_for_user(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id)
{
  sl_log_debug(LOG_TAG,
               "Delete all credential for user %d operation received",
               user_id);

  trigger_credential_deletion(endpoint_node, user_id, 0, 0);

  return SL_STATUS_OK;
}

sl_status_t
  zwave_command_class_user_credential_delete_all_credentials_for_user_by_type(
    attribute_store_node_t endpoint_node,
    user_credential_user_unique_id_t user_id,
    user_credential_type_t credential_type)
{
  sl_log_debug(LOG_TAG,
               "Delete all credential for user %d and credential type %d "
               "operation received",
               user_id,
               credential_type);

  trigger_credential_deletion(endpoint_node, user_id, credential_type, 0);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_credential_learn_start_add(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t credential_type,
  user_credential_slot_t credential_slot,
  user_credential_learn_timeout_t credential_learn_timeout)
{
  auto credential_capabilities
    = get_credential_capabilities(endpoint_node, credential_type);

  if (!credential_capabilities.is_learn_supported()) {
    sl_log_error(LOG_TAG,
                 "Learn is not supported for credential type %d. Not starting "
                 "learn process.",
                 credential_type);
    return SL_STATUS_FAIL;
  }

  if (!credential_capabilities.is_slot_valid(credential_slot)) {
    sl_log_error(LOG_TAG,
                 "Credential slot %d is not valid for Credential Type %d. Not "
                 "starting learn process.",
                 credential_slot,
                 credential_type);
    return SL_STATUS_FAIL;
  }

  // Check parameters values
  if (credential_type == 0 || credential_slot == 0) {
    sl_log_error(
      LOG_TAG,
      "Credential Type and Slot 0 are reserved. Not adding credentials.");
    return SL_STATUS_FAIL;
  }

  // Create or update existing structure
  attribute_store_node_t credential_type_node = ATTRIBUTE_STORE_INVALID_NODE;
  attribute_store_node_t credential_slot_node = ATTRIBUTE_STORE_INVALID_NODE;

  if (!is_credential_available(endpoint_node,
                               credential_type,
                               credential_slot)) {
    sl_log_error(LOG_TAG,
                 "Credential slot %d for Credential Type %d already exists."
                 "Not adding credentials.",
                 credential_slot,
                 credential_type);
    return SL_STATUS_FAIL;
  }

  // Get or add credential type node
  credential_type_node = add_credential_type_node_if_missing(endpoint_node,
                                                             user_id,
                                                             credential_type);

  if (!attribute_store_node_exists(credential_type_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find Credential Type %d for User %d. Not adding "
                 "credentials.",
                 credential_type,
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Debug info
  sl_log_debug(
    LOG_TAG,
    "zwave_command_class_user_credential_credential_learn_start (Add)"
    " called with : ");
  sl_log_debug(LOG_TAG, "\tuser_id : %d", user_id);
  sl_log_debug(LOG_TAG, "\tcredential_type : %d", credential_type);
  sl_log_debug(LOG_TAG, "\tcredential_slot : %d", credential_slot);
  sl_log_debug(LOG_TAG,
               "\tcredential_learn_timeout : %d",
               credential_learn_timeout);

  if (credential_learn_timeout == 0) {
    credential_learn_timeout
      = credential_capabilities.learn_recommended_timeout;
    sl_log_debug(LOG_TAG,
                 "Credential learn timeout is 0. Setting it to default "
                 "reported value (%d seconds).",
                 credential_learn_timeout);
  }

  // Create credential slot with reported value since we don't want
  // to trigger a Credential Get right away
  credential_slot_node = attribute_store_emplace(credential_type_node,
                                                 ATTRIBUTE(CREDENTIAL_SLOT),
                                                 &credential_slot,
                                                 sizeof(credential_slot));

  // Set attributes for Credential Learn
  attribute_store_set_child_reported(credential_slot_node,
                                     ATTRIBUTE(CREDENTIAL_LEARN_TIMEOUT),
                                     &credential_learn_timeout,
                                     sizeof(credential_learn_timeout));

  set_credential_learn_operation_type(credential_slot_node,
                                      USER_CREDENTIAL_OPERATION_TYPE_ADD);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_credential_learn_start_modify(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id,
  user_credential_type_t credential_type,
  user_credential_slot_t credential_slot,
  user_credential_learn_timeout_t credential_learn_timeout)
{
  auto credential_capabilities
    = get_credential_capabilities(endpoint_node, credential_type);

  if (!credential_capabilities.is_learn_supported()) {
    sl_log_error(LOG_TAG,
                 "Learn is not supported for credential type %d. Not starting "
                 "learn process.",
                 credential_type);
    return SL_STATUS_FAIL;
  }

  // Check parameters values
  if (credential_type == 0 || credential_slot == 0) {
    sl_log_error(
      LOG_TAG,
      "Credential Type and Slot 0 are reserved. Not adding credentials.");
    return SL_STATUS_FAIL;
  }

  // Get current structure
  attribute_store_node_t credential_type_node = ATTRIBUTE_STORE_INVALID_NODE;
  attribute_store_node_t credential_slot_node = ATTRIBUTE_STORE_INVALID_NODE;

  get_credential_type_node(endpoint_node,
                           user_id,
                           credential_type,
                           REPORTED_ATTRIBUTE,
                           credential_type_node);
  get_credential_slot_node(credential_type_node,
                           credential_slot,
                           REPORTED_ATTRIBUTE,
                           credential_slot_node);

  if (!attribute_store_node_exists(credential_type_node)
      || !attribute_store_node_exists(credential_slot_node)) {
    sl_log_error(LOG_TAG,
                 "Can't find Credential Type %d for User %d. Not adding "
                 "credentials.",
                 credential_type,
                 user_id);
    return SL_STATUS_FAIL;
  }

  // Debug info
  sl_log_debug(
    LOG_TAG,
    "zwave_command_class_user_credential_credential_learn_start (modify) "
    "called with : ");
  sl_log_debug(LOG_TAG, "\tuser_id : %d", user_id);
  sl_log_debug(LOG_TAG, "\tcredential_type : %d", credential_type);
  sl_log_debug(LOG_TAG, "\tcredential_slot : %d", credential_slot);
  sl_log_debug(LOG_TAG,
               "\tcredential_learn_timeout : %d",
               credential_learn_timeout);

  if (credential_learn_timeout == 0) {
    credential_learn_timeout
      = credential_capabilities.learn_recommended_timeout;
    sl_log_debug(LOG_TAG,
                 "Credential learn timeout is 0. Setting it to default "
                 "reported value (%d seconds).",
                 credential_learn_timeout);
  }

  // Set attributes for Credential Learn
  attribute_store_set_child_reported(credential_slot_node,
                                     ATTRIBUTE(CREDENTIAL_LEARN_TIMEOUT),
                                     &credential_learn_timeout,
                                     sizeof(credential_learn_timeout));

  set_credential_learn_operation_type(credential_slot_node,
                                      USER_CREDENTIAL_OPERATION_TYPE_MODIFY);

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_credential_learn_stop(
  attribute_store_node_t endpoint_node)
{
  uint8_t stop_flag = 1;

  return attribute_store_set_child_desired(endpoint_node,
                                           ATTRIBUTE(CREDENTIAL_LEARN_STOP),
                                           &stop_flag,
                                           sizeof(stop_flag));
}

sl_status_t zwave_command_class_user_credential_uuic_association_set(
  attribute_store_node_t endpoint_node,
  user_credential_type_t credential_type,
  user_credential_user_unique_id_t source_user_id,
  user_credential_slot_t source_credential_slot,
  user_credential_user_unique_id_t destination_user_id,
  user_credential_slot_t destination_credential_slot)
{
  attribute_store_node_t source_user_id_node;
  bool user_exists = get_user_id_node(endpoint_node,
                                      source_user_id,
                                      REPORTED_ATTRIBUTE,
                                      source_user_id_node);
  if (!user_exists) {
    sl_log_error(
      LOG_TAG,
      "Can't find source user with ID %d. Not adding uuic association set.",
      source_user_id);
    return SL_STATUS_FAIL;
  }

  attribute_store_node_t credential_type_node;
  bool cred_type_exists = get_credential_type_node(endpoint_node,
                                                   source_user_id,
                                                   credential_type,
                                                   REPORTED_ATTRIBUTE,
                                                   credential_type_node);

  if (!cred_type_exists) {
    sl_log_error(LOG_TAG,
                 "Can't find credential type %d for user %d. Not adding uuic "
                 "association set.",
                 credential_type,
                 source_user_id);
    return SL_STATUS_FAIL;
  }

  attribute_store_node_t source_credential_slot_node;
  bool cred_slot_exists = get_credential_slot_node(credential_type_node,
                                                   source_credential_slot,
                                                   REPORTED_ATTRIBUTE,
                                                   source_credential_slot_node);

  if (!cred_slot_exists) {
    sl_log_error(LOG_TAG,
                 "Can't find source credential slot %d for credential type %d. "
                 "Not adding uuic association set.",
                 source_credential_slot,
                 credential_type);
    return SL_STATUS_FAIL;
  }

  attribute_store_emplace_desired(source_credential_slot_node,
                                  ATTRIBUTE(ASSOCIATION_DESTINATION_USER_ID),
                                  &destination_user_id,
                                  sizeof(destination_user_id));

  // Slot ID last since it's this attribute that is bound to the SET command
  attribute_store_emplace_desired(
    source_credential_slot_node,
    ATTRIBUTE(ASSOCIATION_DESTINATION_CREDENTIAL_SLOT),
    &destination_credential_slot,
    sizeof(destination_credential_slot));

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_get_user_checksum(
  attribute_store_node_t endpoint_node,
  user_credential_user_unique_id_t user_id)
{
  attribute_store_node_t user_id_node;
  bool user_exists = get_user_id_node(endpoint_node,
                                      user_id,
                                      REPORTED_ATTRIBUTE,
                                      user_id_node);
  if (!user_exists) {
    sl_log_error(
      LOG_TAG,
      "Can't find source user with ID %d. Not setting up User Checksum Get.",
      user_id_node);
    return SL_STATUS_FAIL;
  }

  auto checksum_node
    = attribute_store_get_first_child_by_type(user_id_node,
                                              ATTRIBUTE(USER_CHECKSUM));

  // If node already exists, we clear its value to trigger the GET
  if (attribute_store_node_exists(checksum_node)) {
    attribute_store_undefine_reported(checksum_node);
    attribute_store_undefine_desired(checksum_node);
  } else {
    attribute_store_add_node(ATTRIBUTE(USER_CHECKSUM), user_id_node);
  }

  return SL_STATUS_OK;
}

sl_status_t zwave_command_class_user_credential_get_credential_checksum(
  attribute_store_node_t endpoint_node, user_credential_type_t credential_type)
{
  attribute_store_node_t supported_credential_type_node
    = attribute_store_get_node_child_by_value(
      endpoint_node,
      ATTRIBUTE(SUPPORTED_CREDENTIAL_TYPE),
      REPORTED_ATTRIBUTE,
      &credential_type,
      sizeof(credential_type),
      0);

  if (!attribute_store_node_exists(supported_credential_type_node)) {
    sl_log_error(
      LOG_TAG,
      "Can't find supported credential type %d. Not setting up Checksum get.",
      credential_type);
    return SL_STATUS_FAIL;
  }

  auto checksum_node
    = attribute_store_get_first_child_by_type(supported_credential_type_node,
                                              ATTRIBUTE(CREDENTIAL_CHECKSUM));

  // If node already exists, we clear its value to trigger the GET
  if (attribute_store_node_exists(checksum_node)) {
    attribute_store_undefine_reported(checksum_node);
    attribute_store_undefine_desired(checksum_node);
  } else {
    attribute_store_add_node(ATTRIBUTE(CREDENTIAL_CHECKSUM),
                             supported_credential_type_node);
  }

  return SL_STATUS_OK;
}

/////////////////////////////////////////////////////////////////////////////
// Class logic
/////////////////////////////////////////////////////////////////////////////

// Control handler
sl_status_t zwave_command_class_user_credential_control_handler(
  const zwave_controller_connection_info_t *connection_info,
  const uint8_t *frame_data,
  uint16_t frame_length)
{
  if (frame_length <= COMMAND_INDEX) {
    return SL_STATUS_NOT_SUPPORTED;
  }

  switch (frame_data[COMMAND_INDEX]) {
    case USER_CAPABILITIES_REPORT:
      return zwave_command_class_user_credential_user_capabilities_handle_report(
        connection_info,
        frame_data,
        frame_length);
    case CREDENTIAL_CAPABILITIES_REPORT:
      return zwave_command_class_user_credential_credential_capabilities_handle_report(
        connection_info,
        frame_data,
        frame_length);
    case ALL_USERS_CHECKSUM_REPORT:
      return zwave_command_class_user_credential_all_user_checksum_handle_report(
        connection_info,
        frame_data,
        frame_length);
    case USER_REPORT:
      return zwave_command_class_user_credential_user_handle_report(
        connection_info,
        frame_data,
        frame_length);
    case CREDENTIAL_REPORT:
      return zwave_command_class_user_credential_credential_handle_report(
        connection_info,
        frame_data,
        frame_length);
    case CREDENTIAL_LEARN_REPORT:
      return zwave_command_class_user_credential_credential_learn_status_report(
        connection_info,
        frame_data,
        frame_length);
    case USER_CREDENTIAL_ASSOCIATION_REPORT:
      return zwave_command_class_user_credential_uuic_association_report(
        connection_info,
        frame_data,
        frame_length);
    case USER_CHECKSUM_REPORT:
      return zwave_command_class_user_credential_user_checksum_handle_report(
        connection_info,
        frame_data,
        frame_length);
    case CREDENTIAL_CHECKSUM_REPORT:
      return zwave_command_class_user_credential_credential_checksum_handle_report(
        connection_info,
        frame_data,
        frame_length);
    default:
      return SL_STATUS_NOT_SUPPORTED;
  }
}

// Entry point
sl_status_t zwave_command_class_user_credential_init()
{
  attribute_store_register_callback_by_type(
    &zwave_command_class_user_credential_on_version_attribute_update,
    ATTRIBUTE(VERSION));

  attribute_resolver_register_rule(
    ATTRIBUTE(NUMBER_OF_USERS),
    NULL,
    &zwave_command_class_user_credential_user_capabilities_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(SUPPORT_CREDENTIAL_CHECKSUM),
    NULL,
    &zwave_command_class_user_credential_credential_capabilities_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(ALL_USERS_CHECKSUM),
    NULL,
    &zwave_command_class_user_credential_all_user_checksum_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(USER_UNIQUE_ID),
    NULL,
    &zwave_command_class_user_credential_user_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(USER_OPERATION_TYPE),
    &zwave_command_class_user_credential_user_set,
    NULL);

  attribute_resolver_register_rule(
    ATTRIBUTE(CREDENTIAL_SLOT),
    NULL,
    &zwave_command_class_user_credential_credential_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(CREDENTIAL_OPERATION_TYPE),
    &zwave_command_class_user_credential_credential_set,
    NULL);

  attribute_resolver_register_rule(
    ATTRIBUTE(CREDENTIAL_LEARN_OPERATION_TYPE),
    &zwave_command_class_user_credential_credential_learn_start,
    NULL);

  attribute_resolver_register_rule(
    ATTRIBUTE(CREDENTIAL_LEARN_STOP),
    &zwave_command_class_user_credential_credential_learn_cancel,
    NULL);

  attribute_resolver_register_rule(
    ATTRIBUTE(ASSOCIATION_DESTINATION_CREDENTIAL_SLOT),
    &zwave_command_class_user_credential_uuic_association_set,
    NULL);

  attribute_resolver_register_rule(
    ATTRIBUTE(USER_CHECKSUM),
    NULL,
    &zwave_command_class_user_credential_user_checksum_get);

  attribute_resolver_register_rule(
    ATTRIBUTE(CREDENTIAL_CHECKSUM),
    NULL,
    &zwave_command_class_user_credential_credential_checksum_get);

  // https://github.com/Z-Wave-Alliance/AWG/pull/124#discussion_r1484473752
  // Discussion about delaying the user interview process after the inclusion

  // Proposed Unify-way to delay users get AFTER interview process
  attribute_store_register_callback_by_type(
    &zwave_network_status_changed,
    DOTDOT_ATTRIBUTE_ID_STATE_NETWORK_STATUS);

  zwave_command_handler_t handler = {};
  handler.support_handler         = NULL;
  handler.control_handler = zwave_command_class_user_credential_control_handler;
  // CHECKME : Is this right ?
  handler.minimal_scheme = ZWAVE_CONTROLLER_ENCAPSULATION_SECURITY_2_ACCESS;
  handler.manual_security_validation = false;
  handler.command_class              = COMMAND_CLASS_USER_CREDENTIAL;
  handler.version                    = 1;
  handler.command_class_name         = "User Credential";
  handler.comments                   = "Experimental";

  return zwave_command_handler_register_handler(handler);
}