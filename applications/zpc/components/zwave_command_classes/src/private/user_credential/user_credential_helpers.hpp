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

#ifndef USER_CREDENTIAL_HELPERS_H
#define USER_CREDENTIAL_HELPERS_H

// Get attribute store names
#include "attribute_store_defined_attribute_types.h"
// User credential types
#include "zwave_command_class_user_credential_types.h"

// Cpp
#include "attribute.hpp"
#include "boost/format.hpp"

#include "user_credential_definitions.hpp"

namespace user_credential_helpers
{

using attribute_callback = std::function<void(attribute_store::attribute &)>;

/////////////////////////////////////////////////////////////////////////////
// Data struct
/////////////////////////////////////////////////////////////////////////////

// Represent a credential ID (slot, type, user unique ID)
struct credential_id_nodes {
  attribute_store::attribute slot_node;
  attribute_store::attribute type_node;
  attribute_store::attribute user_unique_id_node;
};

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

/**
 * @brief Create operation_type_node_type if it doesn't exists, and set the desired value to operation_type (and clear reported)
 * 
 * @see set_user_operation_type
 * @see set_credential_operation_type
 * @see set_credential_learn_operation_type
 * 
 * @param base_node Base node to search for the attribute
 * @param operation_type_node_type Type of the operation type node
 * @param operation_type Operation type to set
 *
 */
void set_operation_type(attribute_store::attribute base_node,
                        attribute_store_type_t operation_type_node_type,
                        user_credential_operation_type_t operation_type)
{
  auto operation_type_node = base_node.emplace_node(operation_type_node_type);

  // Undefine reported to be sure that we can so the same operation twice in a row
  operation_type_node.clear_reported();
  operation_type_node.set_desired(operation_type);
}

/**
 * @brief Set User Operation
 * 
 * Set the operation type as desired and clear reported to call SET function
 * 
 * @param user_node User node
 * @param operation_type Operation type to set
 * 
 */
void set_user_operation_type(attribute_store_node_t user_node,
                             user_credential_operation_type_t operation_type)
{
  set_operation_type(
    user_node,
    ATTRIBUTE(USER_OPERATION_TYPE),
    operation_type);
}

/**
 * @brief Set Credential Operation
 * 
 * Set the operation type as desired and clear reported to call SET function
 * 
 * @param slot_node Slot node
 * @param operation_type Operation type to set
 * 
 */
void set_credential_operation_type(
  attribute_store_node_t slot_node,
  user_credential_operation_type_t operation_type)
{
  set_operation_type(slot_node,
                     ATTRIBUTE(CREDENTIAL_OPERATION_TYPE),
                     operation_type);
}

/**
 * @brief Set Credential Learn Operation
 * 
 * Set the operation type as desired and clear reported to call SET function
 * 
 * @param slot_node Slot node
 * @param operation_type Operation type to set
 */
void set_credential_learn_operation_type(
  attribute_store_node_t slot_node,
  user_credential_operation_type_t operation_type)
{
  set_operation_type(slot_node,
                     ATTRIBUTE(CREDENTIAL_LEARN_OPERATION_TYPE),
                     operation_type);
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
         "Credential slot  %1% (state : %2%) not found for %3% / %4%.")
       % cred_slot % state % cred_type_node.value_to_string()
       % cred_type_node.parent().value_to_string())
        .str());
  }

  return cred_slot_node;
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
  auto credential_type_nodes
    = user_id_node.children(ATTRIBUTE(CREDENTIAL_TYPE));
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
  bool credential_available = true;

  for_each_credential_type_nodes(
    endpoint_node,
    [&](attribute_store::attribute &credential_type_node) {
      for (auto &credential_slot_node:
           credential_type_node.children(ATTRIBUTE(CREDENTIAL_SLOT))) {
        // If this credential slot node doesn't have a reported value, check the next one
        if (!credential_slot_node.reported_exists()) {
          continue;
        }

        if (credential_slot_node.reported<user_credential_slot_t>()
            == credential_slot) {
          credential_available = false;
          return;
        }
      }
    },
    credential_type);

  return credential_available;
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

}  // namespace user_credential
#endif  // USER_CREDENTIAL_HELPERS_H