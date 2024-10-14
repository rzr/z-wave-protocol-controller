#!/usr/bin/env python3

import mqtt.mqtt_manager as mqtt_manager
import utils.pretty_print as display

from clusters import user_credential

# Data for the test
# New user
NEW_USER_ID = 1
NEW_USER_NAME = "SHOCKBAR"
# New Credential
NEW_CREDENTIAL_TYPE = user_credential.CredentialType.PINCode
NEW_CREDENTIAL_SLOT = 1 
NEW_CREDENTIAL_ORIGINAL_PIN_CODE = "1273"
NEW_CREDENTIAL_MODIFIED_PIN_CODE = "1291"

# Credential to be deleted
DELETED_CREDENTIAL_TYPE = user_credential.CredentialType.PINCode
DELETED_USER_ID = 1

# Taken from CTT test case
NEW_ADMIN_PIN_CODE = "0112358"

def add_user():
    display.action_description(f"Adding User #{NEW_USER_ID}")
    user_credential.add_user(NEW_USER_ID)

def modify_user():
    display.action_description(f"Modifying Username of User #{NEW_USER_ID} to {NEW_USER_NAME}")
    user_credential.modify_user(NEW_USER_ID, NEW_USER_NAME)

def add_credential():
    display.action_description(f"Adding Credential for User #{NEW_USER_ID}")
    user_credential.add_credential(NEW_USER_ID, NEW_CREDENTIAL_TYPE, NEW_CREDENTIAL_SLOT, NEW_CREDENTIAL_ORIGINAL_PIN_CODE)

def modify_credential():
    display.action_description(f"Modifying Credential for User #{NEW_USER_ID}")
    user_credential.modify_credential(NEW_USER_ID, NEW_CREDENTIAL_TYPE, NEW_CREDENTIAL_SLOT, NEW_CREDENTIAL_MODIFIED_PIN_CODE)

def delete_credential():
    display.action_description(f"Removing Credential for User #{NEW_USER_ID}")
    user_credential.delete_credential(NEW_USER_ID, NEW_CREDENTIAL_TYPE, NEW_CREDENTIAL_SLOT)

def delete_user():
    display.action_description(f"Removing User #{NEW_USER_ID}")
    user_credential.delete_user(NEW_USER_ID)

def delete_all_users():
    display.action_description(f"Removing All Users")
    user_credential.delete_all_users()

def delete_credential_for_user_by_type():
    display.action_description(f"Removing Credential Type {DELETED_CREDENTIAL_TYPE} for User #{NEW_USER_ID}")
    user_credential.delete_credential_for_user_by_type(DELETED_USER_ID, DELETED_CREDENTIAL_TYPE)

def delete_all_credentials_for_user():
    display.action_description(f"Removing All Credentials for User #{NEW_USER_ID}")
    user_credential.delete_all_credentials_for_user(DELETED_USER_ID)

def delete_all_credentials():
    display.action_description(f"Removing All Credentials")
    user_credential.delete_all_credentials()

def delete_all_credential_types():
    display.action_description(f"Removing All Credential Types : {DELETED_CREDENTIAL_TYPE}")
    user_credential.delete_all_credential_types(DELETED_CREDENTIAL_TYPE)

def set_admin_pin_code():
    display.action_description(f"Setting Admin Pin Code to #{NEW_ADMIN_PIN_CODE}")
    user_credential.set_admin_pin_code(NEW_ADMIN_PIN_CODE)

def deactivate_admin_pin_code():
    display.action_description(f"Deactivating Admin Pin Code")
    user_credential.deactivate_admin_pin_code()

if __name__ == '__main__':
    mqtt_manager.add_node()

    add_user()
    modify_user()

    add_credential()
    modify_credential()
    delete_credential()

    delete_user()

    delete_all_users()
    delete_credential_for_user_by_type()
    delete_all_credentials_for_user()
    delete_all_credentials()
    delete_all_credential_types()

    set_admin_pin_code()
    deactivate_admin_pin_code()

    mqtt_manager.remove_node()
