import mqtt.mqtt_manager as mqtt_manager
import utils.utils as utils

CLUSTER_NAME = "UserCredential"

    
class CredentialType:
    PINCode = "PINCode"
    Password = "Password"
    RFIDCode = "RFIDCode"
    BLE = "BLE"
    NFC = "NFC"
    UWB = "UWB"
    EyeBiometric = "EyeBiometric"
    FaceBiometric = "FaceBiometric"
    FingerBiometric = "FingerBiometric"
    HandBiometric = "HandBiometric"
    UnspecifiedBiometric = "UnspecifiedBiometric"


     



def add_user(user_id):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "AddUser", 
                                            '{"UserUniqueID":%d,"UserType":"GeneralUser","UserActiveState":true,"CredentialRule":"Single","UserName":"","ExpiringTimeoutMinutes":0,"UserNameEncoding":"ASCII"}' % user_id)

def modify_user(user_id, user_name):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "ModifyUser", 
                                            '{"UserUniqueID":%d,"UserType":"GeneralUser","UserActiveState":true,"CredentialRule":"Single","UserName":"%s","ExpiringTimeoutMinutes":0,"UserNameEncoding":"ASCII"}' % (user_id, user_name))

def delete_user(user_id):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteUser", 
                                            '{"UserUniqueID":%d}' % user_id)

def add_credential(user_id, credential_type, credential_slot, credential_data):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "AddCredential", 
                                            '{"UserUniqueID":%d,"CredentialType":"%s","CredentialSlot":%d,"CredentialData":"%s"}' % (user_id, credential_type, credential_slot, credential_data))
    
def modify_credential(user_id, credential_type, credential_slot, credential_data):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "ModifyCredential", 
                                            '{"UserUniqueID":%d,"CredentialType":"%s","CredentialSlot":%d,"CredentialData":"%s"}' % (user_id, credential_type, credential_slot, credential_data))
    
def delete_credential(user_id, credential_type, credential_slot):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteCredential", 
                                            '{"UserUniqueID":%d,"CredentialType":"%s","CredentialSlot":%d}' % (user_id, credential_type, credential_slot))
    

def delete_all_users():
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteAllUsers")

def delete_credential_for_user_by_type(user_id, credential_type):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteAllCredentialsForUserByType", 
                                            '{"UserUniqueID":%d,"CredentialType":"%s"}' % (user_id, credential_type))

def delete_all_credentials_for_user(user_id):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteAllCredentialsForUser", 
                                            '{"UserUniqueID":%d}' % user_id)

def delete_all_credentials():
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteAllCredentials")

def delete_all_credential_types(credentials_type):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeleteAllCredentialsByType", 
                                            '{"CredentialType":"%s"}' % credentials_type)
    
def set_admin_pin_code(admin_pin_code):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "SetAdminPINCode", 
                                            '{"PINCode":"%s"}' % admin_pin_code)
    
def deactivate_admin_pin_code():
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "DeactivateAdminPINCode")