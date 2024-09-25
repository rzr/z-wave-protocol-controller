import mqtt.mqtt_manager as mqtt_manager
import utils.utils as utils

CLUSTER_NAME = "UnifySwitchColor"

def command_set_color(color_component_id, value, duration = 0):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "SetColor",
                                           '{"ColorComponentId" : %d, "Value" : %d, "Duration" : %d}'
                                           % (color_component_id, value, duration)
                                           )


def command_start_stop_level_change(start_stop, up_down, ignor_start_level, color_component_id, start_level, duration = 1):
    mqtt_manager.send_unify_cluster_command(CLUSTER_NAME, "StartStopChange",
                                           '{"StartStop" : %s, "UpDown" : %s, "IgnorStartLevel" : %s, "ColorComponentId" : %d, "StartLevel" : %d, "Duration" : %d}' 
                                            % (utils.bool_to_str(start_stop), utils.bool_to_str(up_down), utils.bool_to_str(ignor_start_level), color_component_id, start_level, duration)
                                           )