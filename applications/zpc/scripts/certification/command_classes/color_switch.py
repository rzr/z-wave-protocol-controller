#!/usr/bin/env python3

import mqtt.mqtt_manager as mqtt_manager
import utils.pretty_print as display

from clusters import on_off, level, unify_switch_color

def color_set(color_id, color_value):
    display.action_description(f"Color ID {color_id} Set to {color_value}")
    unify_switch_color.command_set_color(color_id, color_value, 0)

def color_start_change_up(color_id):
    display.action_description(f"Color ID {color_id} Start Level Change Up")
    unify_switch_color.command_start_stop_level_change(True, False, True, color_id, 50, 1)

def color_stop_change(color_id):
    display.action_description(f"Color ID {color_id} Stop Level Change")
    unify_switch_color.command_start_stop_level_change(False, False, True, color_id, 50, 1)

def switch_multilevel_set(level_value):
    display.action_description(f"Switch Multilevel Set to {level_value}")
    level.command_move_level(level_value, True, True)

def switch_binary_set_on():
    display.action_description(f"Switch Binary Set On")
    on_off.command_on()

def switch_binary_set_off():
    display.action_description(f"Switch Binary Set Off")
    on_off.command_off()

if __name__ == '__main__':
    mqtt_manager.add_node()

    # set color component 'Green' (ID = 0x03) with value= 255
    color_set(3, 255)
    # start level change for color component 'Red' (ID = 0x02) increasing its brightness
    color_start_change_up(2)
    # stop level change for color component 'Red' (ID = 0x02)
    color_stop_change(2)
    # binary switch set
    switch_binary_set_on()
    # multilevel switch set
    switch_multilevel_set(50)

    mqtt_manager.remove_node()
