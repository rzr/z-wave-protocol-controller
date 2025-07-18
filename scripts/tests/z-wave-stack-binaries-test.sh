#! /usr/bin/env bash
# -*- mode: Bash; tab-width: 2; indent-tabs-mode: nil; coding: utf-8 -*-
# vim:shiftwidth=4:softtabstop=4:tabstop=4:
#
#% * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * %#

[ "" = "$debug" ] || set
[ "" = "$debug" ] || set -x
set -e
set -o pipefail

# Default configuration can be overloaded from env

# To be explicilty added to env
sudo="${sudo:=}"

duration=3 # Allocated time in mins until watchdog quit

ZPC_COMMAND="${ZPC_COMMAND:=/usr/bin/zpc}"

[ "" != "${z_wave_stack_binaries_bin_dir}" ] \
    || z_wave_stack_binaries_bin_dir="${PWD}/z-wave-stack-binaries/bin"

# Internal

name='z-wave'
code=0
log_suffix=".log.tmp"
code_log="code${log_suffix}"
zpc_log="zpc${log_suffix}"
file="screen.rc"
mqtt_pub_log="mqtt_pub${log_suffix}"
mqtt_sub_log="mqtt_sub${log_suffix}"
mqtt_log="mqtt${log_suffix}"
controller_log="ncp_serial_api_controller${log_suffix}"
node_log="node${log_suffix}"

nocol="\e[0m"
blue="\e[0;34m"
cyan='\e[1;36m'
green="\e[0;32m"
red="\e[0;31m"
yellow='\e[1;33m'


usage_()
{
    cat<<EOF
Usage:

  $0 setup_ # Download dependencies
  $0 # Run installed version

Shortcuts:

  Ctrl+a \ : Quit all windows
  Ctrl+a TAB : change focus
  Ctrl+a ESC : Take focus to use scroll keys

Advanced uses:

Run from docker:

export ZPC_COMMAND="docker-compose up --abort-on-container-exit"
export ZPC_ARGS="--log.level=d"

docker-compose down # Disable local broker (will start a new one)
pidof mosquitto && sudo systemctl stop mosquitto

$0

Run from prebuilt env:

export z_wave_stack_binaries_bin_dir="${HOME}/mnt/z-wave-stack/build-Debug/_CPack_Packages/Linux/TGZ/z-wave-stack-0.0.0-Linux/bin"

export ZPC_COMMAND="$PWD/build/applications/zpc/zpc --mapdir=applications/zpc/components/dotdot_mapper/rules --zpc.datastore_file=tmp.db --zpc.ota.cache_path="tmp" --log.level=d"

sudo systemctl stop mosquitto ; sudo rm /var/lib/mosquitto/mosquitto.db ; sudo systemctl restart mosquitto ;
rm -rfv *.tmp
./scripts/tests/z-wave-stack-binaries-test.sh

More:

This tool depends on:
https://github.com/Z-Wave-Alliance/z-wave-stack-binaries


For debuging:
debug=1 $0

EOF
}


log_()
{
    [ "$debug" != "" ] && echo \
        || clear >/dev/null 2>&1 || reset >/dev/null 2>&1 || :
    printf "${yellow}info: $@ ${nocol}\n"
}


exit_()
{
    local code=0$1
    log_ "exit: $@ code=$code ; Use: debug=1 $0 # To trace script)"
    sleep 10
    [ -z $debug ] || sleep 1000
    echo $code > $code_log
    screen -S "$name" -X "quit" ||:
    ls -l *${log_suffix} && more *${log_suffix} | cat
    exit $code
}


run_()
{
    local task="$1" && shift
    local log="$task${log_suffix}"
    rm -f "$log"
    ${task}_ "$@" 2>&1 | tee "$log"
}


mqtt_()
{
    log_ "mqtt: Wait for broker then flush queue before use and log traffic"
    while true ; do
        pidof mosquitto \
            && mosquitto_sub \
                   -v -t '#' --remove-retained --retained-only -W 1 \
                || [ 27 = $? ] && break ||: # Break on timeout
        sleep .1
    done
    log_ "mqtt: broker is ready, operating for ${duration} mins"
    mosquitto_sub -v -t '#' -W $((60 * ${duration}))
    log_ "mqtt: error: Should have finish before ${duration} may need to update it"
    exit_ 10
}


sub_()
{
    local sub="#"
    local count=1
    local expect=""
    local delay=1
    
    [ "$1" = "" ] || sub="$1"
    [ "$2" = "" ] || expect="$2"
    [ "$3" = "" ] || count="$3"
    [ "$4" = "" ] || delay="$4"

    printf "${cyan}sub: $sub${nocol} (count=${count})\n"
    mosquitto_sub -v -t "$sub" -C $count | tee "$mqtt_sub_log"
    [ "" = "$expect" ] || printf "${blue}exp: $expect${nocol}\n"

    if [ "" != "$expect" ] ; then
        tail -n +$count "$mqtt_sub_log" \
            | head -n1 | grep -E "$expect" 2>&1 > /dev/null \
            || { printf "${red}exp: error:: ${expect}${nocol}\n" ;
                 cat "$mqtt_sub_log"  ;
                 exit_ 11; }
    fi
    sleep $delay
}


pub_()
{
    topic="$1"
    message="$2"
    log_ "pub: $@"

    [ "" = "$message" ] || printf "$message" | jq
    sleep 1
    mosquitto_pub -t "$topic" -m "$message"
    sleep 1
}


pubsub_()
{
    echo ""
    [ "" = "$debug" ] || log_ "pubsub_: $@"
    local pub="$1"
    local message="$2"
    local sub="$pub"
    local expect="$sub"
    local delay=1
    local count=1

    [ "$3" = "" ] || sub="$3"
    [ "$4" = "" ] || expect="$4"
    [ "$5" = "" ] || count="$5"
    [ "$6" = "" ] || delay="$6"

    if [ "" != "$pub" ] ; then
        printf "${green}pub: $pub${nocol}\n"
        if [ "$message" != "" ] ; then
            printf "$message" | jq --color-output
        fi
    fi
    if [ "" != "$pub" ] ; then
        mosquitto_pub -t "$pub" -m "$message" | tee "$mqtt_pub_log"
    fi
    sleep $delay # Needed to dedup
    if [ "" != "$sub" ] ; then
        sub_ "$sub" "$expect" "$count"
    fi
    sleep 1
    [  "0" = "$code" ] || exit_ $code # Quit on 1st failure
}

### Applications

app_()
{
    local app="$1"
    [ "" != "$app" ] || app="soc_switch_on_off"
    local app_file=$(realpath \
                         "${z_wave_stack_binaries_bin_dir}/ZW_zwave_${app}_"*"_REALTIME"*".elf" \
                         | head -n1)
    [ "$debug" = "" ] || file -E "${app_file}"
    "${app_file}" --pty
}


run_app_()
{
    local app="$1" && shift
    local log="$app${log_suffix}"
    rm -f "$log"
    app_ "$app" "$@" 2>&1 | tee "$log"
}

controller_cli_()
{
    app="ncp_serial_api_controller"
    while [ ! -e "${controller_log}" ] ; do sleep 1; done
    sleep 1
    screen -S "$name" -p "${app}" -t "controller: $@" -X stuff "$@^M"
    sleep 1
    case $1 in
        h)
            echo "controller: Should display help"
            ;;

        p)
            PTY=$(grep 'PTY: ' ${controller_log} \
                      | tail -n 1 | sed -e 's|PTY: \(.*\)|\1|g' )
            ;;
        H)
            homeid=$(grep 'HOME_ID: ' "${controller_log}" \
                         | tail -n 1 | sed -e 's|HOME_ID: \(.*\)|\1|g' )
            echo "HOME_ID: ${homeid}"
            [ ! -z $homeid ] || exit_ 19
            conthomeid="$homeid"
            ;;
        n)
            contid=$(grep 'NODE_ID: ' "${controller_log}" \
                         | tail -n 1 | sed -e 's|NODE_ID: \(.*\)|\1|g' )
            echo "NODE_ID: ${contid}"
            contid=$(printf "%04d" $contid)
            contunid="zw-$homeid-$contid"
            echo "NODE_UNID: ${contunid}"
            ;;
        *)
            echo "TODO: handle $1"
            ;;
    esac
}


node_cli_()
{
    [ -z $1 ] || { node="$1" && shift ; }
    [ ! -z $node ] || node="soc_switch_on_off"
    node_log="$node${log_suffix}"
    while [ ! -e "${node_log}" ] ; do sleep 1; done
    screen -S "$name" -p "${node}" -X stuff "$@^M"
    sleep 1
    case $1 in
        h)
            echo "node: ${node}: Should display help"
            ;;
        d)
            DSK=$(grep 'DSK: ' "${node_log}" \
                      | tail -n 1 | sed -e 's|DSK: \([0-9-]*\)|\1|g' )
            SecurityCode=$(echo "$DSK" | sed -e 's|\([0-9]*\)-[0-9-]*$|\1|g')
            ;;
        l)
            echo "node: ${node}: Set to learn mode ${nodeid} needed on add_node"
            ;;
        H)
            nodehomeid=$(grep 'HOME_ID: ' "${node_log}" \
                         | tail -n 1 | sed -e 's|HOME_ID: \(.*\)|\1|g' )
            echo "HOME_ID: ${nodehomeid}"
            [ ! -z $nodehomeid ] || exit_ 19
            ;;
        n)
            nodeid=$(grep 'NODE_ID: ' $node_log \
                         | tail -n 1 | sed -e 's|NODE_ID: \(.*\)|\1|g' )
            echo "NODE_ID: ${nodeid}"
            nodeid=$(printf "%04d" $nodeid)
            nodeunid="zw-$homeid-$nodeid"
            echo "NODE_UNID: ${nodeunid}"
            ;;
        *)
            echo "TODO: handle $1"
            ;;
    esac
}


zpc_()
{
    controller_cli_ p
    file -E "$PTY"
    export ZPC_DEVICE=$(realpath -- "$PTY")
    if [[ "${ZPC_COMMAND}" = "/usr/bin/zpc" \
              || "${ZPC_COMMAND}" =~ .*build/.*/zpc.* ]] ; then
        ZPC_COMMAND="${ZPC_COMMAND} --zpc.serial=${ZPC_DEVICE}"
    fi
    ${ZPC_COMMAND}
    sleep 1
    zpc_cli_ version
    zpc_cli_ help
    exit_ 13
}


zpc_cli_()
{
    log_ "TODO: Fix console that eat some chars, and discard next workaround"
    log_ "TODO: https://github.com/SiliconLabsSoftware/z-wave-engine-application-layer/issues/30"
    if ! true ; then
        screen -S "$name" -p "zpc" -t zpc -X stuff "$@^M"
    else
        string="$@"
        for (( i=0; i<${#string}; i++ )); do
            char="${string:$i:1}"
            screen -S "$name" -p "zpc" -t zpc -X stuff "$char"
            sleep .1
        done
        screen -S "$name" -p "zpc" -t zpc -X stuff "^M"
        sleep 1
        screen -S "$name" -p "zpc" -t zpc -X hardcopy zpc_cli${log_suffix}
    fi
}


play_net_add_node_()
{
    node="soc_switch_on_off"
    [ -z $1 ] || node="$1"

    [ 0 -eq 0$nodeid ] || exit_ 100

    command="add_node"
    log_ "net: $command: (node should be set in learn mode)"
    node_cli_ "$node" H

    controller_cli_ H
    controller_cli_ n

    sub="ucl/by-mqtt-client/zpc/ApplicationMonitoring/SupportedCommands"
    pub="$sub" # Can be anything
    message="{}"
    pubsub_ "$pub" "$message" "$sub"

    log_ "Find controller"

    sub="ucl/by-unid/+/ProtocolController/NetworkManagement"
    message="{}"
    json='{"State":"idle","SupportedStateList":["add node","remove node","reset"]}'
    expect='{"State":"idle","SupportedStateList":\["add node","remove node","reset"\]}'
    expect=$(echo "$json" | sed 's/\[/\\[/g; s/\]/\\]/g')
    pubsub_ "$pub" "$message" "$sub" "$expect"

    sub="ucl/by-unid/$contunid/State"
    json='{"MaximumCommandDelay":0,"NetworkList":[""],"NetworkStatus":"Online functional","Security":"Z-Wave S2 Access Control"}'
    expect=$(echo "$json" | sed 's/\[/\\[/g; s/\]/\\]/g')
    sub_ "$sub" "$expect"
    
    log_ "net: ${command}: node: Set to learn mode"
    node_cli_ "$node" n
    [ 0 -eq 0$nodeid ] || exit_ 16
    node_cli_ "$node" l
    node_cli_ "$node" n

    log_ "net: cont: Add node"
    pub="ucl/by-unid/$contunid/ProtocolController/NetworkManagement/Write"
    message='{"State":"add node"}'
    sub="ucl/by-unid/+/State/SupportedCommands"
    count="2" # NODEID=0001 is controller , NODEID=0002 is expected node
    expect="State/SupportedCommands"
    pubsub_ "$pub" "$message" "$sub" "$expect"
    node_cli_ "$node" H | grep "HOME_ID: ${homeid}" || exit_ 17 # TODO
    node_cli_ "$node" n # Should not be 0
    pub=''
    sub=$(echo "$sub" | sed -e "s|/+/|/$nodeunid/|g")
    pubsub_ "$pub" "$message" "$sub" "$sub"

    node_cli_ "$node" d
    node_cli_ "$node" n

    log_ "Takes time from interviewing to functional"    
    pub="ucl/by-unid/$contunid/ProtocolController/NetworkManagement/Write"
    message='{"State":"add node","StateParameters":{"UserAccept":true,"SecurityCode":"'${SecurityCode}'","AllowMultipleInclusions":false}}'
    sub="ucl/by-unid/$nodeunid/State"
    pub_ "$pub" "$message"

    NetworkStatus='.*' # Match: [ "Online interviewing", "Online functional" ]
    MaximumCommandDelay='.*' # Variable: 1, 300
    Security='.*'
    json='{"MaximumCommandDelay":'${MaximumCommandDelay}',"NetworkList":[""],"NetworkStatus":"'${NetworkStatus}'","Security":"'${Security}'"}'
    expect=$(echo "$json" | sed 's/\[/\\[/g; s/\]/\\]/g')
    expect="$sub $expect"

    NetworkStatus='Online functional'
    Security="Z-Wave S2 Authenticated"
    json='{"MaximumCommandDelay":'${MaximumCommandDelay}',"NetworkList":[""],"NetworkStatus":"'${NetworkStatus}'","Security":"'${Security}'"}'
    over_expect=$(echo "$json" | sed 's/\[/\\[/g; s/\]/\\]/g')
    over_expect="$sub $over_expect"
    over=false
    while ! $over ; do # Multiple steps: "Online interviewing"+
        log_ "is it over ?"
        sub_ "$sub" "$expect"
        # "Z-Wave S2 Authenticated"
        grep -E "$over_expect" "$mqtt_sub_log" && over=true ||:
    done                                      
        
    sub="ucl/by-unid/+/State/Attributes/EndpointIdList/Reported"
    sub=$(echo "$sub "| sed -e "s|/+/|/$nodeunid/|g")
    json='{"value":[0]}'
    expect=$(echo "$json" | sed 's/\[/\\[/g; s/\]/\\]/g')
    expect="$sub $expect"
    # sub_ "$sub" "$expect"

    node_cli_ "$node" H # expected on 1st time
    [ $conthomeid = $nodehomeid ] || exit 17_
    node_cli_ "$node" n # 2 expected on 1st time
    [ $nodeid -ne 0 ] || exit 100
}


play_net_remove_node_()
{
    node="soc_switch_on_off"
    [ -z $1 ] || node="$1"

    [ 0 -ne 0$nodeid ] || exit_ 100 # TODO

    echo
    command="remove_node"
    log_ "net: $command: $nodeid (~T738436)"
    controller_cli_ n > /dev/null

    pub="ucl/by-unid/$contunid/ProtocolController/NetworkManagement/Write"
    message='{"State":"remove node"}'
    sub="ucl/by-unid/+/State/SupportedCommands"
    node_cli_ "$node" n > /dev/null
    expect='(null)'
    expect=$(echo "$expect" | sed sed 's|[()]|\\&|g')
    expect=$(echo "$sub $expect" | sed -e "s|/+/|/$nodeunid/|g")
    node_cli_ "$node" l
    pubsub_ "$pub" "$message" "$sub" "$expect" 3
    node_cli_ "$node" n
    [ 0 -eq $nodeid ] || exit_ 18
}


play_node_soc_switch_on_off_()
{
    echo
    app="soc_switch_on_off"
    type="OnOff"
    node_cli_ "$node" n
    log_ "$type: Play on $nodeunid ~T738437 ~T738442"
    attribute="$type"

    message="{}"
    sub="ucl/by-unid/$nodeunid/ep0/$type/Attributes/$attribute/Reported"
    expect="$sub "'{"value":false}'
    sub_ "$sub" "$expect"
    sleep 1

    command="ForceReadAttributes"
    message="{ \"value\": [\"OnOff\"] }"
    pub="ucl/by-unid/$nodeunid/ep0/$type/Commands/$command"
    sub="ucl/by-unid/$nodeunid/ep0/$type/Attributes/$attribute/Reported"
    expect="$sub "'{"value":false}'
    pubsub_ "$pub" "$message" "$sub" "$expect"
    sleep 1

    command="Toggle" # T738442
    message="{}"
    pub="ucl/by-unid/$nodeunid/ep0/$type/Commands/$command"
    sub="ucl/by-unid/$nodeunid/ep0/$type/Attributes/$attribute/Reported"
    expect="$sub "'{"value":true}'
    pubsub_ "$pub" "$message" "$sub" "$expect"
    sleep 1

    expect="$sub "'{"value":false}'
    pubsub_ "$pub" "$message" "$sub" "$expect"
    sleep 1

    command="On" # T738437
    pub="ucl/by-unid/$nodeunid/ep0/$type/Commands/$command"
    expect="$sub "'{"value":true}'
    pubsub_ "$pub" "$message" "$sub" "$expect"
    sleep 1

    command="Off" # T738437
    pub="ucl/by-unid/$nodeunid/ep0/$type/Commands/$command"
    expect="$sub "'{"value":false}'
    pubsub_ "$pub" "$message" "$sub" "$expect"
    sleep 1

    log_ "$type: Events from device $nodeunid"
    node_cli_ "$node" 1 # From Off to On
    expect="$sub "'{"value":true}'
    sub_ "$sub" "$expect"
    node_cli_ "$node" 1 # From On to Off
    expect="$sub "'{"value":false}'
    sub_ "$sub" "$expect"
}


play_node_soc_multilevel_sensor_()
{  
    local app="soc_multilevel_sensor"
    local type="Battery"
    local property="battery_level"
    local value=100
    
    node_cli_ "$node" n
    log_ "$app: $type: Play on $nodeid ~T738437 ~T738442"

    log_ "$app: $type: Initial state reported after inclusion"
#    sub="zpc/${homeid}/${nodeid}/ep0/${type}/Report/${type}Report"
#    expect="$sub "'{"'${property}'":'$value'' # TODO: Partial payload
#    sub_ "$sub" "$expect"
}


play_uic_s2v2_node_()
{
    type="OnOff"
    node_cli_ "$node" H
    node_cli_ "$node" n
    echo "info: Play $type on $nodeunid"

    command="EnableNls"
    pub="ucl/by-unid/$nodeunid/State/Commands/$command"
    message="{}"
    log_ "TODO: Expect response in MQTT, workaround by looking at debug log"
    log_ "TODO: https://github.com/SiliconLabsSoftware/z-wave-engine-application-layer/issues/31"
    pub_ "$pub" "$message" "" # TODO use pub/sub MQTT not shell (next line)
    # zpc_cli_ zwave_enable_nls ${nodeid}
    sleep 1
    grep 'on_nls_state_set_v2_send_complete' "${zpc_log}" || exit_ 20
    grep 'on_nls_state_get_v2_send_complete' "${zpc_log}" || exit_ 21
    zpc_cli_ "attribute_store_log_search" "NLS"
    zpc_cli_ "attribute_store_log_search" "NLS state" \
        && grep  'NLS state ...............................................' \
                 "${zpc_log}" \
            || echo TODO exit_ 22 # 2 expected
    zpc_cli_ "attribute_store_log_search" "NLS support" \
        && grep  'NLS support .*' \
                 "${zpc_log}" \
            || echo TODO exit_ 23

    pub="ucl/by-unid/$nodeunid/State/Commands/DiscoverNeighbors"
    message='{}'
    pub_ "$pub" "$message"
    grep 'ucl_nm_neighbor_discovery' "${zpc_log}" || exit_ 24
}

play_node_()
{
    node="$1"

    play_net_add_node_ $node
    play_net_remove_node_ $node

    if ! true ; then
        play_net_add_node_ $node
        play_node_${node}_
        play_net_remove_node_ $node
    fi
    if ! true ; then
      play_uic_net_add_node_
      play_uic_s2v2_node_
      play_uic_node_OnOff_
      play_uic_net_remove_node_
    else
        log_ "TODO: https://github.com/orgs/Z-Wave-Alliance/projects/10/views/1"
    fi
}

play_demo_()
{
    nodes=""
    # nodes="soc_switch_on_off"
    nodes="$nodes soc_multilevel_sensor"
    for node in $nodes ; do
        play_node_ $node
    done
}

play_()
{
    log_ "play: Wait for zpc mqtt ready"
    while ! grep -- "\[mqtt_wrapper_mosquitto\]" "${zpc_log}" ; do sleep 1 ; done
    while ! grep -- "\[mqtt_client\] Connection to MQTT broker" "${zpc_log}" ; do sleep 1 ; done

    controller_cli_ h

    play_demo_ || code=$?
    exit_ 0$code
}


setup_()
{
    local project="z-wave-stack-binaries"
    local url="https://github.com/Z-Wave-Alliance/${project}"
    local pattern="$project-*.tar.gz" # TODO: Bump latest release
    local rev="25.1.0-26-g29d304"
    pattern="$project-${rev}-Linux.tar.gz"

    mkdir -p "${project}" && cd "${project}"
    file -E "${pattern}" \
        || gh release download -R "$url" --pattern "$pattern"
    tar xvfz "${project}"*.tar.gz
    # TODO: https://github.com/eclipse-mosquitto/mosquitto/issues/3267
    mosquitto_pub --version \
        || which mosquitto_pub \
        || $sudo apt install mosquitto-clients
}


default_()
{
    usage_
    sleep 1

    log_ "Setup check, if failing please setup using:"
    echo "sudo=sudo $0 setup_"

    [ "" = "$debug" ] || set

    screen --version

    # TODO: https://github.com/eclipse-mosquitto/mosquitto/issues/3267
    mosquitto_pub --version \
        || which mosquitto_pub

    log_ "z-wave-stack-binaries: Check presence in ${z_wave_stack_binaries_bin_dir}"
    file -E "${z_wave_stack_binaries_bin_dir}/"*"REALTIME"*".elf"
    sleep 2

    cat <<EOF | tee "$file"
# https://www.gnu.org/software/screen/manual/screen.html#Command-Summary

hardstatus alwayslastline

split -v
screen -t "ncp_serial_api_controller" "1" $0 run_app_ ncp_serial_api_controller
sleep 1

split
focus down
screen -t "soc_switch_on_off" "2" $0 run_app_ soc_switch_on_off
sleep 1

split
focus down
screen -t "soc_multilevel_sensor" "3" $0 run_app_ soc_multilevel_sensor
sleep 1

split
focus down
screen -t "zpc" "4" $0 run_ zpc
sleep 2

focus right
screen -t "mqtt" "5" $0 run_ mqtt
sleep 1

split
focus down
screen -t "play (quit with: Ctrl+a \)" "6" $0 run_ play

EOF

    screen -wipe ||:
    screen -ls ||:

    # echo "disable tty to test detached mode"
    # exec </dev/null &>/dev/null
    local detached_opt=""
    [ -t 1 ] || detached_opt="-dm -L -Logfile /dev/stdout"
    screen $detached_opt -S "$name" -c "${file}"
    sleep 1

    local ref=$(date -u +%s)
    local delay=$((60 * ${duration}))
    local beat=10
    local expired=$(($delay + $ref))
    local now=$ref
    echo "info: Start watchdog to allow $duration minutes"
    while [ $now -le $expired ]; do
        screen -ls "$name" || break
        [ -z $debug ] || { ls -l *${log_suffix} &&  more *${log_suffix} | cat ; }
        more "${mqtt_log}" | tail ||:
        sleep $beat
        now=$(date -u +%s)
    done

    screen -S "$name" -X quit ||:
    cat "${mqtt_log}"

    code=$(cat ${code_log} || echo 254)
    exit_ 0$code
}


[ "" != "$1" ] || default_

"$@"
