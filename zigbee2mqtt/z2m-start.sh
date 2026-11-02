#!/bin/sh
# Starts Zigbee2MQTT with the instance's settings, applied at every start
# through ZIGBEE2MQTT_CONFIG_* (Zigbee2MQTT writes them into
# configuration.yaml; they win over UI edits). Secrets only travel through
# the environment, never a command line.
#
#   coordinator  Z2M_NETWORK_COORDINATOR (tcp://host:port) wins over
#                Z2M_SERIAL_DEVICE (host USB device, mapped to /dev/zigbee);
#                neither: Zigbee2MQTT is not started (idle, see the log).
#   adapter      Z2M_ADAPTER (auto = Zigbee2MQTT's own detection).
#   broker       Z2M_MQTT_SERVER empty: the bundled mosquitto as user
#                zigbee2mqtt (Z2M_BROKER_PASSWORD); else that server with
#                Z2M_MQTT_USER / Z2M_MQTT_PASSWORD.
set -eu

fail() { echo "zigbee2mqtt: $*" >&2; exit 1; }

idle() {
  echo "zigbee2mqtt: $*" >&2
  echo "zigbee2mqtt: Zigbee2MQTT is not started; set \"Serial device\" or \"Network coordinator\" in the instance settings and restart it." >&2
  trap 'exit 0' TERM INT
  while :; do sleep 3600 & wait $! || true; done
}

if [ -n "${Z2M_NETWORK_COORDINATOR:-}" ]; then
  case "$Z2M_NETWORK_COORDINATOR" in
    tcp://?*:[0-9]*) ;;
    *) fail "Network coordinator must look like tcp://<host>:<port> (got '$Z2M_NETWORK_COORDINATOR')" ;;
  esac
  case "${Z2M_NETWORK_COORDINATOR#tcp://}" in
    *[!A-Za-z0-9.:_-]*) fail "Network coordinator has unexpected characters" ;;
  esac
  [ "${Z2M_ADAPTER:-auto}" != auto ] || fail "a network coordinator needs its Adapter type (ember, zstack, ...) in the instance settings"
  ZIGBEE2MQTT_CONFIG_SERIAL_PORT="$Z2M_NETWORK_COORDINATOR"
elif [ -n "${Z2M_SERIAL_DEVICE:-}" ]; then
  [ -c /dev/zigbee ] || fail "Serial device $Z2M_SERIAL_DEVICE is not a character device inside the container"
  ZIGBEE2MQTT_CONFIG_SERIAL_PORT=/dev/zigbee
else
  idle "no Zigbee coordinator configured."
fi
export ZIGBEE2MQTT_CONFIG_SERIAL_PORT

case "${Z2M_ADAPTER:-auto}" in
  auto) ;;
  ember|zstack|deconz|zigate|zboss|zoh|ezsp) export ZIGBEE2MQTT_CONFIG_SERIAL_ADAPTER="$Z2M_ADAPTER" ;;
  *) fail "unknown Adapter type '$Z2M_ADAPTER'" ;;
esac

if [ -n "${Z2M_MQTT_SERVER:-}" ]; then
  case "$Z2M_MQTT_SERVER" in
    mqtt://?* | mqtts://?*) ;;
    *) fail "MQTT server must be mqtt://<host>:<port> or mqtts://<host>:<port>" ;;
  esac
  ZIGBEE2MQTT_CONFIG_MQTT_SERVER="$Z2M_MQTT_SERVER"
  ZIGBEE2MQTT_CONFIG_MQTT_USER="${Z2M_MQTT_USER:-}"
  ZIGBEE2MQTT_CONFIG_MQTT_PASSWORD="${Z2M_MQTT_PASSWORD:-}"
else
  [ -n "${Z2M_BROKER_PASSWORD:-}" ] || fail "Z2M_BROKER_PASSWORD is not set"
  ZIGBEE2MQTT_CONFIG_MQTT_SERVER=mqtt://mosquitto:1883
  ZIGBEE2MQTT_CONFIG_MQTT_USER=zigbee2mqtt
  ZIGBEE2MQTT_CONFIG_MQTT_PASSWORD="$Z2M_BROKER_PASSWORD"
fi
export ZIGBEE2MQTT_CONFIG_MQTT_SERVER ZIGBEE2MQTT_CONFIG_MQTT_USER ZIGBEE2MQTT_CONFIG_MQTT_PASSWORD
unset Z2M_BROKER_PASSWORD Z2M_MQTT_PASSWORD

cd /app
exec /usr/local/bin/docker-entrypoint.sh /sbin/tini -- node index.js
