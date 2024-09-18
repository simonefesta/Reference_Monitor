#!/bin/bash

# Path del device
DEVICE_PATH="/dev/reference_monitor"

# Definisci il percorso di directory
DIRECTORY_PATH="$(pwd)/directory"

# Imposta lo stato su REC_ON
echo 'Setting state to REC_ON'
printf 'state REC_ON default' > $DEVICE_PATH


# Rimuovi directory dal reference monitor
echo 'Removing directory from monitored paths'
printf 'deletepath %s default' "$DIRECTORY_PATH" > $DEVICE_PATH


# Imposta lo stato su OFF
echo 'Setting state to OFF'
printf 'state OFF default' > $DEVICE_PATH

echo "Any operation within the directory is now allowed."

