#!/bin/bash

# Path del device
DEVICE_PATH="/dev/reference_monitor"

# Definisci il percorso di directory
DIRECTORY_PATH="$(pwd)/directory"

# Imposta lo stato su REC_ON
echo 'Setting state to REC_ON'
printf 'state REC_ON default' > $DEVICE_PATH

# Aggiungi directory al reference monitor
echo 'Adding directory to monitored paths'
printf 'addpath %s default' "$DIRECTORY_PATH" > $DEVICE_PATH


echo "From now on, it is not possible to create or remove anything within the directory. All operations will be logged in 'the_file'. Run 'unlock_dir.sh' to deactivate protection."

