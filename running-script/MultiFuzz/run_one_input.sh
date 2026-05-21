#!/bin/bash

 
BASE_WORKDIR="/home/n0vic3/MultiFuzzAdapter/MultiFuzz/0815RR_crash"
SEED_DIR="/home/n0vic3/MultiFuzzAdapter/MultiFuzz/import"
FIRMWARES=(
    "Gnrc_Networking"
    "GPSTracker"
    "Zephyr_SocketCan"
)

 
INSTANCES_PER_FIRMWARE=3

 
mkdir -p "$BASE_WORKDIR" 

 
mkdir -p "$BASE_WORKDIR/logs"

 
for firmware in "${FIRMWARES[@]}"; do
    for instance in $(seq 1 $INSTANCES_PER_FIRMWARE); do
 
        WORK_DIR="$BASE_WORKDIR/${firmware}_${instance}"
        mkdir -p "$WORK_DIR"
        mkdir -p "$WORK_DIR/imports"
        
 
        if [ -d "$SEED_DIR" ] && [ "$(ls -A $SEED_DIR)" ]; then
            cp "$SEED_DIR"/* "$WORK_DIR/imports/"
        else
            echo "Warning: Seed directory is empty or does not exist: $SEED_DIR"
        fi
        
 
        LOG_FILE="$BASE_WORKDIR/logs/${firmware}_${instance}.log"
        
 
        echo "Starting $firmware instance $instance with workdir: $WORK_DIR"
        (
            WORKDIR="$WORK_DIR" \
            RUN_FOR=24h \
            ICICLE_LOG=off \
            cargo run --release -- "./experiments/$firmware" \
            > "$LOG_FILE" 2>&1
        ) &
        
        sleep 2
    done
done

 
wait

echo "All fuzzing instances have completed."