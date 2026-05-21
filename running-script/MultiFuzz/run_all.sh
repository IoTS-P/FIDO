#!/bin/bash

# Base configuration
BASE_WORKDIR="/home/n0vic3/MultiFuzzAdapter/MultiFuzz/fuzzed_results"
SEED_DIR="/home/n0vic3/MultiFuzzAdapter/MultiFuzz/import"
FIRMWARES=(
    "3Dprinter"
    "Bootstrap_SPI"
    "Bootstrap_UART"
    "CCN-Lite-Relay"
    "Client_Updates"
    "Console"
    "Echo_Server"
    "Filesystem"
    "Gateway"
    "Gnrc_Networking"
    "GPSTracker"
    "Heat_Press"
    "L2cap_Processor"
    "LiteOS_IoT"
    "PLC"
    "Server_Updates"    
    "Snmp_Server"
    "Steering_Control"
    "Soldering_Iron"
    "utasker_USB"
    "Zephyr_SocketCan"
)

# Number of instances to run per firmware
INSTANCES_PER_FIRMWARE=3

# Create base work directory
mkdir -p "$BASE_WORKDIR"

# Create logs directory
mkdir -p "$BASE_WORKDIR/logs"

# Create work directory for each firmware and start instances
for firmware in "${FIRMWARES[@]}"; do
    for instance in $(seq 1 $INSTANCES_PER_FIRMWARE); do
        # Create work directory
        WORK_DIR="$BASE_WORKDIR/${firmware}_${instance}"
        mkdir -p "$WORK_DIR"
        mkdir -p "$WORK_DIR/imports"

        # Copy seed files
        if [ -d "$SEED_DIR" ] && [ "$(ls -A $SEED_DIR)" ]; then
            cp "$SEED_DIR"/* "$WORK_DIR/imports/"
        else
            echo "Warning: Seed directory is empty or does not exist: $SEED_DIR"
        fi

        # Create log file
        LOG_FILE="$BASE_WORKDIR/logs/${firmware}_${instance}.log"

        # Start fuzzer instance: run for 24 hours and redirect all output to the log file
        echo "Starting $firmware instance $instance with workdir: $WORK_DIR"
        (
            WORKDIR="$WORK_DIR" \
            RUN_FOR=24h \
            ICICLE_LOG=off \
            cargo run --release -- "./experiments_fuzzed/$firmware" \
            > "$LOG_FILE" 2>&1
        ) &

        sleep 2
    done
done

# Wait for all background processes to complete
wait

echo "All fuzzing instances have completed."