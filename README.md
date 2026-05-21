# FIDO

This repo maintains the source code and dataset for S&P 2026 paper entiled "Stop Starving or Stuffing Me: Boosting Firmware Fuzzing Efficiency with On-demand Input Delivery".


## Brief Introduction

Micro-controller (MCU) firmware fuzzing has been extensively utilized, yet previous studies have often neglected issues related to optimal input delivery (i.e., input timing and quantity). Without a comprehensive understanding of MCU firmware exceptions, existing solutions tend to deliver fuzzer-generated inputs in an ad-hoc manner. This can either overwhelm the firmware's processing capabilities (*stuffing* problem) or fail to provide sufficient input to activate processing functions (*starving* problem), thereby diminishing fuzzing effectiveness.

This work addresses these gaps by introducing FIDO, an add-on tool designed to improve the test-case delivery effectiveness of existing firmware fuzzers.


## Citing our paper

```bibtex
@inproceedings{harm,
  title={Stop Starving or Stuffing Me: Boosting Firmware Fuzzing Efficiency with On-demand Input Delivery},
  author={Shen, Shandian and Zhou, Wei and Zhao, Keming and Liu, Peng and Kim, Chung Hwan and Guan, Le},
  booktitle={2026 IEEE Symposium on Security and Privacy (SP)},
  year={2026},
  organization={IEEE}
}
```


## Directory Structure
```bash
.
├── docs                             # Documentation for configuration options
├── running-script                   # scripts to launch FIDO
├── FIDO-Static-Component            # source code of Static analysis to locate C and P given R
├── FIDO-Dynamic-Components          # source code of Dynamic extraction of R, buffer_len inference, and fuzzer integration 
|    ├── MultiFuzz                   # MultiFuzz integrated with FIDO
|    ├── Fuzzware                    # Fuzzware integrated with FIDO
|    └── SEmu-Fuzz                   # SEmu-Fuzz integrated with FIDO
├── Experiment 
|    ├── Unit_test_samples           # Samples for generality study
|    ├── Fuzzing                     # Fuzzing data, seeds, configuration comparisons (rr+rr, rr+fuzz, fuzz+fuzz) 
|    |    ├── SEED 
|    |    ├── example_config         # Configuration examples
|    |    ├── MultiFuzz              # Firmware for running with MultiFuzz 
|    |    ├── Fuzzware               # Firmware for running with Fuzzware
|    |    └── SEmu-Fuzz              # Firmware for running with SEmu-Fuzz 
|    ├── Bug Report                  # Discovered 0-day reports 
|    └── Other                       # Experiments on special hooks or input length waste 
└── LICENSE
└── README.md                        # Usage instructions
```

## License

Content of this repository is licensed under GPL-3.0. See [LICENSE](./LICENSE).

## Getting started 

### 1. Dependencies and Environment

FIDO is built on top of the source code of three fuzzing tools, with modifications and additions. Deployment follows the same procedure as the original tools.  

- To install each tool, first enter its corresponding directory under `FIDO-Dynamic-Components`, then follow the installation instructions provided by the original repository:

- Refer to **SEmu-Fuzz** repository: [SEmu-Fuzz](https://github.com/IoTS-P/SEmu-Fuzz)  

- Refer to **Fuzzware** repository: [Fuzzware](https://github.com/fuzzware-fuzzer/fuzzware) 

- Refer to **MultiFuzz** repository: [MultiFuzz](https://github.com/MultiFuzz/MultiFuzz) 

- Install **Ghidra**, and update the `run_Ghidra` script with the appropriate path (e.g. `~/yourpathto/ghidra/support/analyzeHeadless`). The script locations differ depending on the tool.

- **Recommended versions:**  
  - Ghidra: ≥ 10.0  
  - Python: ≥ 3.8
  - AFL / AFL++ / Fuzzer dependencies: follow original tool requirements  

### 2. Delivery Information Inference (S1 + S2)

The identification of **Delivery Points** in S1 and S2 is performed using a combination of dynamic and static analysis:  

- **Dynamic analysis** is coupled with the emulator code of each tool.  

- **Static analysis** is supported by Ghidra. During emulation, Ghidra scripts (`FIDO/FIDO-Static-Component`) are invoked for static analysis.  

- **SEmu-Fuzz**: DT results are saved as JSON files under `ghidra_project` in the same directory as the firmware ELF file.  

- **Fuzzware**: DT results are saved as JSON files in the same directory as the firmware ELF file.  

**Note**:  
- Please import the configuration files from [SEmu_rule](https://github.com/MCUSec/SEmu/tree/main/RuleExtraction/extractedRules). These rule files are required for running SEmu-Fuzz, and Fuzzware parses DR information from them. To run Fuzzware, place the corresponding rule files in the same directory as the firmware ELF file.

- When running DT learning in **SEmu-Fuzz**, the Ghidra port must be configured in the firmware's `semu_config.yml`.  

- In **Fuzzware**, the port is automatically assigned during static analysis.  

### 3. Fuzz Testing with Multi-Route-Aware Input Delivery (S3)

All three tools can perform fuzzing using the **Coordinated Multi-Route-Aware Delivery** algorithm based on Delivery Point (DP) information (`FIDO/Experiment/Fuzzing/Fuzzware/Gateway/xxx.json`).  

#### SEmu-Fuzz Example

The execution of SEmu-Fuzz consists of two steps:  **Pre-learning run** to extract the firmware's first Data Trackers (DT), followed by  **Fuzzing**. SEmu-Fuzz can also continuously identify new DTs triggered during the fuzzing iteration.

1. If the firmware folder does not contain a DT information file, run a single emulation to perform pre-learning.  

    ```bash
    # Enter the directory containing the semu_config.yml
    cd ~/yourpathto/FIDO/Experiment/Fuzzing/SEmu/Gateway

    # Execute the pre-learning run
    semu-fuzz <path_to/input_file> <path_to/semu_config.yml>
    # Example: semu-fuzz base_inputs/ex7_new semu_config.yml
    ```
    **Note:** When finished, the extracted DT information will be saved as a JSON file in the ghidra_project/ folder.

2. Use AFL++ to start the fuzzing loop. During this stage, SEmu-Fuzz loads the known DTs from the JSON file to feed the mutated inputs. Furthermore, if the fuzzer discovers and enables new interrupts, SEmu-Fuzz will dynamically register the associated new DTs without interrupting the fuzzing campaign.

    ```bash
    # Start Fuzzing via AFL++
    afl-fuzz -U -m none -i base_inputs -o output_dir -t 10000 -V 86400 -- semu-fuzz @@ semu_config.yml
    ```

  - **arguments:**
    - `afl-fuzz`: Starts the AFL++ fuzzer.
    - `-U`: Enables Unicorn-mode.
    - `-m none`: Disables memory limits. 
    - `-i base_inputs`: Directory containing initial seed files.
    - `-o output_dir`: Directory to store fuzzing results (crashes/hangs).
    - `-t 10000`: Timeout for each test case execution (10,000 ms).
    - `-V 86400`: Total fuzzing duration limit in seconds (24 hours).

#### Fuzzware Example

1. Ensure that a DT information JSON file exists in the firmware directory.

    ```bash
    # Enter the firmware directory
    cd ~/yourpathto/FIDO/Experiment/Fuzzing/Fuzzware/Gateway

    # Activate the Fuzzware virtualenv and launch the pipeline
    workon <your_env name> && fuzzware pipeline --aflpp --run-for 24:00:00 -p <directory_name>
    ```

  - **arguments:**
    - `fuzzware pipeline` — Launch the full pipeline (modeling → fuzzing → tracing).
    - `--aflpp` — Use AFL++ (default: vanilla AFL).
    - `-p <directory_name>` — Project output directory name (default: fuzzware-project).
    - `--run-for 24:00:00` — Runtime limit in `DD:HH:MM:SS`.

#### MultiFuzz Example

1. Before starting the fuzzer, you must ensure that the DT information is manually registered in the target firmware's configuration file (config.yml). MultiFuzz uses the **adapter** field to define where inputs should be injected.

2. Once the configuration is ready, you can start the fuzzing campaigns using the provided automation scripts under `FIDO/running-script/MultiFuzz`. These scripts handle the setup of work directories, seed imports, and execution of the fuzzer.

We provide two main scripts depending on your fuzzing scale:
- **run_one_input.sh:** Used for launching fuzzing on a single target firmware.
- **run_all.sh:** Used for batch-launching multiple firmware targets at once.

    ```bash
    # Navigate to the script directory
    cd ~/yourpathto/FIDO/running-script/MultiFuzz/

    # Execute the batch fuzzing script
    ./run_all.sh
    ```
    
- **Note on Script Customization:** You can easily adjust the fuzzing settings by modifying variables directly within the scripts (e.g. run_all.sh).
  - `FIRMWARES`: The array list of firmware projects to be fuzzed.
  - `INSTANCES_PER_FIRMWARE`: Configures the number of parallel fuzzing instances per firmware (default is 5).
  - `RUN_FOR=24h`: The environment variable passed to cargo run that determines the duration of the fuzzing campaign (e.g. 24 hours).
  - `BASE_WORKDIR`: The master output directory where all results, crash logs, and instances are mapped.

**Note:** Different base fuzzers support different firmware capabilities, so the number of firmware instances that can run may vary.

## Issues
If you encounter any problems while using our tool, please open an issue. 

For other communications, you can email `shenshandian@hust.edu.cn` or `zhaokeming@hust.edu.cn`