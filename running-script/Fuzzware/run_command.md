## Execution Environment: fuzzware_ufuzzadapter

- Activate virtualenv for fuzzware_ufuzzadapter:
  - workon fuzzware_ufuzzadapter

## Common Commands

- Run fuzz:
  - fuzzware pipeline --aflpp --run-for 24:00:00 -p <directory_name>

- Count basic blocks:
  - In the target test directory, run: fuzzware genstats
  - Basic block information will be generated in the stats directory

- Plot:
  - python3 plot_fuzzware.py
  - Modify the firmware directories to plot in: plot_bb_config.py