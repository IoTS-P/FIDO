## Common Commands

- Run fuzz:
  - Directly use afl-fuzz to run the fuzzer program
  - semu-fuzz-helper run stat_configs.yml, where stat_configs.yml stores the basic configuration of the target firmware

- Count basic blocks:
  - semu-fuzz-helper stat stat_configs.yml --prefix <directory_name> --thread 100 --timeout 60

- Plot:
  - python3 stat_new.py