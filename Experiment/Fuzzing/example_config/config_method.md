## SEmu Configuration (Heat_Press)

- stat_configs.yml (applies to all firmware)
- semu_config.yml (applies to a single firmware)

---

## Fuzzware Configuration

- Use the JSON file extracted by SEMu via CRP
- config.yml file

---

## Multifuzz Configuration

- Based on the JSON extracted by SEMu via CRP, add the adapter in config.yml
- config.yml file

---

## config.yml Settings: interrupt_triggers

This applies to the interrupt_triggers section in both Fuzzware and Multifuzz.

Example block:

```
interrupt_triggers:
  trigger:
    every_nth_tick:
    fuzz_mode:
```

### every_nth_tick controls trigger timing

- Fixed value (e.g., 0x3e8): triggers at a fixed tick interval, e.g., every 1000 ticks

- fuzzed: after each trigger, dynamically chooses the next interval from 8 predefined values:

  ```
  const int64_t FUZZER_TIME_RELOAD_VALS[8] = {
      1000,
      500,
      250,
      1,
      4000,
      8000,
      16000,
      2000,
  };
  ```

### fuzz_mode controls interrupt selection

- round_robin: selects interrupt numbers in a fixed order
- fuzzed: the fuzzer selects interrupt numbers (non-fixed order)

---

## Four Configuration Modes

1. RR+rr (fixed time + round-robin interrupts)

   ```
   interrupt_triggers:
     trigger:
       every_nth_tick: 0x3e8
       fuzz_mode: round_robin
   ```

2. fuzz+rr (fixed time + fuzzed interrupts)

   ```
   interrupt_triggers:
     trigger:
       every_nth_tick: 0x3e8
       fuzz_mode: fuzzed
   ```

3. RR+fuzz (fuzzed time + round-robin interrupts)

   ```
   interrupt_triggers:
     trigger:
       every_nth_tick: fuzzed
       fuzz_mode: round_robin
   ```

4. fuzz+fuzz (fuzzed time + fuzzed interrupts)

   ```
   interrupt_triggers:
     trigger:
       every_nth_tick: fuzzed
       fuzz_mode: fuzzed
   ```