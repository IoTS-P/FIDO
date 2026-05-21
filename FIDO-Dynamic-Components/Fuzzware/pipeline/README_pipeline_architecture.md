# Current System Architecture
## Job Distribution
A single central piece of software, the `pipeline` pushes jobs to a redis database using python [rq](https://python-rq.org/).

A set of workers can be spawned which retrieve jobs from the redis queue, generates a file as a result of the job and places it in a specific directory.

The pipeline asynchronously observes result directories for new job result files being added (implemented in `src/observers`). Once a new file is observed, add it's path to one of the `pipeline`'s internal result queues.

The pipeline's main loop busy-checks queues for new entries. For a given result file path, it uses naming conventions to deduce information about the event (such the path of an input file belonging to a trace output file) and analyzes the result file if necessary. It then pushes new jobs to the redis queue.

## Pipeline Workflow
In order to make navigating the code easier, the typical code flow is described here.

A typical job workflow current looks like the following:
0. Upon invocation, `fuzzware_pipeline.py` creates a `session` instance which sets up listeners for new files in directories like the fuzzers' input `queue` directories
1. Upon start, the pipeline starts fuzzing instances which start fuzzing the firmware image with the given configuration
2. One of the fuzzing instances generates a new input in its `queue` directory
3. The `observers.new_fuzz_input_handler.py` triggers and adds the path of the file to the main loop's fuzzing input queue
4. The main loop checks the different queues and finds a new fuzzing input file's path in it's `queue_fuzz_inputs` member
5. It computes a hash over the file and pushes a new trace generation job to the redis job queue.
6. One of the `gen` workers takes this job and generates traces for the given input. It places the resulting trace file in the fuzzer's `traces` subdirectory.
7. Similarly to `3`, the `observers.new_trace_file_handler.py` triggers and adds the path of the file to the main loop's trace input queue
8. Similarly to `4`, the main loop notices a new entry in its `queue_traces` member
9. Similarly to `5`, the main loop (after checking that all trace types have been created) notes all basic block addresses from the new basic block trace. For every previously unseen MMIO access inside the trace file, it pushes an MMIO access state generation job to the redis queue.
10. Similarly to `6`, one of the workers takes this job and generates the state just before the MMIO access. It places the resulting state file in the project root's `mmio_states` directory.
11. As in `3.` and `7.`, `observers.new_mmio_state_handler.py` triggers, feeds the path to the main loop. The main loop pushes a modeling job to the `modeling` redis queue.
12. The `modeling` job is picked up, an MMIO register config is generated using angr and pushed into the project root's `config_snippets` directory.
13. Using the same observer mechanic as before, the new configuration snippet is eventually picked up by the main loop and merged into the latest configuration file (`mmio_config.yml`) in the project's root directory.

Once enough MMIO model configuration updates are present, the pipeline restarts fuzzer instances with the updated configurations to achieve more efficient fuzzing progress.


## Why this way?
Some state about already existing modeling has to be kept in order to prevent queuing jobs which result in re-doing work such as modeling an MMIO register over and over again. In order to keep this information in a central place, the `pipeline`'s main loop is used.

The rather ugly code deducing information from pure file paths is hidden away in [naming_conventions.py](naming_conventions.py). There have to be more elegant ways of achieving the same thing without using a single main loop and relying so much on predictable file locations. Probably the results of different jobs can be pushed as a job to a redis queue by the workers.
Also, notifying the main loop of finished jobs without observing output directories and relying on polling could be a good step.
