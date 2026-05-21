import copy
import os
import re
from os.path import isfile

import yaml
from fuzzware_harness.globs import MMIO_HOOK_PC_ALL_ACCESS_SITES
from fuzzware_harness.util import load_config_deep
from fuzzware_pipeline.logging_handler import logging_handler

logger = logging_handler().get_logger("pipeline")

EXITAT_ENTRY_NAME_PREFIX = "PIPELINE_EXIT"

def write_yaml(path, config_map):
    # Use hex representation of numbers in generated yml file
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))

    yaml.add_representer(int, hexint_presenter)
    with open(path, "w") as f:
        f.write(yaml.dump(config_map))

def add_exitat_bbl_to_config_file(file_path, bbl):
    if not os.path.isfile(file_path):
        config = {'exit_at': {EXITAT_ENTRY_NAME_PREFIX: bbl}}
    else:
        config = load_config_deep(file_path)
        if bbl not in config['exit_at'].values():
            ind = 0
            while EXITAT_ENTRY_NAME_PREFIX + "_{:03d}".format(ind) in config['exit_at']:
                ind += 1
            config['exit_at'][EXITAT_ENTRY_NAME_PREFIX + "_{:03d}".format(ind)] = bbl
    write_yaml(file_path, config)

def save_config(config_map, dest_yml_path):
    # Use hex representation of numbers in generated yml file
    def hexint_presenter(dumper, data):
        return dumper.represent_int(hex(data))
    yaml.add_representer(int, hexint_presenter)

    with open(dest_yml_path, "w") as f:
        f.write(yaml.dump(config_map, default_flow_style=False))

def save_extra_args(extra_args, out_path):
    assert not any(["\n" in arg for arg in extra_args])
    with open(out_path, "w") as f:
        f.write("\n".join(extra_args))

def load_extra_args(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return [l for l in f.read().split("\n") if l]
    else:
        return []

def parse_extra_args(extra_args, project_path):
    for arg in extra_args:
        # The project directory might have moved. Fix any absolute paths to be relative to our local project
        if "/" in arg:
            orig_project_path = re.split("main.+", arg)[0]
            new_base_path = arg.replace(orig_project_path, '')
            extra_args[extra_args.index(arg)] = os.path.join(project_path, new_base_path)
    return extra_args

def get_modeled_mmio_contexts(config_map) -> set:
    """
    Builds a set of all MMIO model contexts in a config map
    """
    res = set()
    if 'mmio_models' in config_map:
        for model_entries in config_map['mmio_models'].values():
            for model_entry in model_entries.values():
                res.add((model_entry['pc'] if 'pc' in model_entry else MMIO_HOOK_PC_ALL_ACCESS_SITES, model_entry['addr']))

    return res

def merge_config_file_into(target_config_path, other_config_path):
    additional_config = load_config_shallow(other_config_path)
    update_config_file(target_config_path, [additional_config['mmio_models']])

def update_config_file(config_filename, model_entries):
    """
    Updates a config file in-place with a list of model config trees
    """

    config_dict = load_config_shallow(config_filename)

    success = add_config_entries(config_dict['mmio_models'], model_entries)

    write_yaml(config_filename, config_dict)

    return success

def add_config_entries(existing_models, new_models):
    """
    Takes a list of newly created model entry maps and adds them to the existing modeling map
    new_models would look something like this:
    [
        {
            'passthrough': {
                pc_deadbeef_mmio_1234:
                    addr: 0x40012345
                    pc: 0x123
                    val: 0x20
            },
            'linear' : {
                ...
            }
        },
        {
            'passthrough': {
                ...
            },
            'constant': {
                ...
            }
        }
    ]

    @return True, if all merges were completed successfully
    """
    all_good = True
    for entry in new_models:
        for model_type, models in entry.items():
            for model_name, param_map in models.items():
                all_good = all_good and add_config_entry(existing_models, model_type, model_name, param_map)
    return all_good

def load_config_shallow(config_filename):
    if isfile(config_filename):
        with open(config_filename, "r") as config_file:
            config_dict = yaml.safe_load(config_file.read())
    else:
        config_dict = {}

    if 'mmio_models' not in config_dict:
        config_dict['mmio_models'] = {}

    return config_dict

def add_config_entry(existing_models, model_type, entry_name, param_map):
    if model_type not in existing_models:
        existing_models[model_type] = {}

    # entry_name, param_map = list(model_entry.items())[0]
    # Check for conflicting model assignments
    if entry_name in existing_models[model_type] and existing_models[model_type][entry_name] != param_map:
        logger.warning("got conflicting model assignments from different states")
        if 'conflicts' not in existing_models:
            existing_models['conflicts'] = {}
        if entry_name not in existing_models['conflicts']:
            existing_models['conflicts'][entry_name] = []
        if param_map not in existing_models['conflicts'][entry_name]:
            existing_models['conflicts'][entry_name].append(param_map)

        existing_entry = existing_models[model_type][entry_name]
        if existing_entry not in existing_models['conflicts'][entry_name]:
            existing_models['conflicts'][entry_name].append(copy.deepcopy(existing_entry))

        logger.warning("Merging configs:\nExisting: {}\nConflicting: {}".format(existing_entry, param_map))
        if merge_model_conflict(model_type, existing_entry, param_map):
            logger.warning("Successfully merged into {}".format(existing_entry))
            # existing_models[model_type][entry_name] = merged_model_entry
        else:
            logger.warning("Merging failed, existing config kept.")
            return False
    else:
        existing_models[model_type][entry_name] = param_map

    return True

def merge_model_conflict(model_type, existing_entry, new_entry):
    if model_type == "set":
        for val in new_entry['vals']:
            if val not in existing_entry['vals']:
                logger.info("[Set Model Merging] Adding value {:x} to entry".format(val))
                existing_entry['vals'].append(val)
        existing_entry['vals'].sort()
        return True
    if model_type == "bitextract":
        existing_entry['mask'] |= new_entry['mask']
        return True
    return False
