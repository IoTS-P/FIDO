import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from matplotlib.legend_handler import HandlerBase
# Assuming plot_bb_config.py contains baseline_folder and adapter_folder dictionaries
# Make sure plot_bb_config.py is in the same directory or Python path
try:
    from plot_bb_config import baseline_folder, adapter_folder, fuzzed_folder
except ImportError:
    print("Error: Could not import baseline_folder, adapter_folder, and fuzzed_folder from plot_bb_config.py")
    print("Please ensure plot_bb_config.py exists and contains the necessary dictionaries.")
    # Define dummy dictionaries to allow the script to run partially for testing structure
    baseline_folder = {}
    adapter_folder = {}
    fuzzed_folder = {}
    # Example structure (replace with your actual data in plot_bb_config.py)
    # baseline_folder = {'PLC': ['run_1', 'run_2'], 'Gateway': ['run_1', 'run_2'], ...}
    # adapter_folder = {'PLC': ['run_1', 'run_2'], 'Gateway': ['run_1', 'run_2'], ...}
    # fuzzed_folder = {'PLC': ['run_1_new', 'run_2_new'], ...}

from matplotlib.ticker import MaxNLocator # Keep MaxNLocator import from original

# Define your group names and corresponding firmware names
groups_and_firmwares = {
    'P2IM': ["Console","Steering_Control",'Gateway','Heat_Press','PLC',"Soldering_Iron",],
    'uEmu': ['GPSTracker','LiteOS_IoT','3Dprinter','Zephyr_SocketCan','utasker_USB',],
    'new_targets_2025':['BLE-HCI'],
    'Fuzzware_CVE':['Bootstrap_UART','Bootstrap_SPI','Echo_Server','L2cap_Processor','Snmp_Server'],
    'MultiFuzz':['CCN-Lite-Relay','Gnrc_Networking'],
    # Add more groups and firmware names as needed
}

# --- Fill missing entries in config dictionaries if needed (Minimal check for robustness) ---
all_firmware_names_flat = [fw for sublist in groups_and_firmwares.values() for fw in sublist]
for fw_name in all_firmware_names_flat:
    if fw_name not in baseline_folder:
        # print(f"Warning: '{fw_name}' not found in baseline_folder (plot_bb_config.py). Using empty list.")
        baseline_folder[fw_name] = []
    if fw_name not in adapter_folder:
        # print(f"Warning: '{fw_name}' not found in adapter_folder (plot_bb_config.py). Using empty list.")
        adapter_folder[fw_name] = []
    if fw_name not in fuzzed_folder:
        # print(f"Warning: '{fw_name}' not found in fuzzed_folder (plot_bb_config.py). Using empty list.")
        fuzzed_folder[fw_name] = []
# -----------------------------------------------------------------------------


base_path = '/home/n0vic3/fuzzers/fuzzware-examples/fuzzed_test'
graph_save_directory = base_path

# Using the original collect_and_interpolate_data function
def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        # print(f'Collecting data from {path}') # Keep original print behavior if desired
        csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        # Basic check if file exists
        if not os.path.exists(csv_file_path):
            print(f"Warning: CSV file not found at {csv_file_path}, skipping.")
            continue
        try:
            data = pd.read_csv(csv_file_path, delimiter='\t')
            # Basic check for columns
            if '# seconds_into_experiment' not in data.columns or 'num_bbs_total' not in data.columns:
                print(f"Warning: Missing required columns in {csv_file_path}, skipping.")
                continue
            if data.empty:
                 print(f"Warning: Empty data file {csv_file_path}, skipping.")
                 continue
            data['hours'] = data['# seconds_into_experiment'] / 3600.0
            data_frames.append(data.set_index('hours'))
        except Exception as e:
             print(f"Error reading or processing {csv_file_path}: {e}")

    # Check if any dataframes were successfully loaded
    if not data_frames:
        print("Warning: No valid data collected for this set of paths.")
        # Return an empty DataFrame with an 'hours' index to avoid downstream errors
        return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    # Original interpolation logic
    try:
        unified_start = max(df.index.min() for df in data_frames)
        unified_end = min(df.index.max() for df in data_frames)
        # Ensure start is less than end
        if unified_start >= unified_end:
             print(f"Warning: Invalid time range detected (start >= end). Adjusting.")
             # Handle edge case: Maybe return an empty df or df with single point
             if data_frames:
                 # Use the index of the first dataframe as a fallback range?
                 first_df = data_frames[0]
                 if not first_df.empty:
                     unified_start = first_df.index.min()
                     unified_end = first_df.index.max()
                     if unified_start >= unified_end: # Still problematic
                          unified_end = unified_start + 1/3600 # Create minimal range
                 else: # First df empty, return empty
                      return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

             else: # No dataframes at all
                 return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

        # Add small epsilon to include end point
        unified_hours = np.arange(unified_start, unified_end + 1e-9, 1/3600)

    except ValueError: # Catch potential errors if min/max applied to empty list
        print("Warning: Could not determine unified time range. No valid data?")
        return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])


    interpolated_data_frames = []
    for df in data_frames:
        if df.empty: continue # Skip empty ones
        if df.index.duplicated().any():
            # print(f"Warning: Duplicate index entries found. Keeping first.") # Keep original behavior if desired
            df = df[~df.index.duplicated(keep='first')]
        # Original reindex/interpolate
        df = df.reindex(unified_hours, method='nearest', tolerance=1/3600).interpolate('index')
        # Ensure the target column exists before appending
        if 'num_bbs_total' in df.columns:
            interpolated_data_frames.append(df['num_bbs_total'])
        else:
             print(f"Warning: 'num_bbs_total' column missing after interpolation. Skipping this dataframe.")

    if not interpolated_data_frames:
         print("Warning: No dataframes left to combine after interpolation.")
         return pd.DataFrame(index=pd.Index([], name='hours'), columns=[])

    combined_data = pd.concat(interpolated_data_frames, axis=1)
    # Original did not explicitly fill NaNs, let's keep it that way unless needed
    # combined_data.ffill(inplace=True)
    # combined_data.bfill(inplace=True)
    # combined_data.fillna(0, inplace=True)
    return combined_data

# Using the original plot_median_and_range function
def plot_median_and_range(ax, data, color, label, marker):
    if data.empty or data.shape[1] == 0:
         print(f"Skipping plot for '{label}': Data is empty.")
         return
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    # Original markevery
    ax.plot(data.index, median_values, color=color, linewidth=2, marker=marker, markevery=7200, markersize=6, label=label) # Added markersize for visibility
    ax.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')


# --- Main Plotting Logic ---

# Define grid dimensions
nrows = 3
ncols = 7
total_cells = nrows * ncols

# Flatten the list of firmware names to get the total count and the list itself
all_firmwares = [(group, fw) for group, fws in groups_and_firmwares.items() for fw in fws]
num_plots = len(all_firmwares)

if num_plots == 0:
    print("No firmware targets defined. Exiting.")
    exit()

# Adjust figsize based on grid size (original width/height * num cols/rows)
fig_width = 4 * ncols   # 4 units width per plot * 6 columns
fig_height = 3 * nrows  # 3 units height per plot * 3 rows
fig, axs = plt.subplots(nrows, ncols, figsize=(20, 8)) # squeeze=False ensures axs is 2D

# Adjust layout - use original tight_layout first, then adjust spacing
# plt.tight_layout(rect=[0.02, 0.04, 1, 0.85]) # Keep original rect for legend space
plt.subplots_adjust(        
    left=0.07,    
    right=0.96,   
    bottom=0.15,  # Reduced to give more space to the plots
    top=0.85,     # Increased to give more space to the plots
    wspace=0.45,   # Adjusted for better horizontal spacing
    hspace=0.7)  # Add horizontal and vertical spacing

# Add shared axis labels for the whole figure
fig.text(0.02, 0.5, '#BBs Covered', va='center', rotation='vertical', fontsize=20, fontweight='bold')
fig.text(0.5, 0.04, 'Duration(h)', ha='center', fontsize=20, fontweight='bold')

plot_index = 0
for group_name, firmware_names in groups_and_firmwares.items():
    for firmware_name in firmware_names:

        if plot_index >= total_cells:
            print(f"Warning: More plots ({num_plots}) than grid cells ({total_cells}). Skipping remaining plots.")
            break # Stop processing more firmwares

        print(f'Processing: Group={group_name}, Firmware={firmware_name} (Plot {plot_index+1}/{num_plots})')

        # --- Path determination (same as original) ---
        Baseline_base_path = f'/home/n0vic3/fuzzers/fuzzware/examples/{group_name}/{firmware_name}'
        Adapter_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/{group_name}/{firmware_name}'
        
        # NOTE: Update `Fuzzed_base_path` to match the actual storage location of
        # your third set of data.
        # For example, if your third dataset is stored in
        # 'fuzzware-examples/my_third_fuzzer_runs/', set:
        # Fuzzed_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/my_third_fuzzer_runs/{group_name}/{firmware_name}'
        # Ensure that entries in fuzzed_folder[firmware_name] are paths relative
        # to this `Fuzzed_base_path`.
        # The following is a sample path; adjust it as needed for your setup.
        Fuzzed_base_path = f'/home/n0vic3/fuzzers/fuzzware-examples/fuzzed_test/{group_name}/{firmware_name}' # <-- base path for third dataset

        graph_title = f"{firmware_name}"
        if group_name =='new_targets_2025' or group_name == 'MultiFuzz' or group_name == 'Fuzzware_CVE' or firmware_name =='utasker_USB' or firmware_name =='Zephyr_SocketCan':
            Baseline_base_path = Adapter_base_path
        # ------------------------------------------

        # Define the paths to the directories containing your 'covered_bbs_by_second_into_experiment.csv' files
        # Use .get() with default empty list to avoid KeyError if firmware_name not in config dicts
        Baseline_path_list = [os.path.join(Baseline_base_path, path) for path in baseline_folder.get(firmware_name, [])]
        Adapter_path_list = [os.path.join(Adapter_base_path, path) for path in adapter_folder.get(firmware_name, [])]
        Fuzzed_path_list = [os.path.join(Fuzzed_base_path, path) for path in fuzzed_folder.get(firmware_name, [])]  

        # Calculate current axis row and column
        row_idx = plot_index // ncols
        col_idx = plot_index % ncols
        current_ax = axs[row_idx, col_idx]

        # Check if path lists are empty and skip if no data expected
        if not Baseline_path_list and not Adapter_path_list and not Fuzzed_path_list:  
            print(f"  -> Skipping plot for {firmware_name}: No paths defined.")
            current_ax.set_title(f"{graph_title}\n(No data)", fontsize=10) # Indicate no data on plot
            current_ax.axis('off') # Hide axis if no data at all
            plot_index += 1
            continue # Skip to the next firmware

        # Collect and process data
        baseline_data = collect_and_interpolate_data(Baseline_path_list)
        adapter_data = collect_and_interpolate_data(Adapter_path_list)
        fuzzed_group3_data = collect_and_interpolate_data(Fuzzed_path_list)  

        # Plotting on the current axis
        plot_median_and_range(current_ax, baseline_data, '#2078AA', 'Fuzzware(RR)', 'o')
        
        plot_median_and_range(current_ax, fuzzed_group3_data, ' 
        plot_median_and_range(current_ax, adapter_data, '#AE3347', 'Fuzzware+FIDO', '^')

        # --- Apply original styling ---
        current_ax.set_xlim(0, 24)
        # Use original MaxNLocator settings
        current_ax.xaxis.set_major_locator(MaxNLocator(nbins=5, min_n_ticks=5, integer=True)) # Removed steps arg
        current_ax.yaxis.set_major_locator(MaxNLocator(nbins=4, min_n_ticks=3, integer=True)) # Ensure y-axis integer ticks

        current_ax.set_title(graph_title, fontsize=17, pad=10) # Adjusted fontsize slightly for grid
        current_ax.grid(True)
        current_ax.spines['top'].set_visible(False)
        current_ax.spines['right'].set_visible(False)
        current_ax.tick_params(axis='both', labelsize=14) # Adjusted fontsize slightly
        # --- End original styling ---

        plot_index += 1

    if plot_index >= total_cells: # Break outer loop too if limit reached
        break

# Hide any unused subplots
for i in range(plot_index, total_cells):
    row_idx = i // ncols
    col_idx = i % ncols
    axs[row_idx, col_idx].axis('off')

# --- Create Shared Legend (Adapted for 2D axs) ---

# Collect all handles and labels from all subplots
handles, labels = [], []
# Iterate through the flattened 2D array of axes
for ax in axs.flat:
    for handle, label in zip(*ax.get_legend_handles_labels()):
        if label not in labels:
            handles.append(handle)
            labels.append(label)

# Use original custom legend handles and handler
class LegendObject(object):
    def __init__(self, color, marker):
        self.color = color
        self.marker = marker

class HandlerLegendObject(HandlerBase):
    def create_artists(self, legend, orig_handle, xdescent, ydescent, width, height, fontsize, trans):
        import matplotlib.patches as patches
        from matplotlib.lines import Line2D
        legline = Line2D([width / 2], [height / 2], marker=orig_handle.marker,
                         color=orig_handle.color, markersize=10, linestyle='')

        legbox = patches.FancyBboxPatch((xdescent, ydescent), width, height,
                                        boxstyle="round,pad=0.2", edgecolor=orig_handle.color,
                                        facecolor=orig_handle.color, alpha=0.3, transform=trans)

        return [legbox, legline]

# Use the collected handles/labels if found, otherwise use the fixed ones from original code
legend_handles_final = handles if handles else [
    LegendObject('#2078AA', 'o'), 
    LegendObject('#AE3347', '^'),
    LegendObject(' 
]
legend_labels_final = labels if labels else [
    'Fuzzware(RR)', 
    'Fuzzware(Fuzz)'  
    'Fuzzware+FIDO',
]

# Customize the legend (using original settings, adjust anchor slightly for grid)
legend = fig.legend(handles=legend_handles_final,
                   labels=legend_labels_final,
                   loc='upper center',
                   ncol=3,  
                   bbox_to_anchor=(0.5, 0.985), # Adjust vertical position slightly higher for grid
                   fontsize=14,
                   shadow=False,
                   frameon=True,
                   fancybox=True,
                   draggable=True,
                   handler_map={LegendObject: HandlerLegendObject() if not handles else {}}, # Use handler only if using LegendObject
                    handletextpad=0.4,
                    borderpad=0.4
                  )

# Apply original font styling to legend text
for text in legend.get_texts():
    if 'FIDO' in text.get_text():
        text.set_fontstyle('italic')
        text.set_weight('bold')

# --- Save Figure ---
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot_combined_grid_new.png')
# Use tight bbox for saving as in original
plt.savefig(plot_file_path, format='png', dpi=300, bbox_inches='tight', pad_inches=0.05)
print(f'Combined grid plot saved to {plot_file_path}')

plt.close(fig) # Close the figure