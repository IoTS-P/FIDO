import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from matplotlib.legend_handler import HandlerBase

# Define your group names and corresponding firmware names
groups_and_firmwares = {
    'P2IM': ['PLC', 'Gateway', 'Heat_Press', "Console", "Steering_Control"],
    'uEmu': ['3Dprinter'],
    # Add more groups and firmware names as needed
}

base_path = '/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/stat_draw_folder'
graph_save_directory = base_path


# graph_title = "μEmu/Steering_Control"
# graph_save_directory = Adapter_base_path


mode = "semu"
# Define the paths to the directories containing your 'covered_bbs_by_second_into_experiment.csv' files

def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        # Check if "stat_semu|uemu" is contained in the path
        if "stat_"+ mode not in path:
            continue
        # If found, rename the new_blocks.txt file in the stat_semu directory to new_blocks.csv
        # Before that, first check if the new_blocks.csv file exists
        csv_file_path = os.path.join(path,'new_blocks.csv')
        if not os.path.exists(csv_file_path):
            target_path = os.path.join(path, 'new_blocks.txt')
            os.rename(target_path, csv_file_path)
            with open(csv_file_path, 'r+', encoding='utf-8') as file:
                original_content = file.read()  # Read the entire file content into memory
                file.seek(0)  # Move the file cursor to the beginning of the file
                insert_text = "# seconds_into_experiment	num_bbs_total	new_bbs_since_last\n"
                file.write(insert_text + original_content)  # Write new content and original content
                file.truncate()  # If the new content is shorter than the original content, delete the extra part in the file
        
        print(f'Collecting data from {path}')
        # csv_file_path = os.path.join(path, 'stats', 'covered_bbs_by_second_into_experiment.csv')
        data = pd.read_csv(csv_file_path, delimiter='\t')
        data['hours'] = data['# seconds_into_experiment'] / 3600.0
        data_frames.append(data.set_index('hours'))

    unified_start = max(df.index.min() for df in data_frames)
    unified_end = min(df.index.max() for df in data_frames)
    unified_hours = np.arange(unified_start, unified_end + 1/3600, 1/3600)

    interpolated_data_frames = []
    for df in data_frames:
        if df.index.duplicated().any():
            df = df[~df.index.duplicated(keep='first')]
        df = df.reindex(unified_hours, method='nearest', tolerance=1/3600).interpolate('index')
        interpolated_data_frames.append(df['num_bbs_total'])

    combined_data = pd.concat(interpolated_data_frames, axis=1)
    return combined_data

def plot_median_and_range(ax, data, color, label, marker):
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)
    ax.plot(data.index, median_values, color=color, linewidth=2, marker=marker, markevery=7200, label=label)
    ax.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')

# Create a figure with a sub-plot for each firmware name in each group
num_plots = sum(len(firmwares) for firmwares in groups_and_firmwares.values())
fig, axs = plt.subplots(1, num_plots, figsize=(5 * num_plots, 4))
plt.subplots_adjust(
    left=0.05,     
    right=0.95,    
    bottom=0.15,   
    top=0.77,      
    wspace=0.4     
)

plot_index = 0
for group_name, firmware_names in groups_and_firmwares.items():
    for firmware_name in firmware_names:
        print(f'group_name: {group_name}, firmware_name: {firmware_name}')
        Baseline_base_path = f'/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/stat_draw_folder/{group_name}/{firmware_name}'
        Adapter_base_path = f'/home/liyuweiheng/fuzzers/SEmu/DataSet/fuzz_tests/stat_draw_folder/{group_name}/{firmware_name}'
        graph_title = f"{firmware_name}"

        Baseline_path_list = [
            os.path.join(Baseline_base_path,"stat_"+ mode +"_baseline_1"),
            os.path.join(Baseline_base_path,"stat_"+ mode +"_baseline_2"),
            os.path.join(Baseline_base_path,"stat_"+ mode +"_baseline_3"),
            os.path.join(Baseline_base_path,"stat_"+ mode +"_baseline_4"),
            os.path.join(Baseline_base_path,"stat_"+ mode +"_baseline_5")
            ]
        Adapter_path_list = [
            os.path.join(Adapter_base_path,"stat_"+ mode +"_adapter_1"),
            os.path.join(Adapter_base_path,"stat_"+ mode +"_adapter_2"),
            os.path.join(Adapter_base_path,"stat_"+ mode +"_adapter_3"),
            os.path.join(Adapter_base_path,"stat_"+ mode +"_adapter_4"),
            os.path.join(Adapter_base_path,"stat_"+ mode +"_adapter_5")
            ]

        baseline_data = collect_and_interpolate_data(Baseline_path_list)
        adapter_data = collect_and_interpolate_data(Adapter_path_list)

        min_hours = min(baseline_data.index.min(), adapter_data.index.min())
        max_hours = max(baseline_data.index.max(), adapter_data.index.max())

        axs[plot_index].set_xlim(min_hours, max_hours)
        plot_median_and_range(axs[plot_index], baseline_data, '#2078AA', 'SEmu', 'o')
        plot_median_and_range(axs[plot_index], adapter_data, '#AE3347', 'SEmu+F²IDE', '^')

        axs[plot_index].set_title(graph_title, fontsize=16)
        axs[plot_index].grid(True)
        axs[plot_index].spines['top'].set_visible(False)
        axs[plot_index].spines['right'].set_visible(False)
        plot_index += 1

# Collect all handles and labels from all subplots
handles, labels = [], []
for ax in axs:
    for handle, label in zip(*ax.get_legend_handles_labels()):
        if label not in labels:
            handles.append(handle)
            labels.append(label)

# Create custom legend handles with boxes
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
                                        boxstyle="round,pad=0.3", edgecolor=orig_handle.color,
                                        facecolor=orig_handle.color, alpha=0.3, transform=trans)

        return [legbox, legline]

legend_handles = [LegendObject('#2078AA', 'o'), LegendObject('#AE3347', '^')]
legend_labels = ['SEmu', 'SEmu+F²IDE']

# Customize the legend
legend = fig.legend(handles=legend_handles, labels=legend_labels, loc='upper center', ncol=2, bbox_to_anchor=(0.5, 1.02), fontsize=16, shadow=False, frameon=True, fancybox=True, draggable=True, handler_map={LegendObject: HandlerLegendObject()})
for text in legend.get_texts():
    if 'F²IDE' in text.get_text():
        text.set_fontstyle('italic')
        text.set_weight('bold')
fig.text(0.5, 0.02, 'Time (hh:mm)', ha='center', va='center', fontsize=16, fontweight='bold')
# fig.text(0.01, 0.5, '#BBs Covered', ha='center', va='center', rotation='vertical', fontsize=16, fontweight='bold')
plot_file_path = os.path.join(graph_save_directory, 'comparison_plot_combined.png')
plt.savefig(plot_file_path, format='png', dpi=300)
print(f'Combined plot saved to {plot_file_path}')

plt.close()
