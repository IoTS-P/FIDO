import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from matplotlib.legend_handler import HandlerBase
import glob
from matplotlib.ticker import MaxNLocator
from matplotlib.patches import Rectangle

# Define firmware names as a list
firmwares = [
    "Console","Steering_Control",'Gateway','Heat_Press','PLC',"Soldering_Iron",    
    'GPSTracker',"LiteOS_IoT",'3Dprinter',"Zephyr_SocketCan","utasker_USB","Bootstrap_UART","Bootstrap_SPI","Echo_Server","L2cap_Processor","Snmp_Server","CCN-Lite-Relay", "Gnrc_Networking","Filesystem", "Client_Updates","Server_Updates"
]

# highlight_firmwares = ['Zephyr_SocketCan', '3Dprinter']

base_path = '/home/n0vic3/MultiFuzz/'
adapter_path = '/home/n0vic3/MultiFuzzAdapter/MultiFuzz/'
# New fuzzed_results path (MultiFuzz(Fuzz) data)
fuzzed_path = os.path.join(base_path, 'results_fuzzed')
graph_save_directory = base_path

def collect_and_interpolate_data(paths):
    data_frames = []
    for path in paths:
        print(f'Collecting data from {path}')
        txt_file_path = os.path.join(path, 'cur_coverage.txt')
        if not os.path.exists(txt_file_path):
            print(f"Warning: {txt_file_path} does not exist")
            continue
            
        try:
            # Read the txt file
            data = pd.read_csv(txt_file_path, delimiter=',', header=None, 
                             names=['bb_addr', 'timestamp', 'count'])
            
            # Sort by timestamp
            data = data.sort_values('timestamp')
            
            # Count number of basic blocks at each timestamp
            bb_counts = data.groupby('timestamp').size().reset_index(name='bb_increment')
            
            # Calculate cumulative sum to get total basic blocks at each timestamp
            bb_counts['total_bbs'] = bb_counts['bb_increment'].cumsum()
            
            # Convert milliseconds to hours
            bb_counts['hours'] = bb_counts['timestamp'] / 3600000.0
            
            # Create DataFrame with hours and total basic blocks
            df = pd.DataFrame({
                'hours': bb_counts['hours'],
                'num_bbs_total': bb_counts['total_bbs']
            }).set_index('hours')
            
            # Extend the last value to 24 hours
            if len(df) > 0:
                last_value = df['num_bbs_total'].iloc[-1]
                if df.index[-1] < 24:
                    df.loc[24] = last_value
            
            data_frames.append(df['num_bbs_total'])
            
        except Exception as e:
            print(f"Error processing {txt_file_path}: {e}")
            continue

    if not data_frames:
        raise ValueError("No valid data frames collected")

    # Combine all data frames
    all_hours = sorted(set().union(*[df.index for df in data_frames]))
    combined_data = pd.DataFrame(index=all_hours)
    
    for i, df in enumerate(data_frames):
        combined_data[f'run_{i}'] = df
    
    # Forward fill NaN values to extend lines
    combined_data = combined_data.fillna(method='ffill')
    
    return combined_data

def plot_median_and_range(ax, data, color, label, marker):
    median_values = data.median(axis=1)
    min_values = data.min(axis=1)
    max_values = data.max(axis=1)

    # Calculate evenly distributed marker points within time range
    time_range = data.index.max() - data.index.min()
    desired_marks = 10  # Desired number of marker points

    # Create evenly distributed time points
    mark_times = np.linspace(data.index.min(), data.index.max(), desired_marks)

    # Find indices of actual data points closest to these time points
    mark_indices = [np.abs(data.index - t).argmin() for t in mark_times]
    
    ax.plot(data.index, median_values, color=color, linewidth=2, 
            marker=marker, markersize=6, markevery=mark_indices, label=label)
    ax.fill_between(data.index, min_values, max_values, color=color, alpha=0.3, edgecolor='none')

def create_plot_for_firmware(firmware_name):
    print(f'Processing firmware: {firmware_name}')
    
    # Get all result directories for this firmware
    baseline_pattern = os.path.join(base_path, 'results0', f'{firmware_name}_*')
    adapter_pattern = os.path.join(adapter_path, 'results0', f'{firmware_name}_*')
    fuzz_pattern = os.path.join(fuzzed_path, f'{firmware_name}_*')   
    
    baseline_dirs = glob.glob(baseline_pattern)
    adapter_dirs = glob.glob(adapter_pattern)
    fuzz_dirs = glob.glob(fuzz_pattern)
    
    if not baseline_dirs or not adapter_dirs:
        print(f"Warning: No data found for {firmware_name}")
        return
    
    try:
        baseline_data = collect_and_interpolate_data(baseline_dirs)
        adapter_data = collect_and_interpolate_data(adapter_dirs)
        fuzz_data = collect_and_interpolate_data(fuzz_dirs)
        
        # Create a new figure for this firmware
        fig, ax = plt.subplots(figsize=(10, 6))
        
        plot_median_and_range(ax, baseline_data, '#2078AA', 'MultiFuzz(RR)', 'o')
        plot_median_and_range(ax, fuzz_data, '#8FBC8F', 'MultiFuzz(Fuzz)', 's')
        plot_median_and_range(ax, adapter_data, '#AE3347', 'MultiFuzz+FIDO', '^')
        
        ax.set_title(firmware_name, fontsize=16)
        # ax.set_xlabel('Time (hours)', fontsize=12)
        # ax.set_ylabel('Basic Blocks Covered', fontsize=12)
        ax.grid(True)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.set_xlim(0, 24)  # Fixed 24-hour range

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
                               color=orig_handle.color, markersize=20, linestyle='')
                legbox = patches.FancyBboxPatch((xdescent, ydescent), width, height,
                                              boxstyle="round,pad=0.5",
                                              edgecolor=orig_handle.color,
                                              facecolor=orig_handle.color, alpha=0.3, transform=trans)
                return [legbox, legline]

        legend_handles = [LegendObject('#2078AA', 'o'), LegendObject('#8FBC8F', 's'), LegendObject('#AE3347', '^')]
        legend_labels = ['MultiFuzz(RR)', 'MultiFuzz(Fuzz)', 'MultiFuzz+FIDO']

        # Add legend
        legend = ax.legend(handles=legend_handles, labels=legend_labels, 
                         loc='upper center', bbox_to_anchor=(0.5, 1.06),
                         ncol=len(legend_handles), fontsize=8, shadow=False, frameon=True,
                         fancybox=True, handler_map={LegendObject: HandlerLegendObject()})
        
        for text in legend.get_texts():
            if 'FIDO' in text.get_text():
                text.set_fontstyle('italic')
                text.set_weight('bold')

        # Save the plot
        plot_file_path = os.path.join(graph_save_directory, f'comparison_plot_combined_{firmware_name}.png')
        plt.savefig(plot_file_path, format='png', dpi=300, bbox_inches='tight')
        print(f'Plot saved to {plot_file_path}')
        plt.close()
        
    except Exception as e:
        print(f"Error processing {firmware_name}: {e}")

def create_combined_plot(firmwares):
    print("Creating combined plot for all firmwares...")
    
    # Create a 2x5 grid of subplots with better proportions
    fig, axs = plt.subplots(3, 7, figsize=(20, 8))
    
    # Adjust subplot spacing for better layout
    plt.subplots_adjust(
        left=0.07,    
        right=0.96,   
        bottom=0.15,  # Reduced to give more space to the plots
        top=0.85,     # Increased to give more space to the plots
        wspace=0.45,   # Adjusted for better horizontal spacing
        hspace=0.7    # Increased for better vertical spacing
    )
    
    # Flatten axs for easier iteration
    axs_flat = axs.flatten()
    
    fig.text(0.02, 0.5, '#BBs Covered', fontsize=20, fontweight='bold', va='center', rotation='vertical')
    fig.text(0.5, 0.04, 'Duration(h)', fontsize=20, fontweight='bold', ha='center')
    
    for idx, firmware_name in enumerate(firmwares):
        print(f'Adding {firmware_name} to combined plot')
        
        # Get directories
        baseline_pattern = os.path.join(base_path, 'results0', f'{firmware_name}_*')
        adapter_pattern = os.path.join(adapter_path, 'results0', f'{firmware_name}_*')
        fuzz_pattern = os.path.join(fuzzed_path, f'{firmware_name}_*')
        
        baseline_dirs = glob.glob(baseline_pattern)
        adapter_dirs = glob.glob(adapter_pattern)
        fuzz_dirs = glob.glob(fuzz_pattern)
        
        if not baseline_dirs or not adapter_dirs:
            print(f"Warning: No data found for {firmware_name}")
            continue
        
        try:
            baseline_data = collect_and_interpolate_data(baseline_dirs)
            adapter_data = collect_and_interpolate_data(adapter_dirs)
            fuzz_data = collect_and_interpolate_data(fuzz_dirs)
            
            ax = axs_flat[idx]
            plot_median_and_range(ax, baseline_data, '#2078AA', 'MultiFuzz(RR)', 'o')
            plot_median_and_range(ax, fuzz_data, '#8FBC8F', 'MultiFuzz(Fuzz)', 's')
            plot_median_and_range(ax, adapter_data, '#AE3347', 'MultiFuzz+FIDO', '^')

 
 
            # if firmware_name in highlight_firmwares:
            #     bbox = ax.get_position()
            #     pad_x = 0.006
            #     pad_y_bottom = 0.02
            #     pad_y_top = 0.03
            #     rect = Rectangle((bbox.x0 - pad_x, bbox.y0 - pad_y_bottom),
            #                      bbox.width + 2*pad_x, bbox.height + pad_y_top + pad_y_bottom,
            #                      transform=fig.transFigure, facecolor="#908e8e", edgecolor='none',
            #                      zorder=2, alpha=0.2)
            #     fig.patches.append(rect)

 
            #     for line in ax.get_lines():
            #         line.set_zorder(3)
            #         line.set_clip_on(False)
 
            #         col.set_zorder(3)
            #         col.set_clip_on(False)
 
            #     for artist in ax.get_children():
            #         try:
            #             if getattr(artist, 'get_zorder', None) and isinstance(artist, plt.Line2D):
            #                 artist.set_zorder(3)
            #         except Exception:
            #             pass
            # else:
 
            #     pass

            # Increase title font size
            ax.set_title(firmware_name, fontsize=17, pad=10)
            ax.grid(True, alpha=0.3)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            
            # Set x-axis limits and ticks
            ax.set_xlim(0, 24)
            ax.xaxis.set_major_locator(MaxNLocator(nbins=4, min_n_ticks=2, integer=True))
            
            # Set y-axis ticks with appropriate formatting
            ax.yaxis.set_major_locator(MaxNLocator(nbins=4, min_n_ticks=2))
            
            # Increase tick label size
            ax.tick_params(axis='both', which='major', labelsize=14)
            
        except Exception as e:
            print(f"Error processing {firmware_name} for combined plot: {e}")
            continue
    
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
                           color=orig_handle.color, markersize=8, linestyle='')
            legbox = patches.FancyBboxPatch((xdescent, ydescent), width, height,
                                          boxstyle="round,pad=0.4",
                                          edgecolor=orig_handle.color,
                                          facecolor=orig_handle.color, alpha=0.3, transform=trans)
            return [legbox, legline]

    legend_handles = [LegendObject('#2078AA', 'o'), LegendObject('#8FBC8F', 's'), LegendObject('#AE3347', '^')]
    legend_labels = ['MultiFuzz(RR)', 'MultiFuzz(Fuzz)', 'MultiFuzz+FIDO']

    # Add legend with better positioning
    legend = fig.legend(handles=legend_handles, labels=legend_labels, 
                       loc='upper center', bbox_to_anchor=(0.5, 0.985),
                       ncol=len(legend_handles), fontsize=14,
                       shadow=False, frameon=True,
                       fancybox=True, handler_map={LegendObject: HandlerLegendObject()},
                       handletextpad=0.4,
                       borderpad=0.4)
    
    for text in legend.get_texts():
        if 'FIDO' in text.get_text():
            text.set_fontstyle('italic')
            text.set_weight('bold')

    # Save the combined plot
    plot_file_path = os.path.join(graph_save_directory, 'comparison_plot_all_firmwares_three.png')
    plt.savefig(plot_file_path, format='png', dpi=300, bbox_inches='tight')
    print(f'Combined plot saved to {plot_file_path}')
    plt.close()

# Process each firmware separately first
# for firmware_name in firmwares:
#     create_plot_for_firmware(firmware_name)

# Then create the combined plot
create_combined_plot(firmwares)
