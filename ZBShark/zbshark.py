from ast import Num, Str
from typing import Dict, List, Union
from xmlrpc.client import Boolean
import pyshark
import sys
import matplotlib.pyplot as plt
import numpy as np

###INITIALISE HEXADECIMAL DICTIONARIES
# Initialize a dictionary to map wpan frame type values to their names
wpan_frame_type_names = {
    '0x0001': 'Data',
    '0x0003': 'Command',
    '0x0002': 'Acknowledgment',
    '0x0000': 'Beacon'
}
# Initialize a dictionary to map addressing mode values to their names
addressing_mode_names = {
    '0x0002': 'Short Address/ 16-bit',
    '0x0003': 'Extended Address/ 64-bit',
    '0x0000': 'Reserved'
}
# Initialize a dictionary to map zigbee frame type values to their names
zigbee_frame_types_names = {
    '0x0000': 'Data',
    '0x0001': 'Command',
    '0x0002': 'Acknowledgment',
    '0x0003': 'Beacon',
}
# Initialize a dictionary to map zigbee protocol values to their names
protocol_versions = {
    '1': 'Zigbee 2004',
    '2': 'Zigbee Pro',
    '3': 'Zigbee Green Power'
}
# Initialize a dictionary to map zigbee security levels to their names
zigbee_security_levels = {
    '0x00': "None (Highly Vulnerable)",
    '0x01': "MIC-32",
    '0x02': "MIC-64",
    '0x03': "MIC-128",
    '0x04': "ENC (AES Encryption)",
    '0x05': "AES ENC-MIC-32",
    '0x06': "AES ENC-MIC-64",
    '0x07': "AES ENC-MIC-128"
}
# Initialize a dictionary to map zigbee key_identtifiers to their names
key_identifiers = {
    '0x00': 'data key',
    '0x01': 'network key',
    '0x02': 'key-transport key',
    '0x03': 'key-load key'
}
# Initialize a dictionary to map zigbee transport key types to their names
transport_key_types = {
    '0x00': "Trust Center Master Key",
    '0x01': "Standard Network Key",
    '0x02': "Application Master Key",
    '0x03': "Application Link Key",
    '0x04': "Trust Center Link Key",
    '0x05': "High-Security Network Key"
}
# Initialize a dictionary to map zigbee network command frames values to their names
zigbee_network_command_frames = {
    '0x01': "Route Request",
    '0x02': "Route Reply",
    '0x03': "Network Status",
    '0x04': "Leave",
    '0x05': "Route Record",
    '0x06': "Rejoin Request",
    '0x07': "Rejoin Response",
    '0x08': "Link Status",
    '0x09': "Network Report",
    '0x0a': "Network Update",
    '0x0b': "End Device Timeout Request",
    '0x0c': "End Device Timeout Response",
    # 0x0D - 0xFF are Reserved
}
# Initialize a dictionary to map zigbee APS layer delivery modes to their names
aps_delivery_modes = {
    '0x00': 'Unicast',
    '0x01': 'Reserved',
    '0x02': 'Broadcast',
    '0x03': 'Group addressing'
}
# Initialize a dictionary to map zigbee APS layer cluster identifiers to their names
aps_cluster_identifier = {
    # Functional Domain: General
    '0x0000': "basic",
    '0x0001': "power_configuration",
    '0x0002': "device_temperature_configuration",
    '0x0003': "identify",
    '0x0004': "groups",
    '0x0005': "scenes",
    '0x0006': "on_off",
    '0x0007': "on_off_switch_configuration",
    '0x0008': "level_control",
    '0x0009': "alarms",
    '0x000a': "time",
    '0x000b': "rssi_location",
    '0x000c': "analog_input",
    '0x000d': "analog_output",
    '0x000e': "analog_value",
    '0x000f': "binary_input",
    '0x0010': "binary_output",
    '0x0011': "binary_value",
    '0x0012': "multistate_input",
    '0x0013': "multistate_output",
    '0x0014': "multistate_value",
    '0x0015': "commissioning",
    # 0x0016 - 0x00ff reserved
    # Functional Domain: Closures
    '0x0100': "shade_configuration",
    # 0x0101 - 0x01ff reserved
    # Functional Domain: HVAC
    '0x0200': "pump_configuration_and_control",
    '0x0201': "thermostat",
    '0x0202': "fan_control",
    '0x0203': "dehumidification_control",
    '0x0204': "thermostat_user_interface_configuration",
    # 0x0205 - 0x02ff reserved
    # Functional Domain: Lighting
    '0x0300': "color_control",
    '0x0301': "ballast_configuration",
    # Functional Domain: Measurement and sensing
    '0x0400': "illuminance_measurement",
    '0x0401': "illuminance_level_sensing",
    '0x0402': "temperature_measurement",
    '0x0403': "pressure_measurement",
    '0x0404': "flow_measurement",
    '0x0405': "relative_humidity_measurement",
    '0x0406': "occupancy_sensing",
    # Functional Domain: Security and safethy
    '0x0500': "ias_zone",
    '0x0501': "ias_ace",
    '0x0502': "ias_wd",
    # Functional Domain: Protocol Interfaces
    '0x0600': "generic_tunnel",
    '0x0601': "bacnet_protocol_tunnel",
    '0x0602': "analog_input_regular",
    '0x0603': "analog_input_extended",
    '0x0604': "analog_output_regular",
    '0x0605': "analog_output_extended",
    '0x0606': "analog_value_regular",
    '0x0607': "analog_value_extended",
    '0x0608': "binary_input_regular",
    '0x0609': "binary_input_extended",
    '0x060a': "binary_output_regular",
    '0x060b': "binary_output_extended",
    '0x060c': "binary_value_regular",
    '0x060d': "binary_value_extended",
    '0x060e': "multistate_input_regular",
    '0x060f': "multistate_input_extended",
    '0x0610': "multistate_output_regular",
    '0x0611': "multistate_output_extended",
    '0x0612': "multistate_value_regular",
    '0x0613': "multistate_value",
    # Smart Energy Profile Clusters
    '0x0700': "price",
    '0x0701': "demand_response_and_load_control",
    '0x0702': "metering",
    '0x0703': "messaging",
    '0x0704': "smart_energy_tunneling",
    '0x0705': "prepayment",
    # Functional Domain: General
    # Key Establishment
    '0x0800': "key_establishment",
}
# Initialize a dictionary to map zigbee APS layer profile identifiers to their names
aps_profile_identifiers = {
    '0x0000': "Zigbee_Device_Profile",
    '0x0101': "IPM_Industrial_Plant_Monitoring",
    '0x0104': "HA_Home_Automation",
    '0x0105': "CBA_Commercial_Building_Automation",
    '0x0107': "TA_Telecom_Applications",
    '0x0108': "HC_Health_Care",
    '0x0109': "SE_Smart_Energy_Profile",
}
# Initialize a dictionary to map zigbee ZCL layer frame types to their names
zcl_frame_types = {
    '0x00': "Profile-Wide",
    '0x01': "Cluster-Specific",
    '0x02': "Manufacturer-Specific",
    # Add more frame types as needed
}
# Initialize a dictionary to map zigbee ZCL layer command frames to their names
zcl_command_frames = {
    "0x00": "read_attributes",
    "0x01": "read_attributes_response",
    "0x02": "write_attributes",
    "0x03": "write_attributes_undivided",
    "0x04": "write_attributes_response",
    "0x05": "write_attributes_no_response",
    "0x06": "configure_reporting",
    "0x07": "configure_reporting_response",
    "0x08": "read_reporting_configuration",
    "0x09": "read_reporting_configuration_response",
    "0x0a": "report_attributes",
    "0x0b": "default_response",
    "0x0c": "discover_attributes",
    "0x0d": "discover_attributes_response",
    "0x0e": "read_attributes_structured",
    "0x0f": "write_attributes_structured",
    "0x10": "write_attributes_structured_response",
    "0x11": "discover_commands_received",
    "0x12": "discover_commands_received_response",
    "0x13": "discover_commands_generated",
    "0x14": "discover_commands_generated_response",
    "0x15": "discover_attributes_extended",
    "0x16": "discover_attributes_extended_response",
    # "0x17" - "0xff" Reserved
}
# Initialize a dictionary to map zigbee ZCL layer attributes to their names
zcl_attributes = {
    '0x0000': 'Manufacture-Specific Attr',
    '0x0004': 'Manufacturer Name',
    '0x0005': 'Model Identifier',
    '0x0006': 'Date Code',
    '0x0007': 'Power Source',
    '0x0010': 'Location Description',
    '0x0011': 'Physical Environment',
    '0x0014': 'Device Enabled',
    '0x0020': 'Alarm Mask',
    '0x0021': 'Battery Voltage',
    '0x0029': 'Temperature',
    '0x0086': 'Reserved',
    '0x0087': 'Reserved',
    '0x4000': 'Software Build ID'
}


###ASCII Art
zbshark_logo = '''
███████╗██████╗ ███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗    
╚══███╔╝██╔══██╗██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝    
  ███╔╝ ██████╔╝███████╗███████║███████║██████╔╝█████╔╝     
 ███╔╝  ██╔══██╗╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗     
███████╗██████╔╝███████║██║  ██║██║  ██║██║  ██║██║  ██╗    
╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝    
'''                                                         


###FUNCTIONS

# Find the total number of captured packets in the .pcap/.pcapnng file
def cap_len(cap) -> int:
    num = 0
    for packet in cap:
        num +=1
    return num

# Extract the protocols discovered in the capture file along with its frequency
def extract_protocols(cap) -> Dict:
    protocols = {}
    # Iterate through each packet
    for packet in cap:
        # Check if WPAN layer is present
        if 'wpan' in packet:
            # Check if Zigbee Network Layer is present
            if 'zbee_nwk' in packet:
                protocol = 'Zigbee'
            else:
                protocol = 'IEEE 802.15.4'
        else:
            # If no WPAN layer, consider other protocols
            # Extract protocol from the highest layer
            protocol = packet.transport_layer if packet.transport_layer else packet.highest_layer
        
        # Update the protocol count
        if protocol in protocols:
            protocols[protocol] += 1
        else:
            protocols[protocol] = 1
    return protocols

# Extract the Source Addresses discovered in the capture file along with its frequency
def extract_src_add(cap) -> Dict:
    src_adds = {}
    found_src = 0
    # Iterate through each packet
    for packet in cap:
        src_add = None
        # Check if WPAN layer is present
        if 'wpan' in packet:
            # Check if Source Address Present
            try:
                found_src = 1  
                src_add = packet.wpan.src16  
            except:
                continue
                
            # Update the collection of source addresses
            if src_add is not None and src_add in src_adds:
                src_adds[src_add] += 1
            elif src_add is not None:
                src_adds[src_add] = 1
            else:
                continue
    if found_src == 0:
        print("\033[94m\033[1mCouldn't find any source addresses")
        return None
    return src_adds
# Extract the Source Addresses discovered in the capture file along with its frequency
def extract_dest_add(cap) -> Dict:
    dest_adds = {}
    found_dest = 0
    # Iterate through each packet
    for packet in cap:
        dest_add = None
        # Check if WPAN layer is present
        if 'wpan' in packet:
            # Check if Destination Address Present
            try:
                found_dest = 1  
                dest_add = packet.wpan.dst16  
                if dest_add == "0xffff":
                    dest_add = "0xffff(Broadcast)"
            except:
                continue  
            # Update the collection of source addresses
            if dest_add is not None and dest_add in dest_adds:
                dest_adds[dest_add] += 1
            elif dest_add is not None:
                dest_adds[dest_add] = 1
            else:
                continue
    if found_dest == 0:
        print("\033[94m\033[1mCouldn't find any destination addresses")
        return None
    return dest_adds
# Extract the PAN Addresses discovered in the capture file along with its frequency
def extract_pan_add(cap) -> Dict:
    pan_adds = {}
    found_pan = 0
    # Iterate through each packet
    for packet in cap:
        pan_add = None
        # Check if WPAN layer is present
        if 'wpan' in packet:
            # Check if PAN Address Present
            try:
                found_pan = 1  
                pan_add = packet.wpan.dst_pan  
                if pan_add == "0xffff":
                    pan_add = "0xffff(Beacon)"
            except:
                continue
            # Update the collection of source addresses
            if pan_add is not None and pan_add in pan_adds:
                pan_adds[pan_add] += 1
            elif pan_add is not None:
                pan_adds[pan_add] = 1
            else:
                continue
    if found_pan == 0:
        print("\033[94m\033[1mCouldn't find any pan addresses")
        return None
    return pan_adds

# def extract_wpan_ftype(cap) -> Dict:
#     # Initialize counters for different frame types
#     frame_counts = {frame_type: 0 for frame_type 
#                         in wpan_frame_type_names.values()}

#     # Iterate through each packet in the capture
#     for packet in cap:
#         try:
#             # Extract the frame type from the packet
#             frame_type_value = packet.wpan.frame_type
#             # Map the frame type value to its corresponding name
#             frame_type_name = wpan_frame_type_names[frame_type_value]
#             # If the frame type is found in the dictionary, increment the corresponding counter
#             if frame_type_name:
#                 frame_counts[frame_type_name] += 1
#         except AttributeError:
#             # If the frame type attribute is not found, continue to the next packet
#             continue
#     return frame_counts


# Maps the hexadecimal values extracted from specific attributes present in specified zigbee layer using the dictionary provided
def extract_packet_info(cap, layer: str, attribute: str, value_map: Dict[Union[int, str], str], return_max: bool = False, non_zero_only: bool = False) -> Union[Dict, tuple]:
    """
    Extracts information from packets captured in a PyShark capture.

    Args:
    - cap (PyShark capture): The captured packets.
    - layer (str): The layer from which to extract information (e.g., 'wpan', 'zbee_nwk').
    - attribute (str): The attribute to extract (e.g., 'frame_type', 'src_addr_mode').
    - value_map (Dict[Union[int, str], str]): A dictionary mapping attribute values to their corresponding names.
    - return_max (bool, optional): Whether to return only the maximum value and its count. Defaults to False.

    Returns:
    - info (Dict): A dictionary containing the counts of different attribute values, or a tuple containing the maximum value and its count.
    """
    # Initialize counters for different attribute values
    info = {val: 0 for val in value_map.values()}

    # Iterate through each packet in the capture
    for packet in cap:
        try:
            # Extract the attribute value from the packet
            attr_value = getattr(getattr(packet, layer), attribute)
            # Map the attribute value to its corresponding name
            attr_name = value_map[attr_value]

            # If the attribute value is found in the dictionary, increment the corresponding counter
            if attr_name:
                info[attr_name] += 1
        except AttributeError:
            # If the attribute is not found, continue to the next packet
            continue
    if non_zero_only:
        # Filter dictionary to include only non-zero values
        info = {key: val for key, val in info.items() if val != 0}

    if return_max:
        # Find the maximum value and its count
        return max(info, key=info.get)
    else:
        return info

# Finds extended 64-bit source addresses from zigbee network layer and attemps to map it to the truncated 16-bit address given by the coordinated in the PAN network 
def ext_src_mapping(cap):
    ext_map = []
    src_map = []
    # Iterate through eahc packet
    for packet in cap:
        # Check if Zigbee Network layer is present
        if "zbee_nwk" in packet:
            try:
                ext_src = packet.zbee_nwk.zbee_sec_src64
                if ext_src not in ext_map:
                    ext_map.append(ext_src)
                else:
                    continue
                src = packet.zbee_nwk.src
                src_map.append(f"{ext_src}({src})")
            except:
                continue
    if len(src_map) != 0:
        print(f"\033[92m\033[1mExtended Source Addresses Found:\033[0m\033[0m {src_map}")
        return

# Maps the hexadecimal values extracted from specific attributes present in specified zigbee layer using the dictionary provided
def extract_profilecommands(cap):
    # Initialize counters for different frame types
    frame_counts = {frame_type: 0 for frame_type 
                        in zcl_command_frames.values()}

    # Iterate through each packet in the capture
    for packet in cap:
        try:
            if packet.zbee_zcl.type == "0x00":
                # Extract the frame type from the packet
                frame_type_value = packet.zbee_zcl.cmd_id
                # Map the frame type value to its corresponding name
                frame_type_name = zcl_command_frames[frame_type_value]
                # If the frame type is found in the dictionary, increment the corresponding counter
                if frame_type_name:
                    frame_counts[frame_type_name] += 1
        except AttributeError:
            # If the frame type attribute is not found, continue to the next packet
            continue
        non_zero_commands = {key: val for key, val in frame_counts.items() if val != 0}
    return non_zero_commands
# Extracts the string values found in the ZCL layer
def extract_profile_strings(cap):
    # Initialize counters for different frame types
    string_list = []

    # Iterate through each packet in the capture
    for packet in cap:
        try:
            # Extract the frame type from the packet
            string_val = packet.zbee_zcl.attr_str
            if string_val not in string_list:
                string_list.append(string_val)
            # If the frame type is found in the dictionary, increment the corresponding counter
        except AttributeError:
            # If the frame type attribute is not found, continue to the next packet
            continue
    return string_list
# Finds the average packet length the in the capture file
def avg_pkt_len(cap):
    pkt_len = []
    # Iterate through each packet in the capture
    for packet in cap:
        # Check if WPAN-TAP layer is present
        if 'wpan-tap' in packet:
            pkt_len.append(int(packet["wpan-tap"].length) + 
                int(packet["wpan-tap"].data_length))
    if len(pkt_len) != 0:            
        avg = sum(pkt_len)/len(pkt_len)
        print(f"\033[92m\033[1mAverage packet length :\033[0m\033[0m {avg}")
    else:
        return
# Finds the channel at which the sniffer has sniffed the packets
def detect_channel(cap):
    channel = None
    for packet in cap:
        # Check if WPAN-TAP layer is present
        if 'wpan-tap' in packet:
            channel = packet["wpan-tap"].ch_num
            print(f"\033[92m\033[1mSniffing Channel Detected:\033[0m\033[0m {channel}")
            return
    print("\033[94m\033[1mSniffing Channel not detected!!\033[0m\033[0m")
    return
# Checks if Frame Check Sequence is enabled
def detect_fcs(cap):
    fcs = None
    for packet in cap:
        # Check if WPAN-TAP layer is present
        if 'wpan-tap' in packet:
            fcs_type = packet["wpan-tap"].fcs_type
            if fcs_type != "0":
                fcs += 1
    if fcs is not None:
        print(f"\033[92m\033[1mFrame Check Sequence (Error Handling):\033[0m\033[0m detected in {fcs} packets.")
        return
    print("\033[94m\033[1mFrame Check Sequence (Error Handling) not detected!\033[0m")
# Checks if Zigbee Network Security is enabled
def detect_zb_nwk_sec(cap):
    zb_pck = 0
    sec_pck = 0
    for packet in cap:
        if "zbee_nwk" in packet:
            zb_pck += 1
            if packet.zbee_nwk.security == "True":
                sec_pck += 1
    if zb_pck == 0:
        print("\033[94m\033[1mFailed to find any Zigbee Packets!!\033[0m\033[0m")
    else:
        print(f"\033[92m\033[1mSecurity Enabled:\033[0m\033[0m {sec_pck} out of {zb_pck} Zigbee Packets ({sec_pck/zb_pck*100}%)")
# Checks if Zigbee APS Security is enabled
def detect_aps_sec(cap):
    zb_pck = 0
    sec_pck = 0
    for packet in cap:
        if "zbee_aps" in packet:
            zb_pck += 1
            if packet.zbee_aps.security == "True":
                sec_pck += 1
    if zb_pck == 0:
        print("\033[94m\033[1mFailed to find any Zigbee Packets!!\033[0m\033[0m")
    else:
        print(f"\033[92m\033[1mSecurity Enabled:\033[0m\033[0m {sec_pck} out of {zb_pck} Zigbee Packets ({sec_pck/zb_pck*100}%)")

# Checks if Number only genegerated once (NONCE) is enabled
def detect_zb_ext_nonce(cap):
    zb_pck = 0
    n_pck = 0
    for packet in cap:
        try:
            if "zbee_nwk" in packet:
                zb_pck += 1
                if packet.zbee_nwk.zbee_sec_ext_nonce:
                    n_pck += 1
        except:
            continue
    if zb_pck == 0:
        print("\033[94m\033[1mFailed to find any Zigbee Packets!!\033[0m\033[0m")
    else:
        print(f"\033[92m\033[1mNonce Enabled (Freshness):\033[0m\033[0m {n_pck} out of {zb_pck} Zigbee Packets ({n_pck/zb_pck*100}%)")           
# Checks if Zigbee Counter is enabled
def detect_zb_counter(cap):
    zb_pck = 0
    n_pck = 0
    for packet in cap:
        try:
            if "zbee_nwk" in packet:
                zb_pck += 1
                if packet.zbee_nwk.zbee_sec_counter:
                    n_pck += 1
        except:
            continue
    if zb_pck == 0:
        print(f"\033[94m\033[1mFailed to find any Zigbee Packets!!\033[0m\033[0m")
    else:
        print(f"\033[92m\033[1mCounter Enabled (Integrity):\033[0m\033[0m {n_pck} out of {zb_pck} Zigbee Packets ({n_pck/zb_pck*100}%)")           

# Tries to extract the session key if present
def detect_session_key(cap) -> Boolean:
    s_keys = []
    for packet in cap:
        try:
            if 'zbee_sec_key' in packet.zbee_nwk.field_names:
                s_key = packet.zbee_nwk.zbee_sec_key
                if s_key not in s_keys:
                    s_keys.append(s_key)  
        except:
            continue
    if len(s_keys):
        print(f"\033[92m\033[1mSession Keys Detected:\033[0m\033[0m {s_keys}")
        return 1
    else:
        print("\033[94m\033[1mNo session key detected!\033[0m\033[0m") 
        return 0
# Tries to extract the transport key if present
def detect_transport_key(cap) -> Boolean:
    t_keys = []
    keys = []
    for packet in cap:
        try:
            if 'zbee_sec_key' in packet.zbee_aps.field_names:
                t_key = packet.zbee_aps.zbee_sec_key
                if t_key not in keys:
                    keys.append(t_key)
                    try:
                        t_keys.append(f"{t_key}[{packet.zbee_aps.zbee_sec_decryption_key}]")
                    except:
                        t_keys.append(t_key)
            if 'cmd_key' in packet.zbee_aps.field_names:
                t_key = packet.zbee_aps.cmd_key
                if t_key not in keys:
                    keys.append(t_key)
                    try:
                        kname = transport_key_types[packet.zbee_aps.cmd_key_type]
                        t_keys.append(f"{t_key}[{kname}]")
                    except:
                        t_keys.append(t_key)

        except:
            continue
    if len(t_keys):
        print(f"\033[92m\033[1mAPS Keys Detected:\033[0m\033[0m {t_keys}")
        return 1
    else:
        print("\033[94m\033[1mNo key detected!\033[0m\033[0m") 
        return 0

# Plots and saves the graphical respresentation of the specified dictionary
def dict_graph(data_dict, y_label, x_label, file_name):
    """
    Plots and saves the graphical respresentation of the specified dictionary

    Parameters:
        data_dict(dict): A dictionary where keys are hex strings and values are their frequencies.
        y_label (str): Label for the y-axis.
        x_label (str): Label for the x-axis.
        file_name (str): The path where the graph image will be saved.
    """
    try:
        plt.style.use('ggplot')
        y_pos = np.arange(len(list(data_dict.keys())))
        plt.figure(figsize=(14, 8))
        plt.bar(y_pos,list(data_dict.values()),align='center',alpha=0.5,color=['b','g','r','c','m'])
        plt.xticks(y_pos,list(data_dict.keys()))
        plt.ylabel(y_label)
        plt.xlabel(x_label)
        plt.savefig(f"{file_name}.png")
        print(f"\033[94m\033[1m{file_name}.png saved successfully in the code repository!!\033[0m\033[0m")
        plt.close()
    except:
        print(f"\033[94m\033[1mFailed to save {file_name}.png graph.\033[0m\033[0m")

# Summary tool that makes use of all the predefined functions to summarise the packet capture
def sniff_summary(file_path):
    try:
        cap = pyshark.FileCapture(file_path)
        # GENERAL SUMMARY (Contextual Information)
        print("\n\033[93m\033[1m***CONTEXT SUMMARY***\033[0m\033[0m\n")
        print(f"\033[92m\033[1mTotal number of packets sniffed\033[0m\033[0m: {cap_len(cap)}")
        detect_channel(cap)
        detect_fcs(cap)
        avg_pkt_len(cap)
        # WPAN LAYER SUMMARY
        print("\n\033[93m\033[1m***WPAN LAYER SUMMARY***\033[0m\033[0m\n")
        ptcl_dict = extract_protocols(cap)
        print(f"\033[92m\033[1mProtocols detected\033[0m\033[0m: {ptcl_dict}")
        dict_graph(ptcl_dict, "Number of Packets", "Protocols", "protocols")
        print(f"\033[92m\033[1mWPAN Frame Types detected\033[0m\033[0m: {extract_packet_info(cap, 'wpan', 'frame_type', wpan_frame_type_names)}")
        print(f"\033[92m\033[1mMost Common Source Addressing Mode\033[0m\033[0m: {extract_packet_info(cap, 'wpan', 'src_addr_mode', addressing_mode_names, return_max=True)}")
        print(f"\033[92m\033[1mMost Common Destination Addressing Mode\033[0m\033[0m: {extract_packet_info(cap, 'wpan', 'dst_addr_mode', addressing_mode_names, return_max=True)}")
        src_dict = extract_src_add(cap)
        print(f"\033[92m\033[1mUnique Source Addresses detected\033[0m\033[0m: {src_dict}")
        dict_graph(src_dict, "Number of Packets", "Source Address", "src_addresses")
        print(f"\033[92m\033[1mUnique Destination Addresses detected\033[0m\033[0m: {extract_dest_add(cap)}")
        pan_dict = extract_pan_add(cap)
        print(f"\033[92m\033[1mUnique PAN Addresses detected\033[0m\033[0m: {pan_dict}")
        dict_graph(pan_dict, "Number of Packets", "PAN Address", "pan_addresses")
        ext_src_mapping(cap)
        # ZIGBEE NETWORK LAYER SUMMARY
        print("\n\033[93m\033[1m***ZIGBEE NETWORK LAYER SUMMARY***\033[0m\033[0m\n")
        print(f"\033[92m\033[1mZigbee Frame Types detected\033[0m\033[0m: {extract_packet_info(cap, 'zbee_nwk', 'frame_type', zigbee_frame_types_names)}")
        detect_zb_nwk_sec(cap)
        print(f"\033[92m\033[1mMost common Zigbee Version Used\033[0m\033[0m: {extract_packet_info(cap, 'zbee_nwk', 'proto_version', protocol_versions, True)}")
        print(f"\033[92m\033[1mMost common Zigbee Security Level Used\033[0m\033[0m: {extract_packet_info(cap, 'zbee_nwk', 'zbee_sec_sec_level', zigbee_security_levels, True)}")
        print(f"\033[92m\033[1mZigbee Key-ID(s) detected\033[0m\033[0m: {extract_packet_info(cap, 'zbee_nwk', 'zbee_sec_key_id', key_identifiers)}")
        detect_zb_ext_nonce(cap)
        detect_zb_counter(cap)
        has_skey = detect_session_key(cap)
        if has_skey:
            zbee_cmdnds = extract_packet_info(cap, 'zbee_nwk', 'cmd_id', zigbee_network_command_frames, non_zero_only=True)
            print(f"\033[92m\033[1mZigbee Commands detected\033[0m\033[0m: {zbee_cmdnds}")
            dict_graph(zbee_cmdnds, "Number of Packets" ,"Zigbee Commands", "Zigbee Commands")
        # ZIGBEE APS LAYER SUMMARY
        print("\n\033[93m\033[1m***ZIGBEE APS LAYER SUMMARY***\033[0m\033[0m\n")
        print(f"\033[92m\033[1mPacket Delivery Mode(s) detected\033[0m\033[0m: {extract_packet_info(cap, 'zbee_aps', 'delivery', aps_delivery_modes)}")
        detect_aps_sec(cap)
        detect_transport_key(cap)
        # Below given information can only be extracted if the session key is known
        if has_skey:
            zbee_clusters = extract_packet_info(cap, 'zbee_aps', 'cluster', aps_cluster_identifier, return_max=False, non_zero_only=True)
            print(f"\033[92m\033[1mZCL Clusters Discovered\033[0m\033[0m: {zbee_clusters}")
            dict_graph(zbee_clusters, "Number of Packets", "Zigbee Clusters", "Zigbee Clusters")
            print(f"\033[92m\033[1mZCL Profiles Discovered\033[0m\033[0m: {extract_packet_info(cap, 'zbee_aps', 'profile', aps_profile_identifiers, return_max=False, non_zero_only=True)}")
            # ZCL LAYER SUMMARY
            print("\n\033[93m\033[1m***ZCL LAYER SUMMARY**\033[0m\033[0m\n")
            print(f"\033[92m\033[1mZCL Frame Type Detected\033[0m\033[0m: {extract_packet_info(cap, 'zbee_zcl', 'type', zcl_frame_types)}")
            zcl_commands= extract_profilecommands(cap)
            print(f"\033[92m\033[1mZCL Commands Detected (Profile Wide Frames ONLY) \033[0m\033[0m: {zcl_commands}")
            dict_graph(zcl_commands, "Number of Packets", "ZCL Commands", "ZCL Commands")
            print(f"\033[92m\033[1mZCL Strings Detected (Profile Wide Frames ONLY) \033[0m\033[0m: {extract_profile_strings(cap)}")
            print(f"\033[92m\033[1mZCL Attribute Types Detected (Profile Wide Frames ONLY) \033[0m\033[0m: {extract_packet_info(cap, 'zbee_zcl', 'zbee_zcl_general_basic_attr_id', zcl_attributes, non_zero_only=True)}")
            print("\n")
    except:
        print("Failed to execute the summary code.")

# Displays the filtered packets (uses Wireshark filters)
def sniff_with_filter(file_path, filter):
    """
    Capture packets from a file with a specified Wireshark filter and print packet details.
    
    Parameters:
        file_path (str): Path to the pcap file to capture packets from.
        filter (str): Wireshark filter string to apply.
    """
    cap = pyshark.FileCapture(file_path, display_filter=filter)
    for packet in cap:
        packet.pretty_print()
# Captures the packets provided a suitable sniffing tool
def live_capture(interface, file_name, pkt_num=100):
    """
    Capture packets using PyShark from the specified interface and save them to a file.
    
    Parameters:
        interface (str): Name of the network interface to capture packets from.
        file_name (str): Name of the file to save captured packets.
        pkt_num (int): Number of packets to capture (default is 100).
    """
    cap = pyshark.LiveCapture(interface=interface, output_file=file_name)
    print(f"Capturing packets from interface {interface}...")
    
    # Start capturing packets
    cap.sniff_continuously(packet_count=pkt_num)
    
    # Print packet details simultaneously
    for packet in cap:
        print(packet)

# Guidance function to use ZBShark
def print_usage():
    print("Usage: python3 zbshark.py [option]")
    print("Options:")
    print("  live_capture <interface> <output_file> <packet_number>")
    print("  sniff_summary <file_path>")
    print("  sniff_with_filter <file_path> <filter_name>")
    print("  -h, --help: Show this help message")
    sys.exit(1)

# Code initially executes here
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()

    option = sys.argv[1]
    # Help Function
    if option in ("-h", "--help"):
        print_usage()
    # Initiates Live Capture Function
    elif option == "live_capture":
        if len(sys.argv) != 5:
            print("Error: live_capture option requires <interface>, <output_file>, and <packet_number>")
            print_usage()
        interface = sys.argv[2]
        out_file_name = sys.argv[3]
        pkt_num = int(sys.argv[4])
        print(zbshark_logo)
        live_capture(interface, out_file_name, pkt_num)
    # Initiates Summary Function
    elif option == "sniff_summary":
        if len(sys.argv) != 3:
            print("Error: sniff_summary option requires <file_path>")
            print_usage()
        file_path = sys.argv[2]
        print(zbshark_logo)
        sniff_summary(file_path)
    # Inititates the filter function
    elif option == "sniff_with_filter":
        if len(sys.argv) != 4:
            print("Error: sniff_with_filter option requires <file_path> and <filter_name>")
            print_usage()
        file_path = sys.argv[2]
        filter_name = sys.argv[3]
        print(zbshark_logo)
        sniff_with_filter(file_path, filter_name)
    else:
        # In case the right functions not mentioned
        print(f"Error: Unknown option '{option}'")
        print_usage()
