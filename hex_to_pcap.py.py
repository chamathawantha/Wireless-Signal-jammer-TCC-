#!/usr/bin/env python3
from scapy.all import wrpcap, RadioTap
import re

def hex_to_bytes(hex_str):
    """
    Convert a string of hex (with spaces/newlines) into bytes.
    """
    # Remove all whitespace characters.
    hex_str = re.sub(r'\s+', '', hex_str)
    return bytes.fromhex(hex_str)

def parse_frames_from_section(lines):
    """
    Given a list of lines from one section (handshake or management),
    parse them into a list of frame hex strings.
    Expects frame headers like "Frame 1 (XXX bytes):" and offset lines starting with "0x..."
    """
    frames = []
    current_frame = ""
    in_frame = False
    for line in lines:
        line = line.strip()
        # Check for a frame header (e.g., "Frame 1 (133 bytes):")
        print(line)
        if re.search(r'^Frame\s+\d+', line, re.IGNORECASE) or re.search(r'^Management Frame\s+\d+', line, re.IGNORECASE):
            if current_frame:
                frames.append(current_frame.strip())
                current_frame = ""
            in_frame = True
            continue
        # A separator line indicates the end of a frame block.
        if line.startswith("----"):
            if in_frame and current_frame:
                frames.append(current_frame.strip())
                current_frame = ""
            in_frame = False
            continue
        # If we are in a frame block and the line starts with an offset (e.g., "0x0:"), remove the offset.
        print(in_frame)
        #print(line)
        if in_frame and re.match(r'^0x[0-9A-Fa-f]+:\s*', line):
            line = re.sub(r'^0x[0-9A-Fa-f]+:\s*', '', line)
        if in_frame and line:
            current_frame += " " + line
    if current_frame:
        frames.append(current_frame.strip())
    return frames

def parse_capture_file(filename):
    """
    Parse a file that contains two sections:
      ---- Captured Handshake Data ----
      (handshake frames)
      ---- End of Handshake Data ----
      ---- Captured Management Data ----
      (management frames)
      ---- End of Management Data ----
    Returns two lists: handshake_frames, management_frames.
    This version converts each line to lowercase and checks for keywords.
    """
    with open(filename, "r") as f:
        lines = f.readlines()

    handshake_lines = []
    management_lines = []
    current_section = None

    for line in lines:
        # Remove dashes and trim whitespace, then lowercase
        cleaned = line.replace('-', '').strip().lower()
        if "captured handshake data" in cleaned:
            current_section = "handshake"
            continue
        elif "end of handshake data" in cleaned:
            current_section = None
            continue
        elif "captured management data" in cleaned:
            current_section = "management"
            continue
        elif "end of management data" in cleaned:
            current_section = None
            continue

        if current_section == "handshake":
            handshake_lines.append(line)
        elif current_section == "management":
            management_lines.append(line)

    handshake_frames = parse_frames_from_section(handshake_lines)
    management_frames = parse_frames_from_section(management_lines)
    return handshake_frames, management_frames


def main():
    capture_file = "handshake.txt"  # Your capture file with both sections
    handshake_frames, management_frames = parse_capture_file(capture_file)
    
    print(f"Found {len(handshake_frames)} handshake frames and {len(management_frames)} management frames.")
    
    # Merge both lists into one.
    all_frames = handshake_frames + management_frames

    packets = []
    # Minimal Radiotap header (8 bytes): version (0), pad (0), length (8), present (0)
    minimal_rtap = b'\x00\x00\x08\x00\x00\x00\x00\x00'
    
    for idx, frame in enumerate(all_frames):
        try:
            data = hex_to_bytes(frame)
        except Exception as e:
            print(f"Error converting frame {idx+1}: {e}")
            continue
        print(f"Frame {idx+1}: {len(data)} bytes")
        
        packet_bytes = minimal_rtap + data
        
        try:
            pkt = RadioTap(packet_bytes)
        except Exception as e:
            print(f"Error parsing Radiotap packet for frame {idx+1}: {e}")
            continue
        packets.append(pkt)
    
    output_file = "combined_handshake.pcap"
    # Use linktype 127 (DLT_IEEE802_11_RADIO)
    wrpcap(output_file, packets, linktype=127)
    print(f"Wrote {len(packets)} packets to {output_file}")

if __name__ == "__main__":
    main()
