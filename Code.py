import threading
import time
import tkinter as tk
from tkinter import scrolledtext, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, get_if_addr
from datetime import datetime

# Global variables
sniffing = False
packet_count = 0  # Counter for captured packets
protocol_counts = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Other': 0}  # Protocol counter
traffic_stats = []  # Holds packet count at each second for pattern analysis
suspicious_ips = ["192.168.1.100", "10.0.0.5"]  # Suspicious IPs
HIGH_TRAFFIC_THRESHOLD = 10  # Threshold for high traffic alerts
suspicious_detected = False  # Flag to track if suspicious IPs were detected

# Function to update traffic pattern stats
def update_traffic_pattern():
    global packet_count
    traffic_stats.append(packet_count)
    packet_count = 0  # Reset counter every second

# Function to log alerts or packets to the GUI
def log_packet(packet_info, text_area):
    text_area.insert(tk.END, f"{datetime.now()} - {packet_info}\n")
    text_area.see(tk.END)

# Function to display packet headers in the headers text area
def display_packet_headers(packet, headers_area):
    headers_area.delete(1.0, tk.END)
    headers_area.insert(tk.END, f"Packet Headers:\n{packet.show(dump=True)}\n")
    headers_area.see(tk.END)

# Function to analyse packets and update stats
def process_packet(packet, text_area, suspicious_area, headers_area, traffic_area):
    global packet_count, suspicious_detected
    packet_count += 1  # Increment packet count
    
    if IP in packet:
        ip = packet[IP]
        packet_info = f"IP Packet: {ip.src} -> {ip.dst}"

        # Check for suspicious IPs
        if ip.src in suspicious_ips:
            suspicious_detected = True
            suspicious_area.insert(tk.END, f"Suspicious IP Detected: {ip.src}\n")
            suspicious_area.see(tk.END)

        # Update protocol and log
        if TCP in packet:
            protocol_counts['TCP'] += 1
            packet_info += f" [TCP Port: {packet[TCP].sport} -> {packet[TCP].dport}]"
        elif UDP in packet:
            protocol_counts['UDP'] += 1
            packet_info += f" [UDP Port: {packet[UDP].sport} -> {packet[UDP].dport}]"
        elif ICMP in packet:
            protocol_counts['ICMP'] += 1
            packet_info += " [ICMP]"
        else:
            protocol_counts['Other'] += 1

        log_packet(packet_info, text_area)
        display_packet_headers(packet, headers_area)  # Show headers

        # Update traffic patterns every second
        update_traffic_display(traffic_area)

# Function to update traffic pattern and protocol stats in the GUI
def update_traffic_display(traffic_area):
    traffic_area.delete(1.0, tk.END)
    traffic_area.insert(tk.END, "Traffic Pattern and Protocol Stats:\n")
    for proto, count in protocol_counts.items():
        traffic_area.insert(tk.END, f"{proto}: {count} packets\n")
    
    # Display recent traffic stats for analysis
    traffic_area.insert(tk.END, "\nRecent Traffic Pattern:\n")
    traffic_area.insert(tk.END, " | ".join(map(str, traffic_stats[-10:])))
    traffic_area.see(tk.END)

# Function to monitor traffic and issue high traffic alerts
def monitor_traffic(text_area):
    global packet_count
    while sniffing:
        if packet_count > HIGH_TRAFFIC_THRESHOLD:
            text_area.insert(tk.END, f"Alert: High network traffic detected! Packets captured: {packet_count}\n")
            text_area.see(tk.END)
            packet_count = 0  # Reset packet count after alert
        time.sleep(1)  # Monitor every second

# Function to check for intrusions and update GUI if no intrusion is found
def check_intrusion_status(suspicious_area):
    global suspicious_detected
    while sniffing:
        if not suspicious_detected:
            suspicious_area.delete(1.0, tk.END)
            suspicious_area.insert(tk.END, "No intrusion found.\n")
            suspicious_area.see(tk.END)
        suspicious_detected = False  # Reset the flag after checking
        time.sleep(5)  # Check every 5 seconds

# Function to start packet sniffing on a separate thread
def start_sniffing(interface, text_area, suspicious_area, headers_area, traffic_area):
    global sniffing
    sniffing = True
    global packet_count

    def sniff_packets():
        while sniffing:
            sniff(iface=interface, prn=lambda pkt: process_packet(pkt, text_area, suspicious_area, headers_area, traffic_area), store=False, count=1)

    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True
    sniff_thread.start()

    # Start traffic monitoring
    monitor_thread = threading.Thread(target=monitor_traffic, args=(text_area,))
    monitor_thread.daemon = True
    monitor_thread.start()

    # Start intrusion check
    intrusion_thread = threading.Thread(target=check_intrusion_status, args=(suspicious_area,))
    intrusion_thread.daemon = True
    intrusion_thread.start()

    text_area.insert(tk.END, f"Packet sniffing started on interface {interface}...\n")
    text_area.see(tk.END)

# Function to stop packet sniffing
def stop_sniffing(text_area):
    global sniffing
    sniffing = False
    text_area.insert(tk.END, "Packet sniffing stopped.\n")
    text_area.see(tk.END)

# Function to exit the application
def exit_app(root):
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        root.quit()

# Function to clear the output text area
def clear_output(text_area):
    text_area.delete(1.0, tk.END)

# Function to update IP address when an interface is selected
def update_ip_address(interface_var, ip_label):
    interface = interface_var.get()
    try:
        ip_address = get_if_addr(interface)
        ip_label.config(text=f"IP Address: {ip_address}")
    except Exception as e:
        ip_label.config(text=f"IP Address: Not found ({str(e)})")

# Main GUI function using Tkinter
def create_gui():
    root = tk.Tk()
    root.title("Network Traffic Analyser")

    # Frame for controls
    frame = tk.Frame(root)
    frame.pack(pady=10)

    # Interface Label and Dropdown for Network Interfaces
    interface_label = tk.Label(frame, text="Network Interface:")
    interface_label.grid(row=0, column=0, padx=5, pady=5)
    
    interfaces = get_if_list()
    interface_var = tk.StringVar()
    interface_menu = tk.OptionMenu(frame, interface_var, *interfaces, command=lambda _: update_ip_address(interface_var, ip_label))
    interface_var.set(interfaces[0])
    interface_menu.grid(row=0, column=1, padx=5, pady=5)

    # Label for displaying the IP address
    ip_label = tk.Label(frame, text="IP Address: ")
    ip_label.grid(row=1, column=0, columnspan=2, padx=5, pady=5)

    # Start and Stop buttons
    start_button = tk.Button(frame, text="Start Sniffing", command=lambda: start_sniffing(interface_var.get(), output_area, suspicious_area, headers_area, traffic_area))
    start_button.grid(row=0, column=2, padx=5, pady=5)

    stop_button = tk.Button(frame, text="Stop Sniffing", command=lambda: stop_sniffing(output_area))
    stop_button.grid(row=0, column=3, padx=5, pady=5)

    # Clear Output button
    clear_button = tk.Button(frame, text="Clear Output", command=lambda: clear_output(output_area))
    clear_button.grid(row=0, column=4, padx=5, pady=5)

    # Scrolled Text widget to display output
    output_area = scrolledtext.ScrolledText(root, width=100, height=10)
    output_area.pack(padx=10, pady=10)

    # Scrolled Text widget to display suspicious IP addresses
    suspicious_area_label = tk.Label(root, text="Suspicious IP Addresses Detected:")
    suspicious_area_label.pack()
    suspicious_area = scrolledtext.ScrolledText(root, width=100, height=5, bg='lightyellow')
    suspicious_area.pack(padx=10, pady=10)

    # Scrolled Text widget to display packet headers
    headers_area_label = tk.Label(root, text="Packet Headers:")
    headers_area_label.pack()
    headers_area = scrolledtext.ScrolledText(root, width=100, height=5, bg='lightblue')
    headers_area.pack(padx=10, pady=10)

    # Scrolled Text widget to display traffic patterns and protocol stats
    traffic_area_label = tk.Label(root, text="Traffic Patterns and Protocol Stats:")
    traffic_area_label.pack()
    traffic_area = scrolledtext.ScrolledText(root, width=100, height=5, bg='light green')
    traffic_area.pack(padx=10, pady=10)

    # Exit button
    exit_button = tk.Button(root, text="Exit", command=lambda: exit_app(root))
    exit_button.pack(pady=10)

    root.protocol("WM_DELETE_WINDOW", lambda: exit_app(root))
    root.mainloop()

if __name__ == "__main__":
    create_gui()
