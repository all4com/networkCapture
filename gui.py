import threading
import tkinter as tk
from tkinter import Listbox, Text, Scrollbar, OptionMenu, StringVar, Button, Frame, messagebox
from scapy.all import sniff, TCP, IP, Raw
from datetime import datetime
import psutil
import os
import json

class PacketCaptureGUI:
    def __init__(self, root):
        """Initialize the GUI and packet capture settings."""
        self.root = root
        self.root.title("Redstone Packet Capture")
        self.root.geometry("800x600")
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)  # ウィンドウを閉じるイベントを設定
        
        self.packet_list = []
        self.sniffer_thread = None
        self.sniffing = False

        self.start_button = None

        # Setup GUI layout
        self.setup_interface_selection()
        self.setup_listbox()
        self.setup_text_boxes()
        self.setup_buttons()
        self.load_previous_iface()  # 前回の設定を読み込む


    def setup_interface_selection(self):
        """Setup interface selection dropdown menu."""
        self.interface_frame = Frame(self.root)
        self.interface_frame.pack(fill="x")

        self.iface_var = StringVar()
        self.iface_var.set("Select Interface")

        self.interfaces = self.get_if_list()  # Get a list of interfaces
        self.iface_menu = OptionMenu(self.interface_frame, self.iface_var, *self.interfaces)
        self.iface_menu.pack(side="left")

    def get_if_list(self):
        """Retrieve a list of available network interfaces."""
        interfaces = psutil.net_if_addrs()
        return interfaces

    def setup_listbox(self):
        """Setup the listbox for displaying packet summaries."""
        self.listbox_frame = tk.Frame(self.root)
        self.listbox_frame.pack(side="left", fill="y")

        self.listbox = Listbox(self.listbox_frame, width=40, height=30)
        self.listbox.pack(side="left", fill="y")

        self.scrollbar = Scrollbar(self.listbox_frame)
        self.scrollbar.pack(side="right", fill="y")

        self.listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.listbox.yview)
        
        self.listbox.bind("<<ListboxSelect>>", self.display_packet_details)

    def setup_text_boxes(self):
        """Setup text boxes for packet details and input."""
        self.text_detail = Text(self.root, width=60, height=15, wrap="word", state="disabled")
        self.text_detail.pack(side="top", fill="both", expand=True)

        self.text_input = Text(self.root, width=60, height=15, wrap="word")
        self.text_input.pack(side="bottom", fill="both", expand=True)

    def setup_buttons(self):
        """Setup Start/Stop button for packet capture."""
        self.start_button = Button(self.interface_frame, text="Start", command=self.start_stop_sniffer)
        self.start_button.pack(side="left", padx=10)

    def format_binary_data(self, raw_data):
        """Format raw data into a hex and ASCII string view."""
        hex_output = ""
        ascii_output = ""
        result = ""

        for i in range(len(raw_data)):
            hex_output += f"{raw_data[i]:02x} "
            ascii_output += chr(raw_data[i]) if 32 <= raw_data[i] < 127 else '.'
            
            if (i + 1) % 16 == 0:
                result += f"{hex_output:<48} | {ascii_output}\n"
                hex_output = ""
                ascii_output = ""

        if hex_output:
            result += f"{hex_output:<48} | {ascii_output}\n"
        
        return result

    def display_packet_details(self, event):
        """Display detailed packet information when a listbox item is selected."""
        selection = self.listbox.curselection()
        if selection:
            index = selection[0]
            packet = self.packet_list[index]
            
            self.text_detail.config(state="normal")
            self.text_detail.delete(1.0, tk.END)
            
            if Raw in packet:
                raw_data = packet[Raw].load
                self.text_detail.insert(tk.END, "Data:\n")
                self.text_detail.insert(tk.END, self.format_binary_data(raw_data))
            
            self.text_detail.config(state="disabled")
            self.listbox.see(tk.END)

    def start_stop_sniffer(self):
        """Toggle packet capture start and stop."""
        if not self.sniffing:
            selected_iface = self.iface_var.get()
            if selected_iface == "Select Interface":
                messagebox.showwarning("Warning", "Please select a valid interface.")
                return

            self.sniffing = True
            self.start_button.config(text="Stop")

            self.sniffer_thread = threading.Thread(target=self.packet_sniffer, args=(selected_iface,), daemon=True)
            self.sniffer_thread.start()
        else:
            self.sniffing = False
            self.start_button.config(text="Start")

    def packet_sniffer(self, iface):
        """Capture packets and update the GUI list."""
        def packet_callback(packet):
            if not self.sniffing:
                self.sniffer_thread.join()
                return

            if TCP in packet:
                tcp_layer = packet[TCP]
                if tcp_layer.flags == "PA":
                    self.packet_list.append(packet)
                    
                    src_info = "Srv->Cli" if tcp_layer.sport == [55661, 54631, 56621] else "Cli->Srv"
                    packet_type = int.from_bytes(packet[Raw].load[2:4], byteorder='little')
                    timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
                    data_size = int.from_bytes(packet[Raw].load[0:2], byteorder='little')
                    summary = f"{timestamp} [{src_info}] {hex(packet_type)} ({data_size})"
                    self.listbox.insert(tk.END, summary)
                    self.listbox.see(tk.END)  # Scroll to the bottom

        filter_conditions = "port 55661 or port 54631 or port 56621"
        sniff(iface=iface, filter=filter_conditions, prn=packet_callback)

    def on_closing(self):
        """Save the current interface to a JSON file when closing the window."""
        self.save_current_iface()
        self.root.destroy()

    def load_previous_iface(self):
        """Load the previously used interface from a JSON file."""
        if os.path.exists("setting.json"):
            with open("setting.json", "r") as f:
                data = json.load(f)
                iface = data.get("iface")
                if iface and iface in self.interfaces:
                    self.iface_var.set(iface)
                    self.start_stop_sniffer()  # Automatically start capturing

    def save_current_iface(self):
        """Save the currently selected interface to a JSON file."""
        iface = self.iface_var.get()
        with open("setting.json", "w") as f:
            json.dump({"iface": iface}, f)

# Main loop setup
if __name__ == "__main__":
    root = tk.Tk()
    app = PacketCaptureGUI(root)
    root.mainloop()
