import threading
import tkinter as tk
from tkinter import Listbox, Text, Scrollbar, OptionMenu, StringVar, Button, Frame, messagebox, Menu, Entry
from scapy.all import sniff, TCP, IP, Raw
from datetime import datetime
import psutil
import os
import json
from common import get_packet_name, get_server_name, get_server_port

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
        self.setup_search_bar()
        self.setup_interface_selection()
        self.setup_listbox()
        self.setup_text_boxes()
        self.setup_buttons()
        self.load_previous_iface()  # 前回の設定を読み込む

    def setup_search_bar(self):
        """Setup the search bar for the listbox."""
        self.search_var = tk.StringVar()
        search_frame = Frame(self.root)
        search_frame.pack(fill="x", padx=5, pady=(5, 0))

        search_label = tk.Label(search_frame, text="Search:")
        search_label.pack(side="left")

        self.search_entry = Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side="left", fill="x", expand=True)
        self.search_entry.bind("<KeyRelease>", self.filter_list)
        self.search_entry.bind("<Escape>", self.clear_search)

    def filter_list(self, event=None):
        """Filter listbox items based on search query."""
        query = self.search_var.get().lower()
        self.listbox.delete(0, tk.END)  # Clear the listbox
        for packet in self.packet_list:
            summary = self.get_packet_summary(packet)
            if query in summary.lower():
                self.listbox.insert(tk.END, summary)  # Add matching items

    def clear_search(self, event=None):
        """Clear the search entry field and reset the listbox view."""
        self.search_var.set("")  # Clear the search field
        self.filter_list()       # Reset listbox to show all items

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
        """Setup the listbox for displaying packet summaries with horizontal scroll."""
        self.listbox_frame = Frame(self.root)
        self.listbox_frame.pack(side="left", fill="both", expand=True)

        self.listbox = Listbox(self.listbox_frame, font="TkFixedFont")
        self.listbox.pack(side="left", fill="both", expand=True)

        self.scrollbar_y = Scrollbar(self.listbox_frame)
        self.scrollbar_y.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=self.scrollbar_y.set)
        self.scrollbar_y.config(command=self.listbox.yview)


        self.scrollbar_x = Scrollbar(self.listbox, orient="horizontal")
        self.scrollbar_x.pack(side="bottom", fill="x")
        self.listbox.config(xscrollcommand=self.scrollbar_x.set)
        self.scrollbar_x.config(command=self.listbox.xview)
        self.listbox.bind("<<ListboxSelect>>", self.display_packet_details)

        self.root.bind('<Control-c>', self.copy_selection)
        self.root.bind('<Control-f>', self.search_selection)

    def copy_selection(self, event=None):
        """Copy the selected item from the listbox to the clipboard."""
        selection = self.listbox.curselection()
        if selection:
            index = selection[0]
            item = self.listbox.get(index)
            self.root.clipboard_clear()  # Clear the clipboard
            self.root.clipboard_append(item.split(" ")[-1])  # Append the selected item to the clipboard

    def search_selection(self):
        """Insert the selected item text into the search box for filtering."""
        try:
            selection = self.listbox.get(self.listbox.curselection())
            self.search_var.set(selection.split(" ")[-1])  # Set selected text in search box
            self.filter_list()  # Trigger the filtering to update the listbox
        except tk.TclError:
            pass  # Ignore if no item is selected

    def setup_text_boxes(self):
        """Setup text boxes for packet details and input."""
        self.text_detail = Text(self.root, width=70, wrap="word", state="disabled")
        self.text_detail.pack(side="top", fill="both", expand=True)

        # self.text_input = Text(self.root, width=70, wrap="word")
        # self.text_input.pack(side="bottom", fill="both", expand=True)

    def setup_context_menu(self):
        """Setup context menu for the listbox."""
        self.context_menu = Menu(self.root, tearoff=0)  # context menu
        self.context_menu.add_command(label="Search", command=self.search_selection)  # add find command

        # right click event
        self.listbox.bind("<Button-3>", self.show_context_menu)

    def show_context_menu(self, event):
        """Show context menu on right-click."""
        self.context_menu.post(event.x_root, event.y_root)

    def setup_buttons(self):
        """Setup Start/Stop button for packet capture."""
        self.start_button = Button(self.interface_frame, text="Start", command=self.start_stop_sniffer)
        self.start_button.pack(side="left", padx=10)
        self.setup_context_menu()

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

                    self.listbox.see(tk.END)  # Scroll to the bottom
                    query = self.search_var.get().lower()
                    summary = self.get_packet_summary(packet)
                    if not query or query in summary.lower():
                        self.listbox.insert(tk.END, summary)

        filter_conditions = ""
        for item in get_server_port():
            filter_conditions = filter_conditions +  "port {} or ".format(item)
        filter_conditions = filter_conditions[:-3]
        sniff(iface=iface, filter=filter_conditions, prn=packet_callback)


    def get_packet_summary(self, packet):
        tcp_layer = packet[TCP]
        if tcp_layer.sport in get_server_port() :
            src_info = "{}->C".format(get_server_name(tcp_layer.sport)[0:1])
        else:
            src_info = "C->{}".format(get_server_name(tcp_layer.dport)[0:1])
        packet_type = int.from_bytes(packet[Raw].load[2:4], byteorder='little')
        packet_name = get_packet_name(packet_type)
        timestamp = datetime.now().strftime('%Y/%m/%d %H:%M:%S')
        data_size = int.from_bytes(packet[Raw].load[0:2], byteorder='little')
        summary = f"{timestamp} [{src_info}] {hex(packet_type)} ({data_size:4}) {packet_name}"
        return summary

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
