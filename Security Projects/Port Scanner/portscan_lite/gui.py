#!/usr/bin/env python3
"""PortScan-Lite GUI: A Tkinter-based graphical interface for the port scanner."""

import queue
import re
import threading
import tkinter as tk
import webbrowser
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from portscan_lite.scanner import check_port, get_cve_search_url, get_hardening_tip, load_ports


class PortScanGUI:
    # Dark theme colors
    BG_COLOR = "black"
    FG_COLOR = "white"
    ENTRY_BG = "#1a1a1a"
    BUTTON_BG = "#333333"
    BUTTON_ACTIVE = "#444444"

    def __init__(self, root):
        self.root = root
        self.root.title("PortScan-Lite")
        self.root.geometry("600x500")
        self.root.minsize(400, 300)
        self.root.configure(bg=self.BG_COLOR)

        self.queue = queue.Queue()
        self.scanning = False
        self.link_counter = 0

        self._create_widgets()
        self._configure_tags()

    def _create_widgets(self):
        # Input frame
        input_frame = tk.Frame(self.root, bg=self.BG_COLOR, padx=10, pady=10)
        input_frame.pack(fill=tk.X)

        # Target IP
        tk.Label(
            input_frame, text="Target IP:", bg=self.BG_COLOR, fg=self.FG_COLOR
        ).grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.ip_entry = tk.Entry(
            input_frame, width=20, bg=self.ENTRY_BG, fg=self.FG_COLOR,
            insertbackground=self.FG_COLOR, relief=tk.FLAT, highlightthickness=1,
            highlightcolor="#555555", highlightbackground="#333333"
        )
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, sticky=tk.W, padx=(0, 15))
        self.ip_entry.bind("<Return>", self.start_scan)
        self.ip_entry.bind("<KP_Enter>", self.start_scan)

        # Ports
        tk.Label(
            input_frame, text="Ports (optional):", bg=self.BG_COLOR, fg=self.FG_COLOR
        ).grid(row=0, column=2, sticky=tk.W, padx=(0, 5))
        self.ports_entry = tk.Entry(
            input_frame, width=25, bg=self.ENTRY_BG, fg=self.FG_COLOR,
            insertbackground=self.FG_COLOR, relief=tk.FLAT, highlightthickness=1,
            highlightcolor="#555555", highlightbackground="#333333"
        )
        self.ports_entry.grid(row=0, column=3, sticky=tk.W, padx=(0, 15))
        self.ports_entry.bind("<Return>", self.start_scan)
        self.ports_entry.bind("<KP_Enter>", self.start_scan)

        # Start button
        self.scan_button = tk.Button(
            input_frame, text="Start Scan", command=self.start_scan,
            bg=self.BUTTON_BG, fg=self.FG_COLOR, activebackground=self.BUTTON_ACTIVE,
            activeforeground=self.FG_COLOR, relief=tk.FLAT, padx=10, pady=3,
            highlightthickness=0, bd=0
        )
        self.scan_button.grid(row=0, column=4, sticky=tk.E)

        # Configure grid weights
        input_frame.columnconfigure(4, weight=1)

        # Results area
        results_frame = tk.Frame(self.root, bg=self.BG_COLOR, padx=10, pady=10)
        results_frame.pack(fill=tk.BOTH, expand=True)

        self.results_text = ScrolledText(
            results_frame, wrap=tk.WORD, font=("Courier", 10),
            bg=self.BG_COLOR, fg=self.FG_COLOR, insertbackground=self.FG_COLOR,
            relief=tk.FLAT, highlightthickness=1, highlightcolor="#555555",
            highlightbackground="#333333"
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.config(state=tk.DISABLED)

        # Style the scrollbar
        self.results_text.vbar.configure(
            bg=self.BUTTON_BG, troughcolor=self.BG_COLOR,
            activebackground=self.BUTTON_ACTIVE, highlightthickness=0
        )

    def _configure_tags(self):
        self.results_text.tag_configure("open", foreground="lime")
        self.results_text.tag_configure("closed", foreground="#ff6666")
        self.results_text.tag_configure("header", foreground="cyan", font=("Courier", 10, "bold"))
        self.results_text.tag_configure("banner", foreground="#aaaaaa")
        self.results_text.tag_configure("advice", foreground="orange")

    def _add_clickable_link(self, text, url):
        """Add a clickable link to the results text widget."""
        self.link_counter += 1
        tag_name = f"link_{self.link_counter}"

        # Configure the tag with cyan color and underline (readable on dark bg)
        self.results_text.tag_configure(tag_name, foreground="cyan", underline=True)

        # Bind click event to open URL
        self.results_text.tag_bind(tag_name, "<Button-1>", lambda e: webbrowser.open(url))

        # Change cursor on hover
        self.results_text.tag_bind(tag_name, "<Enter>", lambda e: self.results_text.config(cursor="hand2"))
        self.results_text.tag_bind(tag_name, "<Leave>", lambda e: self.results_text.config(cursor=""))

        # Insert the text with the tag
        self.results_text.config(state=tk.NORMAL)
        self.results_text.insert(tk.END, text, tag_name)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)

    def _append_text(self, text, tag=None):
        self.results_text.config(state=tk.NORMAL)
        if tag:
            self.results_text.insert(tk.END, text, tag)
        else:
            self.results_text.insert(tk.END, text)
        self.results_text.see(tk.END)
        self.results_text.config(state=tk.DISABLED)

    def _parse_ports(self, ports_str):
        """Parse ports from comma or space-separated string."""
        if not ports_str.strip():
            return None
        # Split by comma, space, or both
        parts = re.split(r'[,\s]+', ports_str.strip())
        ports = []
        for part in parts:
            if part.isdigit():
                ports.append(int(part))
        return ports if ports else None

    def start_scan(self, event=None):
        if self.scanning:
            return

        ip = self.ip_entry.get().strip()
        if not ip:
            ip = "127.0.0.1"

        ports_str = self.ports_entry.get()
        ports = self._parse_ports(ports_str)
        if ports is None:
            try:
                ports = load_ports()
            except FileNotFoundError:
                ports = [22, 80, 443, 8080]

        # Clear results and reset link counter
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        self.results_text.config(state=tk.DISABLED)
        self.link_counter = 0

        # Update UI
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self._append_text(f"Scanning {ip}...\n", "header")

        # Start worker thread
        thread = threading.Thread(target=self._scan_worker, args=(ip, ports), daemon=True)
        thread.start()

        # Start polling
        self.root.after(100, self._poll_queue)

    def _scan_worker(self, ip, ports):
        """Worker thread that performs the scan."""
        total = len(ports)
        open_count = 0

        for port in ports:
            is_open, banner = check_port(ip, port)
            if is_open:
                open_count += 1
            self.queue.put(("result", port, is_open, banner))

        self.queue.put(("done", open_count, total))

    def _poll_queue(self):
        """Poll the queue for results and update the GUI."""
        try:
            while True:
                msg = self.queue.get_nowait()

                if msg[0] == "result":
                    _, port, is_open, banner = msg
                    if is_open:
                        self._append_text(f"  Port {port}: ", None)
                        self._append_text("OPEN", "open")
                        if banner:
                            # Show first line of banner, truncated
                            banner_line = banner.split('\n')[0][:50]
                            self._append_text(f" | {banner_line}", "banner")
                            # Add clickable vulnerability search link if available
                            cve_url = get_cve_search_url(banner)
                            if cve_url:
                                self._append_text("\n           ", None)
                                self._add_clickable_link("🔎 [View CVEs]", cve_url)
                        # Display hardening advice
                        tip = get_hardening_tip(port)
                        self._append_text(f"\n           {tip}", "advice")
                        self._append_text("\n")
                    else:
                        self._append_text(f"  Port {port}: ", None)
                        self._append_text("CLOSED", "closed")
                        self._append_text("\n")

                elif msg[0] == "done":
                    _, open_count, total = msg
                    self._append_text(f"\nScan complete: {open_count}/{total} ports open\n", "header")
                    self.scanning = False
                    self.scan_button.config(state=tk.NORMAL)
                    return

        except queue.Empty:
            pass

        # Continue polling if still scanning
        if self.scanning:
            self.root.after(100, self._poll_queue)


def main():
    root = tk.Tk()
    app = PortScanGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
