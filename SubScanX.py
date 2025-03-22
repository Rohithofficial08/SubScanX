import dns.resolver
import requests
import subprocess
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from threading import Thread

# Common subdomains to try resolving
subdomain_list = [
    "www", "mail", "ftp", "dev", "staging", "api", "shop", "blog", "test", "web",
    "m", "mobile", "app", "support", "docs", "portal", "help", "secure", "internal", "vpn"
]

# Define colors for dark and light modes
DARK_MODE = {
    "bg": "#1e1e1e",
    "fg": "#ffffff",
    "accent": "#ff4444",
    "entry_bg": "#2d2d2d",
    "button_bg": "#ff4444",
    "button_fg": "#ffffff",
    "text_bg": "#2d2d2d",
    "text_fg": "#ffffff",
    "watermark": "#333333",
    "watermark2": "#00ff00"
}

LIGHT_MODE = {
    "bg": "#ffffff",
    "fg": "#000000",
    "accent": "#ff4444",
    "entry_bg": "#f0f0f0",
    "button_bg": "#ff4444",
    "button_fg": "#ffffff",
    "text_bg": "#f0f0f0",
    "text_fg": "#000000",
    "watermark": "#cccccc",
    "watermark2": "#00ff00"
}

current_mode = DARK_MODE  # Default mode

def apply_theme():
    """Apply the current theme to all widgets."""
    root.configure(bg=current_mode["bg"])
    canvas.configure(bg=current_mode["bg"])
    domain_label.config(bg=current_mode["bg"], fg=current_mode["fg"])
    virustotal_label.config(bg=current_mode["bg"], fg=current_mode["fg"])
    output_file_label.config(bg=current_mode["bg"], fg=current_mode["fg"])
    domain_entry.config(bg=current_mode["entry_bg"], fg=current_mode["fg"], insertbackground=current_mode["fg"])
    virustotal_api_key_entry.config(bg=current_mode["entry_bg"], fg=current_mode["fg"], insertbackground=current_mode["fg"])
    output_file_entry.config(bg=current_mode["entry_bg"], fg=current_mode["fg"], insertbackground=current_mode["fg"])
    start_button.config(bg=current_mode["button_bg"], fg=current_mode["button_fg"])
    clear_button.config(bg=current_mode["button_bg"], fg=current_mode["button_fg"])
    toggle_mode_button.config(bg=current_mode["button_bg"], fg=current_mode["button_fg"])
    status_label.config(bg=current_mode["bg"], fg=current_mode["fg"])
    output_text.config(bg=current_mode["text_bg"], fg=current_mode["text_fg"])
    progress_bar.config(style="red.Horizontal.TProgressbar" if current_mode == DARK_MODE else "blue.Horizontal.TProgressbar")

def toggle_mode():
    """Toggle between dark and light modes."""
    global current_mode
    current_mode = LIGHT_MODE if current_mode == DARK_MODE else DARK_MODE
    apply_theme()

def get_subdomains(domain):
    """Attempt to resolve common subdomains."""
    subdomains = []
    for sub in subdomain_list:
        try:
            answer = dns.resolver.resolve(f"{sub}.{domain}", 'A')
            for ipval in answer:
                subdomains.append(f"{sub}.{domain}")
        except dns.resolver.NXDOMAIN:
            pass
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            print(f"[!] Timeout while resolving {sub}.{domain}")
            pass
    return subdomains

def get_subdomains_from_crtsh(domain):
    """Query crt.sh for subdomains."""
    url = f"https://crt.sh/?q={domain}&output=json"
    try:
        response = requests.get(url)
        subdomains = set()
        for entry in response.json():
            if domain in entry["name_value"]:
                subdomains.add(entry["name_value"])
        return subdomains
    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying crt.sh: {e}")
        return set()

def get_subdomains_from_virustotal(domain, api_key):
    """Query VirusTotal for subdomains."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            subdomains = set()
            data = response.json()
            for subdomain in data['data']:
                subdomains.add(subdomain['id'])
            return subdomains
        else:
            print(f"[!] Error fetching VirusTotal subdomains: {response.status_code}")
            return set()
    except requests.exceptions.RequestException as e:
        print(f"[!] Error querying VirusTotal: {e}")
        return set()

def get_subdomains_from_sublist3r(domain):
    """Run Sublist3r to get subdomains."""
    try:
        result = subprocess.check_output(["sublist3r", "-d", domain, "-o", "subdomains.txt"], text=True)
        with open("subdomains.txt", "r") as file:
            subdomains = file.readlines()
        return [sub.strip() for sub in subdomains]
    except FileNotFoundError:
        messagebox.showerror("Error", "Sublist3r not found. Please install it first.")
        return []
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error", f"Error running Sublist3r: {e}")
        return []

def get_all_subdomains(domain, virustotal_api_key=None):
    """Combine subdomain enumeration from multiple methods."""
    subdomains = set()

    # 1. Get from common subdomains
    subdomains.update(get_subdomains(domain))

    # 2. Get from crt.sh
    subdomains.update(get_subdomains_from_crtsh(domain))

    # 3. Get from VirusTotal if API key is provided
    if virustotal_api_key:
        subdomains.update(get_subdomains_from_virustotal(domain, virustotal_api_key))

    # 4. Get from Sublist3r
    subdomains.update(get_subdomains_from_sublist3r(domain))

    return subdomains

def count_words_in_file(file_path):
    """Count the number of words in a file."""
    try:
        with open(file_path, "r") as file:
            text = file.read()
            words = text.split()
            return len(words)
    except FileNotFoundError:
        print(f"[!] Error: File '{file_path}' not found.")
        return 0
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        return 0

def run_recon_scan(domain, virustotal_api_key, output_text_widget, output_file_name, status_label, progress_bar):
    """Run the recon scan in a separate thread."""
    status_label.config(text="Status: Scanning...", fg=current_mode["accent"])
    progress_bar["value"] = 0
    output_text_widget.config(state="normal")
    output_text_widget.insert(tk.END, f"[*] Starting Recon Scan for {domain}...\n")
    output_text_widget.yview(tk.END)  # Scroll to the bottom

    subdomains = get_all_subdomains(domain, virustotal_api_key)

    if subdomains:
        output_text_widget.insert(tk.END, f"[+] Subdomains Found:\n")
        for subdomain in subdomains:
            output_text_widget.insert(tk.END, f"{subdomain}\n")

        # Save results to the specified file
        try:
            with open(output_file_name, "w") as file:
                file.write(f"Subdomains for {domain}:\n")
                for subdomain in subdomains:
                    file.write(f"{subdomain}\n")
            output_text_widget.insert(tk.END, f"[+] Results saved to {output_file_name}\n")

            # Count words in the file
            word_count = count_words_in_file(output_file_name)
            output_text_widget.insert(tk.END, f"[+] Word count in file: {word_count}\n")
        except Exception as e:
            output_text_widget.insert(tk.END, f"[!] Error saving results to file: {e}\n")
    else:
        output_text_widget.insert(tk.END, f"[-] No subdomains found.\n")

    output_text_widget.insert(tk.END, "[+] Recon Scan Completed.\n")
    output_text_widget.yview(tk.END)  # Scroll to the bottom

    # Disable the widget again to make it read-only
    output_text_widget.config(state="disabled")
    status_label.config(text="Status: Completed", fg=current_mode["accent"])
    progress_bar["value"] = 100

def start_scan():
    """Start the recon scan in a separate thread."""
    domain = domain_entry.get()
    virustotal_api_key = virustotal_api_key_entry.get()  # Optional
    output_file_name = output_file_entry.get()

    if not domain:
        messagebox.showerror("Error", "Please enter a domain.")
        return

    if not output_file_name:
        messagebox.showerror("Error", "Please enter a file name to save results.")
        return

    if not virustotal_api_key:
        virustotal_api_key = None

    # Start recon scan in a separate thread
    scan_thread = Thread(target=run_recon_scan, args=(domain, virustotal_api_key, output_text, output_file_name, status_label, progress_bar))
    scan_thread.start()

def clear_output():
    """Clear the output text widget."""
    output_text.config(state="normal")  # Enable the widget
    output_text.delete(1.0, tk.END)    # Clear the content
    output_text.config(state="disabled")  # Disable the widget again

# Create the main window
root = tk.Tk()
root.title("Recon Project")

# Create a canvas for the background design
canvas = tk.Canvas(root, bg=current_mode["bg"], highlightthickness=0)
canvas.pack(fill="both", expand=True)

# Add hacking-style text in the background (on the right side)
hacking_text = "Rohithofficial08"
canvas.create_text(950, 500, text=hacking_text, font=("Courier", 24), fill=current_mode["watermark"], angle=45)

# Add this for the user information that there will be some error on the terminal dont mind it
foryourinfo_text = "Dont mind the errors"
canvas.create_text(1000, 750, text=foryourinfo_text, font=("Courier", 20), fill=current_mode["watermark2"], angle=0)

# Create UI components
domain_label = tk.Label(canvas, text="Domain:", bg=current_mode["bg"], fg=current_mode["fg"])
domain_label.place(x=10, y=10)
domain_entry = tk.Entry(canvas, width=50, bg=current_mode["entry_bg"], fg=current_mode["fg"], insertbackground=current_mode["fg"])
domain_entry.place(x=120, y=10)

virustotal_label = tk.Label(canvas, text="VirusTotal API Key (Optional):", bg=current_mode["bg"], fg=current_mode["fg"])
virustotal_label.place(x=10, y=50)
virustotal_api_key_entry = tk.Entry(canvas, width=50, bg=current_mode["entry_bg"], fg=current_mode["fg"], insertbackground=current_mode["fg"])
virustotal_api_key_entry.place(x=220, y=50)

output_file_label = tk.Label(canvas, text="Output File Name:", bg=current_mode["bg"], fg=current_mode["fg"])
output_file_label.place(x=10, y=90)
output_file_entry = tk.Entry(canvas, width=50, bg=current_mode["entry_bg"], fg=current_mode["fg"], insertbackground=current_mode["fg"])
output_file_entry.place(x=150, y=90)

start_button = tk.Button(canvas, text="Start Recon Scan", command=start_scan, bg=current_mode["button_bg"], fg=current_mode["button_fg"])
start_button.place(x=10, y=130)

clear_button = tk.Button(canvas, text="Clear Output", command=clear_output, bg=current_mode["button_bg"], fg=current_mode["button_fg"])
clear_button.place(x=150, y=130)

toggle_mode_button = tk.Button(canvas, text="Toggle Mode", command=toggle_mode, bg=current_mode["button_bg"], fg=current_mode["button_fg"])
toggle_mode_button.place(x=300, y=130)

status_label = tk.Label(canvas, text="Status: Idle", bg=current_mode["bg"], fg=current_mode["fg"])
status_label.place(x=10, y=170)

# Progress bar
progress_bar = ttk.Progressbar(canvas, orient="horizontal", length=780, mode="determinate")
progress_bar.place(x=10, y=200)

# Create a frame to hold the ScrolledText widget
output_frame = tk.Frame(canvas, bg=current_mode["bg"])
output_frame.place(x=10, y=230, width=780, height=400)

output_text = scrolledtext.ScrolledText(output_frame, width=80, height=20, state="disabled", bg=current_mode["text_bg"], fg=current_mode["text_fg"])
output_text.pack(fill="both", expand=True)

# Run the application
root.mainloop()
