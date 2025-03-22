# SubScanX

SubScanX is a powerful Python-based tool for **subdomain enumeration** with a user-friendly GUI. It combines multiple enumeration techniques to discover subdomains efficiently. Whether you're a security researcher, bug bounty hunter, or just curious about domain structures, SubScanX is here to help!

---

## Features

- **Subdomain Enumeration**: Discover subdomains using multiple methods:
  - Common subdomain brute-forcing.
  - Querying [crt.sh](https://crt.sh/) for certificate transparency logs.
  - Integration with [VirusTotal API](https://www.virustotal.com/) (requires API key).
  - Using [Sublist3r](https://github.com/aboul3la/Sublist3r) for advanced enumeration.
- **Progress Bar**: Track the progress of your scans in real-time.
- **Dark/Light Mode**: Toggle between dark and light themes for better usability.
- **Export Results**: Save discovered subdomains to a text file.
- **User-Friendly GUI**: Built with `tkinter` for ease of use.

---

## How to Use

### Installation
#### Prerequisites
- Python 3.x
- Git (optional, for cloning the repository)

#### Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Rohithofficial08/SubScanX.git
   cd SubScanX
   ```
2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Run the Tool**:
   ```bash
   python subscanx.py
   ```

### Usage
1. **Enter a Domain**: Input the target domain (e.g., example.com).
2. **Optional: VirusTotal API Key**: Enter your API key for additional subdomain discovery.
3. **Output File**: Specify a file name to save results (e.g., `subdomains.txt`).
4. **Start Scan**: Click **Start Recon Scan** to begin the enumeration process.
5. **View Results**: Discovered subdomains will be displayed in the output box and saved to the specified file.

---

## Donate
If you find **SubScanX** useful, consider supporting its development:

- **Buy Me a Coffee**: [Support Here](#)
- **Bitcoin**: `your-bitcoin-address`

Happy Hacking! 🚀

