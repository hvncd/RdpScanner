# RDP Scanner - Rust Edition (Fast)

A high-performance RDP (Remote Desktop Protocol) scanner converted from Python to Rust with an advanced GUI and Firebase authentication.

## Features

- **Firebase Authentication** - Secure login system required on first launch
- **Fast multi-threaded scanning** - Default 500 threads for ~200+ IPs/sec
- Random IP generation (excludes private and loopback addresses)
- Port 3389 (RDP) scanning with configurable timeout
- **Four tabs:**
  - **Scanner Tab:** Find open RDP ports
    - Left panel: Found open ports
    - Right panel: Recently scanned IPs (live feed)
    - **Unlimited Mode:** Checkbox to scan continuously without target limit
    - Target Count field grays out when Unlimited is enabled
  - **Checker Tab:** Advanced NLA verification with detailed info
    - Professional table layout with resizable columns
    - **OS Filter:** Filter results by Windows Desktop or Windows Server
    - **Color Coding:**
      - 🟡 Golden color for Windows Desktop (special/valuable)
      - 🟢 Green color for Windows Server
    - Right-click context menu on each result:
      - 📋 Copy IP:Port
      - ℹ️ Get Info (detailed information window with ADVANCED INFO)
      - 🔗 Connect (launch RDP connection)
    - Advanced information includes:
      - OS detection (Windows Server/Desktop)
      - Country, City, Region
      - Full Location string
      - ISP information
      - BlueKeep (CVE-2019-0708) vulnerability status
    - Only shows RDP servers with NLA disabled
  - **Cracker Tab:** 🔓 RDP Password Cracker
    - Attempts to crack RDP credentials using common username/password combinations
    - Tests against all NLA-disabled servers found in Checker tab
    - Configurable thread count (recommended: 5-10 to avoid detection)
    - Tests common credentials:
      - Usernames: administrator, admin, root, user, guest, test
      - Passwords: password, Password1, P@ssw0rd, 123456, admin123, (empty)
    - Professional table showing cracked credentials:
      - IP:Port (red color for compromised systems)
      - Username
      - Password (shows "(empty)" for blank passwords)
      - OS
      - Location
    - Right-click context menu:
      - 📋 Copy IP:Port
      - 📋 Copy Credentials (username:password format)
      - 🔗 Connect (launch RDP with known credentials)
    - Real-time statistics: Targets | Attempts | Cracked
    - ⚠️ Warning: Only use on systems you own or have explicit permission to test!
  - **Settings Tab:** Customize your experience
    - ☀️ Light Mode / 🌙 Dark Mode toggle
    - Performance information
    - Credits window
- Real-time speed counter (IPs/sec)
- Configurable target count, timeout, and thread count

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

Or run the compiled executable:
```bash
.\target\release\rdpscan.exe
```

## Usage

### First Launch - License Activation
1. When you first open the application, you'll see a clean license activation screen
2. Enter your **License Key** (format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX)
3. Click **Activate License** or press Enter to authenticate
4. The application uses KeyAuth for secure license verification
5. Once activated, you'll have access to all features

### Scanner Tab
1. Set the **Target Count** (number of open ports to find, default: 100)
   - Or check **Unlimited** to scan continuously (Target Count will be grayed out)
2. Set the **Timeout** in seconds (connection timeout per IP, default: 0.3)
3. Set the **Threads** (number of concurrent threads, default: 500)
4. Click **START SCAN** to begin scanning
5. Click **STOP** to stop the scan
6. Watch the live feed of scanned IPs on the right panel
7. Found open ports appear on the left panel
8. Stats show: Scanned count | Found count / Target (or ∞ if unlimited) | Speed

### Checker Tab
1. Run the Scanner first to find open RDP ports
2. Switch to the **Checker** tab
3. Click **START CHECKING** to verify NLA status and gather advanced info
4. Use the **OS Filter** to show:
   - **All** - Show all results
   - **🟡 Windows Desktop** - Show only Desktop (golden color)
   - **🟢 Windows Server** - Show only Server (green color)
5. Results appear in a professional table with columns:
   - Status indicator (🟡 for Desktop, 🟢 for Server)
   - IP:Port (colored: golden for Desktop, green for Server)
   - Status (NLA Disabled)
   - OS
   - Location
   - ISP

### Cracker Tab
1. Run the Scanner and Checker first to find NLA-disabled RDP servers
2. Switch to the **Cracker** tab
3. Set the **Threads** (recommended: 5-10 to avoid detection, default: 10)
4. Click **🚀 START CRACKING** to begin credential testing
5. Click **⏹ STOP** to stop the cracking process
6. Results appear in a professional table showing:
   - IP:Port (red color for compromised systems)
   - Username (green color)
   - Password (green color, shows "(empty)" for blank passwords)
   - OS
   - Location
7. Right-click on any result to:
   - Copy IP:Port
   - Copy Credentials (username:password format)
   - Connect to RDP
8. Stats show: Targets | Attempts | Cracked

**⚠️ IMPORTANT:** Only use the password cracker on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

#### Right-Click Context Menu
Right-click on any result to access:
- **Copy IP:Port** - Copy the address to clipboard
- **Get Info** - Open detailed information window showing:
  - IP:Port
  - Status
  - Operating System
  - Country, City, Region
  - Full Location
  - ISP
  - NLA Status
  - BlueKeep vulnerability status (⚠️ VULNERABLE or ✓ Not Vulnerable)
  - Quick connect button
- **Connect** - Automatically create and launch RDP connection
  - Creates temporary .rdp file
  - Launches Windows Remote Desktop (mstsc)
  - Auto-cleans up temp file

### Settings Tab
- **Theme Toggle:** Switch between Light Mode (☀️) and Dark Mode (🌙)
- **Performance Info:** View default configuration details
- **Credits:** View creator information (@larpexe, nullvex)

## Performance

- Default configuration scans at ~200+ IPs per second
- Adjust threads and timeout for different speeds
- More threads = faster scanning (but more CPU usage)
- Lower timeout = faster per-IP check (but may miss slower connections)
- Checker uses up to 50 concurrent threads for verification

## What is NLA?

Network Level Authentication (NLA) is a security feature in RDP. When NLA is disabled, the RDP server allows connections without pre-authentication, making it more accessible but less secure. The Checker tab identifies these servers and provides detailed information about them.

## Advanced Features

- **Firebase Authentication** - Secure login system with email/password
- **Professional Table UI** - Resizable columns, striped rows, proper alignment
- **OS Filtering** - Filter results by Windows Desktop or Windows Server
- **Color Coding System:**
  - 🟡 Golden color for Windows Desktop (special/valuable targets)
  - 🟢 Green color for Windows Server
  - 🔴 Red color for compromised systems (cracked credentials)
- **Context Menus** - Right-click functionality for quick actions
- **Advanced Info Windows** - Comprehensive server information including:
  - Detailed geolocation (Country, City, Region)
  - ISP information
  - BlueKeep vulnerability detection
- **RDP Password Cracker** - Automated credential testing with common passwords
  - Tests 29 common username/password combinations
  - Configurable thread count for stealth
  - Real-time attempt tracking
  - Credential export functionality
- **Auto RDP Connection** - One-click connection to discovered servers
- **Clipboard Integration** - Easy copying of IP addresses and credentials
- **Theme Support** - Light and Dark mode
- **Credits System** - Proper attribution

## Credits

Created by:
- **@larpexe**
- **nullvex**
- **@hvncd**

Converted from Python to Rust with advanced GUI and features.

## Notes

- **License key required** - You must activate with a valid license key to use the application
- This is an enhanced version of the original Python scanner
- Implements RDP protocol negotiation to detect NLA status
- Uses ip-api.com for geolocation and ISP lookup
- Includes BlueKeep (CVE-2019-0708) vulnerability detection
- The GUI shows live scanning activity in real-time
- Scans random public IPs for port 3389 (RDP)
- Green indicators show RDP servers with NLA disabled
- Windows-only RDP connection feature (uses mstsc)
- **Password cracker uses simplified RDP authentication probes** - For educational/testing purposes only
- The cracker tests 29 common username/password combinations per target
- Delay between attempts helps avoid detection and rate limiting

## Security

- KeyAuth license verification ensures only authorized users can access the scanner
- License keys are validated securely via HTTPS
- HWID binding prevents license sharing across devices
- Authentication tokens are managed by KeyAuth
- No credentials are stored locally

## Dependencies

- `eframe` - GUI framework
- `egui` - Immediate mode GUI library
- `egui_extras` - Table and advanced UI components
- `rand` - Random number generation
- `ureq` - HTTP client for location/ISP lookups
- `serde` / `serde_json` - JSON serialization
- `base64` - Encoding for authentication probes
- `chrono` - Timestamp generation for exports
- `keyauth` - License verification and authentication
