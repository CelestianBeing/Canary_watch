# CanaryWatch

> Advanced Personal Intrusion Detection System (IDS) and Digital Tripwire Framework for Windows

CanaryWatch is a defensive cybersecurity tool designed to detect unauthorized access, suspicious activity, and early indicators of compromise on Windows systems.

By deploying canary files, monitoring sensitive assets, tracking system events, and generating real-time alerts, CanaryWatch provides defenders with immediate visibility into activity that should never occur under normal circumstances.

Built for security enthusiasts, blue-teamers, researchers, students, and system administrators, CanaryWatch combines deception techniques with host-based monitoring in a lightweight desktop application.

---

## Features

### Dashboard & Analytics

* Real-time monitoring dashboard
* Active canary statistics
* Alert activity visualization
* Alert severity tracking
* System uptime monitoring
* Alert breakdown by category

---

### File Canary Monitoring

Monitor individual files and receive alerts when they are:

* Opened
* Accessed
* Modified

Ideal for:

* Sensitive documents
* Decoy credentials
* Research files
* Administrative data

---

### Folder Canary Monitoring

Monitor entire directories for:

* File creation
* File modification
* File deletion
* General filesystem activity

Useful for:

* Shared folders
* Sensitive project directories
* Administrative workspaces

---

### Deception & Honey Files

Deploy realistic decoy assets designed to attract attackers:

* Fake passwords.txt
* Fake SSH private key
* Fake configuration file
* Fake AWS credentials

If an attacker interacts with these assets, CanaryWatch immediately generates an alert.

---

### USB Device Monitoring

Detect:

* Removable storage insertion
* New USB drive activity

Useful for detecting:

* Unauthorized storage devices
* Data exfiltration attempts
* Physical intrusion events

---

### Screenshot Detection

Detect Print Screen key activity and receive alerts when screenshots may be taken.

---

### Process Monitoring

Monitor high-risk tools and receive alerts when they launch.

Examples:

* taskmgr.exe
* regedit.exe
* cmd.exe
* powershell.exe
* custom user-defined processes

---

### Login Monitoring

Monitor Windows authentication events and detect:

* New logins
* Suspicious access activity
* Security log events

---

### Network Canary

Monitor selected ports and generate alerts when unexpected network connections appear.

Example watch ports:

* 22 (SSH)
* 3389 (RDP)
* 5900 (VNC)
* 4444 (Common reverse shell port)

---

### Registry Canary

Monitor Windows Registry locations for changes.

Examples:

* Startup persistence locations
* Autorun keys
* Security-sensitive registry entries

---

### Clipboard Canary

Detect unexpected clipboard modifications and clipboard hijacking behavior.

Useful for:

* Cryptocurrency clipboard hijackers
* Credential theft monitoring
* Malware detection

---

### Multi-Channel Alerting

Receive alerts through:

* Desktop popups
* Email notifications
* Telegram bot alerts
* Discord webhooks
* Optional sound notifications

---

### Alert Management

* Severity classification (LOW / MEDIUM / HIGH)
* Searchable alert history
* Detailed alert inspection
* Exportable logs
* Local alert storage

---

### System Tray Operation

Run silently in the background with:

* Minimize-to-tray support
* Quick restore
* Background monitoring

---

## Screenshots

### Dashboard

![Dashboard](screenshots/dashboard.png)

### Canary Deployment

![Deploy](screenshots/deploy.png)

### Alert Log

![Alerts](screenshots/alerts.png)

### Configuration

![Config](screenshots/config.png)

---

## Installation

### Requirements

* Windows 10 / Windows 11
* Python 3.9+
* Administrator privileges recommended

### Clone Repository

```bash
git clone https://github.com/YOUR_USERNAME/CanaryWatch.git
cd CanaryWatch
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run

```bash
python canarywatch.py
```

---

## Dependencies

```txt
watchdog
requests
pystray
Pillow
```

Install manually:

```bash
pip install watchdog requests pystray pillow
```

---

## Quick Start

### 1. Launch CanaryWatch

```bash
python canarywatch.py
```

### 2. Deploy Canaries

Choose from:

* File Canary
* Folder Canary
* USB Canary
* Screenshot Canary
* Process Canary
* Login Canary
* Network Canary
* Registry Canary
* Clipboard Canary

Or deploy deception assets:

* Fake Passwords File
* Fake Private Key
* Fake Configuration File
* Fake AWS Credentials

### 3. Configure Alert Channels

Configure:

* Email
* Telegram
* Discord
* Sound notifications

### 4. Arm Monitoring

Click:

```
Arm All Canaries
```

CanaryWatch begins monitoring immediately.

---

## Architecture

CanaryWatch combines several defensive security techniques:

* Host-based intrusion detection
* Deception technology
* Canary files
* Event monitoring
* Network monitoring
* Registry monitoring
* Alert correlation

All monitoring occurs locally on the endpoint.

---

## Data Storage

Configuration and alert history are stored locally:

```text
~/.canarywatch/
├── data.json
└── alerts.log
```

No telemetry is collected.

No data is sent to external services unless configured for alert delivery.

---

## Use Cases

### Blue Team Labs

Deploy canaries and observe attacker behavior.

### Personal Security

Monitor sensitive files and folders.

### Insider Threat Detection

Use decoy assets to detect unauthorized access.

### Research & Education

Learn host-based intrusion detection concepts.

### Home Lab Monitoring

Add visibility to personal Windows systems.

---

## Security Notice

CanaryWatch is designed for defensive monitoring purposes only.

Always ensure you have authorization to monitor the systems on which the software is deployed.

Some monitoring features may require elevated privileges depending on operating system configuration.

---

## Future Development

Planned enhancements:

* Windows executable releases
* Digital signatures
* SIEM integrations
* YARA rule integration
* File hash integrity monitoring
* Remote alert dashboard
* Multi-host monitoring
* Threat intelligence enrichment

---

## Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a pull request

---

## Disclaimer

This software is provided for educational, research, and defensive security purposes only.

The authors assume no liability for misuse, damage, or unauthorized deployment.

Use responsibly and only on systems you own or are authorized to monitor.

---

## Author

Developed as a cybersecurity project focused on intrusion detection, deception technology, and defensive monitoring.
