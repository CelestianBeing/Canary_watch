# CanaryWatch

> Personal Intrusion Detection System (IDS) for Windows using canary files, activity monitoring, and real-time alerts.

CanaryWatch is a lightweight defensive security tool that helps detect unauthorized access and suspicious activity on Windows systems. By deploying digital tripwires ("canaries"), monitoring sensitive files and folders, and watching for system events, CanaryWatch provides immediate visibility into potential intrusions.

Whether you're a security enthusiast, system administrator, or privacy-conscious user, CanaryWatch helps you know when someone interacts with files, devices, or processes that should not normally be touched.

---

## Features

### 📄 File Canaries
Monitor specific files and receive alerts when they are:
- Opened
- Accessed
- Modified

Perfect for monitoring sensitive documents or decoy files.

### 📁 Folder Canaries
Watch entire directories and detect:
- File creation
- Modification
- Deletion
- General activity

### 🎣 Decoy (Honey) Files
Quickly deploy fake assets designed to attract attention:

- Fake passwords file
- Fake private key file
- Fake configuration file

If someone accesses these files, you'll know immediately.

### 🔌 USB Device Monitoring
Detect when removable USB storage devices are connected to the system.

### 📸 Screenshot Detection
Alert when the Print Screen key is pressed.

### ⚙️ Process Monitoring
Monitor selected processes and receive alerts when they launch.

Examples:
- taskmgr.exe
- regedit.exe
- cmd.exe
- powershell.exe

### 🔐 Login Monitoring
Detect new Windows login events using Security Event Logs.

### 🚨 Multi-Channel Alerting
Receive alerts through:

- Desktop notifications
- Email (Gmail)
- Telegram
- Discord Webhooks

### 📜 Alert Logging
Maintain a searchable history of alerts and export logs when needed.

---

## Screenshots

Add screenshots of the UI here.

### Main Dashboard

![Dashboard](screenshots/dashboard.png)

### Alert Log

![Alerts](screenshots/alerts.png)

---

## Installation

### Requirements

- Windows 10/11
- Python 3.9+
- Administrator privileges recommended for some monitoring features

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

```text
watchdog
requests
```

Install manually if needed:

```bash
pip install watchdog requests
```

---

## Quick Start

### 1. Launch CanaryWatch

```bash
python canarywatch.py
```

### 2. Deploy a Canary

Choose one of the following:

- File Canary
- Folder Canary
- USB Canary
- Screenshot Canary
- Process Canary
- Login Canary
- Fake Passwords File
- Fake Private Key
- Fake Config File

### 3. Configure Alerts

Navigate to:

```
Alert Config
```

Configure:

- Email notifications
- Telegram bot alerts
- Discord webhook alerts

### 4. Arm Monitoring

Click:

```
Arm All Canaries
```

CanaryWatch will begin monitoring selected assets and system events.

---

## Alert Types

| Alert Type | Description |
|------------|-------------|
| File Canary | Monitors access and modification of specific files |
| Folder Canary | Detects activity inside monitored directories |
| USB Canary | Detects removable drive insertion |
| Screenshot Canary | Detects Print Screen key presses |
| Process Canary | Detects launch of monitored processes |
| Login Canary | Detects Windows login events |

---

## Use Cases

### Personal Security
Monitor sensitive files and folders for unauthorized access.

### Insider Threat Detection
Deploy decoy files to identify curious or unauthorized users.

### Workstation Monitoring
Track activity on shared computers and administrative systems.

### Honeypot-Style Detection
Place fake credentials or configuration files where an intruder may look first.

---

## Data Storage

CanaryWatch stores configuration and alert history locally:

```text
~/.canarywatch/
├── data.json
└── alerts.log
```

No telemetry or cloud services are required.

---

## Security Notes

- CanaryWatch is intended for defensive monitoring.
- Monitor only systems you own or are authorized to administer.
- Some monitoring features may require elevated permissions.
- Alert delivery services (Email, Telegram, Discord) require valid credentials and configuration.

---

## Roadmap

Planned improvements include:

- System tray support
- Native Windows notifications
- Executable (.exe) releases
- Alert filtering and severity levels
- Remote dashboard
- SIEM integration
- File hash monitoring
- Registry monitoring
- Dark mode enhancements

---

## Contributing

Contributions, bug reports, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Submit a pull request

---

## Disclaimer

CanaryWatch is provided for educational and defensive security purposes only.

The software should only be used on systems you own or have explicit authorization to monitor. The authors assume no responsibility for misuse or damages resulting from use of this software.

---

## Author

Built with Python for defenders, researchers, and security enthusiasts.