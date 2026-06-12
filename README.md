# OS Hardening Tools for CTF/LKS

Collection of automated tools for Linux OS hardening competitions (CTF/LKS).

## Tools Included

### 1. Network Security Wizard (`network-wizard.sh`)
Automates network security hardening including:
- Firewall configuration (UFW/firewalld/iptables)
- Kernel hardening (sysctl parameters)
- TCP Wrappers configuration

**Usage:**
```bash
sudo ./network-wizard.sh
```

### 2. Dangerous Services Killer (`dangerous-services-killer.sh`)
Detects and removes dangerous/unnecessary services:
- Scans listening ports and firewall rules
- Identifies dangerous services (Telnet, FTP, TFTP, etc.)
- Can stop, disable, or uninstall services
- Manual port blocking feature

**Usage:**
```bash
sudo ./dangerous-services-killer.sh
```

### 3. PAM Hardening Wizard (`pam-wizard.sh`)
Manages PAM (Pluggable Authentication Modules) security:
- Sudo management
- Password policy configuration
- Account management
- Password expiry settings
- Account lockout policies

**Usage:**
```bash
sudo ./pam-wizard.sh
```

### 4. Service Security Wizard (`service-security-wizard.sh`)
Hardens running services:
- SSH hardening
- Apache/Nginx security
- MySQL/PostgreSQL hardening
- Auto-detection of installed services

**Usage:**
```bash
sudo ./service-security-wizard.sh
```

## Requirements

- Linux (Ubuntu/Debian/CentOS/RHEL)
- Root/sudo access
- Basic networking knowledge

## Installation

```bash
git clone https://github.com/novi4nthrilll/hardening-tools.git
cd hardening-tools
chmod +x *.sh
```

## Quick Start

Run all tools in sequence:
```bash
sudo ./network-wizard.sh
sudo ./dangerous-services-killer.sh
sudo ./pam-wizard.sh
sudo ./service-security-wizard.sh
```

## Features

- 🚀 Auto-detection of OS and services
- 🔒 Comprehensive security hardening
- 💾 Automatic backups before changes
- ↩️ Undo functionality
- 📊 Detailed reporting
- ✅ Configuration validation

## Use Cases

- CTF/LKS competitions
- Security audits
- Production server hardening
- Learning Linux security

## Warning

⚠️ These tools make system-level changes. Always:
- Test in a non-production environment first
- Have backup/snapshot before running
- Review changes before applying
- Keep SSH access open during configuration

## License

MIT License - Free to use for educational and competition purposes.

## Author

novi4nth - LKS/CTF OS Hardening Tools

## Contributing

Pull requests are welcome! For major changes, please open an issue first.
