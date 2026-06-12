#!/bin/bash

################################################################################
#                    NETWORK SECURITY HARDENING WIZARD                         #
#                          For CTF OS Hardening                                #
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
BACKUP_DIR="/root/network-backup-$(date +%Y%m%d-%H%M%S)"
SSH_PORT=""
SCORING_IP=""
SELECTED_FIREWALL=""

################################################################################
# UTILITY FUNCTIONS
################################################################################

print_header() {
    echo ""
    echo "========================================"
    echo "  $1"
    echo "========================================"
    echo ""
}

print_step() {
    echo -e "${BLUE}[*]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then 
        print_error "Please run as root (sudo)"
        exit 1
    fi
}

create_backup() {
    print_step "Creating backup..."
    mkdir -p "$BACKUP_DIR"
    
    # Backup firewall configs
    if [ -f /etc/ufw/ufw.conf ]; then
        cp -r /etc/ufw "$BACKUP_DIR/" 2>/dev/null
    fi
    
    # Backup iptables
    iptables-save > "$BACKUP_DIR/iptables.rules" 2>/dev/null
    
    # Backup sysctl
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null
    
    # Backup TCP wrappers
    cp /etc/hosts.allow "$BACKUP_DIR/" 2>/dev/null
    cp /etc/hosts.deny "$BACKUP_DIR/" 2>/dev/null
    
    print_success "Backup created: $BACKUP_DIR"
}

################################################################################
# DETECTION FUNCTIONS
################################################################################

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS"
        exit 1
    fi
}

detect_firewalls() {
    HAS_UFW=false
    HAS_FIREWALLD=false
    HAS_IPTABLES=false
    ACTIVE_FIREWALL="none"
    
    # Check UFW
    if command -v ufw &> /dev/null; then
        HAS_UFW=true
        if systemctl is-active --quiet ufw 2>/dev/null; then
            ACTIVE_FIREWALL="ufw"
        fi
    fi
    
    # Check firewalld
    if command -v firewall-cmd &> /dev/null; then
        HAS_FIREWALLD=true
        if systemctl is-active --quiet firewalld 2>/dev/null; then
            ACTIVE_FIREWALL="firewalld"
        fi
    fi
    
    # Check iptables
    if command -v iptables &> /dev/null; then
        HAS_IPTABLES=true
        if [ "$ACTIVE_FIREWALL" = "none" ]; then
            # Check if iptables has rules
            if [ $(iptables -L 2>/dev/null | wc -l) -gt 8 ]; then
                ACTIVE_FIREWALL="iptables"
            fi
        fi
    fi
}

detect_network() {
    # Get primary interface
    PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -1)
    PRIMARY_IP=$(ip addr show $PRIMARY_INTERFACE | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    
    # Get all interfaces
    ALL_INTERFACES=$(ip link show | grep -E "^[0-9]+" | awk -F': ' '{print $2}' | grep -v lo)
}

check_open_ports() {
    print_step "Scanning open ports..."
    OPEN_PORTS=$(ss -tulpn 2>/dev/null | grep LISTEN | awk '{print $5}' | cut -d: -f2 | sort -u)
}

check_sysctl() {
    IP_FORWARD=$(sysctl -n net.ipv4.ip_forward 2>/dev/null)
    ACCEPT_REDIRECTS=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
    SEND_REDIRECTS=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)
    ACCEPT_SOURCE_ROUTE=$(sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null)
    SYN_COOKIES=$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)
}

################################################################################
# DISPLAY FUNCTIONS
################################################################################

show_system_info() {
    print_header "NETWORK SECURITY WIZARD v1.0"
    
    print_step "Detecting system..."
    detect_os
    detect_firewalls
    detect_network
    check_open_ports
    check_sysctl
    
    echo "    ✓ OS: $OS $OS_VERSION"
    echo "    ✓ Primary interface: $PRIMARY_INTERFACE ($PRIMARY_IP)"
    echo ""
    
    print_step "Available firewalls:"
    if [ "$HAS_UFW" = true ]; then
        echo "    ✓ UFW (Uncomplicated Firewall)"
    else
        echo "    ✗ UFW - NOT INSTALLED"
    fi
    
    if [ "$HAS_FIREWALLD" = true ]; then
        echo "    ✓ firewalld"
    else
        echo "    ✗ firewalld - NOT INSTALLED"
    fi
    
    if [ "$HAS_IPTABLES" = true ]; then
        echo "    ✓ iptables (always available)"
    fi
    
    echo ""
    echo "    Current active firewall: $ACTIVE_FIREWALL"
    echo ""
    
    print_step "Current security status:"
    echo ""
    echo "FIREWALL:"
    if [ "$ACTIVE_FIREWALL" = "none" ]; then
        echo -e "  Status: ${RED}Inactive${NC}                           ✗ CRITICAL"
    else
        echo -e "  Status: ${GREEN}Active${NC} ($ACTIVE_FIREWALL)"
    fi
    
    echo ""
    echo "KERNEL PARAMETERS:"
    if [ "$IP_FORWARD" = "1" ]; then
        echo -e "  IP Forwarding: ${RED}Enabled${NC}                     ✗ INSECURE"
    else
        echo -e "  IP Forwarding: ${GREEN}Disabled${NC}                    ✓ SECURE"
    fi
    
    if [ "$ACCEPT_REDIRECTS" = "1" ]; then
        echo -e "  ICMP Redirects: ${RED}Enabled${NC}                    ✗ INSECURE"
    else
        echo -e "  ICMP Redirects: ${GREEN}Disabled${NC}                   ✓ SECURE"
    fi
    
    if [ "$SYN_COOKIES" = "1" ]; then
        echo -e "  SYN Cookies: ${GREEN}Enabled${NC}                       ✓ SECURE"
    else
        echo -e "  SYN Cookies: ${RED}Disabled${NC}                      ✗ INSECURE"
    fi
    
    echo ""
    echo "OPEN PORTS:"
    if [ -n "$OPEN_PORTS" ]; then
        for port in $OPEN_PORTS; do
            case $port in
                21) echo -e "  ${RED}21${NC} (FTP)                                    ✗ DANGEROUS" ;;
                22) echo -e "  ${YELLOW}22${NC} (SSH)                                    ⚠ DEFAULT PORT" ;;
                23) echo -e "  ${RED}23${NC} (Telnet)                                 ✗ DANGEROUS" ;;
                80) echo "  80 (HTTP)" ;;
                443) echo "  443 (HTTPS)" ;;
                *) echo "  $port" ;;
            esac
        done
    else
        echo "  No open ports detected"
    fi
    echo ""
}

################################################################################
# FIREWALL FUNCTIONS
################################################################################

configure_firewall_wizard() {
    print_header "FIREWALL CONFIGURATION"
    
    # Auto-select firewall
    if [ "$HAS_UFW" = true ]; then
        SELECTED_FIREWALL="ufw"
        print_step "Selected: UFW (recommended for Ubuntu)"
    elif [ "$HAS_FIREWALLD" = true ]; then
        SELECTED_FIREWALL="firewalld"
        print_step "Selected: firewalld (CentOS/RHEL)"
    elif [ "$HAS_IPTABLES" = true ]; then
        SELECTED_FIREWALL="iptables"
        print_step "Selected: iptables (universal)"
    else
        print_error "No firewall available!"
        return 1
    fi
    
    echo ""
    print_warning "Strategy: Block ALL ports, then open ONLY what you need"
    echo ""
    
    # Get allowed ports
    ALLOWED_PORTS=""
    echo "Enter ports to ALLOW (one by one, press Enter when done):"
    echo "Example: 22, 80, 443, 3306, etc."
    echo ""
    
    while true; do
        read -p "Port number (or press Enter to finish): " port
        if [ -z "$port" ]; then
            break
        fi
        
        # Validate port number
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            print_error "Invalid port number: $port"
            continue
        fi
        
        ALLOWED_PORTS="$ALLOWED_PORTS $port"
        print_success "Added port $port"
    done
    
    # Get allowed IPs
    ALLOWED_IPS=""
    echo ""
    echo "Enter IPs to ALLOW ALL TRAFFIC (one by one, press Enter when done):"
    echo "Example: 10.10.50.1 (scoring system), 192.168.1.100, etc."
    echo ""
    
    while true; do
        read -p "IP address (or press Enter to finish): " ip
        if [ -z "$ip" ]; then
            break
        fi
        
        ALLOWED_IPS="$ALLOWED_IPS $ip"
        print_success "Added IP $ip"
    done
    
    # Review
    echo ""
    print_header "REVIEW & CONFIRM"
    echo ""
    echo "Firewall rules to be applied:"
    echo ""
    echo "DEFAULT POLICIES:"
    echo "  ✓ Incoming: DENY (block all by default)"
    echo "  ✓ Outgoing: ALLOW (allow all outbound)"
    echo ""
    
    if [ -n "$ALLOWED_PORTS" ]; then
        echo "ALLOWED PORTS:"
        for port in $ALLOWED_PORTS; do
            echo "  ✓ Port $port/tcp"
        done
        echo ""
    fi
    
    if [ -n "$ALLOWED_IPS" ]; then
        echo "ALLOWED IPs (all traffic):"
        for ip in $ALLOWED_IPS; do
            echo "  ✓ $ip"
        done
        echo ""
    fi
    
    if [ -z "$ALLOWED_PORTS" ] && [ -z "$ALLOWED_IPS" ]; then
        print_warning "No ports or IPs specified! This will block ALL incoming traffic!"
        echo ""
    fi
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    # Apply firewall rules
    apply_firewall_rules
}

apply_firewall_rules() {
    print_step "Applying firewall rules..."
    echo ""
    
    case $SELECTED_FIREWALL in
        ufw)
            apply_ufw_rules
            ;;
        firewalld)
            apply_firewalld_rules
            ;;
        iptables)
            apply_iptables_rules
            ;;
    esac
    
    echo ""
    print_success "Firewall configured successfully!"
    echo ""
    print_warning "IMPORTANT: Test connections in a NEW terminal before closing this one!"
    echo ""
}

apply_ufw_rules() {
    step=1
    total_steps=3
    
    echo "    [$step/$total_steps] Setting default policies..."
    ufw --force default deny incoming > /dev/null 2>&1
    ufw --force default allow outgoing > /dev/null 2>&1
    print_success "      Default policies set"
    step=$((step+1))
    
    if [ -n "$ALLOWED_PORTS" ]; then
        echo "    [$step/$total_steps] Allowing ports..."
        for port in $ALLOWED_PORTS; do
            ufw --force allow $port/tcp > /dev/null 2>&1
            print_success "      Port $port allowed"
        done
        step=$((step+1))
    fi
    
    if [ -n "$ALLOWED_IPS" ]; then
        echo "    [$step/$total_steps] Allowing IPs..."
        for ip in $ALLOWED_IPS; do
            ufw --force allow from $ip > /dev/null 2>&1
            print_success "      IP $ip allowed"
        done
        step=$((step+1))
    fi
    
    echo "    [$total_steps/$total_steps] Enabling firewall..."
    ufw --force enable > /dev/null 2>&1
    print_success "      Firewall enabled"
    
    echo ""
    print_step "Verification:"
    ufw status verbose
}

apply_firewalld_rules() {
    step=1
    total_steps=3
    
    echo "    [$step/$total_steps] Setting default zone..."
    firewall-cmd --set-default-zone=drop > /dev/null 2>&1
    print_success "      Default zone set to drop"
    step=$((step+1))
    
    if [ -n "$ALLOWED_PORTS" ]; then
        echo "    [$step/$total_steps] Allowing ports..."
        for port in $ALLOWED_PORTS; do
            firewall-cmd --add-port=$port/tcp --permanent > /dev/null 2>&1
            print_success "      Port $port allowed"
        done
        step=$((step+1))
    fi
    
    if [ -n "$ALLOWED_IPS" ]; then
        echo "    [$step/$total_steps] Allowing IPs..."
        for ip in $ALLOWED_IPS; do
            firewall-cmd --add-rich-rule="rule family='ipv4' source address='$ip' accept" --permanent > /dev/null 2>&1
            print_success "      IP $ip allowed"
        done
        step=$((step+1))
    fi
    
    echo "    [$total_steps/$total_steps] Reloading firewall..."
    firewall-cmd --reload > /dev/null 2>&1
    print_success "      Firewall reloaded"
    
    echo ""
    print_step "Verification:"
    firewall-cmd --list-all
}

apply_iptables_rules() {
    step=1
    total_steps=5
    
    echo "    [$step/$total_steps] Flushing existing rules..."
    iptables -F
    iptables -X
    print_success "      Rules flushed"
    step=$((step+1))
    
    echo "    [$step/$total_steps] Allowing loopback & established connections..."
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    print_success "      Loopback & established connections allowed"
    step=$((step+1))
    
    if [ -n "$ALLOWED_PORTS" ]; then
        echo "    [$step/$total_steps] Allowing ports..."
        for port in $ALLOWED_PORTS; do
            iptables -A INPUT -p tcp --dport $port -j ACCEPT
            print_success "      Port $port allowed"
        done
        step=$((step+1))
    fi
    
    if [ -n "$ALLOWED_IPS" ]; then
        echo "    [$step/$total_steps] Allowing IPs..."
        for ip in $ALLOWED_IPS; do
            iptables -A INPUT -s $ip -j ACCEPT
            print_success "      IP $ip allowed"
        done
        step=$((step+1))
    fi
    
    echo "    [$step/$total_steps] Setting default policies..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    print_success "      Default policies set"
    step=$((step+1))
    
    echo "    [$total_steps/$total_steps] Saving rules..."
    if command -v iptables-save &> /dev/null; then
        mkdir -p /etc/iptables
        iptables-save > /etc/iptables/rules.v4
        print_success "      Rules saved to /etc/iptables/rules.v4"
    else
        print_warning "      iptables-save not found, rules not persistent"
    fi
    
    echo ""
    print_step "Verification:"
    iptables -L -n -v
}

################################################################################
# SYSCTL HARDENING
################################################################################

configure_sysctl() {
    print_header "KERNEL HARDENING (SYSCTL)"
    
    echo "This will harden kernel network parameters:"
    echo "  ✓ Disable IP forwarding"
    echo "  ✓ Disable ICMP redirects"
    echo "  ✓ Disable source routing"
    echo "  ✓ Enable SYN cookies"
    echo "  ✓ Enable reverse path filtering"
    echo ""
    
    read -p "Disable IPv6? (y/n) [default: y]: " DISABLE_IPV6
    DISABLE_IPV6=${DISABLE_IPV6:-y}
    
    read -p "Ignore ping requests? (y/n) [default: n]: " IGNORE_PING
    IGNORE_PING=${IGNORE_PING:-n}
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    apply_sysctl_hardening
}

apply_sysctl_hardening() {
    print_step "Applying kernel hardening..."
    echo ""
    
    echo "    [1/10] Disabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=0 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.forwarding=0 > /dev/null 2>&1
    print_success "      IP forwarding disabled"
    
    echo "    [2/10] Disabling ICMP redirects (accept)..."
    sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.accept_redirects=0 > /dev/null 2>&1
    print_success "      ICMP redirects (accept) disabled"
    
    echo "    [3/10] Disabling ICMP redirects (send)..."
    sysctl -w net.ipv4.conf.all.send_redirects=0 > /dev/null 2>&1
    print_success "      ICMP redirects (send) disabled"
    
    echo "    [4/10] Disabling source routing..."
    sysctl -w net.ipv4.conf.all.accept_source_route=0 > /dev/null 2>&1
    sysctl -w net.ipv6.conf.all.accept_source_route=0 > /dev/null 2>&1
    print_success "      Source routing disabled"
    
    echo "    [5/10] Enabling SYN cookies..."
    sysctl -w net.ipv4.tcp_syncookies=1 > /dev/null 2>&1
    print_success "      SYN cookies enabled"
    
    echo "    [6/10] Enabling reverse path filtering..."
    sysctl -w net.ipv4.conf.all.rp_filter=1 > /dev/null 2>&1
    print_success "      Reverse path filtering enabled"
    
    echo "    [7/10] Ignoring broadcast pings..."
    sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 > /dev/null 2>&1
    print_success "      Broadcast pings ignored"
    
    echo "    [8/10] Enabling martian packet logging..."
    sysctl -w net.ipv4.conf.all.log_martians=1 > /dev/null 2>&1
    print_success "      Martian packet logging enabled"
    
    if [ "$IGNORE_PING" = "y" ]; then
        echo "    [9/10] Ignoring ping requests..."
        sysctl -w net.ipv4.icmp_echo_ignore_all=1 > /dev/null 2>&1
        print_success "      Ping requests ignored"
    fi
    
    if [ "$DISABLE_IPV6" = "y" ]; then
        echo "    [10/10] Disabling IPv6..."
        sysctl -w net.ipv6.conf.all.disable_ipv6=1 > /dev/null 2>&1
        sysctl -w net.ipv6.conf.default.disable_ipv6=1 > /dev/null 2>&1
        print_success "      IPv6 disabled"
    fi
    
    # Make persistent
    echo ""
    print_step "Making changes persistent..."
    
    cat >> /etc/sysctl.conf << EOF

# Network Security Hardening - $(date)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
EOF

    if [ "$IGNORE_PING" = "y" ]; then
        echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
    fi
    
    if [ "$DISABLE_IPV6" = "y" ]; then
        echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
        echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    fi
    
    print_success "Changes saved to /etc/sysctl.conf"
    
    echo ""
    print_success "Kernel hardening completed!"
}

################################################################################
# TCP WRAPPERS
################################################################################

configure_tcp_wrappers() {
    print_header "TCP WRAPPERS CONFIGURATION"
    
    echo "TCP Wrappers provide additional access control for services."
    echo "You can restrict which IPs can access specific services (SSH, FTP, etc.)"
    echo ""
    
    read -p "Configure TCP Wrappers? (y/n) [default: y]: " CONFIGURE_TCP
    CONFIGURE_TCP=${CONFIGURE_TCP:-y}
    
    if [ "$CONFIGURE_TCP" != "y" ]; then
        echo "Skipped."
        return 0
    fi
    
    # Get allowed IPs
    TCP_ALLOWED_IPS=""
    echo ""
    echo "Enter IPs to ALLOW for SSH access (one by one, press Enter when done):"
    echo "Example: 10.10.50.1, 192.168.1.100, etc."
    echo ""
    
    while true; do
        read -p "IP address (or press Enter to finish): " ip
        if [ -z "$ip" ]; then
            break
        fi
        
        TCP_ALLOWED_IPS="$TCP_ALLOWED_IPS $ip"
        print_success "Added IP $ip"
    done
    
    if [ -z "$TCP_ALLOWED_IPS" ]; then
        print_warning "No IPs specified, skipping TCP Wrappers configuration"
        return 0
    fi
    
    echo ""
    echo "Will configure:"
    echo "  /etc/hosts.allow:"
    for ip in $TCP_ALLOWED_IPS; do
        echo "    sshd: $ip"
    done
    echo "    sshd: 127.0.0.1"
    echo "    ALL: 127.0.0.1"
    echo ""
    echo "  /etc/hosts.deny:"
    echo "    sshd: ALL"
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    apply_tcp_wrappers
}

apply_tcp_wrappers() {
    print_step "Configuring TCP Wrappers..."
    
    # hosts.allow
    cat > /etc/hosts.allow << EOF
# TCP Wrappers - Allow
# Generated by Network Security Wizard - $(date)

EOF
    
    for ip in $TCP_ALLOWED_IPS; do
        echo "sshd: $ip" >> /etc/hosts.allow
    done
    
    cat >> /etc/hosts.allow << EOF
sshd: 127.0.0.1
ALL: 127.0.0.1
EOF
    
    print_success "Created /etc/hosts.allow"
    
    # hosts.deny
    cat > /etc/hosts.deny << EOF
# TCP Wrappers - Deny
# Generated by Network Security Wizard - $(date)

sshd: ALL
EOF
    
    print_success "Created /etc/hosts.deny"
    
    echo ""
    print_success "TCP Wrappers configured!"
}

################################################################################
# COMPLETE HARDENING
################################################################################

complete_hardening() {
    print_header "COMPLETE NETWORK HARDENING"
    
    echo "This will configure ALL network security aspects:"
    echo "  ✓ Firewall (block all, allow only what you specify)"
    echo "  ✓ Kernel parameters (disable forwarding, redirects, etc)"
    echo "  ✓ TCP Wrappers (restrict SSH access)"
    echo ""
    
    # Get firewall configuration
    print_step "STEP 1: Firewall Configuration"
    echo ""
    
    # Get allowed ports
    ALLOWED_PORTS=""
    echo "Enter ports to ALLOW (one by one, press Enter when done):"
    echo "Example: 22 (SSH), 80 (HTTP), 443 (HTTPS), etc."
    echo ""
    
    while true; do
        read -p "Port number (or press Enter to finish): " port
        if [ -z "$port" ]; then
            break
        fi
        
        if ! [[ "$port" =~ ^[0-9]+$ ]] || [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
            print_error "Invalid port number: $port"
            continue
        fi
        
        ALLOWED_PORTS="$ALLOWED_PORTS $port"
        print_success "Added port $port"
    done
    
    # Get allowed IPs
    ALLOWED_IPS=""
    echo ""
    echo "Enter IPs to ALLOW ALL TRAFFIC (one by one, press Enter when done):"
    echo "Example: 10.10.50.1 (scoring system), etc."
    echo ""
    
    while true; do
        read -p "IP address (or press Enter to finish): " ip
        if [ -z "$ip" ]; then
            break
        fi
        
        ALLOWED_IPS="$ALLOWED_IPS $ip"
        print_success "Added IP $ip"
    done
    
    # Get kernel configuration
    echo ""
    print_step "STEP 2: Kernel Hardening"
    echo ""
    
    read -p "Disable IPv6? (y/n) [default: y]: " DISABLE_IPV6
    DISABLE_IPV6=${DISABLE_IPV6:-y}
    
    read -p "Ignore ping requests? (y/n) [default: n]: " IGNORE_PING
    IGNORE_PING=${IGNORE_PING:-n}
    
    # Get TCP Wrappers configuration
    echo ""
    print_step "STEP 3: TCP Wrappers"
    echo ""
    
    TCP_ALLOWED_IPS=""
    echo "Enter IPs to ALLOW for SSH access (one by one, press Enter when done):"
    echo ""
    
    while true; do
        read -p "IP address (or press Enter to finish): " ip
        if [ -z "$ip" ]; then
            break
        fi
        
        TCP_ALLOWED_IPS="$TCP_ALLOWED_IPS $ip"
        print_success "Added IP $ip"
    done
    
    # Review
    echo ""
    print_header "REVIEW & CONFIRM"
    echo ""
    echo "Will apply:"
    echo ""
    echo "FIREWALL:"
    echo "  ✓ Block all incoming (default deny)"
    if [ -n "$ALLOWED_PORTS" ]; then
        echo "  ✓ Allowed ports:"
        for port in $ALLOWED_PORTS; do
            echo "    - Port $port/tcp"
        done
    fi
    if [ -n "$ALLOWED_IPS" ]; then
        echo "  ✓ Allowed IPs (all traffic):"
        for ip in $ALLOWED_IPS; do
            echo "    - $ip"
        done
    fi
    echo ""
    echo "KERNEL PARAMETERS:"
    echo "  ✓ Disable IP forwarding"
    echo "  ✓ Disable ICMP redirects"
    echo "  ✓ Disable source routing"
    echo "  ✓ Enable SYN cookies"
    [ "$DISABLE_IPV6" = "y" ] && echo "  ✓ Disable IPv6"
    [ "$IGNORE_PING" = "y" ] && echo "  ✓ Ignore ping requests"
    echo ""
    if [ -n "$TCP_ALLOWED_IPS" ]; then
        echo "TCP WRAPPERS:"
        echo "  ✓ Restrict SSH to:"
        for ip in $TCP_ALLOWED_IPS; do
            echo "    - $ip"
        done
    else
        echo "TCP WRAPPERS:"
        echo "  ✗ Not configured (skipped)"
    fi
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    # Create backup
    create_backup
    
    # Apply all hardening
    print_header "APPLYING COMPLETE HARDENING"
    
    # Detect firewall
    if [ "$HAS_UFW" = true ]; then
        SELECTED_FIREWALL="ufw"
    elif [ "$HAS_FIREWALLD" = true ]; then
        SELECTED_FIREWALL="firewalld"
    else
        SELECTED_FIREWALL="iptables"
    fi
    
    # Apply firewall
    echo ""
    print_step "[1/3] Configuring firewall..."
    apply_firewall_rules
    
    # Apply sysctl
    echo ""
    print_step "[2/3] Hardening kernel parameters..."
    apply_sysctl_hardening
    
    # Apply TCP wrappers
    if [ -n "$TCP_ALLOWED_IPS" ]; then
        echo ""
        print_step "[3/3] Configuring TCP Wrappers..."
        apply_tcp_wrappers
    else
        echo ""
        print_step "[3/3] Skipping TCP Wrappers (no IPs specified)"
    fi
    
    echo ""
    print_header "COMPLETE HARDENING DONE!"
    
    echo ""
    print_success "All network security measures applied!"
    echo ""
    echo "Summary:"
    echo "  ✓ Firewall: Active ($SELECTED_FIREWALL)"
    echo "  ✓ Kernel: Hardened"
    if [ -n "$TCP_ALLOWED_IPS" ]; then
        echo "  ✓ TCP Wrappers: Configured"
    else
        echo "  ✗ TCP Wrappers: Skipped"
    fi
    echo ""
    echo "Backup location: $BACKUP_DIR"
    echo ""
    print_warning "IMPORTANT: Test connections in new terminal!"
    echo ""
}

################################################################################
# MAIN MENU
################################################################################

main_menu() {
    while true; do
        show_system_info
        
        print_header "MAIN MENU"
        
        echo "[1] Complete Network Hardening (RECOMMENDED)"
        echo "    → Firewall + Kernel + TCP Wrappers"
        echo ""
        echo "[2] Firewall Configuration Only"
        echo "    → UFW/firewalld/iptables setup"
        echo ""
        echo "[3] Kernel Hardening (sysctl)"
        echo "    → IP forwarding, ICMP, etc"
        echo ""
        echo "[4] TCP Wrappers Configuration"
        echo "    → hosts.allow & hosts.deny"
        echo ""
        echo "[0] Exit"
        echo ""
        
        read -p "Choose [0-4]: " choice
        
        case $choice in
            1)
                complete_hardening
                read -p "Press Enter to continue..."
                ;;
            2)
                create_backup
                configure_firewall_wizard
                read -p "Press Enter to continue..."
                ;;
            3)
                create_backup
                configure_sysctl
                read -p "Press Enter to continue..."
                ;;
            4)
                create_backup
                configure_tcp_wrappers
                read -p "Press Enter to continue..."
                ;;
            0)
                echo "Goodbye!"
                exit 0
                ;;
            *)
                print_error "Invalid choice"
                sleep 2
                ;;
        esac
    done
}

################################################################################
# MAIN
################################################################################

check_root
main_menu
