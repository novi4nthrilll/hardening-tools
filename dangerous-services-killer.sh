#!/bin/bash

################################################################################
#                    DANGEROUS SERVICES KILLER                                 #
#                          For CTF OS Hardening                                #
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Variables
BACKUP_DIR="/root/services-backup-$(date +%Y%m%d-%H%M%S)"
OS=""
OS_VERSION=""
SERVICE_MANAGER=""
FIREWALL_TYPE=""

# Service lists
declare -A SUPER_DANGEROUS
declare -A DANGEROUS
declare -A SUSPICIOUS

# Detection results
declare -A FOUND_SERVICES
declare -A SERVICE_STATUS
declare -A SERVICE_PORTS

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

print_danger() {
    echo -e "${RED}[DANGER]${NC} $1"
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
    
    # Backup systemd/init configs
    if [ -d /etc/systemd/system ]; then
        cp -r /etc/systemd/system "$BACKUP_DIR/" 2>/dev/null
    fi
    
    if [ -d /etc/init.d ]; then
        cp -r /etc/init.d "$BACKUP_DIR/" 2>/dev/null
    fi
    
    # Backup xinetd
    if [ -d /etc/xinetd.d ]; then
        cp -r /etc/xinetd.d "$BACKUP_DIR/" 2>/dev/null
    fi
    
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
    
    # Detect service manager
    if command -v systemctl &> /dev/null; then
        SERVICE_MANAGER="systemd"
    elif command -v service &> /dev/null; then
        SERVICE_MANAGER="sysvinit"
    else
        print_error "Cannot detect service manager"
        exit 1
    fi
}

detect_firewall() {
    # Check UFW
    if command -v ufw &> /dev/null && systemctl is-active --quiet ufw 2>/dev/null; then
        FIREWALL_TYPE="ufw"
        return
    fi
    
    # Check firewalld
    if command -v firewall-cmd &> /dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        FIREWALL_TYPE="firewalld"
        return
    fi
    
    # Check iptables
    if command -v iptables &> /dev/null; then
        if [ $(iptables -L 2>/dev/null | wc -l) -gt 8 ]; then
            FIREWALL_TYPE="iptables"
            return
        fi
    fi
    
    FIREWALL_TYPE="none"
}

initialize_service_lists() {
    # SUPER DANGEROUS - Must kill immediately
    SUPER_DANGEROUS=(
        ["vsftpd"]="FTP Server (vsftpd)"
        ["proftpd"]="FTP Server (proftpd)"
        ["pure-ftpd"]="FTP Server (pure-ftpd)"
        ["telnetd"]="Telnet Server"
        ["telnet"]="Telnet Server"
        ["rsh"]="Remote Shell"
        ["rlogin"]="Remote Login"
        ["rexec"]="Remote Exec"
        ["tftp"]="TFTP Server"
        ["tftpd"]="TFTP Server"
    )
    
    # DANGEROUS - Should be removed if not needed
    DANGEROUS=(
        ["apache2"]="Apache Web Server"
        ["httpd"]="Apache Web Server"
        ["nginx"]="Nginx Web Server"
        ["mysql"]="MySQL Database"
        ["mysqld"]="MySQL Database"
        ["mariadb"]="MariaDB Database"
        ["postgresql"]="PostgreSQL Database"
        ["smbd"]="Samba File Server"
        ["nmbd"]="Samba NetBIOS"
        ["nfs-server"]="NFS Server"
        ["nfs-kernel-server"]="NFS Server"
        ["rpcbind"]="RPC Bind"
        ["snmpd"]="SNMP Daemon"
        ["dovecot"]="Dovecot Mail Server"
        ["postfix"]="Postfix Mail Server"
        ["sendmail"]="Sendmail"
    )
    
    # SUSPICIOUS - Usually not needed
    SUSPICIOUS=(
        ["avahi-daemon"]="Avahi Zeroconf"
        ["cups"]="CUPS Printing"
        ["cupsd"]="CUPS Printing"
        ["bluetooth"]="Bluetooth Service"
        ["isc-dhcp-server"]="DHCP Server"
        ["dhcpd"]="DHCP Server"
        ["bind9"]="DNS Server (BIND)"
        ["named"]="DNS Server (BIND)"
    )
}

check_service_status() {
    local service=$1
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            echo "running"
        elif systemctl is-enabled --quiet "$service" 2>/dev/null; then
            echo "enabled"
        elif systemctl list-unit-files | grep -q "^${service}.service"; then
            echo "installed"
        else
            echo "not_found"
        fi
    else
        if service "$service" status 2>/dev/null | grep -q "running"; then
            echo "running"
        elif [ -f "/etc/init.d/$service" ]; then
            echo "installed"
        else
            echo "not_found"
        fi
    fi
}

check_package_installed() {
    local package=$1
    
    if command -v dpkg &> /dev/null; then
        dpkg -l | grep -q "^ii.*$package" && echo "yes" || echo "no"
    elif command -v rpm &> /dev/null; then
        rpm -qa | grep -q "$package" && echo "yes" || echo "no"
    else
        echo "unknown"
    fi
}

get_port_description() {
    local port=$1
    
    case $port in
        # SUPER DANGEROUS
        21) echo "FTP|super" ;;
        23) echo "Telnet|super" ;;
        69) echo "TFTP|super" ;;
        512) echo "rexec|super" ;;
        513) echo "rlogin|super" ;;
        514) echo "rsh/syslog|super" ;;
        
        # DANGEROUS
        20) echo "FTP Data|dangerous" ;;
        25) echo "SMTP|dangerous" ;;
        53) echo "DNS|dangerous" ;;
        80) echo "HTTP|dangerous" ;;
        110) echo "POP3|dangerous" ;;
        111) echo "RPC|dangerous" ;;
        135) echo "MS RPC|dangerous" ;;
        139) echo "NetBIOS|dangerous" ;;
        143) echo "IMAP|dangerous" ;;
        161) echo "SNMP|dangerous" ;;
        162) echo "SNMP Trap|dangerous" ;;
        389) echo "LDAP|dangerous" ;;
        445) echo "SMB|dangerous" ;;
        631) echo "CUPS|dangerous" ;;
        873) echo "rsync|dangerous" ;;
        1433) echo "MS SQL|dangerous" ;;
        2049) echo "NFS|dangerous" ;;
        3306) echo "MySQL|dangerous" ;;
        5432) echo "PostgreSQL|dangerous" ;;
        5900) echo "VNC|dangerous" ;;
        6379) echo "Redis|dangerous" ;;
        8080) echo "HTTP Alt|dangerous" ;;
        27017) echo "MongoDB|dangerous" ;;
        
        # SUSPICIOUS
        5353) echo "mDNS|suspicious" ;;
        
        # SAFE
        22) echo "SSH|safe" ;;
        443) echo "HTTPS|safe" ;;
        
        # UNKNOWN
        *) echo "Unknown|unknown" ;;
    esac
}

scan_open_ports() {
    print_step "Scanning ALL open ports (listening)..."
    
    # Get all listening ports with process info
    local port_data=$(ss -tulnp 2>/dev/null | grep LISTEN)
    
    # Parse each line
    while IFS= read -r line; do
        # Extract port number
        local port=$(echo "$line" | awk '{print $5}' | grep -oE '[0-9]+$')
        
        # Extract process name if available
        local process=$(echo "$line" | grep -oP 'users:\(\(".*?"' | grep -oP '"\K[^"]+' | head -1)
        
        if [ -n "$port" ]; then
            # Get port description and category
            local port_info=$(get_port_description "$port")
            local description=$(echo "$port_info" | cut -d'|' -f1)
            local category=$(echo "$port_info" | cut -d'|' -f2)
            
            # Store port info
            SERVICE_PORTS["$port"]="$description|$category|$process|listening"
        fi
    done <<< "$port_data"
    
    print_success "Found ${#SERVICE_PORTS[@]} listening ports"
}

scan_firewall_ports() {
    print_step "Scanning firewall allowed ports..."
    
    local fw_port_count=0
    
    case $FIREWALL_TYPE in
        ufw)
            # Parse UFW status - only ALLOW rules
            local ufw_output=$(ufw status numbered 2>/dev/null | grep -E "ALLOW" | grep -v "DENY")
            
            while IFS= read -r line; do
                # Extract port from UFW output
                # Example: [ 1] 22/tcp                     ALLOW IN    Anywhere
                local port=$(echo "$line" | grep -oE '[0-9]+/(tcp|udp)' | cut -d'/' -f1)
                
                if [ -n "$port" ] && [ -z "${SERVICE_PORTS[$port]}" ]; then
                    # Port allowed in firewall but not listening
                    local port_info=$(get_port_description "$port")
                    local description=$(echo "$port_info" | cut -d'|' -f1)
                    local category=$(echo "$port_info" | cut -d'|' -f2)
                    
                    SERVICE_PORTS["$port"]="$description|$category||firewall_only"
                    fw_port_count=$((fw_port_count+1))
                fi
            done <<< "$ufw_output"
            ;;
            
        firewalld)
            # Parse firewalld ports
            local fw_ports=$(firewall-cmd --list-ports 2>/dev/null)
            
            for port_proto in $fw_ports; do
                local port=$(echo "$port_proto" | cut -d'/' -f1)
                
                if [ -n "$port" ] && [ -z "${SERVICE_PORTS[$port]}" ]; then
                    local port_info=$(get_port_description "$port")
                    local description=$(echo "$port_info" | cut -d'|' -f1)
                    local category=$(echo "$port_info" | cut -d'|' -f2)
                    
                    SERVICE_PORTS["$port"]="$description|$category||firewall_only"
                    fw_port_count=$((fw_port_count+1))
                fi
            done
            ;;
            
        iptables)
            # Parse iptables ACCEPT rules only
            local ipt_output=$(iptables -L INPUT -n --line-numbers 2>/dev/null | grep ACCEPT | grep dpt:)
            
            while IFS= read -r line; do
                local port=$(echo "$line" | grep -oP 'dpt:\K[0-9]+')
                
                if [ -n "$port" ] && [ -z "${SERVICE_PORTS[$port]}" ]; then
                    local port_info=$(get_port_description "$port")
                    local description=$(echo "$port_info" | cut -d'|' -f1)
                    local category=$(echo "$port_info" | cut -d'|' -f2)
                    
                    SERVICE_PORTS["$port"]="$description|$category||firewall_only"
                    fw_port_count=$((fw_port_count+1))
                fi
            done <<< "$ipt_output"
            ;;
            
        none)
            print_warning "No active firewall detected"
            ;;
    esac
    
    if [ $fw_port_count -gt 0 ]; then
        print_success "Found $fw_port_count ports allowed in firewall (not listening)"
    else
        print_success "No firewall-only ports found"
    fi
}

scan_all_services() {
    print_step "Scanning for dangerous services..."
    echo ""
    
    local total=0
    local found=0
    
    # Scan super dangerous
    for service in "${!SUPER_DANGEROUS[@]}"; do
        total=$((total+1))
        status=$(check_service_status "$service")
        if [ "$status" != "not_found" ]; then
            FOUND_SERVICES["$service"]="super"
            SERVICE_STATUS["$service"]="$status"
            found=$((found+1))
        fi
    done
    
    # Scan dangerous
    for service in "${!DANGEROUS[@]}"; do
        total=$((total+1))
        status=$(check_service_status "$service")
        if [ "$status" != "not_found" ]; then
            FOUND_SERVICES["$service"]="dangerous"
            SERVICE_STATUS["$service"]="$status"
            found=$((found+1))
        fi
    done
    
    # Scan suspicious
    for service in "${!SUSPICIOUS[@]}"; do
        total=$((total+1))
        status=$(check_service_status "$service")
        if [ "$status" != "not_found" ]; then
            FOUND_SERVICES["$service"]="suspicious"
            SERVICE_STATUS["$service"]="$status"
            found=$((found+1))
        fi
    done
    
    print_success "Scan complete: Found $found services (scanned $total)"
}

################################################################################
# DISPLAY FUNCTIONS
################################################################################

show_scan_results() {
    print_header "SCAN RESULTS"
    
    local super_count=0
    local dangerous_count=0
    local suspicious_count=0
    
    # Count by category
    for service in "${!FOUND_SERVICES[@]}"; do
        case "${FOUND_SERVICES[$service]}" in
            super) super_count=$((super_count+1)) ;;
            dangerous) dangerous_count=$((dangerous_count+1)) ;;
            suspicious) suspicious_count=$((suspicious_count+1)) ;;
        esac
    done
    
    echo "System: $OS $OS_VERSION (Service Manager: $SERVICE_MANAGER)"
    echo ""
    
    # Show super dangerous
    if [ $super_count -gt 0 ]; then
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${RED}  SUPER DANGEROUS ($super_count found)${NC}"
        echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        for service in "${!FOUND_SERVICES[@]}"; do
            if [ "${FOUND_SERVICES[$service]}" = "super" ]; then
                local desc="${SUPER_DANGEROUS[$service]}"
                local status="${SERVICE_STATUS[$service]}"
                
                case $status in
                    running)
                        echo -e "${RED}[✗ RUNNING]${NC} $service - $desc"
                        ;;
                    enabled)
                        echo -e "${YELLOW}[! ENABLED]${NC} $service - $desc"
                        ;;
                    installed)
                        echo -e "${YELLOW}[! INSTALLED]${NC} $service - $desc"
                        ;;
                esac
            fi
        done
        echo ""
    fi
    
    # Show dangerous
    if [ $dangerous_count -gt 0 ]; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${YELLOW}  DANGEROUS ($dangerous_count found)${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        for service in "${!FOUND_SERVICES[@]}"; do
            if [ "${FOUND_SERVICES[$service]}" = "dangerous" ]; then
                local desc="${DANGEROUS[$service]}"
                local status="${SERVICE_STATUS[$service]}"
                
                case $status in
                    running)
                        echo -e "${RED}[✗ RUNNING]${NC} $service - $desc"
                        ;;
                    enabled)
                        echo -e "${YELLOW}[! ENABLED]${NC} $service - $desc"
                        ;;
                    installed)
                        echo -e "${BLUE}[i INSTALLED]${NC} $service - $desc"
                        ;;
                esac
            fi
        done
        echo ""
    fi
    
    # Show suspicious
    if [ $suspicious_count -gt 0 ]; then
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BLUE}  SUSPICIOUS ($suspicious_count found)${NC}"
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
        
        for service in "${!FOUND_SERVICES[@]}"; do
            if [ "${FOUND_SERVICES[$service]}" = "suspicious" ]; then
                local desc="${SUSPICIOUS[$service]}"
                local status="${SERVICE_STATUS[$service]}"
                
                case $status in
                    running)
                        echo -e "${RED}[✗ RUNNING]${NC} $service - $desc"
                        ;;
                    enabled)
                        echo -e "${YELLOW}[! ENABLED]${NC} $service - $desc"
                        ;;
                    installed)
                        echo -e "${BLUE}[i INSTALLED]${NC} $service - $desc"
                        ;;
                esac
            fi
        done
        echo ""
    fi
    
    # Show all open ports categorized
    if [ ${#SERVICE_PORTS[@]} -gt 0 ]; then
        local super_ports=0
        local dangerous_ports=0
        local suspicious_ports=0
        local safe_ports=0
        local unknown_ports=0
        
        # Count by category
        for port in "${!SERVICE_PORTS[@]}"; do
            local port_info="${SERVICE_PORTS[$port]}"
            local category=$(echo "$port_info" | cut -d'|' -f2)
            
            case $category in
                super) super_ports=$((super_ports+1)) ;;
                dangerous) dangerous_ports=$((dangerous_ports+1)) ;;
                suspicious) suspicious_ports=$((suspicious_ports+1)) ;;
                safe) safe_ports=$((safe_ports+1)) ;;
                unknown) unknown_ports=$((unknown_ports+1)) ;;
            esac
        done
        
        # Show super dangerous ports
        if [ $super_ports -gt 0 ]; then
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${RED}  SUPER DANGEROUS PORTS ($super_ports open)${NC}"
            echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            
            for port in "${!SERVICE_PORTS[@]}"; do
                local port_info="${SERVICE_PORTS[$port]}"
                local description=$(echo "$port_info" | cut -d'|' -f1)
                local category=$(echo "$port_info" | cut -d'|' -f2)
                local process=$(echo "$port_info" | cut -d'|' -f3)
                local status=$(echo "$port_info" | cut -d'|' -f4)
                
                if [ "$category" = "super" ]; then
                    if [ "$status" = "listening" ]; then
                        if [ -n "$process" ]; then
                            echo -e "${RED}[✗ LISTENING]${NC} Port $port - $description (Process: $process)"
                        else
                            echo -e "${RED}[✗ LISTENING]${NC} Port $port - $description"
                        fi
                    else
                        echo -e "${YELLOW}[! FIREWALL]${NC} Port $port - $description (allowed in firewall only)"
                    fi
                fi
            done
            echo ""
        fi
        
        # Show dangerous ports
        if [ $dangerous_ports -gt 0 ]; then
            echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${YELLOW}  DANGEROUS PORTS ($dangerous_ports open)${NC}"
            echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            
            for port in "${!SERVICE_PORTS[@]}"; do
                local port_info="${SERVICE_PORTS[$port]}"
                local description=$(echo "$port_info" | cut -d'|' -f1)
                local category=$(echo "$port_info" | cut -d'|' -f2)
                local process=$(echo "$port_info" | cut -d'|' -f3)
                local status=$(echo "$port_info" | cut -d'|' -f4)
                
                if [ "$category" = "dangerous" ]; then
                    if [ "$status" = "listening" ]; then
                        if [ -n "$process" ]; then
                            echo -e "${YELLOW}[! LISTENING]${NC} Port $port - $description (Process: $process)"
                        else
                            echo -e "${YELLOW}[! LISTENING]${NC} Port $port - $description"
                        fi
                    else
                        echo -e "${BLUE}[i FIREWALL]${NC} Port $port - $description (allowed in firewall only)"
                    fi
                fi
            done
            echo ""
        fi
        
        # Show suspicious ports
        if [ $suspicious_ports -gt 0 ]; then
            echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${BLUE}  SUSPICIOUS PORTS ($suspicious_ports open)${NC}"
            echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            
            for port in "${!SERVICE_PORTS[@]}"; do
                local port_info="${SERVICE_PORTS[$port]}"
                local description=$(echo "$port_info" | cut -d'|' -f1)
                local category=$(echo "$port_info" | cut -d'|' -f2)
                local process=$(echo "$port_info" | cut -d'|' -f3)
                local status=$(echo "$port_info" | cut -d'|' -f4)
                
                if [ "$category" = "suspicious" ]; then
                    if [ "$status" = "listening" ]; then
                        if [ -n "$process" ]; then
                            echo -e "${BLUE}[i LISTENING]${NC} Port $port - $description (Process: $process)"
                        else
                            echo -e "${BLUE}[i LISTENING]${NC} Port $port - $description"
                        fi
                    else
                        echo -e "${BLUE}[i FIREWALL]${NC} Port $port - $description (allowed in firewall only)"
                    fi
                fi
            done
            echo ""
        fi
        
        # Show safe ports
        if [ $safe_ports -gt 0 ]; then
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${GREEN}  SAFE PORTS ($safe_ports open)${NC}"
            echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            
            for port in "${!SERVICE_PORTS[@]}"; do
                local port_info="${SERVICE_PORTS[$port]}"
                local description=$(echo "$port_info" | cut -d'|' -f1)
                local category=$(echo "$port_info" | cut -d'|' -f2)
                local process=$(echo "$port_info" | cut -d'|' -f3)
                local status=$(echo "$port_info" | cut -d'|' -f4)
                
                if [ "$category" = "safe" ]; then
                    if [ "$status" = "listening" ]; then
                        if [ -n "$process" ]; then
                            echo -e "${GREEN}[✓ LISTENING]${NC} Port $port - $description (Process: $process)"
                        else
                            echo -e "${GREEN}[✓ LISTENING]${NC} Port $port - $description"
                        fi
                    else
                        echo -e "${GREEN}[✓ FIREWALL]${NC} Port $port - $description (allowed in firewall only)"
                    fi
                fi
            done
            echo ""
        fi
        
        # Show unknown ports
        if [ $unknown_ports -gt 0 ]; then
            echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo -e "${MAGENTA}  UNKNOWN PORTS ($unknown_ports open)${NC}"
            echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            echo ""
            
            for port in "${!SERVICE_PORTS[@]}"; do
                local port_info="${SERVICE_PORTS[$port]}"
                local description=$(echo "$port_info" | cut -d'|' -f1)
                local category=$(echo "$port_info" | cut -d'|' -f2)
                local process=$(echo "$port_info" | cut -d'|' -f3)
                local status=$(echo "$port_info" | cut -d'|' -f4)
                
                if [ "$category" = "unknown" ]; then
                    if [ "$status" = "listening" ]; then
                        if [ -n "$process" ]; then
                            echo -e "${MAGENTA}[? LISTENING]${NC} Port $port - $description (Process: $process)"
                        else
                            echo -e "${MAGENTA}[? LISTENING]${NC} Port $port - $description"
                        fi
                    else
                        echo -e "${MAGENTA}[? FIREWALL]${NC} Port $port - $description (allowed in firewall only)"
                    fi
                fi
            done
            echo ""
        fi
    fi
    
    if [ $super_count -eq 0 ] && [ $dangerous_count -eq 0 ] && [ $suspicious_count -eq 0 ]; then
        print_success "No dangerous services found! System looks clean."
        echo ""
    fi
}

################################################################################
# ACTION FUNCTIONS
################################################################################

stop_service() {
    local service=$1
    
    if [ "$SERVICE_MANAGER" = "systemd" ]; then
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    else
        service "$service" stop 2>/dev/null
        update-rc.d "$service" disable 2>/dev/null || chkconfig "$service" off 2>/dev/null
    fi
}

remove_service() {
    local service=$1
    
    # Stop first
    stop_service "$service"
    
    # Remove package
    if command -v apt-get &> /dev/null; then
        apt-get remove -y "$service" 2>/dev/null
        apt-get purge -y "$service" 2>/dev/null
    elif command -v yum &> /dev/null; then
        yum remove -y "$service" 2>/dev/null
    elif command -v dnf &> /dev/null; then
        dnf remove -y "$service" 2>/dev/null
    fi
}

kill_super_dangerous() {
    print_header "KILLING SUPER DANGEROUS SERVICES"
    
    local count=0
    for service in "${!FOUND_SERVICES[@]}"; do
        if [ "${FOUND_SERVICES[$service]}" = "super" ]; then
            count=$((count+1))
        fi
    done
    
    if [ $count -eq 0 ]; then
        print_success "No super dangerous services found!"
        return 0
    fi
    
    echo "Will STOP & DISABLE these services:"
    for service in "${!FOUND_SERVICES[@]}"; do
        if [ "${FOUND_SERVICES[$service]}" = "super" ]; then
            echo "  - $service (${SUPER_DANGEROUS[$service]})"
        fi
    done
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    for service in "${!FOUND_SERVICES[@]}"; do
        if [ "${FOUND_SERVICES[$service]}" = "super" ]; then
            print_step "Stopping $service..."
            stop_service "$service"
            
            # Verify
            if [ "$SERVICE_MANAGER" = "systemd" ]; then
                if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                    print_success "$service stopped"
                else
                    print_error "$service still running!"
                fi
            fi
        fi
    done
    
    echo ""
    print_success "Super dangerous services killed!"
}

kill_all_dangerous() {
    print_header "KILLING ALL DANGEROUS SERVICES"
    
    local count=${#FOUND_SERVICES[@]}
    
    if [ $count -eq 0 ]; then
        print_success "No dangerous services found!"
        return 0
    fi
    
    echo "Will STOP & DISABLE ALL found services:"
    for service in "${!FOUND_SERVICES[@]}"; do
        local category="${FOUND_SERVICES[$service]}"
        case $category in
            super) echo -e "  ${RED}- $service${NC} (${SUPER_DANGEROUS[$service]})" ;;
            dangerous) echo -e "  ${YELLOW}- $service${NC} (${DANGEROUS[$service]})" ;;
            suspicious) echo -e "  ${BLUE}- $service${NC} (${SUSPICIOUS[$service]})" ;;
        esac
    done
    echo ""
    
    print_warning "WARNING: This will stop web servers, databases, etc!"
    read -p "Are you sure? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    for service in "${!FOUND_SERVICES[@]}"; do
        print_step "Stopping $service..."
        stop_service "$service"
        
        if [ "$SERVICE_MANAGER" = "systemd" ]; then
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                print_success "$service stopped"
            else
                print_error "$service still running!"
            fi
        fi
    done
    
    echo ""
    print_success "All dangerous services killed!"
}

remove_all_packages() {
    print_header "REMOVING ALL DANGEROUS PACKAGES"
    
    local count=${#FOUND_SERVICES[@]}
    
    if [ $count -eq 0 ]; then
        print_success "No dangerous services found!"
        return 0
    fi
    
    echo "Will REMOVE (uninstall) ALL found services:"
    for service in "${!FOUND_SERVICES[@]}"; do
        echo "  - $service"
    done
    echo ""
    
    print_warning "WARNING: This will PERMANENTLY remove packages!"
    read -p "Are you sure? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    for service in "${!FOUND_SERVICES[@]}"; do
        print_step "Removing $service..."
        remove_service "$service"
        print_success "$service removed"
    done
    
    echo ""
    print_success "All dangerous packages removed!"
}

manual_selection() {
    print_header "MANUAL SELECTION"
    
    declare -A selected_services
    
    echo "Select services to STOP & DISABLE:"
    echo "(Enter service name, or 'done' to finish)"
    echo ""
    
    # Show available services
    local index=1
    declare -A service_index
    
    for service in "${!FOUND_SERVICES[@]}"; do
        service_index[$index]="$service"
        local category="${FOUND_SERVICES[$service]}"
        
        case $category in
            super)
                echo -e "[$index] ${RED}$service${NC} - ${SUPER_DANGEROUS[$service]}"
                ;;
            dangerous)
                echo -e "[$index] ${YELLOW}$service${NC} - ${DANGEROUS[$service]}"
                ;;
            suspicious)
                echo -e "[$index] ${BLUE}$service${NC} - ${SUSPICIOUS[$service]}"
                ;;
        esac
        
        index=$((index+1))
    done
    
    echo ""
    
    while true; do
        read -p "Select number (or 'done'): " choice
        
        if [ "$choice" = "done" ]; then
            break
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${service_index[$choice]}" ]; then
            local service="${service_index[$choice]}"
            selected_services["$service"]=1
            print_success "Selected: $service"
        else
            print_error "Invalid selection"
        fi
    done
    
    if [ ${#selected_services[@]} -eq 0 ]; then
        echo "No services selected."
        return 0
    fi
    
    echo ""
    echo "Will stop these services:"
    for service in "${!selected_services[@]}"; do
        echo "  - $service"
    done
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    for service in "${!selected_services[@]}"; do
        print_step "Stopping $service..."
        stop_service "$service"
        
        if [ "$SERVICE_MANAGER" = "systemd" ]; then
            if ! systemctl is-active --quiet "$service" 2>/dev/null; then
                print_success "$service stopped"
            else
                print_error "$service still running!"
            fi
        fi
    done
    
    echo ""
    print_success "Selected services killed!"
}

kill_ports_by_process() {
    print_header "KILL DANGEROUS PORTS (AUTO)"
    
    # Count dangerous ports
    local count=0
    for port in "${!SERVICE_PORTS[@]}"; do
        local port_info="${SERVICE_PORTS[$port]}"
        local category=$(echo "$port_info" | cut -d'|' -f2)
        
        if [ "$category" = "super" ] || [ "$category" = "dangerous" ]; then
            count=$((count+1))
        fi
    done
    
    if [ $count -eq 0 ]; then
        print_success "No dangerous ports found!"
        return 0
    fi
    
    echo "Will kill processes AND block ports in firewall:"
    for port in "${!SERVICE_PORTS[@]}"; do
        local port_info="${SERVICE_PORTS[$port]}"
        local description=$(echo "$port_info" | cut -d'|' -f1)
        local category=$(echo "$port_info" | cut -d'|' -f2)
        local process=$(echo "$port_info" | cut -d'|' -f3)
        local status=$(echo "$port_info" | cut -d'|' -f4)
        
        if [ "$category" = "super" ] || [ "$category" = "dangerous" ]; then
            if [ "$status" = "listening" ]; then
                if [ -n "$process" ]; then
                    echo -e "  ${RED}- Port $port${NC} ($description) - Process: $process [KILL + BLOCK]"
                else
                    echo -e "  ${RED}- Port $port${NC} ($description) - Process: Unknown [BLOCK]"
                fi
            else
                echo -e "  ${YELLOW}- Port $port${NC} ($description) - Firewall only [BLOCK]"
            fi
        fi
    done
    echo ""
    
    if [ "$FIREWALL_TYPE" = "none" ]; then
        print_warning "No firewall active! Will only kill processes."
    else
        print_step "Firewall: $FIREWALL_TYPE (will block ports)"
    fi
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    for port in "${!SERVICE_PORTS[@]}"; do
        local port_info="${SERVICE_PORTS[$port]}"
        local category=$(echo "$port_info" | cut -d'|' -f2)
        local process=$(echo "$port_info" | cut -d'|' -f3)
        local status=$(echo "$port_info" | cut -d'|' -f4)
        
        if [ "$category" = "super" ] || [ "$category" = "dangerous" ]; then
            print_step "Processing port $port..."
            
            # Kill process if listening
            if [ "$status" = "listening" ] && [ -n "$process" ]; then
                # Try to stop via systemctl first
                if systemctl stop "$process" 2>/dev/null; then
                    systemctl disable "$process" 2>/dev/null
                    print_success "  Stopped $process via systemctl"
                else
                    # Kill by PID
                    local pids=$(ss -tulnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+')
                    if [ -n "$pids" ]; then
                        for pid in $pids; do
                            kill -9 "$pid" 2>/dev/null
                            print_success "  Killed PID $pid"
                        done
                    fi
                fi
            fi
            
            # Block port in firewall
            if [ "$FIREWALL_TYPE" != "none" ]; then
                case $FIREWALL_TYPE in
                    ufw)
                        ufw delete allow $port/tcp 2>/dev/null
                        ufw deny $port/tcp 2>/dev/null
                        print_success "  Blocked port $port in UFW"
                        ;;
                    firewalld)
                        firewall-cmd --remove-port=$port/tcp --permanent 2>/dev/null
                        firewall-cmd --add-rich-rule="rule family='ipv4' port port='$port' protocol='tcp' reject" --permanent 2>/dev/null
                        firewall-cmd --reload 2>/dev/null
                        print_success "  Blocked port $port in firewalld"
                        ;;
                    iptables)
                        # Remove any ACCEPT rules for this port
                        iptables -D INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                        # Add DROP rule
                        iptables -I INPUT -p tcp --dport $port -j DROP 2>/dev/null
                        # Save rules
                        if command -v iptables-save &> /dev/null; then
                            mkdir -p /etc/iptables
                            iptables-save > /etc/iptables/rules.v4 2>/dev/null
                        fi
                        print_success "  Blocked port $port in iptables"
                        ;;
                esac
            fi
        fi
    done
    
    echo ""
    print_success "Dangerous ports killed and blocked!"
}

manual_block_ports() {
    print_header "MANUAL PORT BLOCKING"
    
    if [ ${#SERVICE_PORTS[@]} -eq 0 ]; then
        print_warning "No ports found!"
        return 0
    fi
    
    declare -A selected_ports
    
    echo "Select ports to BLOCK (one by one, or 'done' to finish):"
    echo ""
    
    # Show all ports with index
    local index=1
    declare -A port_index
    
    for port in $(echo "${!SERVICE_PORTS[@]}" | tr ' ' '\n' | sort -n); do
        local port_info="${SERVICE_PORTS[$port]}"
        local description=$(echo "$port_info" | cut -d'|' -f1)
        local category=$(echo "$port_info" | cut -d'|' -f2)
        local process=$(echo "$port_info" | cut -d'|' -f3)
        local status=$(echo "$port_info" | cut -d'|' -f4)
        
        port_index[$index]="$port"
        
        case $category in
            super)
                if [ "$status" = "listening" ]; then
                    echo -e "[$index] ${RED}Port $port${NC} - $description (Process: $process) [LISTENING]"
                else
                    echo -e "[$index] ${RED}Port $port${NC} - $description [FIREWALL ONLY]"
                fi
                ;;
            dangerous)
                if [ "$status" = "listening" ]; then
                    echo -e "[$index] ${YELLOW}Port $port${NC} - $description (Process: $process) [LISTENING]"
                else
                    echo -e "[$index] ${YELLOW}Port $port${NC} - $description [FIREWALL ONLY]"
                fi
                ;;
            suspicious)
                if [ "$status" = "listening" ]; then
                    echo -e "[$index] ${BLUE}Port $port${NC} - $description (Process: $process) [LISTENING]"
                else
                    echo -e "[$index] ${BLUE}Port $port${NC} - $description [FIREWALL ONLY]"
                fi
                ;;
            safe)
                if [ "$status" = "listening" ]; then
                    echo -e "[$index] ${GREEN}Port $port${NC} - $description (Process: $process) [LISTENING]"
                else
                    echo -e "[$index] ${GREEN}Port $port${NC} - $description [FIREWALL ONLY]"
                fi
                ;;
            unknown)
                if [ "$status" = "listening" ]; then
                    echo -e "[$index] ${MAGENTA}Port $port${NC} - $description (Process: $process) [LISTENING]"
                else
                    echo -e "[$index] ${MAGENTA}Port $port${NC} - $description [FIREWALL ONLY]"
                fi
                ;;
        esac
        
        index=$((index+1))
    done
    
    echo ""
    
    while true; do
        read -p "Select number (or 'done'): " choice
        
        if [ "$choice" = "done" ]; then
            break
        fi
        
        if [[ "$choice" =~ ^[0-9]+$ ]] && [ -n "${port_index[$choice]}" ]; then
            local port="${port_index[$choice]}"
            selected_ports["$port"]=1
            print_success "Selected: Port $port"
        else
            print_error "Invalid selection"
        fi
    done
    
    if [ ${#selected_ports[@]} -eq 0 ]; then
        echo "No ports selected."
        return 0
    fi
    
    echo ""
    echo "Will block these ports:"
    for port in "${!selected_ports[@]}"; do
        local port_info="${SERVICE_PORTS[$port]}"
        local description=$(echo "$port_info" | cut -d'|' -f1)
        local process=$(echo "$port_info" | cut -d'|' -f3)
        local status=$(echo "$port_info" | cut -d'|' -f4)
        
        if [ "$status" = "listening" ] && [ -n "$process" ]; then
            echo "  - Port $port ($description) - Process: $process [KILL + BLOCK]"
        else
            echo "  - Port $port ($description) [BLOCK]"
        fi
    done
    echo ""
    
    if [ "$FIREWALL_TYPE" = "none" ]; then
        print_warning "No firewall active! Will only kill processes."
    else
        print_step "Firewall: $FIREWALL_TYPE (will block ports)"
    fi
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    for port in "${!selected_ports[@]}"; do
        local port_info="${SERVICE_PORTS[$port]}"
        local process=$(echo "$port_info" | cut -d'|' -f3)
        local status=$(echo "$port_info" | cut -d'|' -f4)
        
        print_step "Processing port $port..."
        
        # Kill process if listening
        if [ "$status" = "listening" ] && [ -n "$process" ]; then
            # Try to stop via systemctl first
            if systemctl stop "$process" 2>/dev/null; then
                systemctl disable "$process" 2>/dev/null
                print_success "  Stopped $process via systemctl"
            else
                # Kill by PID
                local pids=$(ss -tulnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K[0-9]+')
                if [ -n "$pids" ]; then
                    for pid in $pids; do
                        kill -9 "$pid" 2>/dev/null
                        print_success "  Killed PID $pid"
                    done
                fi
            fi
        fi
        
        # Block port in firewall
        if [ "$FIREWALL_TYPE" != "none" ]; then
            case $FIREWALL_TYPE in
                ufw)
                    ufw delete allow $port/tcp 2>/dev/null
                    ufw deny $port/tcp 2>/dev/null
                    print_success "  Blocked port $port in UFW"
                    ;;
                firewalld)
                    firewall-cmd --remove-port=$port/tcp --permanent 2>/dev/null
                    firewall-cmd --add-rich-rule="rule family='ipv4' port port='$port' protocol='tcp' reject" --permanent 2>/dev/null
                    firewall-cmd --reload 2>/dev/null
                    print_success "  Blocked port $port in firewalld"
                    ;;
                iptables)
                    # Remove any ACCEPT rules for this port
                    iptables -D INPUT -p tcp --dport $port -j ACCEPT 2>/dev/null
                    # Add DROP rule
                    iptables -I INPUT -p tcp --dport $port -j DROP 2>/dev/null
                    # Save rules
                    if command -v iptables-save &> /dev/null; then
                        mkdir -p /etc/iptables
                        iptables-save > /etc/iptables/rules.v4 2>/dev/null
                    fi
                    print_success "  Blocked port $port in iptables"
                    ;;
            esac
        fi
    done
    
    echo ""
    print_success "Selected ports blocked!"
}

main_menu() {
    # Initial scan
    detect_os
    detect_firewall
    initialize_service_lists
    scan_open_ports
    scan_firewall_ports
    scan_all_services
    
    while true; do
        show_scan_results
        
        print_header "MAIN MENU"
        
        echo "[1] Kill SUPER DANGEROUS only (FTP, Telnet, etc)"
        echo "    → Stop & disable critical threats"
        echo ""
        echo "[2] Kill ALL dangerous services"
        echo "    → Stop & disable everything found"
        echo ""
        echo "[3] Remove ALL packages (uninstall)"
        echo "    → Permanently remove all found services"
        echo ""
        echo "[4] Manual selection"
        echo "    → Choose which services to kill"
        echo ""
        echo "[5] Kill dangerous PORTS (by process)"
        echo "    → Kill processes using dangerous ports"
        echo ""
        echo "[6] Manual block PORTS"
        echo "    → Choose which ports to block"
        echo ""
        echo "[7] Rescan"
        echo "    → Scan again for services & ports"
        echo ""
        echo "[0] Exit"
        echo ""
        
        read -p "Choose [0-7]: " choice
        
        case $choice in
            1)
                create_backup
                kill_super_dangerous
                read -p "Press Enter to continue..."
                # Rescan
                FOUND_SERVICES=()
                SERVICE_STATUS=()
                scan_all_services
                ;;
            2)
                create_backup
                kill_all_dangerous
                read -p "Press Enter to continue..."
                # Rescan
                FOUND_SERVICES=()
                SERVICE_STATUS=()
                SERVICE_PORTS=()
                scan_open_ports
                scan_firewall_ports
                scan_all_services
                ;;
            3)
                create_backup
                remove_all_packages
                read -p "Press Enter to continue..."
                # Rescan
                FOUND_SERVICES=()
                SERVICE_STATUS=()
                SERVICE_PORTS=()
                scan_open_ports
                scan_firewall_ports
                scan_all_services
                ;;
            4)
                create_backup
                manual_selection
                read -p "Press Enter to continue..."
                # Rescan
                FOUND_SERVICES=()
                SERVICE_STATUS=()
                SERVICE_PORTS=()
                scan_open_ports
                scan_firewall_ports
                scan_all_services
                ;;
            5)
                create_backup
                kill_ports_by_process
                read -p "Press Enter to continue..."
                # Rescan
                SERVICE_PORTS=()
                scan_open_ports
                scan_firewall_ports
                ;;
            6)
                create_backup
                manual_block_ports
                read -p "Press Enter to continue..."
                # Rescan
                SERVICE_PORTS=()
                scan_open_ports
                scan_firewall_ports
                ;;
            7)
                FOUND_SERVICES=()
                SERVICE_STATUS=()
                SERVICE_PORTS=()
                detect_firewall
                scan_open_ports
                scan_firewall_ports
                scan_all_services
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
