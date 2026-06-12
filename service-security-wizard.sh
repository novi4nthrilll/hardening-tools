#!/bin/bash

################################################################################
#                    SERVICE SECURITY HARDENING WIZARD                         #
#                          For CTF OS Hardening                                #
################################################################################

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Variables
BACKUP_DIR="/root/service-backup-$(date +%Y%m%d-%H%M%S)"
OS=""
OS_VERSION=""

# Detection results
declare -A FOUND_SERVICES
declare -A SERVICE_ISSUES

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
    
    # Backup SSH
    [ -f /etc/ssh/sshd_config ] && cp /etc/ssh/sshd_config "$BACKUP_DIR/"
    
    # Backup Apache
    [ -d /etc/apache2 ] && cp -r /etc/apache2 "$BACKUP_DIR/" 2>/dev/null
    [ -d /etc/httpd ] && cp -r /etc/httpd "$BACKUP_DIR/" 2>/dev/null
    
    # Backup Nginx
    [ -d /etc/nginx ] && cp -r /etc/nginx "$BACKUP_DIR/" 2>/dev/null
    
    # Backup MySQL
    [ -f /etc/mysql/mysql.conf.d/mysqld.cnf ] && cp /etc/mysql/mysql.conf.d/mysqld.cnf "$BACKUP_DIR/" 2>/dev/null
    [ -f /etc/my.cnf ] && cp /etc/my.cnf "$BACKUP_DIR/" 2>/dev/null
    
    # Backup PostgreSQL
    [ -d /etc/postgresql ] && cp -r /etc/postgresql "$BACKUP_DIR/" 2>/dev/null
    
    print_success "Backup created: $BACKUP_DIR"
}

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

################################################################################
# SERVICE DETECTION
################################################################################

detect_services() {
    print_step "Detecting running services..."
    echo ""
    
    # Check SSH
    if systemctl is-active --quiet sshd 2>/dev/null || systemctl is-active --quiet ssh 2>/dev/null; then
        FOUND_SERVICES["ssh"]="running"
        print_success "SSH detected"
    fi
    
    # Check Apache
    if systemctl is-active --quiet apache2 2>/dev/null || systemctl is-active --quiet httpd 2>/dev/null; then
        FOUND_SERVICES["apache"]="running"
        print_success "Apache detected"
    fi
    
    # Check Nginx
    if systemctl is-active --quiet nginx 2>/dev/null; then
        FOUND_SERVICES["nginx"]="running"
        print_success "Nginx detected"
    fi
    
    # Check MySQL
    if systemctl is-active --quiet mysql 2>/dev/null || systemctl is-active --quiet mysqld 2>/dev/null || systemctl is-active --quiet mariadb 2>/dev/null; then
        FOUND_SERVICES["mysql"]="running"
        print_success "MySQL/MariaDB detected"
    fi
    
    # Check PostgreSQL
    if systemctl is-active --quiet postgresql 2>/dev/null; then
        FOUND_SERVICES["postgresql"]="running"
        print_success "PostgreSQL detected"
    fi
    
    # Check Postfix
    if systemctl is-active --quiet postfix 2>/dev/null; then
        FOUND_SERVICES["postfix"]="running"
        print_success "Postfix detected"
    fi
    
    echo ""
    print_success "Found ${#FOUND_SERVICES[@]} services"
}

################################################################################
# SSH SECURITY CHECKS
################################################################################

check_ssh_security() {
    print_step "Analyzing SSH security..."
    
    local issues=0
    local config_file="/etc/ssh/sshd_config"
    
    # Check root login
    if grep -q "^PermitRootLogin yes" "$config_file" 2>/dev/null; then
        print_error "Root login: ENABLED (insecure!)"
        issues=$((issues+1))
    elif grep -q "^PermitRootLogin no" "$config_file" 2>/dev/null; then
        print_success "Root login: DISABLED"
    else
        print_warning "Root login: DEFAULT (should disable)"
        issues=$((issues+1))
    fi
    
    # Check port
    local ssh_port=$(grep "^Port " "$config_file" 2>/dev/null | awk '{print $2}')
    if [ -z "$ssh_port" ] || [ "$ssh_port" = "22" ]; then
        print_error "SSH Port: 22 (default, should change)"
        issues=$((issues+1))
    else
        print_success "SSH Port: $ssh_port (custom)"
    fi
    
    # Check password authentication
    if grep -q "^PasswordAuthentication yes" "$config_file" 2>/dev/null; then
        print_error "Password auth: ENABLED (should use keys)"
        issues=$((issues+1))
    elif grep -q "^PasswordAuthentication no" "$config_file" 2>/dev/null; then
        print_success "Password auth: DISABLED"
    else
        print_warning "Password auth: DEFAULT (should disable)"
        issues=$((issues+1))
    fi
    
    # Check empty passwords
    if grep -q "^PermitEmptyPasswords yes" "$config_file" 2>/dev/null; then
        print_error "Empty passwords: ALLOWED (insecure!)"
        issues=$((issues+1))
    else
        print_success "Empty passwords: DENIED"
    fi
    
    # Check X11 forwarding
    if grep -q "^X11Forwarding yes" "$config_file" 2>/dev/null; then
        print_warning "X11 Forwarding: ENABLED (should disable)"
        issues=$((issues+1))
    else
        print_success "X11 Forwarding: DISABLED"
    fi
    
    SERVICE_ISSUES["ssh"]=$issues
    echo ""
}

################################################################################
# APACHE SECURITY CHECKS
################################################################################

check_apache_security() {
    print_step "Analyzing Apache security..."
    
    local issues=0
    local config_file=""
    
    if [ -f /etc/apache2/conf-enabled/security.conf ]; then
        config_file="/etc/apache2/conf-enabled/security.conf"
    elif [ -f /etc/httpd/conf/httpd.conf ]; then
        config_file="/etc/httpd/conf/httpd.conf"
    fi
    
    # Check ServerTokens
    if grep -q "^ServerTokens Prod" "$config_file" 2>/dev/null; then
        print_success "ServerTokens: Prod (secure)"
    else
        print_error "ServerTokens: NOT Prod (version exposed!)"
        issues=$((issues+1))
    fi
    
    # Check ServerSignature
    if grep -q "^ServerSignature Off" "$config_file" 2>/dev/null; then
        print_success "ServerSignature: Off (secure)"
    else
        print_error "ServerSignature: NOT Off (info exposed!)"
        issues=$((issues+1))
    fi
    
    # Check directory listing
    if grep -q "Options.*-Indexes" /etc/apache2/apache2.conf 2>/dev/null || grep -q "Options.*-Indexes" /etc/httpd/conf/httpd.conf 2>/dev/null; then
        print_success "Directory listing: DISABLED"
    else
        print_error "Directory listing: ENABLED (insecure!)"
        issues=$((issues+1))
    fi
    
    # Check TraceEnable
    if grep -q "^TraceEnable off" "$config_file" 2>/dev/null; then
        print_success "TRACE method: DISABLED"
    else
        print_warning "TRACE method: NOT disabled"
        issues=$((issues+1))
    fi
    
    SERVICE_ISSUES["apache"]=$issues
    echo ""
}

################################################################################
# NGINX SECURITY CHECKS
################################################################################

check_nginx_security() {
    print_step "Analyzing Nginx security..."
    
    local issues=0
    local config_file="/etc/nginx/nginx.conf"
    
    # Check server_tokens
    if grep -q "server_tokens off" "$config_file" 2>/dev/null; then
        print_success "server_tokens: off (secure)"
    else
        print_error "server_tokens: NOT off (version exposed!)"
        issues=$((issues+1))
    fi
    
    # Check autoindex
    if grep -q "autoindex off" "$config_file" 2>/dev/null || grep -q "autoindex off" /etc/nginx/sites-available/default 2>/dev/null; then
        print_success "autoindex: off (secure)"
    else
        print_error "autoindex: NOT off (directory listing!)"
        issues=$((issues+1))
    fi
    
    # Check client_max_body_size
    if grep -q "client_max_body_size" "$config_file" 2>/dev/null; then
        print_success "client_max_body_size: SET"
    else
        print_warning "client_max_body_size: NOT set"
        issues=$((issues+1))
    fi
    
    SERVICE_ISSUES["nginx"]=$issues
    echo ""
}

################################################################################
# MYSQL SECURITY CHECKS
################################################################################

check_mysql_security() {
    print_step "Analyzing MySQL security..."
    
    local issues=0
    local config_file=""
    
    if [ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]; then
        config_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
    elif [ -f /etc/my.cnf ]; then
        config_file="/etc/my.cnf"
    fi
    
    # Check bind-address
    local bind_addr=$(grep "^bind-address" "$config_file" 2>/dev/null | awk '{print $3}')
    if [ "$bind_addr" = "127.0.0.1" ]; then
        print_success "bind-address: 127.0.0.1 (secure)"
    elif [ "$bind_addr" = "0.0.0.0" ]; then
        print_error "bind-address: 0.0.0.0 (insecure! allows remote)"
        issues=$((issues+1))
    else
        print_warning "bind-address: NOT set (should be 127.0.0.1)"
        issues=$((issues+1))
    fi
    
    # Check test database
    if mysql -e "SHOW DATABASES" 2>/dev/null | grep -q "^test$"; then
        print_error "Test database: EXISTS (should remove)"
        issues=$((issues+1))
    else
        print_success "Test database: NOT found"
    fi
    
    # Check anonymous users
    if mysql -e "SELECT User FROM mysql.user WHERE User=''" 2>/dev/null | grep -q "^$"; then
        print_error "Anonymous users: EXIST (should remove)"
        issues=$((issues+1))
    else
        print_success "Anonymous users: NOT found"
    fi
    
    SERVICE_ISSUES["mysql"]=$issues
    echo ""
}

################################################################################
# POSTGRESQL SECURITY CHECKS
################################################################################

check_postgresql_security() {
    print_step "Analyzing PostgreSQL security..."
    
    local issues=0
    local config_file=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
    
    if [ -z "$config_file" ]; then
        print_warning "Config file not found"
        return
    fi
    
    # Check listen_addresses
    local listen_addr=$(grep "^listen_addresses" "$config_file" 2>/dev/null | cut -d"'" -f2)
    if [ "$listen_addr" = "localhost" ]; then
        print_success "listen_addresses: localhost (secure)"
    else
        print_error "listen_addresses: NOT localhost (insecure!)"
        issues=$((issues+1))
    fi
    
    SERVICE_ISSUES["postgresql"]=$issues
    echo ""
}

################################################################################
# DISPLAY RESULTS
################################################################################

show_security_analysis() {
    print_header "SECURITY ANALYSIS RESULTS"
    
    local total_issues=0
    
    for service in "${!FOUND_SERVICES[@]}"; do
        local issues=${SERVICE_ISSUES[$service]:-0}
        total_issues=$((total_issues + issues))
        
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        if [ $issues -eq 0 ]; then
            echo -e "${GREEN}  ${service^^} - SECURE (0 issues)${NC}"
        elif [ $issues -le 2 ]; then
            echo -e "${YELLOW}  ${service^^} - NEEDS ATTENTION ($issues issues)${NC}"
        else
            echo -e "${RED}  ${service^^} - INSECURE ($issues issues)${NC}"
        fi
        
        echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    done
    
    echo ""
    if [ $total_issues -eq 0 ]; then
        print_success "All services are secure!"
    else
        print_warning "Total issues found: $total_issues"
    fi
    echo ""
}

################################################################################
# HARDENING FUNCTIONS - SSH
################################################################################

harden_ssh() {
    print_header "HARDENING SSH"
    
    local config_file="/etc/ssh/sshd_config"
    
    echo "This will apply SSH hardening:"
    echo "  ✓ Disable root login"
    echo "  ✓ Change port to 2222"
    echo "  ✓ Disable password authentication"
    echo "  ✓ Disable empty passwords"
    echo "  ✓ Disable X11 forwarding"
    echo "  ✓ Set max auth tries to 3"
    echo "  ✓ Set login grace time to 30s"
    echo ""
    
    print_warning "IMPORTANT: Make sure you have SSH key setup!"
    print_warning "Keep this terminal open and test in NEW terminal!"
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    print_step "Applying SSH hardening..."
    
    # Backup
    cp "$config_file" "${config_file}.bak"
    
    # Apply settings
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' "$config_file"
    sed -i 's/^#*Port.*/Port 2222/' "$config_file"
    sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' "$config_file"
    sed -i 's/^#*PermitEmptyPasswords.*/PermitEmptyPasswords no/' "$config_file"
    sed -i 's/^#*X11Forwarding.*/X11Forwarding no/' "$config_file"
    sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 3/' "$config_file"
    sed -i 's/^#*LoginGraceTime.*/LoginGraceTime 30/' "$config_file"
    
    # Add if not exists
    grep -q "^PermitRootLogin" "$config_file" || echo "PermitRootLogin no" >> "$config_file"
    grep -q "^Port" "$config_file" || echo "Port 2222" >> "$config_file"
    grep -q "^PasswordAuthentication" "$config_file" || echo "PasswordAuthentication no" >> "$config_file"
    
    # Test config
    print_step "Testing SSH config..."
    if sshd -t 2>/dev/null; then
        print_success "Config syntax OK"
    else
        print_error "Config syntax error! Restoring backup..."
        cp "${config_file}.bak" "$config_file"
        return 1
    fi
    
    # Restart SSH
    print_step "Restarting SSH..."
    systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
    
    echo ""
    print_success "SSH hardened successfully!"
    echo ""
    print_warning "IMPORTANT: Test SSH in NEW terminal NOW!"
    echo "    Command: ssh -p 2222 user@$(hostname -I | awk '{print $1}')"
    echo ""
    print_warning "Do NOT close this terminal until you verify SSH works!"
    echo ""
}

################################################################################
# HARDENING FUNCTIONS - APACHE
################################################################################

harden_apache() {
    print_header "HARDENING APACHE"
    
    echo "This will apply Apache hardening:"
    echo "  ✓ Hide version (ServerTokens Prod)"
    echo "  ✓ Disable signature (ServerSignature Off)"
    echo "  ✓ Disable directory listing"
    echo "  ✓ Disable TRACE method"
    echo "  ✓ Add security headers"
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    print_step "Applying Apache hardening..."
    
    # Detect config location
    if [ -f /etc/apache2/conf-enabled/security.conf ]; then
        local security_conf="/etc/apache2/conf-enabled/security.conf"
        local main_conf="/etc/apache2/apache2.conf"
        local service_name="apache2"
    elif [ -f /etc/httpd/conf/httpd.conf ]; then
        local security_conf="/etc/httpd/conf/httpd.conf"
        local main_conf="/etc/httpd/conf/httpd.conf"
        local service_name="httpd"
    else
        print_error "Apache config not found"
        return 1
    fi
    
    # ServerTokens & ServerSignature
    if grep -q "^ServerTokens" "$security_conf"; then
        sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$security_conf"
    else
        echo "ServerTokens Prod" >> "$security_conf"
    fi
    
    if grep -q "^ServerSignature" "$security_conf"; then
        sed -i 's/^ServerSignature.*/ServerSignature Off/' "$security_conf"
    else
        echo "ServerSignature Off" >> "$security_conf"
    fi
    
    # TraceEnable
    if grep -q "^TraceEnable" "$security_conf"; then
        sed -i 's/^TraceEnable.*/TraceEnable off/' "$security_conf"
    else
        echo "TraceEnable off" >> "$security_conf"
    fi
    
    # Disable directory listing
    sed -i 's/Options Indexes/Options -Indexes/' "$main_conf"
    
    # Enable headers module
    if [ "$service_name" = "apache2" ]; then
        a2enmod headers 2>/dev/null
    fi
    
    # Add security headers
    cat >> "$security_conf" << 'EOF'

# Security Headers
<IfModule mod_headers.c>
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-XSS-Protection "1; mode=block"
</IfModule>
EOF
    
    # Test config
    print_step "Testing Apache config..."
    if apache2ctl configtest 2>/dev/null || apachectl configtest 2>/dev/null; then
        print_success "Config syntax OK"
    else
        print_error "Config syntax error!"
        return 1
    fi
    
    # Restart Apache
    print_step "Restarting Apache..."
    systemctl restart "$service_name"
    
    echo ""
    print_success "Apache hardened successfully!"
    echo ""
}

################################################################################
# HARDENING FUNCTIONS - NGINX
################################################################################

harden_nginx() {
    print_header "HARDENING NGINX"
    
    echo "This will apply Nginx hardening:"
    echo "  ✓ Hide version (server_tokens off)"
    echo "  ✓ Disable directory listing (autoindex off)"
    echo "  ✓ Limit request size (1MB)"
    echo "  ✓ Set timeouts"
    echo "  ✓ Add security headers"
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    print_step "Applying Nginx hardening..."
    
    local config_file="/etc/nginx/nginx.conf"
    
    # Add settings in http block
    if ! grep -q "server_tokens off" "$config_file"; then
        sed -i '/http {/a \    server_tokens off;' "$config_file"
    fi
    
    if ! grep -q "client_max_body_size" "$config_file"; then
        sed -i '/http {/a \    client_max_body_size 1M;' "$config_file"
    fi
    
    if ! grep -q "client_body_timeout" "$config_file"; then
        sed -i '/http {/a \    client_body_timeout 10;\n    client_header_timeout 10;\n    keepalive_timeout 5 5;\n    send_timeout 10;' "$config_file"
    fi
    
    # Add security headers
    if ! grep -q "X-Frame-Options" "$config_file"; then
        sed -i '/http {/a \    add_header X-Frame-Options "SAMEORIGIN" always;\n    add_header X-Content-Type-Options "nosniff" always;\n    add_header X-XSS-Protection "1; mode=block" always;' "$config_file"
    fi
    
    # Disable autoindex in default site
    if [ -f /etc/nginx/sites-available/default ]; then
        if ! grep -q "autoindex off" /etc/nginx/sites-available/default; then
            sed -i '/server {/a \    autoindex off;' /etc/nginx/sites-available/default
        fi
    fi
    
    # Test config
    print_step "Testing Nginx config..."
    if nginx -t 2>/dev/null; then
        print_success "Config syntax OK"
    else
        print_error "Config syntax error!"
        return 1
    fi
    
    # Restart Nginx
    print_step "Restarting Nginx..."
    systemctl restart nginx
    
    echo ""
    print_success "Nginx hardened successfully!"
    echo ""
}

################################################################################
# HARDENING FUNCTIONS - MYSQL
################################################################################

harden_mysql() {
    print_header "HARDENING MYSQL"
    
    echo "This will apply MySQL hardening:"
    echo "  ✓ Bind to localhost only"
    echo "  ✓ Remove test database"
    echo "  ✓ Remove anonymous users"
    echo "  ✓ Disable remote root login"
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    print_step "Applying MySQL hardening..."
    
    # Detect config location
    if [ -f /etc/mysql/mysql.conf.d/mysqld.cnf ]; then
        local config_file="/etc/mysql/mysql.conf.d/mysqld.cnf"
    elif [ -f /etc/my.cnf ]; then
        local config_file="/etc/my.cnf"
    else
        print_error "MySQL config not found"
        return 1
    fi
    
    # Set bind-address
    if grep -q "^bind-address" "$config_file"; then
        sed -i 's/^bind-address.*/bind-address = 127.0.0.1/' "$config_file"
    else
        echo "bind-address = 127.0.0.1" >> "$config_file"
    fi
    
    # Remove test database
    print_step "Removing test database..."
    mysql -e "DROP DATABASE IF EXISTS test;" 2>/dev/null
    mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';" 2>/dev/null
    
    # Remove anonymous users
    print_step "Removing anonymous users..."
    mysql -e "DELETE FROM mysql.user WHERE User='';" 2>/dev/null
    
    # Disable remote root
    print_step "Disabling remote root login..."
    mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null
    
    # Flush privileges
    mysql -e "FLUSH PRIVILEGES;" 2>/dev/null
    
    # Restart MySQL
    print_step "Restarting MySQL..."
    systemctl restart mysql 2>/dev/null || systemctl restart mysqld 2>/dev/null || systemctl restart mariadb 2>/dev/null
    
    echo ""
    print_success "MySQL hardened successfully!"
    echo ""
}

################################################################################
# HARDENING FUNCTIONS - POSTGRESQL
################################################################################

harden_postgresql() {
    print_header "HARDENING POSTGRESQL"
    
    echo "This will apply PostgreSQL hardening:"
    echo "  ✓ Bind to localhost only"
    echo "  ✓ Configure authentication"
    echo ""
    
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    echo ""
    print_step "Applying PostgreSQL hardening..."
    
    local config_file=$(find /etc/postgresql -name "postgresql.conf" 2>/dev/null | head -1)
    
    if [ -z "$config_file" ]; then
        print_error "PostgreSQL config not found"
        return 1
    fi
    
    # Set listen_addresses
    if grep -q "^listen_addresses" "$config_file"; then
        sed -i "s/^listen_addresses.*/listen_addresses = 'localhost'/" "$config_file"
    else
        echo "listen_addresses = 'localhost'" >> "$config_file"
    fi
    
    # Restart PostgreSQL
    print_step "Restarting PostgreSQL..."
    systemctl restart postgresql
    
    echo ""
    print_success "PostgreSQL hardened successfully!"
    echo ""
}

################################################################################
# AUTO HARDEN ALL
################################################################################

auto_harden_all() {
    print_header "AUTO-HARDEN ALL SERVICES"
    
    echo "This will harden ALL detected services:"
    for service in "${!FOUND_SERVICES[@]}"; do
        echo "  - ${service^^}"
    done
    echo ""
    
    print_warning "This will apply best practices to all services!"
    read -p "Proceed? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "Aborted."
        return 1
    fi
    
    create_backup
    
    echo ""
    
    # Harden each service
    for service in "${!FOUND_SERVICES[@]}"; do
        case $service in
            ssh)
                harden_ssh
                ;;
            apache)
                harden_apache
                ;;
            nginx)
                harden_nginx
                ;;
            mysql)
                harden_mysql
                ;;
            postgresql)
                harden_postgresql
                ;;
        esac
    done
    
    echo ""
    print_header "ALL SERVICES HARDENED!"
    echo ""
    print_success "Backup location: $BACKUP_DIR"
    echo ""
}

################################################################################
# MAIN MENU
################################################################################

main_menu() {
    # Initial detection
    detect_os
    detect_services
    
    if [ ${#FOUND_SERVICES[@]} -eq 0 ]; then
        print_warning "No services detected!"
        exit 0
    fi
    
    # Run security checks
    echo ""
    print_header "RUNNING SECURITY ANALYSIS"
    
    for service in "${!FOUND_SERVICES[@]}"; do
        case $service in
            ssh)
                check_ssh_security
                ;;
            apache)
                check_apache_security
                ;;
            nginx)
                check_nginx_security
                ;;
            mysql)
                check_mysql_security
                ;;
            postgresql)
                check_postgresql_security
                ;;
        esac
    done
    
    while true; do
        show_security_analysis
        
        print_header "MAIN MENU"
        
        echo "[1] Auto-harden ALL services (RECOMMENDED)"
        echo "    → Apply best practices to all services"
        echo ""
        
        if [ -n "${FOUND_SERVICES[ssh]}" ]; then
            echo "[2] Harden SSH only"
        fi
        
        if [ -n "${FOUND_SERVICES[apache]}" ]; then
            echo "[3] Harden Apache only"
        fi
        
        if [ -n "${FOUND_SERVICES[nginx]}" ]; then
            echo "[4] Harden Nginx only"
        fi
        
        if [ -n "${FOUND_SERVICES[mysql]}" ]; then
            echo "[5] Harden MySQL only"
        fi
        
        if [ -n "${FOUND_SERVICES[postgresql]}" ]; then
            echo "[6] Harden PostgreSQL only"
        fi
        
        echo ""
        echo "[9] Rescan services"
        echo "[0] Exit"
        echo ""
        
        read -p "Choose: " choice
        
        case $choice in
            1)
                auto_harden_all
                read -p "Press Enter to continue..."
                # Rescan
                FOUND_SERVICES=()
                SERVICE_ISSUES=()
                detect_services
                for service in "${!FOUND_SERVICES[@]}"; do
                    case $service in
                        ssh) check_ssh_security ;;
                        apache) check_apache_security ;;
                        nginx) check_nginx_security ;;
                        mysql) check_mysql_security ;;
                        postgresql) check_postgresql_security ;;
                    esac
                done
                ;;
            2)
                if [ -n "${FOUND_SERVICES[ssh]}" ]; then
                    create_backup
                    harden_ssh
                    read -p "Press Enter to continue..."
                    check_ssh_security
                fi
                ;;
            3)
                if [ -n "${FOUND_SERVICES[apache]}" ]; then
                    create_backup
                    harden_apache
                    read -p "Press Enter to continue..."
                    check_apache_security
                fi
                ;;
            4)
                if [ -n "${FOUND_SERVICES[nginx]}" ]; then
                    create_backup
                    harden_nginx
                    read -p "Press Enter to continue..."
                    check_nginx_security
                fi
                ;;
            5)
                if [ -n "${FOUND_SERVICES[mysql]}" ]; then
                    create_backup
                    harden_mysql
                    read -p "Press Enter to continue..."
                    check_mysql_security
                fi
                ;;
            6)
                if [ -n "${FOUND_SERVICES[postgresql]}" ]; then
                    create_backup
                    harden_postgresql
                    read -p "Press Enter to continue..."
                    check_postgresql_security
                fi
                ;;
            9)
                FOUND_SERVICES=()
                SERVICE_ISSUES=()
                detect_services
                for service in "${!FOUND_SERVICES[@]}"; do
                    case $service in
                        ssh) check_ssh_security ;;
                        apache) check_apache_security ;;
                        nginx) check_nginx_security ;;
                        mysql) check_mysql_security ;;
                        postgresql) check_postgresql_security ;;
                    esac
                done
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
