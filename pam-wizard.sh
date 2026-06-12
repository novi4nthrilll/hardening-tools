#!/bin/bash

################################################################################
#                         PAM HARDENING WIZARD                                 #
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
BACKUP_DIR="/root/pam-backup-$(date +%Y%m%d-%H%M%S)"
UNDO_LOG="/tmp/pam-undo.log"
OS=""
OS_VERSION=""

# User lists
declare -A ALL_USERS
declare -A SUDO_USERS
declare -A LOCKED_USERS

################################################################################
# UTILITY FUNCTIONS
################################################################################

print_header() {
    clear
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
    
    # Backup PAM configs
    cp -r /etc/pam.d "$BACKUP_DIR/" 2>/dev/null
    cp /etc/login.defs "$BACKUP_DIR/" 2>/dev/null
    cp /etc/sudoers "$BACKUP_DIR/" 2>/dev/null
    cp -r /etc/sudoers.d "$BACKUP_DIR/" 2>/dev/null
    
    print_success "Backup created: $BACKUP_DIR"
}

log_action() {
    local action=$1
    local details=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S')|$action|$details" >> "$UNDO_LOG"
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
# USER SCANNING
################################################################################

scan_all_users() {
    ALL_USERS=()
    
    # Get all human users (UID >= 1000, excluding nobody)
    while IFS=: read -r username _ uid _ _ home shell; do
        if [ "$uid" -ge 1000 ] && [ "$uid" -ne 65534 ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
            ALL_USERS["$username"]="$uid|$home|$shell"
        fi
    done < /etc/passwd
    
    # Always include root
    ALL_USERS["root"]="0|/root|/bin/bash"
}

scan_sudo_users() {
    SUDO_USERS=()
    
    # Check sudoers file
    for user in "${!ALL_USERS[@]}"; do
        if sudo -l -U "$user" 2>/dev/null | grep -q "may run"; then
            SUDO_USERS["$user"]=1
        fi
    done
}

scan_locked_users() {
    LOCKED_USERS=()
    
    for user in "${!ALL_USERS[@]}"; do
        if passwd -S "$user" 2>/dev/null | grep -q " L "; then
            LOCKED_USERS["$user"]=1
        fi
    done
}

get_user_info() {
    local user=$1
    local uid=$(echo "${ALL_USERS[$user]}" | cut -d'|' -f1)
    local last_login=$(lastlog -u "$user" 2>/dev/null | tail -1 | awk '{print $4, $5, $6, $7}')
    local pass_expiry=$(chage -l "$user" 2>/dev/null | grep "Password expires" | cut -d: -f2 | xargs)
    
    echo "UID: $uid | Last login: $last_login | Password expiry: $pass_expiry"
}

################################################################################
# DISPLAY FUNCTIONS
################################################################################

show_users_list() {
    local filter=$1  # "all", "sudo", "locked"
    local index=1
    declare -g -A USER_INDEX
    
    case $filter in
        sudo)
            if [ ${#SUDO_USERS[@]} -eq 0 ]; then
                print_warning "No users with sudo access found"
                return 1
            fi
            
            for user in "${!SUDO_USERS[@]}"; do
                USER_INDEX[$index]="$user"
                echo -e "[$index] ${YELLOW}$user${NC}"
                echo "    $(get_user_info "$user")"
                echo ""
                index=$((index+1))
            done
            ;;
            
        locked)
            if [ ${#LOCKED_USERS[@]} -eq 0 ]; then
                print_warning "No locked users found"
                return 1
            fi
            
            for user in "${!LOCKED_USERS[@]}"; do
                USER_INDEX[$index]="$user"
                echo -e "[$index] ${RED}$user${NC} (LOCKED)"
                echo "    $(get_user_info "$user")"
                echo ""
                index=$((index+1))
            done
            ;;
            
        *)
            for user in "${!ALL_USERS[@]}"; do
                USER_INDEX[$index]="$user"
                
                local color="${NC}"
                local status=""
                
                if [ -n "${SUDO_USERS[$user]}" ]; then
                    color="${YELLOW}"
                    status=" (SUDO)"
                fi
                
                if [ -n "${LOCKED_USERS[$user]}" ]; then
                    color="${RED}"
                    status=" (LOCKED)"
                fi
                
                echo -e "[$index] ${color}$user${NC}$status"
                echo "    $(get_user_info "$user")"
                echo ""
                index=$((index+1))
            done
            ;;
    esac
    
    return 0
}

select_users() {
    echo ""
    echo "Select users (space-separated numbers, 'all', or 'back'):"
    read -p "> " selection
    
    if [ "$selection" = "back" ]; then
        return 1
    fi
    
    declare -g -a SELECTED_USERS
    SELECTED_USERS=()
    
    if [ "$selection" = "all" ]; then
        for user in "${USER_INDEX[@]}"; do
            SELECTED_USERS+=("$user")
        done
    else
        for num in $selection; do
            if [ -n "${USER_INDEX[$num]}" ]; then
                SELECTED_USERS+=("${USER_INDEX[$num]}")
            fi
        done
    fi
    
    if [ ${#SELECTED_USERS[@]} -eq 0 ]; then
        print_error "No valid users selected"
        return 1
    fi
    
    echo ""
    print_success "Selected users: ${SELECTED_USERS[*]}"
    return 0
}

################################################################################
# SUDO MANAGEMENT
################################################################################

sudo_management_menu() {
    while true; do
        print_header "SUDO MANAGEMENT"
        
        echo "[1] Add sudo access to user(s)"
        echo "[2] Remove sudo access from user(s)"
        echo "[3] View users with sudo access"
        echo "[4] Configure sudo timeout"
        echo "[5] Enable sudo logging"
        echo ""
        echo "[B] Back to main menu"
        echo "[0] Exit"
        echo ""
        
        read -p "Choose action: " choice
        
        case $choice in
            1) add_sudo_access ;;
            2) remove_sudo_access ;;
            3) view_sudo_users ;;
            4) configure_sudo_timeout ;;
            5) enable_sudo_logging ;;
            [Bb]) return ;;
            0) exit 0 ;;
            *) print_error "Invalid choice" ; sleep 2 ;;
        esac
    done
}

add_sudo_access() {
    print_header "ADD SUDO ACCESS"
    
    scan_all_users
    scan_sudo_users
    
    echo "Users WITHOUT sudo access:"
    echo ""
    
    # Show only users without sudo
    local index=1
    declare -g -A USER_INDEX
    USER_INDEX=()
    
    for user in "${!ALL_USERS[@]}"; do
        if [ -z "${SUDO_USERS[$user]}" ]; then
            USER_INDEX[$index]="$user"
            echo -e "[$index] ${GREEN}$user${NC}"
            echo "    $(get_user_info "$user")"
            echo ""
            index=$((index+1))
        fi
    done
    
    if [ ${#USER_INDEX[@]} -eq 0 ]; then
        print_warning "All users already have sudo access"
        read -p "Press Enter to continue..."
        return
    fi
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Add sudo access"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    echo "Will add these users to sudoers group"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        usermod -aG sudo "$user" 2>/dev/null || usermod -aG wheel "$user" 2>/dev/null
        log_action "ADD_SUDO" "$user"
        print_success "Added sudo access for $user"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

remove_sudo_access() {
    print_header "REMOVE SUDO ACCESS"
    
    scan_all_users
    scan_sudo_users
    
    if [ ${#SUDO_USERS[@]} -eq 0 ]; then
        print_warning "No users with sudo access found"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Users WITH sudo access:"
    echo ""
    
    show_users_list "sudo" || return
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Remove sudo access"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    print_warning "WARNING: Removing sudo access will prevent these users from using sudo!"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        gpasswd -d "$user" sudo 2>/dev/null || gpasswd -d "$user" wheel 2>/dev/null
        log_action "REMOVE_SUDO" "$user"
        print_success "Removed sudo access from $user"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

view_sudo_users() {
    print_header "USERS WITH SUDO ACCESS"
    
    scan_all_users
    scan_sudo_users
    
    if [ ${#SUDO_USERS[@]} -eq 0 ]; then
        print_warning "No users with sudo access found"
    else
        for user in "${!SUDO_USERS[@]}"; do
            echo -e "${YELLOW}$user${NC}"
            echo "    $(get_user_info "$user")"
            echo ""
        done
    fi
    
    read -p "Press Enter to continue..."
}

configure_sudo_timeout() {
    print_header "CONFIGURE SUDO TIMEOUT"
    
    echo "Current sudo timeout: $(sudo -V | grep 'Authentication timestamp timeout' | cut -d: -f2 | xargs) minutes"
    echo ""
    echo "Recommended: 5 minutes"
    echo ""
    
    read -p "Set timeout (minutes) [default: 5]: " timeout
    timeout=${timeout:-5}
    
    # Confirmation
    echo ""
    echo "Will set sudo timeout to $timeout minutes"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    echo "Defaults timestamp_timeout=$timeout" > /etc/sudoers.d/timeout
    chmod 440 /etc/sudoers.d/timeout
    log_action "SUDO_TIMEOUT" "$timeout"
    
    print_success "Sudo timeout set to $timeout minutes"
    read -p "Press Enter to return to menu..."
}

enable_sudo_logging() {
    print_header "ENABLE SUDO LOGGING"
    
    echo "This will enable detailed sudo logging to /var/log/sudo.log"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    cat > /etc/sudoers.d/logging << 'EOF'
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output
EOF
    chmod 440 /etc/sudoers.d/logging
    log_action "SUDO_LOGGING" "enabled"
    
    print_success "Sudo logging enabled"
    read -p "Press Enter to return to menu..."
}

################################################################################
# PASSWORD POLICY
################################################################################

password_policy_menu() {
    while true; do
        print_header "PASSWORD POLICY"
        
        echo "[1] Configure password complexity (global)"
        echo "[2] Set minimum password length"
        echo "[3] Require uppercase letters"
        echo "[4] Require lowercase letters"
        echo "[5] Require digits"
        echo "[6] Require special characters"
        echo "[7] View current policy"
        echo ""
        echo "[B] Back to main menu"
        echo "[0] Exit"
        echo ""
        
        read -p "Choose action: " choice
        
        case $choice in
            1) configure_password_complexity ;;
            2) set_min_length ;;
            3) require_uppercase ;;
            4) require_lowercase ;;
            5) require_digits ;;
            6) require_special ;;
            7) view_password_policy ;;
            [Bb]) return ;;
            0) exit 0 ;;
            *) print_error "Invalid choice" ; sleep 2 ;;
        esac
    done
}

configure_password_complexity() {
    print_header "CONFIGURE PASSWORD COMPLEXITY"
    
    echo "This will set (GLOBAL for all users):"
    echo "  ✓ Minimum length: 10 characters"
    echo "  ✓ Require: 1 uppercase letter"
    echo "  ✓ Require: 1 lowercase letter"
    echo "  ✓ Require: 1 digit"
    echo "  ✓ Require: 1 special character"
    echo "  ✓ Minimum 3 characters different from old password"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying password complexity..."
    
    # Detect PAM config location
    if [ -f /etc/pam.d/common-password ]; then
        local pam_file="/etc/pam.d/common-password"
    elif [ -f /etc/pam.d/system-auth ]; then
        local pam_file="/etc/pam.d/system-auth"
    else
        print_error "PAM config file not found"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Remove old pam_pwquality line
    sed -i '/pam_pwquality.so/d' "$pam_file"
    sed -i '/pam_cracklib.so/d' "$pam_file"
    
    # Add new line
    echo "password requisite pam_pwquality.so retry=3 minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 difok=3 maxrepeat=3" >> "$pam_file"
    
    log_action "PASSWORD_COMPLEXITY" "minlen=10,ucredit=-1,lcredit=-1,dcredit=-1,ocredit=-1"
    
    print_success "Password complexity configured"
    echo ""
    print_warning "New policy will apply to password changes only"
    read -p "Press Enter to return to menu..."
}

set_min_length() {
    print_header "SET MINIMUM PASSWORD LENGTH"
    
    echo "Current minimum length: $(grep minlen /etc/pam.d/common-password 2>/dev/null | grep -oP 'minlen=\K[0-9]+' || echo 'Not set')"
    echo ""
    echo "Recommended: 10 characters"
    echo ""
    
    read -p "Set minimum length [default: 10]: " minlen
    minlen=${minlen:-10}
    
    echo ""
    echo "Will set minimum password length to $minlen characters (GLOBAL)"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    if [ -f /etc/pam.d/common-password ]; then
        sed -i "s/minlen=[0-9]*/minlen=$minlen/" /etc/pam.d/common-password
    fi
    
    log_action "MIN_LENGTH" "$minlen"
    print_success "Minimum password length set to $minlen"
    read -p "Press Enter to return to menu..."
}

require_uppercase() {
    apply_credit_requirement "ucredit" "uppercase letter" "A-Z"
}

require_lowercase() {
    apply_credit_requirement "lcredit" "lowercase letter" "a-z"
}

require_digits() {
    apply_credit_requirement "dcredit" "digit" "0-9"
}

require_special() {
    apply_credit_requirement "ocredit" "special character" "!@#$%^&*"
}

apply_credit_requirement() {
    local credit_type=$1
    local description=$2
    local examples=$3
    
    print_header "REQUIRE ${description^^}"
    
    echo "This will require at least 1 $description ($examples) in passwords (GLOBAL)"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    if [ -f /etc/pam.d/common-password ]; then
        if grep -q "$credit_type" /etc/pam.d/common-password; then
            sed -i "s/$credit_type=[0-9-]*/$credit_type=-1/" /etc/pam.d/common-password
        else
            sed -i "/pam_pwquality.so/ s/$/ $credit_type=-1/" /etc/pam.d/common-password
        fi
    fi
    
    log_action "REQUIRE_${credit_type^^}" "enabled"
    print_success "Requirement for $description enabled"
    read -p "Press Enter to return to menu..."
}

view_password_policy() {
    print_header "CURRENT PASSWORD POLICY"
    
    if [ -f /etc/pam.d/common-password ]; then
        echo "PAM Configuration:"
        grep "pam_pwquality\|pam_cracklib" /etc/pam.d/common-password
    else
        print_warning "PAM config not found"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

################################################################################
# ACCOUNT MANAGEMENT
################################################################################

account_management_menu() {
    while true; do
        print_header "ACCOUNT MANAGEMENT"
        
        echo "[1] Lock user account(s)"
        echo "[2] Unlock user account(s)"
        echo "[3] Delete user(s)"
        echo "[4] Force password change on next login"
        echo "[5] Set account expiration date"
        echo "[6] View locked accounts"
        echo ""
        echo "[B] Back to main menu"
        echo "[0] Exit"
        echo ""
        
        read -p "Choose action: " choice
        
        case $choice in
            1) lock_accounts ;;
            2) unlock_accounts ;;
            3) delete_users ;;
            4) force_password_change ;;
            5) set_account_expiration ;;
            6) view_locked_accounts ;;
            [Bb]) return ;;
            0) exit 0 ;;
            *) print_error "Invalid choice" ; sleep 2 ;;
        esac
    done
}

lock_accounts() {
    print_header "LOCK USER ACCOUNTS"
    
    scan_all_users
    scan_locked_users
    
    echo "Active users (NOT locked):"
    echo ""
    
    # Show only unlocked users
    local index=1
    declare -g -A USER_INDEX
    USER_INDEX=()
    
    for user in "${!ALL_USERS[@]}"; do
        if [ -z "${LOCKED_USERS[$user]}" ]; then
            USER_INDEX[$index]="$user"
            echo -e "[$index] ${GREEN}$user${NC}"
            echo "    $(get_user_info "$user")"
            echo ""
            index=$((index+1))
        fi
    done
    
    if [ ${#USER_INDEX[@]} -eq 0 ]; then
        print_warning "All users are already locked"
        read -p "Press Enter to continue..."
        return
    fi
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Lock accounts"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    print_warning "WARNING: Locked users cannot login!"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Locking accounts..."
    
    for user in "${SELECTED_USERS[@]}"; do
        passwd -l "$user" 2>/dev/null
        log_action "LOCK_ACCOUNT" "$user"
        print_success "Locked account: $user"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

unlock_accounts() {
    print_header "UNLOCK USER ACCOUNTS"
    
    scan_all_users
    scan_locked_users
    
    if [ ${#LOCKED_USERS[@]} -eq 0 ]; then
        print_warning "No locked users found"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo "Locked users:"
    echo ""
    
    show_users_list "locked" || return
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Unlock accounts"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Unlocking accounts..."
    
    for user in "${SELECTED_USERS[@]}"; do
        passwd -u "$user" 2>/dev/null
        log_action "UNLOCK_ACCOUNT" "$user"
        print_success "Unlocked account: $user"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

delete_users() {
    print_header "DELETE USERS"
    
    scan_all_users
    
    echo "All users:"
    echo ""
    
    show_users_list "all"
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: DELETE users"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    print_error "WARNING: This will PERMANENTLY delete these users and their home directories!"
    echo ""
    echo "[C] Confirm and DELETE"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Deleting users..."
    
    for user in "${SELECTED_USERS[@]}"; do
        userdel -r "$user" 2>/dev/null
        log_action "DELETE_USER" "$user"
        print_success "Deleted user: $user"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

force_password_change() {
    print_header "FORCE PASSWORD CHANGE"
    
    scan_all_users
    
    echo "All users:"
    echo ""
    
    show_users_list "all"
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Force password change on next login"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    echo "These users will be required to change their password on next login"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        chage -d 0 "$user" 2>/dev/null
        log_action "FORCE_PASSWORD_CHANGE" "$user"
        print_success "$user will be forced to change password on next login"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

set_account_expiration() {
    print_header "SET ACCOUNT EXPIRATION"
    
    scan_all_users
    
    echo "All users:"
    echo ""
    
    show_users_list "all"
    
    select_users || return
    
    echo ""
    echo "Set expiration date (YYYY-MM-DD) or '-1' for never:"
    read -p "> " exp_date
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Set account expiration"
    echo "Users: ${SELECTED_USERS[*]}"
    echo "Expiration date: $exp_date"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        chage -E "$exp_date" "$user" 2>/dev/null
        log_action "ACCOUNT_EXPIRATION" "$user|$exp_date"
        print_success "Set expiration for $user: $exp_date"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

view_locked_accounts() {
    print_header "LOCKED ACCOUNTS"
    
    scan_all_users
    scan_locked_users
    
    if [ ${#LOCKED_USERS[@]} -eq 0 ]; then
        print_success "No locked accounts found"
    else
        for user in "${!LOCKED_USERS[@]}"; do
            echo -e "${RED}$user${NC} (LOCKED)"
            echo "    $(get_user_info "$user")"
            echo ""
        done
    fi
    
    read -p "Press Enter to continue..."
}

################################################################################
# PASSWORD EXPIRY
################################################################################

password_expiry_menu() {
    while true; do
        print_header "PASSWORD EXPIRY"
        
        echo "[1] Set password expiry (90 days) - Apply to specific users"
        echo "[2] Set password expiry (90 days) - Apply to ALL users"
        echo "[3] Set custom expiry period"
        echo "[4] Set warning period (14 days before expiry)"
        echo "[5] View expiry settings for all users"
        echo ""
        echo "[B] Back to main menu"
        echo "[0] Exit"
        echo ""
        
        read -p "Choose action: " choice
        
        case $choice in
            1) set_expiry_specific ;;
            2) set_expiry_all ;;
            3) set_custom_expiry ;;
            4) set_warning_period ;;
            5) view_expiry_settings ;;
            [Bb]) return ;;
            0) exit 0 ;;
            *) print_error "Invalid choice" ; sleep 2 ;;
        esac
    done
}

set_expiry_specific() {
    print_header "SET PASSWORD EXPIRY (90 DAYS)"
    
    scan_all_users
    
    echo "All users:"
    echo ""
    
    show_users_list "all"
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Set password expiry to 90 days"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    echo "Password will expire after 90 days and must be changed"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        chage -M 90 -m 7 -W 14 "$user" 2>/dev/null
        log_action "PASSWORD_EXPIRY" "$user|90"
        print_success "Set password expiry for $user: 90 days"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

set_expiry_all() {
    print_header "SET PASSWORD EXPIRY FOR ALL USERS"
    
    scan_all_users
    
    echo "This will set password expiry to 90 days for ALL users:"
    echo ""
    
    for user in "${!ALL_USERS[@]}"; do
        echo "  - $user"
    done
    
    echo ""
    print_warning "This affects ALL users on the system!"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${!ALL_USERS[@]}"; do
        chage -M 90 -m 7 -W 14 "$user" 2>/dev/null
        log_action "PASSWORD_EXPIRY_ALL" "$user|90"
        print_success "Set password expiry for $user: 90 days"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

set_custom_expiry() {
    print_header "SET CUSTOM PASSWORD EXPIRY"
    
    echo "Enter password expiry period (days):"
    read -p "> " days
    
    scan_all_users
    
    echo ""
    echo "All users:"
    echo ""
    
    show_users_list "all"
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Set password expiry to $days days"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        chage -M "$days" "$user" 2>/dev/null
        log_action "PASSWORD_EXPIRY_CUSTOM" "$user|$days"
        print_success "Set password expiry for $user: $days days"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

set_warning_period() {
    print_header "SET WARNING PERIOD"
    
    echo "Enter warning period (days before expiry):"
    read -p "[default: 14]: " days
    days=${days:-14}
    
    scan_all_users
    
    echo ""
    echo "All users:"
    echo ""
    
    show_users_list "all"
    
    select_users || return
    
    # Confirmation
    print_header "CONFIRMATION"
    echo "Action: Set warning period to $days days"
    echo "Users: ${SELECTED_USERS[*]}"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Applying changes..."
    
    for user in "${SELECTED_USERS[@]}"; do
        chage -W "$days" "$user" 2>/dev/null
        log_action "WARNING_PERIOD" "$user|$days"
        print_success "Set warning period for $user: $days days"
    done
    
    echo ""
    print_success "Changes saved!"
    read -p "Press Enter to return to menu..."
}

view_expiry_settings() {
    print_header "PASSWORD EXPIRY SETTINGS"
    
    scan_all_users
    
    for user in "${!ALL_USERS[@]}"; do
        echo -e "${BLUE}$user${NC}"
        chage -l "$user" 2>/dev/null | grep -E "Password expires|Password inactive|Account expires"
        echo ""
    done
    
    read -p "Press Enter to continue..."
}

################################################################################
# ACCOUNT LOCKOUT
################################################################################

account_lockout_menu() {
    while true; do
        print_header "ACCOUNT LOCKOUT"
        
        echo "[1] Configure account lockout (5 failed attempts, 15 min lock)"
        echo "[2] Custom lockout configuration"
        echo "[3] Disable account lockout"
        echo "[4] View current lockout policy"
        echo ""
        echo "[B] Back to main menu"
        echo "[0] Exit"
        echo ""
        
        read -p "Choose action: " choice
        
        case $choice in
            1) configure_lockout_default ;;
            2) configure_lockout_custom ;;
            3) disable_lockout ;;
            4) view_lockout_policy ;;
            [Bb]) return ;;
            0) exit 0 ;;
            *) print_error "Invalid choice" ; sleep 2 ;;
        esac
    done
}

configure_lockout_default() {
    print_header "CONFIGURE ACCOUNT LOCKOUT"
    
    echo "This will configure (GLOBAL):"
    echo "  ✓ Lock account after 5 failed login attempts"
    echo "  ✓ Lock duration: 15 minutes (900 seconds)"
    echo "  ✓ Track failed attempts"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Configuring account lockout..."
    
    # Detect PAM config
    if [ -f /etc/pam.d/common-auth ]; then
        local pam_auth="/etc/pam.d/common-auth"
    elif [ -f /etc/pam.d/system-auth ]; then
        local pam_auth="/etc/pam.d/system-auth"
    else
        print_error "PAM auth config not found"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Remove old faillock lines
    sed -i '/pam_faillock/d' "$pam_auth"
    
    # Add faillock configuration
    sed -i '1i auth required pam_faillock.so preauth deny=5 unlock_time=900' "$pam_auth"
    sed -i '/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900' "$pam_auth"
    sed -i '/pam_permit.so/i auth sufficient pam_faillock.so authsucc' "$pam_auth"
    
    log_action "ACCOUNT_LOCKOUT" "deny=5,unlock_time=900"
    
    print_success "Account lockout configured"
    echo ""
    print_warning "Users will be locked after 5 failed login attempts for 15 minutes"
    read -p "Press Enter to return to menu..."
}

configure_lockout_custom() {
    print_header "CUSTOM LOCKOUT CONFIGURATION"
    
    echo "Enter failed attempts before lockout:"
    read -p "[default: 5]: " attempts
    attempts=${attempts:-5}
    
    echo ""
    echo "Enter lock duration (minutes):"
    read -p "[default: 15]: " duration
    duration=${duration:-15}
    
    local seconds=$((duration * 60))
    
    echo ""
    echo "Will configure (GLOBAL):"
    echo "  ✓ Lock after $attempts failed attempts"
    echo "  ✓ Lock duration: $duration minutes"
    echo ""
    echo "[C] Confirm and apply"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Configuring account lockout..."
    
    if [ -f /etc/pam.d/common-auth ]; then
        local pam_auth="/etc/pam.d/common-auth"
    elif [ -f /etc/pam.d/system-auth ]; then
        local pam_auth="/etc/pam.d/system-auth"
    else
        print_error "PAM auth config not found"
        read -p "Press Enter to continue..."
        return
    fi
    
    sed -i '/pam_faillock/d' "$pam_auth"
    sed -i "1i auth required pam_faillock.so preauth deny=$attempts unlock_time=$seconds" "$pam_auth"
    sed -i "/pam_unix.so/a auth [default=die] pam_faillock.so authfail deny=$attempts unlock_time=$seconds" "$pam_auth"
    sed -i '/pam_permit.so/i auth sufficient pam_faillock.so authsucc' "$pam_auth"
    
    log_action "ACCOUNT_LOCKOUT_CUSTOM" "deny=$attempts,unlock_time=$seconds"
    
    print_success "Account lockout configured"
    read -p "Press Enter to return to menu..."
}

disable_lockout() {
    print_header "DISABLE ACCOUNT LOCKOUT"
    
    echo "This will disable account lockout policy (GLOBAL)"
    echo ""
    print_warning "WARNING: System will be vulnerable to brute force attacks!"
    echo ""
    echo "[C] Confirm and disable"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    # Apply
    create_backup
    echo ""
    print_step "Disabling account lockout..."
    
    if [ -f /etc/pam.d/common-auth ]; then
        sed -i '/pam_faillock/d' /etc/pam.d/common-auth
    fi
    
    if [ -f /etc/pam.d/system-auth ]; then
        sed -i '/pam_faillock/d' /etc/pam.d/system-auth
    fi
    
    log_action "DISABLE_LOCKOUT" "disabled"
    
    print_success "Account lockout disabled"
    read -p "Press Enter to return to menu..."
}

view_lockout_policy() {
    print_header "CURRENT LOCKOUT POLICY"
    
    if [ -f /etc/pam.d/common-auth ]; then
        echo "PAM Configuration:"
        grep "pam_faillock" /etc/pam.d/common-auth || echo "No lockout policy configured"
    elif [ -f /etc/pam.d/system-auth ]; then
        echo "PAM Configuration:"
        grep "pam_faillock" /etc/pam.d/system-auth || echo "No lockout policy configured"
    else
        print_warning "PAM config not found"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

################################################################################
# VIEW ALL USERS
################################################################################

view_all_users_menu() {
    print_header "ALL USERS"
    
    scan_all_users
    scan_sudo_users
    scan_locked_users
    
    for user in "${!ALL_USERS[@]}"; do
        local color="${NC}"
        local badges=""
        
        if [ -n "${SUDO_USERS[$user]}" ]; then
            badges="${badges}${YELLOW}[SUDO]${NC} "
        fi
        
        if [ -n "${LOCKED_USERS[$user]}" ]; then
            badges="${badges}${RED}[LOCKED]${NC} "
        fi
        
        echo -e "${BLUE}$user${NC} $badges"
        echo "    $(get_user_info "$user")"
        
        # Show password expiry
        local expiry=$(chage -l "$user" 2>/dev/null | grep "Password expires" | cut -d: -f2 | xargs)
        echo "    Password expires: $expiry"
        echo ""
    done
    
    read -p "Press Enter to continue..."
}

################################################################################
# UNDO LAST ACTION
################################################################################

undo_last_action() {
    print_header "UNDO LAST ACTION"
    
    if [ ! -f "$UNDO_LOG" ] || [ ! -s "$UNDO_LOG" ]; then
        print_warning "No actions to undo"
        read -p "Press Enter to continue..."
        return
    fi
    
    # Get last action
    local last_line=$(tail -1 "$UNDO_LOG")
    local timestamp=$(echo "$last_line" | cut -d'|' -f1)
    local action=$(echo "$last_line" | cut -d'|' -f2)
    local details=$(echo "$last_line" | cut -d'|' -f3)
    
    echo "Last action:"
    echo "  Time: $timestamp"
    echo "  Action: $action"
    echo "  Details: $details"
    echo ""
    echo "Undo this action?"
    echo ""
    echo "[C] Confirm and undo"
    echo "[B] Back (cancel)"
    echo ""
    
    read -p "Choose: " confirm
    
    if [ "$confirm" != "C" ] && [ "$confirm" != "c" ]; then
        return
    fi
    
    echo ""
    print_step "Undoing action..."
    
    case $action in
        ADD_SUDO)
            gpasswd -d "$details" sudo 2>/dev/null || gpasswd -d "$details" wheel 2>/dev/null
            print_success "Removed sudo access from $details"
            ;;
        REMOVE_SUDO)
            usermod -aG sudo "$details" 2>/dev/null || usermod -aG wheel "$details" 2>/dev/null
            print_success "Restored sudo access for $details"
            ;;
        LOCK_ACCOUNT)
            passwd -u "$details" 2>/dev/null
            print_success "Unlocked account: $details"
            ;;
        UNLOCK_ACCOUNT)
            passwd -l "$details" 2>/dev/null
            print_success "Locked account: $details"
            ;;
        FORCE_PASSWORD_CHANGE)
            chage -d -1 "$details" 2>/dev/null
            print_success "Removed forced password change for $details"
            ;;
        *)
            print_warning "Cannot undo this action type: $action"
            print_warning "Please restore from backup: $BACKUP_DIR"
            ;;
    esac
    
    # Remove last line from log
    sed -i '$d' "$UNDO_LOG"
    
    echo ""
    read -p "Press Enter to continue..."
}

################################################################################
# MAIN MENU
################################################################################

main_menu() {
    while true; do
        print_header "PAM HARDENING WIZARD"
        
        echo "What do you want to do?"
        echo ""
        echo "[1] Sudo Management"
        echo "    → Manage sudo access for users"
        echo ""
        echo "[2] Password Policy"
        echo "    → Configure password requirements"
        echo ""
        echo "[3] Account Management"
        echo "    → Lock/unlock, delete, expire accounts"
        echo ""
        echo "[4] Password Expiry"
        echo "    → Set password expiration policies"
        echo ""
        echo "[5] Account Lockout"
        echo "    → Configure failed login lockout"
        echo ""
        echo "[6] View All Users"
        echo "    → List all users and their status"
        echo ""
        echo "[U] Undo Last Action"
        echo ""
        echo "[0] Exit"
        echo ""
        
        read -p "Choose category: " choice
        
        case $choice in
            1) sudo_management_menu ;;
            2) password_policy_menu ;;
            3) account_management_menu ;;
            4) password_expiry_menu ;;
            5) account_lockout_menu ;;
            6) view_all_users_menu ;;
            [Uu]) undo_last_action ;;
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
detect_os
scan_all_users
scan_sudo_users
scan_locked_users

# Initialize undo log
touch "$UNDO_LOG"

main_menu
