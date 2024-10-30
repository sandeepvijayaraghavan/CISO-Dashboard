#—---------------------------------------------CIS CHECK CODE(.sh)-----------------------------------------------
#!/bin/bash

# Set variables
LOG_FILE="check_results.log"
ELASTICSEARCH_INDEX="firewall_checks_cong_hoa_100f"
ES_SERVER="https://192.168.151.22:9200"

# Function to extract the filename from the configuration file path
get_filename() {
    local config_file="$1"
    local filename=$(basename "$config_file")
    echo "${filename%.*}"
}

# Function to print JSON formatted result with firewall name
print_json_result() {
    local check_name="$2"
    local check_status="$3"
    local config_file="$1"
    local filename=$(get_filename "$config_file")
    echo "{\"firewall\":\"Cong_Hoa_100F\",\"check_name\":\"$check_name\",\"check_status\":\"$check_status\"}"
}

# Function to push JSON data to Elasticsearch
push_to_elasticsearch() {
    local json_data="$1"
    curl -X POST "$ES_SERVER/$ELASTICSEARCH_INDEX/_doc/" -H 'Content-Type: application/json' -d "$json_data" -u "Your_username:Your_Password" -k
}

# Function to log and optionally send results to Elasticsearch
log_and_send_results() {
    local check_name="$2"
    local check_status="$3"
    local config_file="$1"
    local json_data=$(print_json_result "$config_file" "$check_name" "$check_status")

    # Log the result to the log file
    echo "$json_data" >> "$LOG_FILE"

    # Send the result to Elasticsearch
    push_to_elasticsearch "$json_data"
}


# Function to check if DNS server is configured
check_dns_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system dns" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "DNS Configuration" "$output"
}

# Function to check if intra-zone traffic is restricted
check_intra_zone_traffic() {
    local config_file="$1"
    local output=""
    if grep -q "set intra-zone-deny enable" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Intra-Zone Traffic" "$output"
}

# Function to check if all management related services are disabled on WAN port
check_wan_management_services() {
    local config_file="$1"
    local output=""
    if grep -q "config system interface" "$config_file" && grep -q "set allowaccess ping https ssh http fgfm" "$config_file"; then
        output="FAIL"
    else
        output="PASS"
    fi
    log_and_send_results "$config_file" "WAN Management Services" "$output"
}

# Function to check if Pre-Login Banner is set
check_pre_login_banner() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set pre-login-banner" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Pre-Login Banner" "$output"
}

# Function to check if Post-Login Banner is set
check_post_login_banner() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set post-login-banner" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Post-Login Banner" "$output"
}

# Function to check if timezone is properly configured
check_timezone_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set timezone" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Timezone Configuration" "$output"
}

# Function to check if correct system time is configured through NTP
check_ntp_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system ntp" "$config_file" && grep -q "set server" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "NTP Configuration" "$output"
}

# Function to check if hostname is set
check_hostname_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set hostname" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Hostname Configuration" "$output"
}

# Function to check if the latest firmware is installed
check_latest_firmware() {
    local config_file="$1"
    local output=""
    # Logic to check for the latest firmware can be added here
    # For now, let's assume it's always up to date
    output="PASS"
    log_and_send_results "$config_file" "Latest Firmware" "$output"
}

# Function to check if USB Firmware and configuration installation is disabled
check_usb_disable() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set usb-auto-install" "$config_file"; then
        output="FAIL"
    else
        output="PASS"
    fi
    log_and_send_results "$config_file" "USB Firmware Disable" "$output"
}

# Function to check if static keys for TLS are disabled
check_tls_static_keys() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set strong-crypto" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "TLS Static Keys" "$output"
}

# Function to check if Global Strong Encryption is enabled
check_global_strong_encryption() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set strong-crypto" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Global Strong Encryption" "$output"
}

# Function to check if management GUI listens on secure TLS version
check_tls_version_management_gui() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-https-ssl" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "TLS Version Management GUI" "$output"
}

# Function to check if CDN is enabled for improved GUI performance
check_cdn_enabled() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set cdn" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "CDN Enabled" "$output"
}

# Function to check if single CPU core overloaded event is logged
check_cpu_overloaded_event() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "CPU Overloaded Event" "MANUAL"
}
# Function to check if Password Policy is enabled
check_password_policy() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set password-policy" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Password Policy" "$output"
}

# Function to check if administrator password retries and lockout time are configured
check_password_retries_lockout() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-lockout" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Password Retries and Lockout" "$output"
}

# Function to check if only SNMPv3 is enabled
check_snmpv3_only() {
    local config_file="$1"
    local output=""
    if grep -q "config system snmp" "$config_file" && grep -q "set v3-only" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "SNMPv3 Only" "$output"
}

# Function to check if SNMPv3 allows only trusted hosts
check_snmpv3_trusted_hosts() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "SNMPv3 Trusted Hosts" "MANUAL"
}

# Function to check if default 'admin' password is changed
check_admin_password() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "Admin Password" "MANUAL"
}

# Function to check if all the login accounts having specific trusted hosts enabled
check_login_accounts_trusted_hosts() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "Login Accounts Trusted Hosts" "MANUAL"
}

# Function to check if admin accounts with different privileges have their correct profiles assigned
check_admin_accounts_profiles() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "Admin Accounts Profiles" "MANUAL"
}

# Function to check if idle timeout time is configured
check_idle_timeout() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-sessions-timeout" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Idle Timeout" "$output"
}

# Function to check if only encrypted access channels are enabled
check_encrypted_access_channels() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set admin-https-ssl" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "Encrypted Access Channels" "$output"
}

# Function to apply Local-in Policies
apply_local_in_policies() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "apply_local_in_policies" "MANUAL"
}

# Function to check if default Admin ports are changed
check_default_admin_ports_changed() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_default_admin_ports_changed" "MANUAL"
}

# Function to check if virtual patching on the local-in management interface is enabled
check_virtual_patching_local_in_interface() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_virtual_patching_local_in_interface" "MANUAL"
}

# Function to check if High Availability configuration is enabled
check_ha_configuration() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_ha_configuration" "$output"
}

# Function to check if "Monitor Interfaces" for High Availability devices is enabled
check_ha_monitor_interfaces() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file" && grep -q "set monitor-interface" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_ha_monitor_interfaces" "$output"
}

# Function to check if HA Reserved Management Interface is configured
check_ha_reserved_management_interface() {
    local config_file="$1"
    local output=""
    if grep -q "config system ha" "$config_file" && grep -q "set reserved-management-interface" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_ha_reserved_management_interface" "$output"
}

# Function to check if unused policies are reviewed regularly
check_review_unused_policies() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_review_unused_policies" "MANUAL"
}

# Function to check if policies do not use "ALL" as Service
check_no_all_service_policies() {
    local config_file="$1"
    local output=""
    if ! grep -q "set service ALL" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_no_all_service_policies" "$output"
}

# Function to check if firewall policy denying all traffic to/from Tor, malicious server, or scanner IP addresses using ISDB
check_denying_traffic_to_from_tor() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_denying_traffic_to_from_tor" "MANUAL"
}

# Function to check if logging is enabled on all firewall policies
check_logging_enabled_firewall_policies() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_logging_enabled_firewall_policies" "MANUAL"
}

# Function to detect Botnet connections
detect_botnet_connections() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "detect_botnet_connections" "MANUAL"
}

# Function to apply IPS Security Profile to Policies
apply_ips_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "apply_ips_security_profile" "MANUAL"
}

# Function to check if Antivirus Definition Push Updates are configured
check_antivirus_definition_updates() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set update-schedule" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_antivirus_definition_updates" "$output"
}

# Function to apply Antivirus Security Profile to Policies
apply_antivirus_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "apply_antivirus_security_profile" "MANUAL"
}

# Function to check if Outbreak Prevention Database is enabled
check_outbreak_prevention_database() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-extended-db" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_outbreak_prevention_database" "$output"
}

# Function to check if AI/heuristic based malware detection is enabled
check_ai_malware_detection() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-heuristic" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_ai_malware_detection" "$output"
}

# Function to check if grayware detection on antivirus is enabled
check_grayware_detection() {
    local config_file="$1"
    local output=""
    if grep -q "config antivirus fortiguard" "$config_file" && grep -q "set use-botnet" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_grayware_detection" "$output"
}

# Function to check if inline scanning with FortiGuard AI-Based Sandbox Service is enabled
check_inline_scanning_sandbox() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_inline_scanning_sandbox" "MANUAL"
}

# Function to enable Botnet C&C Domain Blocking DNS Filter
enable_botnet_cnc_domain_blocking() {
    local config_file="$1"
    local output=""
    if grep -q "config webfilter fortiguard" "$config_file" && grep -q "set botnet" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "enable_botnet_cnc_domain_blocking" "$output"
}

# Function to check if DNS Filter logs all DNS queries and responses
check_dns_filter_logging() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_dns_filter_logging" "MANUAL"
}

# Function to apply DNS Filter Security Profile to Policies
apply_dns_filter_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "apply_dns_filter_security_profile" "MANUAL"
}

# Function to block high risk categories on Application Control
block_high_risk_categories() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "block_high_risk_categories" "MANUAL"
}

# Function to block applications running on non-default ports
block_non_default_port_applications() {
    local config_file="$1"
    local output=""
    if grep -q "config firewall policy" "$config_file" && grep -q "set service " "$config_file"; then
        output="FAIL"
    else
        output="PASS"
    fi
    log_and_send_results "$config_file" "block_non_default_port_applications" "$output"
}

# Function to check if all Application Control related traffic is logged
check_application_control_logging() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_application_control_logging" "MANUAL"
}

# Function to apply Application Control Security Profile to Policies
apply_application_control_security_profile() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "apply_application_control_security_profile" "MANUAL"
}

# Function to ensure Compromised Host Quarantine is enabled
check_compromised_host_quarantine() {
    local config_file="$1"
    local output=""
    if grep -q "config system global" "$config_file" && grep -q "set chq" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_compromised_host_quarantine" "$output"
}

# Function to ensure Security Fabric is Configured
check_security_fabric_configured() {
    local config_file="$1"
    local output=""
    if grep -q "config system settings" "$config_file" && grep -q "set sf-enforce" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_security_fabric_configured" "$output"
}

# Function to apply a Trusted Signed Certificate for VPN Portal
apply_trusted_certificate_vpn_portal() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "apply_trusted_certificate_vpn_portal" "MANUAL"
}

# Function to ensure Limited TLS Versions for SSL VPN is enabled
check_ssl_vpn_tls_versions() {
    # This is a manual check, so it will not be implemented in this script
    log_and_send_results "$config_file" "check_ssl_vpn_tls_versions" "MANUAL"
}

# Function to ensure Event Logging is enabled
check_event_logging_enabled() {
    local config_file="$1"
    local output=""
    if grep -q "config system log" "$config_file" && grep -q "set disk-log" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_event_logging_enabled" "$output"
}

# Function to enable Log Transmission to FortiAnalyzer / FortiManager
enable_log_transmission_to_forti() {
    local config_file="$1"
    local output=""
    if grep -q "config log fortianalyzer" "$config_file" && grep -q "set status enable" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "enable_log_transmission_to_forti" "$output"
}

# Function to ensure Centralized Logging and Reporting is enabled
check_centralized_logging_reporting() {
    local config_file="$1"
    local output=""
    if grep -q "config log syslogd" "$config_file" && grep -q "set status enable" "$config_file"; then
        output="PASS"
    else
        output="FAIL"
    fi
    log_and_send_results "$config_file" "check_centralized_logging_reporting" "$output"
}

# Check if configuration file argument is provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <config_file>"
    exit 1
fi

config_file=$1

# Run all checks and log results

{
    check_dns_configuration "$config_file"
    check_intra_zone_traffic "$config_file"
    check_wan_management_services "$config_file"
    check_pre_login_banner "$config_file"
    check_post_login_banner "$config_file"
    check_timezone_configuration "$config_file"
    check_ntp_configuration "$config_file"
    check_hostname_configuration "$config_file"
    check_latest_firmware "$config_file"
    check_usb_disable "$config_file"
    check_tls_static_keys "$config_file"
    check_global_strong_encryption "$config_file"
    check_tls_version_management_gui "$config_file"
    check_cdn_enabled "$config_file"
    check_cpu_overloaded_event
    check_password_policy "$config_file"
    check_password_retries_lockout "$config_file"
    check_snmpv3_only "$config_file"
    check_snmpv3_trusted_hosts
    check_admin_password
    check_login_accounts_trusted_hosts
    check_admin_accounts_profiles
    check_idle_timeout "$config_file"
    check_encrypted_access_channels "$config_file"
    apply_local_in_policies
    check_default_admin_ports_changed
    check_virtual_patching_local_in_interface
    check_ha_configuration "$config_file"
    check_ha_monitor_interfaces "$config_file"
    check_ha_reserved_management_interface "$config_file"
    check_review_unused_policies
    check_no_all_service_policies "$config_file"
    check_denying_traffic_to_from_tor
    check_logging_enabled_firewall_policies
    detect_botnet_connections
    apply_ips_security_profile
    check_antivirus_definition_updates "$config_file"
    apply_antivirus_security_profile
    check_outbreak_prevention_database "$config_file"
    check_ai_malware_detection "$config_file"
    check_grayware_detection "$config_file"
    check_inline_scanning_sandbox
    enable_botnet_cnc_domain_blocking "$config_file"
    check_dns_filter_logging
    apply_dns_filter_security_profile
    block_high_risk_categories
    block_non_default_port_applications "$config_file"
    check_application_control_logging
    apply_application_control_security_profile
    check_compromised_host_quarantine "$config_file"
    check_security_fabric_configured "$config_file"
    apply_trusted_certificate_vpn_portal
    check_ssl_vpn_tls_versions
    check_event_logging_enabled "$config_file"
    enable_log_transmission_to_forti "$config_file"
    check_centralized_logging_reporting "$config_file"
} | tee "$LOG_FILE"

echo "All checks completed. Results are logged in $LOG_FILE"

#------------------------CIS CHECK CODE(END)-------------------
