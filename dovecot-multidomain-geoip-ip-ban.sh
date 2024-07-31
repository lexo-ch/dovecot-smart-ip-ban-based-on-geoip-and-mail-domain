#!/bin/bash

# Configuration
DOVECOT_LOG="/var/log/dovecot-info.log"  # The path to your dovecot-info.log file
DOVECOT_LOG_1="/var/log/dovecot-info.log.1"  # Previous log file for rotation handling
BAN_LOG="/var/log/dovecot-multidomain-ip-ban.log"
AMOUNTOFHOURSTOCHECK=24  # Number of hours to look back for failed logins
JAIL_NAME="dovecot-multidomain"  # Fail2Ban jail name
GEOIP_BIN=$(which mmdblookup)  # Path to GeoIP lookup binary
COUNTRY_DB="/var/lib/GeoIP/GeoLite2-Country.mmdb"  # GeoIP database file
HIGH_THRESHOLD_COUNTRIES="CH LI CA"  # Countries with higher threshold for banning
LOW_THRESHOLD=2  # Minimum number of domains for most countries
HIGH_THRESHOLD=4  # Minimum number of domains for high-threshold countries
MAX_AMOUNT_LINES=600000  # Maximum lines to fetch from log files. Lower values improve speed but may miss entries with large logs or longer check periods. Adjust based on log volume and AMOUNTOFHOURSTOCHECK.
WHITELIST="127.0.0.1 178.22.109.64"  # IPs that should never be banned
CONSOLE_DEBUG_OUTPUT=1  # Set to 0 to disable console output

# Function to log messages with timestamp and log level
log_message() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S,%3N')
    printf "%-23s %-7s %s\n" "$timestamp" "[$level]" "$message" >> "$BAN_LOG"
}

# Function to get country code from IP using GeoIP database
get_country_code() {
    local ip=$1
    ${GEOIP_BIN} -f ${COUNTRY_DB} -i "$ip" country iso_code | awk -F'"' '{print $2}' | xargs
}

# Function to determine minimum domains required for banning based on country
get_min_domains() {
    local country=$1
    if [[ " $HIGH_THRESHOLD_COUNTRIES " =~ " $country " ]]; then
        echo $HIGH_THRESHOLD
    else
        echo $LOW_THRESHOLD
    fi
}

# Function to ban an IP using Fail2Ban
ban_ip() {
    local ip=$1
    local country=$2
    local domains=$3
    local domain_list=$4
    if [[ ! " $WHITELIST " =~ " $ip " ]]; then
        RETVAL=$( fail2ban-client set $JAIL_NAME banip $ip )
        # Console output for debugging purposes
        if [ "$CONSOLE_DEBUG_OUTPUT" -eq 1 ]; then
            # Console output for debugging
            if [ $RETVAL -eq 1 ]; then
                echo "BANNED [ ${ip} ], Origin [ ${country} ]"
            fi
        fi

        log_message "SEPA" "==========================================================="
        log_message "WARN" "=>   BANNED"
        log_message "SEPA" "==========================================================="
        log_message "SEPA" ""
    else
        log_message "SEPA" "==========================================================="
        log_message "INFO" "=>   SKIPPED (whitelisted)"
        log_message "SEPA" "==========================================================="
        log_message "SEPA" ""
    fi
}

log_message "INFO" "Script execution start"

# Build the regex pattern for the last X hours
# This creates a pattern to match timestamps from the current time back to AMOUNTOFHOURSTOCHECK hours ago
FAILED_LOGIN_PATTERN=""
for (( i = ${AMOUNTOFHOURSTOCHECK}; i > 0; i-- )); do
    hour=$(date -d "-${i} hour" '+%Y-%m-%d %H')
    FAILED_LOGIN_PATTERN+="(${hour}.*auth failed)|"
done
FAILED_LOGIN_PATTERN=${FAILED_LOGIN_PATTERN%|}  # Remove trailing '|'

# Fetch all failed login attempts from the log
# Handle log rotation by checking if it's the first day of the month and early morning
current_day=$(date +%d)
current_hour=$(date +%H)
if [ "$current_day" -eq 1 ] && [ "$current_hour" -lt "$AMOUNTOFHOURSTOCHECK" ]; then
    # Include both current and previous log files
    FAILED_LOGINS=$(tail -q -n ${MAX_AMOUNT_LINES} "$DOVECOT_LOG_1" "$DOVECOT_LOG" | grep -h -E "$FAILED_LOGIN_PATTERN")
else
    # Only use current log file
    FAILED_LOGINS=$(tail -q -n ${MAX_AMOUNT_LINES} "$DOVECOT_LOG" | grep -h -E "$FAILED_LOGIN_PATTERN")
fi

# Count total failed logins and unique IPs
FAILED_LOGIN_COUNT=$(echo "$FAILED_LOGINS" | wc -l)
UNIQUE_IP_COUNT=$(echo "$FAILED_LOGINS" | grep -oP 'rip=\K[0-9.]+' | sort -u | wc -l)

log_message "INFO" "Amount of failed logins found: $FAILED_LOGIN_COUNT"
log_message "INFO" "Number of unique IPs: $UNIQUE_IP_COUNT"

# Process failed logins
# This section extracts IP, domain, and timestamp from each failed login attempt,
# then aggregates the data by IP to count unique domains and find the earliest timestamp
echo "$FAILED_LOGINS" | while read -r line; do
    ip=$(echo "$line" | grep -oP 'rip=\K[0-9.]+')
    domain=$(echo "$line" | grep -oP 'user=<[^@]+@\K[^>]+')
    timestamp=$(echo "$line" | awk '{print $1, $2}')

    if [ -n "$ip" ] && [ -n "$domain" ] && [ -n "$timestamp" ]; then
        echo "$ip $domain $timestamp"
    fi
done | sort | uniq | awk '
{
    ip[$1] = $1
    domains[$1][$2] = 1
    if (!timestamp[$1] || $3 " " $4 < timestamp[$1]) {
        timestamp[$1] = $3 " " $4
    }
}
END {
    for (i in ip) {
        printf "%s: ", i
        domain_list = ""
        for (d in domains[i]) {
            domain_list = domain_list d " "
        }
        printf "%s|%s\n", domain_list, timestamp[i]
    }
}' | while read -r line; do
    # Extract information for each IP
    ip=$(echo "$line" | cut -d':' -f1)
    domain_info=$(echo "$line" | cut -d':' -f2-)
    domain_list=$(echo "$domain_info" | cut -d'|' -f1 | sed 's/^ *//' | sed 's/ *$//')
    earliest_timestamp=$(echo "$domain_info" | cut -d'|' -f2)
    domains=$(echo "$domain_list" | wc -w)
    country=$(get_country_code "$ip")
    min_domains=$(get_min_domains "$country")

    # Log details for each IP
    log_message "INFO" "Checking IP: $ip"
    log_message "INFO" "    Earliest failed auth: $earliest_timestamp"
    log_message "INFO" "    Country: $country"
    log_message "INFO" "    Domains: $domains [$domain_list]"
    log_message "INFO" "    Min required: $min_domains"

    # Decide whether to ban the IP based on the number of unique domains
    if [ "$domains" -ge "$min_domains" ]; then
        ban_ip "$ip" "$country" "$domains" "$domain_list"
    else
        log_message "SEPA" "==========================================================="
        log_message "INFO" "=>   SKIPPED (unique domains: $domains < $min_domains)"
        log_message "SEPA" "==========================================================="
        log_message "SEPA" ""
    fi
done

log_message "INFO" "Script execution completed"
