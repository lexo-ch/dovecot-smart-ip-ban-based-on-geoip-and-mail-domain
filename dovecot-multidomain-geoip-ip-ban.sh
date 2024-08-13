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

# Console output control:
# Set CONSOLE_DEBUG_OUTPUT to 1 to enable any console output, 0 to disable all console output
CONSOLE_DEBUG_OUTPUT=1
# Set CONSOLE_DEBUG_OUTPUT_VERBOSE to 1 for full console output (all skipped, banned, and already banned messages),
# or 0 to show only newly banned IPs. This setting has no effect if CONSOLE_DEBUG_OUTPUT is set to 0.
CONSOLE_DEBUG_OUTPUT_VERBOSE=0

# Function to log messages with timestamp and log level
log_message() {
    local level=$1
    shift
    local message="$@"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$BAN_LOG"
    
    # Control console output based on debug settings
    if [ "$CONSOLE_DEBUG_OUTPUT" -eq 1 ]; then
        if [ "$CONSOLE_DEBUG_OUTPUT_VERBOSE" -eq 1 ] || [[ "$message" == BANNED* ]]; then
            echo "[$timestamp] [$level] $message"
        fi
    fi
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

# Function to check if an IP is already banned
is_ip_banned() {
    local ip=$1
    fail2ban-client status $JAIL_NAME | grep -q "$ip"
    return $?
}

log_message "INFO" "Script execution start"

# Build the regex pattern for the last X hours
FAILED_LOGIN_PATTERN=""
for (( i = ${AMOUNTOFHOURSTOCHECK}; i > 0; i-- )); do
    hour=$(date -d "-${i} hour" '+%Y-%m-%d %H')
    FAILED_LOGIN_PATTERN+="(${hour}.*auth failed)|"
done
FAILED_LOGIN_PATTERN=${FAILED_LOGIN_PATTERN%|}  # Remove trailing '|'

# Fetch all failed login attempts from the log
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
echo "$FAILED_LOGINS" | while read -r line; do
    ip=$(echo "$line" | grep -oP 'rip=\K[0-9.]+')
    user=$(echo "$line" | grep -oP 'user=<\K[^>]+')
    timestamp=$(echo "$line" | awk '{print $1, $2}')

    # Check if the user field contains a domain
    if [[ $user == *@* ]]; then
        domain=$(echo "$user" | cut -d'@' -f2)
    else
        domain="no_domain.tld"
    fi

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

    # Create a single-line log entry for each IP
    log_entry="IP: $ip | Country: $country | Domains: $domains/$min_domains | Earliest: $earliest_timestamp | List: [$domain_list]"

    # Decide whether to ban the IP based on the number of unique domains
    if [ "$domains" -ge "$min_domains" ]; then
        if [[ ! " $WHITELIST " =~ " $ip " ]]; then
            if is_ip_banned "$ip"; then
                log_message "INFO" "ALREADY BANNED | $log_entry"
            else
                RETVAL=$(fail2ban-client set $JAIL_NAME banip $ip)
                if [ $RETVAL -eq 0 ]; then
                    log_message "WARN" "BANNED | $log_entry"
                else
                    log_message "ERROR" "FAILED TO BAN | $log_entry"
                fi
            fi
        else
            log_message "INFO" "SKIPPED (whitelisted) | $log_entry"
        fi
    else
        log_message "INFO" "SKIPPED (insufficient domains) | $log_entry"
    fi
done

log_message "INFO" "Script execution completed"