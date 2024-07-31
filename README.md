# Dovecot Multi-Domain IP Banning Script

This script enhances Dovecot email server security by automatically banning IP addresses that attempt to access multiple domains with failed login attempts. It analyzes Dovecot logs, applies country-specific thresholds using GeoIP data, and integrates with fail2ban to block potential brute-force attacks across multiple domains.

## Features

- Multi-domain login attempt analysis
- GeoIP-based country-specific thresholds
- fail2ban integration for IP banning
- Efficient log processing with rotation handling
- Whitelist support for trusted IPs

## Dependencies

- AWK (pre-installed on most Unix-like systems)
- fail2ban
- GeoIP database and mmdblookup
- CRON (for scheduled execution)

## Setup

### Install fail2ban:

1. Install packages (examples based on Debian or Debian related distros)

```
sudo apt-get update
sudo apt-get install fail2ban
```

2. Configure fail2ban:
Create `/etc/fail2ban/filter.d/empty.conf`:

```
[Definition]
failregex =
ignoreregex =
```

Create `/etc/fail2ban/jail.d/dovecot-multidomain.conf`:

```
[dovecot-multidomain]
enabled = true
port = 110,143,993,995
filter = empty
logpath = /dev/null
maxretry = 0
findtime = 86400
bantime = 86400
```

3. Restart fail2ban:

```
sudo systemctl restart fail2ban
```

### Set up log rotation 

1. Create `/etc/logrotate.d/dovecot.conf`:

```
/var/log/dovecot*.log {
rotate 6
monthly
missingok
notifempty
compress
sharedscripts
delaycompress
postrotate
doveadm log reopen
endscript
}
```

## Set up a CRON job to run the script every 5 minutes:

Enter crontab as root or the user you want to have the job executed as:

root: `sudo crontab -e`

user: `sudo -u username crontab -e`

```
*/5 * * * * /path/to/dovecot-multidomain-ip-ban
```

## Installing GeoIP Dependencies

1. Install required packages:

```
sudo apt-get update
sudo apt-get install mmdb-bin geoipupdate
```

2. Configure GeoIP update:

Edit `/etc/GeoIP.conf` and add your MaxMind account ID and license key:

```
AccountID YOUR_ACCOUNT_ID
LicenseKey YOUR_LICENSE_KEY
EditionIDs GeoLite2-Country GeoLite2-City
```

3. Perform initial GeoIP database update:

`sudo geoipupdate`

4. Set up a cron job for weekly updates:

_This is usually handled automatically by your distro. You can check the /etc/cron.d directory for a file called `geoipupdate` or search your CRON files for a geoipupdate entry. Anyway in most cases you won't need to do the next step_

Edit Crontab
`sudo crontab -e`

```
47	3	*	*	*   root    test -x /usr/bin/geoipupdate && /usr/bin/geoipupdate
```

## Script configuration parameters explained

Adjust the following variables in the script as needed:

- `DOVECOT_LOG`: Path to your Dovecot log file
- `BAN_LOG`: Path for the ban log
- `AMOUNTOFHOURSTOCHECK`: Number of hours to look back for failed logins
- `HIGH_THRESHOLD_COUNTRIES`: Countries with a higher banning threshold
- `LOW_THRESHOLD`: Minimum number of domains for most countries
- `HIGH_THRESHOLD`: Minimum number of domains for high-threshold countries
- `WHITELIST`: IPs that should never be banned

## How It Works

1. The script analyzes Dovecot logs for failed login attempts.
2. It identifies IPs attempting to access multiple domains.
3. GeoIP data is used to apply country-specific thresholds.
4. IPs exceeding the threshold are banned using fail2ban.
5. The process is logged for monitoring and analysis.

## Conclusion

This script provides a powerful, customizable solution for protecting Dovecot email servers from brute-force attacks across multiple domains. By leveraging GeoIP data and fail2ban integration, it offers an additional layer of security beyond standard authentication measures.

## Disclaimer

This script is provided as-is, without any warranty or guarantee. Users should understand that they are using this script at their own risk. The authors do not take any responsibilities or liabilities for any data loss, system damage, or other issues that may arise from the use of this script. It is strongly recommended to thoroughly test the script in a non-production environment before using it on critical systems. Always ensure you have multiple backups of your important data using various methods.

## More Information

For a detailed explanation and discussion, please visit our blog post:
[Dovecot Defender: Multi-Domain IP Banning](https://www.lexo.ch/blog/2024/07/dovecot-defender-multi-domain-ip-banning-geoip-smart-script-catches-brute-force-attacks-across-mail-sender-domains-boost-your-e-mail-security)

