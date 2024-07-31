## Configuration

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