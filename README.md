# dovecot-smart-ip-ban-based-on-geoip-and-mail-domain
This script enhances Dovecot email server security by automatically banning IP addresses that attempt to access multiple domains with failed login attempts. It analyzes Dovecot logs, applies country-specific thresholds using GeoIP data, and integrates with fail2ban to block potential brute-force attacks across multiple domains.
