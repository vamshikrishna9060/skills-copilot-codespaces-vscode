# 🔐 Cybersecurity Architect Roadmap (Hands-On)

**Status:** Building from Linux fundamentals → Cloud security architecture  
**Duration:** 8-12 weeks (self-paced)  
**Prerequisites:** Basic Linux, can run Node.js scripts  
**Target:** Entry-level Security Architect / Senior SOC role

---

## 📋 Quick Navigation

1. [Phase 1: Linux Security Fundamentals](#phase-1-linux-security-fundamentals)
2. [Phase 2: Networking & Protocol Analysis](#phase-2-networking--protocol-analysis)
3. [Phase 3: Blue Team & SOC Operations](#phase-3-blue-team--soc-operations)
4. [Phase 4: Red Team Basics](#phase-4-red-team-basics)
5. [Phase 5: Cloud Security Foundations](#phase-5-cloud-security-foundations)
6. [Phase 6: Architecture & Integration](#phase-6-architecture--integration)

---

## Phase 1: Linux Security Fundamentals

**Duration:** 1-2 weeks  
**Goal:** Master file permissions, user/group management, logs, process monitoring

### Core Concepts

- **File Permissions & Ownership** - Why chmod/chown matters
- **User/Group Management** - Privilege separation, sudoers
- **Audit Logging** - auditd, syslog, wtmp/btmp
- **Process Isolation** - Running with least privilege
- **Package Security** - GPG signatures, package verification

### 1.1: File Permissions Deep Dive

**Concept:** Every file has owner, group, and permission bits. Attackers exploit misconfigured permissions.

```bash
# Lab: Permission Analysis
cd /tmp
touch sensitive.conf
chmod 777 sensitive.conf          # DANGEROUS - everyone can read/write/execute
ls -l sensitive.conf              # See permissions

# Check actual permission bits
stat sensitive.conf

# Fix it properly (owner rw, group r, others nothing)
chmod 640 sensitive.conf
ls -l sensitive.conf

# Who owns what?
ls -l /etc/shadow                 # Only root can read passwords
ls -l /etc/passwd                 # Everyone can read users

# Find world-writable files (security risk!)
find / -perm -002 -type f 2>/dev/null | head -20

# Find SUID binaries (can escalate privileges)
find / -perm -4000 -type f 2>/dev/null | head -20
```

**Lab 1.1 Exercise:**
```bash
# Create a security audit script
mkdir -p ~/security-labs/phase1
cat > ~/security-labs/phase1/permission_audit.sh << 'EOF'
#!/bin/bash
echo "=== SECURITY AUDIT: FILE PERMISSIONS ==="
echo ""
echo "1. World-writable files:"
find / -perm -002 -type f 2>/dev/null | wc -l

echo ""
echo "2. SUID binaries (check these manually):"
find / -perm -4000 -type f 2>/dev/null

echo ""
echo "3. Files with no group protection:"
find /home -perm -020 2>/dev/null

echo ""
echo "4. Unowned files (orphaned):"
find / -nouser -o -nogroup 2>/dev/null | head -10
EOF

chmod +x ~/security-labs/phase1/permission_audit.sh
# Run it and analyze output
```

### 1.2: User & Group Privilege Management

**Concept:** Least privilege principle - users should have minimum needed permissions.

```bash
# Lab: User/Group Management
# Who am I?
whoami
id
groups

# What can I do?
sudo -l

# Create test user (simulate developer/service account)
sudo useradd -m -s /bin/bash appuser
sudo usermod -aG sudo appuser        # Add to sudo group (be careful!)

# Check sudoers without opening file
sudo grep appuser /etc/sudoers
sudo grep appuser /etc/sudoers.d/*

# Remove excessive sudoers access
sudo visudo -c                       # Check sudoers syntax

# Remove user safely
sudo userdel -r appuser              # -r removes home directory

# Check what's in /etc/sudoers
sudo cat /etc/sudoers | grep -v "^#"

# Lock/unlock accounts
sudo passwd -l appuser               # Lock (deny login)
sudo passwd -u appuser               # Unlock
```

**Lab 1.2 Exercise:**
```bash
# Create a service account with NO shell access
sudo useradd -r -s /usr/sbin/nologin webservice
id webservice

# Verify it can't login
sudo su - webservice                 # Should fail

# But it can own files/processes
sudo chown webservice:webservice /var/www/app
ls -l /var/www/app                   # Verify ownership
```

### 1.3: Audit Logging (auditd)

**Concept:** Every security event must be logged and monitored.

```bash
# Lab: System Auditing
# Install auditd
sudo apt-get install auditd audispd-plugins -y

# Check auditd status
sudo systemctl status auditd

# View audit logs
sudo tail -f /var/log/audit/audit.log

# Add audit rule: Monitor /etc/passwd changes
sudo auditctl -w /etc/passwd -p wa -k passwd_changes

# Test it - modify passwd
sudo cat /etc/passwd | tail -1

# View the audit event
sudo ausearch -k passwd_changes

# List all audit rules
sudo auditctl -l

# Make rules persistent (survives reboot)
sudo cat /etc/audit/rules.d/audit.rules
```

**Lab 1.3 Exercise:**
```bash
# Create a monitoring script
cat > ~/security-labs/phase1/audit_monitor.sh << 'EOF'
#!/bin/bash

# Monitor critical files for changes
sudo auditctl -w /etc/shadow -p wa -k shadow_changes
sudo auditctl -w /etc/sudoers -p wa -k sudoers_changes
sudo auditctl -w /root/.ssh -p wa -k root_ssh_changes

# Monitor failed login attempts
sudo auditctl -a always,exit -F arch=b64 -S execve -F exe=/bin/bash -k shell_exec

echo "Audit rules configured. Check: sudo auditctl -l"
EOF

chmod +x ~/security-labs/phase1/audit_monitor.sh
```

### 1.4: Process Monitoring & Security

**Concept:** Know what's running, who runs it, what resources it uses.

```bash
# Lab: Process Security
# List all processes
ps aux

# Process hierarchy (parent-child)
ps auxf

# Find processes by user
ps -u root
ps -u $(whoami)

# Monitor in real-time
top -b -n 1 | head -20

# Check open files/connections by process
sudo lsof -p <PID>                   # Replace <PID> with process ID
sudo lsof -i :80                     # Processes on port 80

# Watch for suspicious processes
# Example: Python script connecting to unusual IP
sudo netstat -tulpn | grep LISTEN

# Check running services
sudo systemctl list-units --type=service --all

# Disable unnecessary services (reduce attack surface)
sudo systemctl list-unit-files | grep enabled
```

**Lab 1.4 Exercise:**
```bash
# Create a process baseline
cat > ~/security-labs/phase1/process_baseline.sh << 'EOF'
#!/bin/bash

echo "=== PROCESS BASELINE (SAVE THIS) ==="
date > ~/process_baseline.txt
ps auxf >> ~/process_baseline.txt

echo ""
echo "=== LISTENING PORTS ==="
sudo netstat -tulpn | grep LISTEN >> ~/process_baseline.txt

echo ""
echo "Baseline saved to ~/process_baseline.txt"
echo "Compare after system changes to detect anomalies"
EOF

chmod +x ~/security-labs/phase1/process_baseline.sh
```

### 1.5: Package Security & Integrity

**Concept:** Verify packages aren't compromised.

```bash
# Lab: Package Verification
# Check installed packages
apt list --installed | wc -l

# Verify package GPG signatures
sudo apt-key list                    # Keys trusted for package signing

# Check integrity of system binaries
sudo apt-file list | head -20

# Verify specific package wasn't modified
dpkg -V coreutils                    # No output = OK

# Remove unnecessary packages (reduce surface)
apt autoremove -y

# Check for security updates
apt list --upgradable | head -10

# Install security updates
sudo apt update && sudo apt upgrade -y
```

---

## Phase 2: Networking & Protocol Analysis

**Duration:** 2-3 weeks  
**Goal:** Understand TCP/IP, packet analysis, network tools, threat detection

### Core Concepts

- **TCP/IP Stack** - Layers, headers, flags
- **Packet Sniffing** - tcpdump, Wireshark
- **DNS & HTTP** - Protocol weaknesses, DNS spoofing
- **Network Tools** - nmap, netcat, iperf
- **Network Isolation** - Firewalls, VPCs

### 2.1: TCP/IP Fundamentals & Scanning

**Concept:** Understanding the network stack is foundational for both attack and defense.

```bash
# Lab: Network Reconnaissance
# Your network info
ifconfig
ip addr show

# Routing table (how packets move)
ip route show
netstat -rn

# Local network discovery
arp -a                               # ARP table (IP to MAC mapping)

# Ping sweep (find active hosts)
ping -c 1 8.8.8.8                    # Test connectivity

# DNS lookups
nslookup google.com
dig google.com +short
host google.com

# Reverse DNS (who owns this IP?)
nslookup 8.8.8.8
dig -x 8.8.8.8
```

**Lab 2.1 Exercise - Port Scanning:**
```bash
# Install nmap if needed
sudo apt-get install nmap -y

# Scan localhost (safe practice)
nmap localhost
nmap -sV localhost                   # Service version detection
nmap -O localhost                    # OS detection
nmap -sS localhost                   # SYN scan (stealth)
nmap -p 1-65535 localhost            # All ports (slow)

# Scan a specific port
nmap -p 22 localhost                 # SSH port

# Understanding scan types:
# -sS: SYN scan (stealth, doesn't complete handshake)
# -sT: TCP connect (completes handshake, logged)
# -sU: UDP scan
# -sA: ACK scan (firewall detection)

# NEVER scan without permission! This is for localhost only.
```

### 2.2: Packet Sniffing with tcpdump

**Concept:** Capture and analyze network traffic - defenders use this to hunt threats.

```bash
# Lab: Packet Capture
# List network interfaces
tcpdump -D

# Simple capture on eth0
sudo tcpdump -i eth0 -n -c 10       # Capture 10 packets

# Capture with detailed info
sudo tcpdump -i eth0 -v -c 5

# Filter by protocol
sudo tcpdump -i eth0 -n icmp        # ICMP (ping) traffic
sudo tcpdump -i eth0 -n tcp         # Only TCP
sudo tcpdump -i eth0 -n tcp port 22 # SSH traffic

# Filter by host
sudo tcpdump -i eth0 -n host 8.8.8.8

# Save to file (analyze later)
sudo tcpdump -i eth0 -w capture.pcap -n port 443

# Read captured file
tcpdump -r capture.pcap

# More complex filters
sudo tcpdump -i eth0 '(tcp and port 80) or (icmp)'

# Show packet contents (hex dump)
sudo tcpdump -i eth0 -X -c 2
```

**Lab 2.2 Exercise - Protocol Analysis:**
```bash
# Create a traffic analysis script
cat > ~/security-labs/phase2/traffic_analysis.sh << 'EOF'
#!/bin/bash

echo "=== NETWORK TRAFFIC BASELINE ==="
echo "Time: $(date)"
echo ""

# Current connections
echo "=== ESTABLISHED CONNECTIONS ==="
netstat -tan | grep ESTABLISHED | awk '{print $4, $5}'

echo ""
echo "=== DNS QUERIES (last 10) ==="
# Note: Requires systemd-resolved
sudo journalctl -u systemd-resolved -n 10 --no-pager | grep -i "query"

echo ""
echo "=== TOP TALKERS ==="
# This would require tcpdump, showing top source IPs
echo "(Run with: sudo tcpdump -i eth0 -n 'not port 22' | head -10)"
EOF

chmod +x ~/security-labs/phase2/traffic_analysis.sh
```

### 2.3: HTTP/HTTPS Protocol Security

**Concept:** Most web attacks happen at application layer.

```bash
# Lab: HTTP/HTTPS Analysis
# Make HTTP request with headers
curl -v http://example.com 2>&1 | head -20

# HTTPS with certificate info
curl -v https://example.com 2>&1 | head -30

# Show response headers only
curl -I https://example.com

# Follow redirects
curl -L https://example.com

# Save request/response
curl -D response_headers.txt https://example.com

# Check SSL certificate
openssl s_client -connect example.com:443

# Extract certificate details
openssl x509 -in cert.pem -text -noout

# Check certificate expiry
curl -I https://example.com 2>&1 | grep "SSL"
```

**Lab 2.3 Exercise - HTTPS Security:**
```bash
# Generate self-signed certificate (like attackers do!)
mkdir ~/security-labs/phase2/certs
cd ~/security-labs/phase2/certs

# Create private key
openssl genrsa -out server.key 2048

# Create certificate request
openssl req -new -key server.key -out server.csr \
  -subj "/C=US/ST=CA/L=SF/O=Test/CN=localhost"

# Self-sign the cert
openssl x509 -req -in server.csr -signkey server.key \
  -out server.crt -days 365

# Verify certificate
openssl x509 -in server.crt -text -noout

# Create a simple HTTPS server with Node.js
cat > ~/security-labs/phase2/https_server.js << 'EOJS'
#!/usr/bin/env node
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('./certs/server.key'),
  cert: fs.readFileSync('./certs/server.crt')
};

https.createServer(options, (req, res) => {
  res.writeHead(200);
  res.end('Secure Server Running!');
}).listen(8443);

console.log('HTTPS server on https://localhost:8443');
EOJS

chmod +x ~/security-labs/phase2/https_server.js

# Run it (in background)
cd ~/security-labs/phase2
node https_server.js &

# Test it
curl -k https://localhost:8443          # -k ignores self-signed warning

# Check the certificate
openssl s_client -connect localhost:8443
```

### 2.4: DNS Security & Attacks

**Concept:** DNS is critical infrastructure - attackers poison it, defenders detect it.

```bash
# Lab: DNS Analysis
# Query specific DNS record types
nslookup -type=A google.com
nslookup -type=MX google.com          # Mail servers
nslookup -type=NS google.com          # Nameservers
nslookup -type=TXT google.com         # Text records (SPF, DKIM, DMARC)

# Use dig (more powerful)
dig google.com                        # Full query response
dig google.com +short                 # Just answer
dig @8.8.8.8 google.com               # Use specific nameserver
dig +trace google.com                 # Show full resolution path

# Check your system's DNS
cat /etc/resolv.conf

# Query local DNS cache
sudo journalctl -u systemd-resolved --no-pager | tail -20

# Monitor DNS queries in real-time
sudo tcpdump -i eth0 -n 'udp port 53'
```

**Lab 2.4 Exercise - DNS Security:**
```bash
# Check DNS records for security issues
cat > ~/security-labs/phase2/dns_audit.sh << 'EOF'
#!/bin/bash

DOMAIN="google.com"

echo "=== DNS SECURITY AUDIT for $DOMAIN ==="
echo ""

echo "1. A Records (IPv4):"
dig +short $DOMAIN

echo ""
echo "2. AAAA Records (IPv6):"
dig +short $DOMAIN AAAA

echo ""
echo "3. MX Records (Mail):"
dig +short $DOMAIN MX

echo ""
echo "4. NS Records (Nameservers):"
dig +short $DOMAIN NS

echo ""
echo "5. SPF Records (Email auth):"
dig +short $DOMAIN TXT | grep v=spf

echo ""
echo "6. Full DNS resolution path:"
dig +trace +short $DOMAIN | head -20

echo ""
echo "7. DNSSEC validation:"
dig $DOMAIN +dnssec | grep -i "ad\|RRSIG"
EOF

chmod +x ~/security-labs/phase2/dns_audit.sh
bash ~/security-labs/phase2/dns_audit.sh
```

---

## Phase 3: Blue Team & SOC Operations

**Duration:** 3-4 weeks  
**Goal:** Learn detection, response, incident handling, SIEM concepts

### Core Concepts

- **Intrusion Detection** - IDS/IPS, Suricata, Snort rules
- **Log Aggregation** - ELK stack, Splunk basics
- **Alerting & Correlation** - False positives, tuning
- **Incident Response** - Playbooks, timeline, evidence
- **Threat Intelligence** - MITRE ATT&CK, IOCs

### 3.1: Intrusion Detection with Suricata

**Concept:** IDS watches for malicious patterns - like a network immune system.

```bash
# Lab: Intrusion Detection
# Install Suricata
sudo apt-get install suricata suricata-update -y

# Check status
sudo systemctl status suricata

# Suricata config
sudo cat /etc/suricata/suricata.yaml | head -50

# Update threat rules
sudo suricata-update

# View installed rules
ls -la /var/lib/suricata/rules/

# Run Suricata on pcap
sudo suricata -r capture.pcap

# Real-time monitoring
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# View alerts
sudo tail -f /var/log/suricata/eve.json

# Parse JSON alerts (pretty print)
sudo jq . /var/log/suricata/eve.json | head -50
```

**Lab 3.1 Exercise - Custom Detection Rules:**
```bash
# Create custom Suricata rule
cat > ~/security-labs/phase3/custom_rules.rules << 'EOF'
# Detect suspicious outbound HTTPS to unusual ports
alert tls any any -> any !80:443 (msg:"Suspicious TLS on unusual port"; 
  flow:established,to_server; tls.version:any; sid:1000001; rev:1;)

# Detect large data exfiltration
alert http any any -> any any (msg:"Large HTTP response"; 
  flow:established,to_client; content:"HTTP/"; http_stat_code:200; 
  content_length:>1000000; sid:1000002; rev:1;)

# Detect SQL injection patterns
alert http any any -> any any (msg:"Possible SQL injection";
  flow:to_server,established; content:"SELECT"; 
  content:"FROM"; nocase; http_uri; sid:1000003; rev:1;)
EOF

# Load custom rules
sudo cp ~/security-labs/phase3/custom_rules.rules /etc/suricata/rules/

# Test rule syntax
sudo suricata -T -c /etc/suricata/suricata.yaml
```

### 3.2: Log Aggregation & Analysis (ELK Stack)

**Concept:** Centralize logs, parse them, search, create dashboards.

```bash
# Lab: Log Analysis with grep/awk (lightweight alternative to ELK)

# System logs location
/var/log/syslog
/var/log/auth.log
/var/log/apache2/access.log

# Parse auth failures
sudo grep "Failed password" /var/log/auth.log | wc -l

# Show failed logins by user
sudo grep "Failed password" /var/log/auth.log | \
  awk '{print $(NF-5)}' | sort | uniq -c | sort -rn

# Failed SSH attempts
sudo grep "Invalid user" /var/log/auth.log | wc -l

# Show attempted usernames
sudo grep "Invalid user" /var/log/auth.log | \
  awk '{print $7}' | sort | uniq -c | sort -rn

# Root access attempts
sudo grep "sudo" /var/log/auth.log | tail -10

# System errors
grep "ERROR" /var/log/syslog | tail -20

# Timeline of events
sudo journalctl --since="2 hours ago" --until="now"
```

**Lab 3.2 Exercise - Log Monitoring Script:**
```bash
# Create a SOC analyst's log monitoring tool
cat > ~/security-labs/phase3/soc_monitor.sh << 'EOF'
#!/bin/bash

echo "=== SOC LOG MONITORING REPORT ==="
echo "Generated: $(date)"
echo ""

echo "--- FAILED LOGIN ATTEMPTS (Last 24h) ---"
sudo journalctl -u sshd --since="24 hours ago" | grep "Failed password" | wc -l

echo ""
echo "--- TOP ATTACKERS (Source IPs) ---"
sudo journalctl -u sshd --since="24 hours ago" | grep "Failed password" | \
  grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | \
  sort | uniq -c | sort -rn | head -10

echo ""
echo "--- SUDO COMMAND EXECUTIONS ---"
sudo journalctl -u sudo --since="24 hours ago" | grep "COMMAND" | tail -5

echo ""
echo "--- SYSTEM ERRORS (Last 10) ---"
sudo journalctl --priority=err --since="24 hours ago" | tail -10

echo ""
echo "--- LISTENING PORTS ---"
sudo netstat -tulpn | grep LISTEN

echo ""
echo "--- NEW USER ACCOUNTS (Last 24h) ---"
sudo journalctl _COMM=useradd --since="24 hours ago" | tail -5
EOF

chmod +x ~/security-labs/phase3/soc_monitor.sh
```

### 3.3: MITRE ATT&CK Framework

**Concept:** Standardized way to categorize attacker techniques.

```bash
# Lab: Map events to MITRE ATT&CK
# Common techniques:
# - T1021: Remote Services (SSH, RDP)
# - T1059: Command & Scripting (Shell execution)
# - T1082: System Information Discovery
# - T1083: File & Directory Discovery
# - T1005: Data from Local System
# - T1020: Automated Exfiltration

# Example: Detect file discovery (T1083)
sudo grep "find\|locate\|ls -" /var/log/auth.log

# Example: Detect command execution (T1059)
sudo grep "bash\|python\|perl" /var/log/auth.log

# Create incident detection logic
cat > ~/security-labs/phase3/mitre_detector.sh << 'EOF'
#!/bin/bash

echo "=== MITRE ATT&CK DETECTION ==="
echo ""

echo "T1021 - Remote Services (SSH attempts):"
sudo journalctl -u sshd -n 100 | wc -l

echo ""
echo "T1082 - System Information Discovery:"
sudo grep "uname\|whoami\|hostname" /var/log/auth.log | wc -l

echo ""
echo "T1005 - Data from Local System (unusual access):"
sudo grep "cat /etc/shadow\|cat /etc/passwd" /var/log/auth.log | wc -l

echo ""
echo "T1078 - Valid Accounts (multiple failed then success):"
sudo grep "Failed password" /var/log/auth.log | \
  tail -1 | awk '{print $(NF-5)}'
EOF

chmod +x ~/security-labs/phase3/mitre_detector.sh
```

### 3.4: Incident Response Playbook

**Concept:** Structured process for responding to security incidents.

```bash
# Lab: Incident Response Steps

# 1. DETECTION & ANALYSIS
# Question: Is this real? What happened?
# Action: Collect all relevant logs
sudo journalctl --since="1 hour ago" > incident.log
sudo cp /var/log/auth.log auth_backup.log
sudo cp /var/log/syslog syslog_backup.log

# 2. CONTAINMENT
# Question: How do we stop the attack?
# Action: Block the attacker IP (if known)
ATTACKER_IP="192.168.1.100"
# sudo iptables -I INPUT -s $ATTACKER_IP -j DROP
# Or disable compromised account
# sudo usermod -L suspecteduser

# 3. ERADICATION
# Question: How do we remove the attacker?
# Action: Remove backdoors, reset passwords
# sudo userdel -r backdooraccount
# sudo find / -name "*.sh" -newer suspicious_file -type f

# 4. RECOVERY
# Question: How do we restore normal operations?
# Action: Restart affected services
# sudo systemctl restart ssh
# sudo systemctl restart apache2

# 5. LESSONS LEARNED
# Question: What should we do differently?
# Action: Write post-incident review
cat > incident_report.txt << 'REPORT'
INCIDENT REPORT
Date: $(date)
Summary: [Describe what happened]
Timeline: [When did each event occur]
Impact: [What was affected]
Root Cause: [Why did this happen]
Response: [What did we do]
Improvements: [What could be better]
REPORT
```

**Lab 3.4 Exercise - IR Playbook:**
```bash
# Create a playbook for common scenarios
cat > ~/security-labs/phase3/ir_playbook.sh << 'EOF'
#!/bin/bash

echo "=== INCIDENT RESPONSE PLAYBOOK ==="
echo "Scenario: Unauthorized SSH Access Detected"
echo ""

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
INCIDENT_DIR="/tmp/incident_$TIMESTAMP"
mkdir -p $INCIDENT_DIR

echo "1. PRESERVE EVIDENCE"
echo "  - Collecting system state..."
sudo cp /var/log/auth.log $INCIDENT_DIR/
sudo cp /var/log/syslog $INCIDENT_DIR/
ps auxf > $INCIDENT_DIR/processes.txt
sudo netstat -tupn > $INCIDENT_DIR/connections.txt
w > $INCIDENT_DIR/logged_in_users.txt

echo ""
echo "2. ANALYZE ATTACK"
echo "  - Finding unauthorized access..."
sudo grep "Accepted publickey\|Accepted password" $INCIDENT_DIR/auth.log | \
  tail -10 | tee $INCIDENT_DIR/unauthorized_access.txt

echo ""
echo "3. FIND LATERAL MOVEMENT"
echo "  - Checking for privilege escalation..."
sudo grep "sudo" $INCIDENT_DIR/auth.log | tail -10 | tee $INCIDENT_DIR/sudo_usage.txt

echo ""
echo "4. BACKUP FOR FORENSICS"
echo "  - All evidence saved to: $INCIDENT_DIR"
tar czf $INCIDENT_DIR.tar.gz $INCIDENT_DIR

echo ""
echo "5. NEXT STEPS"
echo "  - Review evidence: ls -la $INCIDENT_DIR"
echo "  - Backup: $INCIDENT_DIR.tar.gz"
echo "  - Notify: Incident response team"
echo "  - Contain: Block attacker IP / disable accounts"
EOF

chmod +x ~/security-labs/phase3/ir_playbook.sh
```

---

## Phase 4: Red Team Basics

**Duration:** 2-3 weeks  
**Goal:** Understand attack perspective, reconnaissance, initial access

### ⚠️ IMPORTANT: Legal Disclaimer

**DO NOT execute attacks on systems you don't own or have written permission for.**

All exercises below are for:
- Educational purposes only
- Your own systems or lab environments
- Understanding attacker techniques to defend against them

### Core Concepts

- **Reconnaissance** - OSINT, passive scanning
- **Social Engineering** - Common tactics (for awareness)
- **Initial Access** - Weak credentials, misconfigurations
- **Privilege Escalation** - Linux vulnerability exploitation
- **Lateral Movement** - How attackers spread

### 4.1: Open Source Intelligence (OSINT)

**Concept:** Attackers gather information from public sources before attacking.

```bash
# Lab: OSINT Reconnaissance

# 1. Domain/IP Research
whois google.com
whois 8.8.8.8

# DNS enumeration
nslookup -type=* google.com           # All records
dig google.com +nocmd +noall +answer

# Subdomain enumeration (passive - no harm)
# Using DNS brute force (educational only on your own domains)
# for sub in www mail ftp admin; do
#   dig $sub.google.com +short
# done

# 2. People research (ethical OSINT)
# LinkedIn searches, GitHub account findings, etc.
# Tools: sherlock, hunter.io, people search engines

# 3. Technology stack discovery
curl -I https://example.com | grep -i "server\|powered"

# Check website technologies
# Online tool: https://builtwith.com or wappalyzer

# 4. Email discovery
# hunt3r, email enumeration (find company email pattern)

# 5. Wayback machine (historical snapshots)
# https://web.archive.org - see old versions of websites

# 6. Google dorking (using search operators)
# site:example.com             # Only this domain
# site:example.com inurl:admin # Admin pages
# filetype:pdf                 # PDFs only
# intitle:"index of"           # Directory listings
# "password" OR "admin"        # Sensitive info
```

**Lab 4.1 Exercise - OSINT Report:**
```bash
# Create OSINT gathering script
cat > ~/security-labs/phase4/osint_gather.sh << 'EOF'
#!/bin/bash

TARGET=$1
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <domain>"
  exit 1
fi

echo "=== OSINT INTELLIGENCE GATHERING ==="
echo "Target: $TARGET"
echo "Time: $(date)"
echo ""

echo "1. WHOIS REGISTRATION INFO"
whois $TARGET | grep -E "Registrant|Registrar|Created|Expires"

echo ""
echo "2. NAMESERVERS"
dig $TARGET NS +short

echo ""
echo "3. MAIL SERVERS"
dig $TARGET MX +short

echo ""
echo "4. IP ADDRESS"
dig $TARGET +short

echo ""
echo "5. DNS RECORDS"
dig $TARGET ANY +short

echo ""
echo "6. WEBSITE HEADERS"
curl -I https://$TARGET 2>/dev/null | grep -iE "Server|Powered|X-"

echo ""
echo "7. SSL CERTIFICATE INFO"
openssl s_client -connect $TARGET:443 -servername $TARGET < /dev/null 2>/dev/null | \
  openssl x509 -noout -dates -subject

echo ""
echo "=== OSINT COMPLETE ==="
EOF

chmod +x ~/security-labs/phase4/osint_gather.sh
# Test on your own domain: bash osint_gather.sh example.com
```

### 4.2: Passive Vulnerability Identification

**Concept:** Find weak credentials, exposed configs, misconfigurations.

```bash
# Lab: Common Vulnerabilities

# 1. Default credentials (NEVER change - for education only!)
# ssh -u admin -p admin 192.168.1.1              # Router default
# mysql -h localhost -u root                     # No password!

# 2. Information disclosure
# Check for .git exposure
curl https://example.com/.git/config 2>/dev/null

# Check for .env files (credentials!)
curl https://example.com/.env 2>/dev/null

# Check for backup files
curl https://example.com/web.backup 2>/dev/null
curl https://example.com/app.tar.gz 2>/dev/null

# 3. Weak SSL/TLS
# Check SSL strength
sudo apt-get install testssl.sh -y
testssl.sh https://example.com

# 4. Directory listing (should be disabled!)
curl https://example.com/uploads/

# 5. HTTP methods allowed
curl -v -X OPTIONS https://example.com 2>&1 | grep "Allow"

# 6. Security headers missing
curl -I https://example.com | grep -iE "Strict-Transport|Content-Security|X-Frame"
```

**Lab 4.2 Exercise - Vulnerability Scanner:**
```bash
# Create a simple web vulnerability scanner
cat > ~/security-labs/phase4/vuln_scanner.sh << 'EOF'
#!/bin/bash

TARGET=$1
if [ -z "$TARGET" ]; then
  echo "Usage: $0 <url>"
  exit 1
fi

echo "=== VULNERABILITY SCANNER ==="
echo "Target: $TARGET"
echo ""

# Check for common exposures
echo "1. Checking for .git exposure..."
curl -s -o /dev/null -w "%{http_code}" "$TARGET/.git/config"

echo ""
echo "2. Checking for .env exposure..."
curl -s -o /dev/null -w "%{http_code}" "$TARGET/.env"

echo ""
echo "3. Checking for backup files..."
curl -s -o /dev/null -w "%{http_code}" "$TARGET/web.backup"

echo ""
echo "4. Checking security headers..."
curl -I "$TARGET" 2>/dev/null | grep -iE "Strict-Transport|CSP|X-Frame" || echo "WARNING: Missing security headers!"

echo ""
echo "5. Checking SSL/TLS version..."
openssl s_client -connect ${TARGET#https://}:443 -tls1_2 2>/dev/null | grep "TLSv" || echo "Weak TLS detected"

echo ""
echo "=== SCAN COMPLETE ==="
EOF

chmod +x ~/security-labs/phase4/vuln_scanner.sh
```

### 4.3: Credential Weakness Testing

**Concept:** Many breaches start with weak credentials.

```bash
# Lab: Password Security Testing

# 1. Crack weak hashes (educational - on YOUR accounts only!)
# Example: Generate and crack hash
echo -n "Password123!" | sha256sum
# Result: abcd1234...

# Use hashcat or john on your own hashes
# sudo apt-get install john -y

# 2. Default credential lists
# SecLists has common passwords/usernames
# github.com/danielmiessler/SecLists

# 3. Common patterns attackers try:
# - admin/admin
# - admin/password
# - admin/123456
# - user/user
# - root/root

# 4. Test YOUR OWN password strength
cat > ~/security-labs/phase4/password_strength.sh << 'EOF'
#!/bin/bash

PASSWORD=$1
if [ -z "$PASSWORD" ]; then
  echo "Usage: $0 <password>"
  exit 1
fi

echo "=== PASSWORD STRENGTH ANALYSIS ==="
echo "Length: ${#PASSWORD}"

if [[ $PASSWORD =~ [a-z] ]]; then
  echo "✓ Contains lowercase"
else
  echo "✗ Missing lowercase"
fi

if [[ $PASSWORD =~ [A-Z] ]]; then
  echo "✓ Contains uppercase"
else
  echo "✗ Missing uppercase"
fi

if [[ $PASSWORD =~ [0-9] ]]; then
  echo "✓ Contains numbers"
else
  echo "✗ Missing numbers"
fi

if [[ $PASSWORD =~ [\!\@\#\$\%\^\&\*] ]]; then
  echo "✓ Contains special chars"
else
  echo "✗ Missing special chars"
fi

if [ ${#PASSWORD} -lt 12 ]; then
  echo "✗ Too short (should be 12+)"
else
  echo "✓ Good length"
fi
EOF

chmod +x ~/security-labs/phase4/password_strength.sh
```

### 4.4: Privilege Escalation Basics

**Concept:** After gaining access, attackers elevate privileges.

```bash
# Lab: Privilege Escalation - Local Enumeration

# 1. Enumerate current user
whoami
id
sudo -l                               # What can we sudo?

# 2. Find SUID binaries (can escalate!)
find / -perm -4000 2>/dev/null

# 3. Check for weak sudo rules
sudo -l -U username 2>/dev/null

# 4. Find world-writable files
find / -perm -002 -type f 2>/dev/null

# 5. Check kernel version (might have CVE)
uname -a
uname -r

# 6. Find installed packages with known CVEs
apt list --installed | cut -d/ -f1 | sort

# 7. Check for cron jobs
crontab -l                            # Your crons
sudo crontab -u root -l              # Root crons (if visible)

# 8. Find password files
sudo grep -r "password\|passwd" /home 2>/dev/null | head -10
```

**Lab 4.4 Exercise - Privilege Escalation Enumeration:**
```bash
# Create enumeration tool
cat > ~/security-labs/phase4/priv_esc_enum.sh << 'EOF'
#!/bin/bash

echo "=== PRIVILEGE ESCALATION ENUMERATION ==="
echo ""

echo "1. CURRENT PRIVILEGES:"
id
groups

echo ""
echo "2. SUDO CAPABILITIES:"
sudo -l 2>/dev/null || echo "No sudo access"

echo ""
echo "3. SUID BINARIES:"
find / -perm -4000 -type f 2>/dev/null | head -10

echo ""
echo "4. KERNEL VULNERABILITY RISK:"
uname -r
# Check: cvedetails.com for kernel version CVEs

echo ""
echo "5. READABLE SENSITIVE FILES:"
[ -r /etc/shadow ] && echo "✗ Can read /etc/shadow!" || echo "✓ /etc/shadow protected"
[ -r /root/.ssh/id_rsa ] && echo "✗ Can read root SSH key!" || echo "✓ SSH keys protected"

echo ""
echo "6. WORLD-WRITABLE DIRECTORIES:"
find / -perm -002 -type d 2>/dev/null | head -10

echo ""
echo "7. CRON JOBS:"
crontab -l 2>/dev/null || echo "No cron access"
EOF

chmod +x ~/security-labs/phase4/priv_esc_enum.sh
```

---

## Phase 5: Cloud Security Foundations

**Duration:** 2-3 weeks  
**Goal:** AWS/Azure basics, IAM, cloud misconfigurations, shared responsibility

### Core Concepts

- **Cloud Service Models** - IaaS, PaaS, SaaS
- **AWS Fundamentals** - EC2, S3, IAM, VPC
- **Azure Basics** - VMs, Storage, Azure AD
- **Cloud IAM** - Principle of least privilege
- **Misconfigurations** - S3 bucket exposure, security groups

### 5.1: AWS Fundamentals

**Concept:** Most enterprise uses AWS - security knowledge is critical.

```bash
# Lab: AWS Setup & Security
# Prerequisites: AWS account (free tier available)

# Install AWS CLI
sudo apt-get install awscli -y

# Configure credentials (use test account!)
aws configure
# Enter: Access Key ID
# Enter: Secret Access Key
# Enter: Default region (us-east-1)

# Test connection
aws sts get-caller-identity

# List your EC2 instances
aws ec2 describe-instances

# List S3 buckets
aws s3 ls

# Check IAM users
aws iam list-users

# List security groups
aws ec2 describe-security-groups

# Describe VPCs
aws ec2 describe-vpcs
```

**Lab 5.1 Exercise - AWS Security Assessment:**
```bash
# Create cloud security audit script
cat > ~/security-labs/phase5/aws_security_audit.sh << 'EOF'
#!/bin/bash

echo "=== AWS SECURITY AUDIT ==="
echo ""

echo "1. ACCOUNT INFO:"
aws sts get-caller-identity

echo ""
echo "2. ACTIVE IAM USERS:"
aws iam list-users --query 'Users[*].[UserName,CreateDate]'

echo ""
echo "3. ACCESS KEYS AGE (should rotate if >90 days):"
aws iam list-access-keys | grep CreateDate

echo ""
echo "4. S3 BUCKETS WITH PUBLIC ACCESS (DANGEROUS!):"
aws s3api list-buckets --query 'Buckets[*].Name' | while read bucket; do
  acl=$(aws s3api get-bucket-acl --bucket $bucket 2>/dev/null | grep PublicRead)
  [ -n "$acl" ] && echo "⚠️  PUBLIC: $bucket"
done

echo ""
echo "5. EC2 SECURITY GROUPS (check for 0.0.0.0/0):"
aws ec2 describe-security-groups --query 'SecurityGroups[*].[GroupName,IpPermissions[*].[IpRanges[*].CidrIp]]'

echo ""
echo "6. CLOUDTRAIL ENABLED (API logging):"
aws cloudtrail describe-trails | grep IsMultiRegionTrail

echo ""
echo "=== AUDIT COMPLETE ==="
EOF

chmod +x ~/security-labs/phase5/aws_security_audit.sh
```

### 5.2: S3 Bucket Misconfigurations

**Concept:** Public S3 buckets leak massive amounts of data.

```bash
# Lab: S3 Security

# List your buckets
aws s3 ls

# Check bucket ACL (who can access?)
aws s3api get-bucket-acl --bucket your-bucket-name

# Check bucket policy (more detailed access)
aws s3api get-bucket-policy --bucket your-bucket-name

# List bucket contents
aws s3 ls s3://your-bucket-name --recursive

# Block public access (AWS recommendation)
aws s3api put-public-access-block \
  --bucket your-bucket-name \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable versioning (prevent deletion)
aws s3api put-bucket-versioning \
  --bucket your-bucket-name \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket your-bucket-name \
  --server-side-encryption-configuration '{...}'
```

### 5.3: IAM Security Best Practices

**Concept:** IAM is core to cloud security - misconfigurations = breaches.

```bash
# Lab: IAM Security

# Check root account usage (should be minimal!)
aws cloudtrail lookup-events --max-results 10

# List IAM policies
aws iam list-policies | grep -i custom

# Check policy attachments
aws iam list-user-policies --user-name username

# Find overprivileged users (using Admin policy)
aws iam list-users --query 'Users[*].UserName' | \
  while read user; do
    aws iam list-user-policies --user-name $user | \
      grep -q "AdministratorAccess" && echo "⚠️  ADMIN: $user"
  done

# Create least-privilege policy
cat > restrictive_policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-bucket",
        "arn:aws:s3:::my-bucket/*"
      ]
    }
  ]
}
EOF

# Review MFA (should be enabled!)
aws iam list-users --query 'Users[*].UserName' | \
  while read user; do
    mfa=$(aws iam list-mfa-devices --user-name $user)
    [ -z "$mfa" ] && echo "⚠️  NO MFA: $user"
  done
```

---

## Phase 6: Architecture & Integration

**Duration:** 2-3 weeks  
**Goal:** Design secure systems, threat modeling, put it all together

### Core Concepts

- **Threat Modeling** - STRIDE, attack surfaces
- **Defense in Depth** - Layered security
- **Architecture Patterns** - DMZ, segmentation
- **Monitoring Strategy** - What to alert on
- **Incident Response Integration** - Automation

### 6.1: Threat Modeling

**Concept:** Design security in, don't add it later.

```bash
# Lab: STRIDE Threat Modeling

# STRIDE = Spoofing, Tampering, Repudiation, Information Disclosure, 
#          Denial of Service, Elevation of Privilege

# Example: Web app with database

cat > threat_model.txt << 'EOF'
APPLICATION ARCHITECTURE:
[User] --HTTP--> [Web Server] --SQL--> [Database]

THREATS:

1. SPOOFING (fake identity)
   - Attacker impersonates user via stolen credentials
   - Mitigation: MFA, strong passwords, account lockout

2. TAMPERING (modify data)
   - Attacker modifies data in transit or at rest
   - Mitigation: HTTPS encryption, database encryption, signing

3. INFORMATION DISCLOSURE (leak data)
   - Attacker reads sensitive data from network/storage
   - Mitigation: Encryption in transit (TLS), at rest (AES)

4. DENIAL OF SERVICE (disable service)
   - Attacker floods server with requests
   - Mitigation: Rate limiting, DDoS protection, auto-scaling

5. ELEVATION OF PRIVILEGE (gain admin)
   - Attacker escalates from user to admin
   - Mitigation: Least privilege, input validation, no SUID

For each threat:
- What's the attack path?
- What's the current mitigation?
- What's the residual risk?
- What controls should we add?
EOF

cat threat_model.txt
```

### 6.2: Defense in Depth Architecture

**Concept:** Multiple layers - if one fails, others catch it.

```bash
# Lab: Design a secure architecture

cat > defense_in_depth.txt << 'EOF'
DEFENSE IN DEPTH ARCHITECTURE:

LAYER 1: PERIMETER (Stop attacks at boundary)
  - DDoS mitigation (CloudFlare, AWS Shield)
  - WAF (Web Application Firewall)
  - Rate limiting
  
LAYER 2: NETWORK (Segment traffic)
  - Network segmentation (VPCs, subnets)
  - Network ACLs
  - Security groups
  - VPN for remote access
  
LAYER 3: HOST (Secure individual systems)
  - OS hardening (remove unnecessary services)
  - Host-based firewall (iptables)
  - Host IDS (monitoring)
  - Patch management
  
LAYER 4: APPLICATION (Secure code)
  - Input validation (prevent injection)
  - Authentication (who are you?)
  - Authorization (what can you do?)
  - Logging/auditing (what did you do?)
  
LAYER 5: DATA (Protect what matters)
  - Encryption at rest (AES-256)
  - Encryption in transit (TLS 1.2+)
  - Access controls (who can read?)
  - Data minimization (only store what's needed)
  
LAYER 6: DETECTION & RESPONSE (Catch breaches)
  - Security monitoring (SIEM)
  - Intrusion detection (IDS)
  - Incident response (playbooks)
  - Forensic capability (preserve evidence)

EXAMPLE: Web Application Compromise Scenario

Attack Path: Internet -> DDoS -> WAF -> Network -> Host -> App Code -> Database

Defense:
1. DDoS mitigation blocks traffic surge
2. WAF blocks malicious HTTP requests
3. Network ACLs block suspicious IPs
4. Host IDS detects suspicious processes
5. App input validation prevents SQL injection
6. Database encryption protects data at rest
7. Monitoring alerts on anomalies
8. IR playbook activates response team
EOF

cat defense_in_depth.txt
```

### 6.3: Monitoring & Alerting Strategy

**Concept:** Detect threats early - most value in first 24 hours.

```bash
# Lab: Build monitoring strategy

cat > monitoring_strategy.sh << 'EOF'
#!/bin/bash

echo "=== SECURITY MONITORING STRATEGY ==="
echo ""

# KEY METRICS TO MONITOR:

echo "1. AUTHENTICATION EVENTS:"
echo "   - Failed login attempts (threshold: >5 in 10 min)"
sudo grep "Failed password" /var/log/auth.log | wc -l

echo ""
echo "2. PRIVILEGE ESCALATION:"
echo "   - Sudo usage (should be rare)"
sudo grep "sudo" /var/log/auth.log | tail -5

echo ""
echo "3. FILE INTEGRITY:"
echo "   - Changes to critical files"
sudo auditctl -l | grep -E "/etc|/root"

echo ""
echo "4. NETWORK CONNECTIONS:"
echo "   - Unusual outbound connections"
sudo netstat -tulpn | grep ESTABLISHED | awk '{print $5}'

echo ""
echo "5. PROCESS EXECUTION:"
echo "   - Suspicious processes (calc.exe, powershell on Linux?)"
ps aux | grep -E "bash|python|perl"

echo ""
echo "6. SERVICE STATE:"
echo "   - Unexpected services running"
sudo systemctl list-units --type=service --state=running | wc -l

echo ""
echo "ALERT LOGIC:"
echo "IF (failed_logins > 5) THEN alert('Brute Force Attempt')"
echo "IF (unauthorized_sudo) THEN alert('Privilege Escalation')"
echo "IF (file_changed AND critical) THEN alert('Tampering')"
echo "IF (outbound_to_rare_ip) THEN alert('Data Exfiltration')"
EOF

chmod +x monitoring_strategy.sh
```

### 6.4: Security Roadmap for Your Organization

**Concept:** Phased approach to build mature security program.

```bash
# Lab: Build a security roadmap

cat > security_roadmap.txt << 'EOF'
ORGANIZATION SECURITY ROADMAP

PHASE 1: FOUNDATION (Months 1-3)
Goal: Stop obvious attacks
Actions:
  ✓ Inventory all systems/apps
  ✓ Enable MFA on all accounts
  ✓ Patch critical vulnerabilities
  ✓ Enable basic monitoring (syslog centralization)
  ✓ Create incident response playbook
  ✓ User security training
Cost: Low | Team: 1-2 people

PHASE 2: HARDENING (Months 4-6)
Goal: Reduce attack surface
Actions:
  ✓ Disable unnecessary services
  ✓ Implement WAF
  ✓ Deploy IDS/IPS
  ✓ Network segmentation
  ✓ Encryption (data at rest + transit)
  ✓ Regular backups (immutable)
Cost: Medium | Team: 2-4 people

PHASE 3: DETECTION (Months 7-9)
Goal: Detect breaches faster
Actions:
  ✓ Deploy SIEM (ELK/Splunk)
  ✓ Create detection rules
  ✓ Security metrics dashboard
  ✓ Threat intelligence integration
  ✓ Threat hunting exercises
Cost: Medium-High | Team: 3-5 people (SOC)

PHASE 4: RESPONSE (Months 10-12)
Goal: Respond faster
Actions:
  ✓ Automated response playbooks
  ✓ Forensic capability
  ✓ Red team exercises
  ✓ Breach simulation drills
  ✓ Security operations center (SOC) 24/7
Cost: High | Team: 5+ people

PHASE 5: MATURE (Year 2+)
Goal: Architect for security
Actions:
  ✓ Security by design (shift-left)
  ✓ DevSecOps integration
  ✓ Predictive threat modeling
  ✓ Bug bounty program
  ✓ Security compliance (ISO, SOC2)
Cost: Very High | Team: 10+ people

SUCCESS METRICS:
- MTTD (Mean Time to Detect): <1 hour
- MTTR (Mean Time to Respond): <4 hours
- Vulnerability remediation: <30 days
- Patch compliance: >95%
- Security incident rate: Trending down
EOF

cat security_roadmap.txt
```

---

## Practical Integration Labs

### Lab 1: Build a Complete Detection Pipeline

```bash
# Create end-to-end security pipeline
mkdir ~/security-labs/integration

cat > ~/security-labs/integration/full_pipeline.sh << 'EOF'
#!/bin/bash

echo "=== COMPLETE SECURITY DETECTION PIPELINE ==="
echo ""

# 1. COLLECT (Gather events from all sources)
echo "STEP 1: Event Collection"
journalctl -n 1000 > /tmp/events.log
sudo tcpdump -i eth0 -w /tmp/network.pcap -c 1000 &
sleep 2

# 2. PARSE (Extract relevant info)
echo "STEP 2: Parse Events"
cat /tmp/events.log | grep -E "auth|sudo|ssh|fail" > /tmp/parsed.log

# 3. ENRICH (Add context)
echo "STEP 3: Enrich Data"
# Add threat intel, geolocation, etc.

# 4. DETECT (Find anomalies)
echo "STEP 4: Threat Detection"
echo "Failed logins: $(grep 'Failed password' /tmp/parsed.log | wc -l)"
echo "Sudo attempts: $(grep 'sudo' /tmp/parsed.log | wc -l)"
echo "SSH connections: $(grep 'sshd' /tmp/parsed.log | wc -l)"

# 5. ALERT (Notify humans)
echo "STEP 5: Generate Alerts"
if [ $(grep 'Failed password' /tmp/parsed.log | wc -l) -gt 5 ]; then
  echo "⚠️  ALERT: Brute force attack detected!"
fi

# 6. RESPOND (Take action)
echo "STEP 6: Response"
echo "Recommended actions:"
echo "  1. Review failed login attempts"
echo "  2. Check for compromised accounts"
echo "  3. Enable rate limiting"
echo "  4. Notify security team"

echo ""
echo "=== PIPELINE COMPLETE ==="
EOF

chmod +x ~/security-labs/integration/full_pipeline.sh
```

### Lab 2: Simulate a Security Incident

```bash
# Create realistic incident scenario
cat > ~/security-labs/integration/incident_sim.sh << 'EOF'
#!/bin/bash

echo "=== SECURITY INCIDENT SIMULATION ==="
echo "Scenario: Unauthorized SSH access from attacker"
echo ""

# Step 1: Attack happens (simulate)
echo "[ATTACKER] Attempting brute force..."
for i in {1..10}; do
  echo "Failed password for invalid user attacker from 192.168.1.100 port $RANDOM" >> /tmp/attack.log
done

# Step 2: Detection (our monitoring)
echo "[DETECTION] Running security checks..."
echo "Failed attempts: $(grep 'Failed password' /tmp/attack.log | wc -l)"

# Step 3: Incident Response Activation
echo "[INCIDENT RESPONSE] Incident detected!"
INCIDENT_ID="INC-$(date +%s)"
INCIDENT_DIR="/tmp/$INCIDENT_ID"
mkdir -p $INCIDENT_DIR

# Step 4: Collect Evidence
echo "[FORENSICS] Collecting evidence..."
cp /tmp/attack.log $INCIDENT_DIR/
ps auxf > $INCIDENT_DIR/processes.txt
sudo netstat -tulpn > $INCIDENT_DIR/connections.txt

# Step 5: Analyze
echo "[ANALYSIS] Analyzing attack..."
ATTACKER_IP=$(grep 'from' /tmp/attack.log | head -1 | awk '{print $NF}')
echo "Attacker IP: $ATTACKER_IP"
echo "Attack type: Brute force SSH"
echo "Severity: HIGH"

# Step 6: Containment
echo "[CONTAINMENT] Blocking attacker..."
# sudo iptables -I INPUT -s $ATTACKER_IP -j DROP
echo "Would block: $ATTACKER_IP"

# Step 7: Documentation
echo "[DOCUMENTATION] Creating incident report..."
cat > $INCIDENT_DIR/incident_report.txt << 'REPORT'
INCIDENT REPORT
ID: INC-$(date)
Severity: HIGH
Status: INVESTIGATING

Timeline:
- T+0: Attacker began SSH brute force
- T+2min: Automated detection triggered
- T+5min: IR team activated
- T+10min: Attacker IP blocked
- T+30min: Systems analyzed

Actions Taken:
✓ Blocked source IP
✓ Reviewed authentication logs
✓ Checked for unauthorized access
✓ Reset affected account passwords
✓ Increased monitoring sensitivity

Next Steps:
- Determine if any access was successful
- Check for lateral movement
- Update firewall rules permanently
- Security awareness training
REPORT

echo "[SUMMARY] Incident response complete"
echo "Evidence saved to: $INCIDENT_DIR"
EOF

chmod +x ~/security-labs/integration/incident_sim.sh
```

---

## 📚 Learning Resources

### Tools to Install & Practice

```bash
# Essential security tools
sudo apt-get install -y \
  nmap \
  tcpdump \
  wireshark \
  nikto \
  hydra \
  john \
  hashcat \
  git \
  curl \
  wget \
  awscli \
  terraform

# For advanced labs
sudo apt-get install -y \
  metasploit-framework \
  suricata \
  zeek \
  osquery \
  elasticsearch \
  kibana
```

### Online Certifications to Target

1. **CompTIA Security+** - Foundation
2. **CEH (Certified Ethical Hacker)** - Practical hacking
3. **OSCP (Offensive Security)** - Advanced exploitation
4. **CISSP (Certified Information Systems Security Professional)** - Architect level
5. **AWS Security Fundamentals** - Cloud specific
6. **Azure Security Engineer** - Cloud specific

### Free Practice Platforms

- **HackTheBox** (hackthebox.eu) - CTF challenges
- **TryHackMe** (tryhackme.com) - Guided labs
- **OWASP WebGoat** - Web security
- **PentesterLab** (free tier) - Web pentesting
- **OverTheWire** - Wargames and CTFs

### Books to Read

1. "The Security Engineer's Handbook" - All phases
2. "Blue Team Field Manual" - Defense
3. "Red Team Field Manual" - Offense
4. "The Art of Network Penetration Testing"
5. "Cloud Security" - AWS/Azure specific

---

## 🎯 Next Immediate Steps

Pick ONE area and spend 1 week:

**Week 1:** Linux Security Fundamentals
```bash
cd ~/security-labs/phase1
bash ./permission_audit.sh
bash ./audit_monitor.sh
bash ./process_baseline.sh
```

**Week 2-3:** Networking & Packets
```bash
cd ~/security-labs/phase2
bash ./traffic_analysis.sh
bash ./dns_audit.sh
node https_server.js &
```

**Week 4-7:** Blue Team SOC Skills
```bash
cd ~/security-labs/phase3
bash ./soc_monitor.sh
bash ./mitre_detector.sh
bash ./ir_playbook.sh
```

Then progress through remaining phases.

---

## ✅ Success Criteria

After completing this roadmap, you should be able to:

✓ Audit system security autonomously  
✓ Detect intrusions in network traffic  
✓ Respond to security incidents  
✓ Design defense-in-depth architecture  
✓ Understand attacker perspective  
✓ Deploy cloud security controls  
✓ Build security monitoring dashboards  
✓ Mentor junior security engineers  

---

**Status:** Roadmap Created ✅  
**Ready for Phase 1:** YES  
**Estimated Total Time:** 12-16 weeks (self-paced)  
**Your Starting Point:** Linux basics + Node.js knowledge  

Choose a phase and start building. The goal isn't to memorize commands—it's to understand **why** each control matters.

Good luck! 🔐
