# 🐧 DevOps Bash Automation Scripts

This Jupyter Notebook contains a curated collection of **Bash scripts** for automating essential DevOps tasks.  
Each cell includes commented Bash code that you can adapt and reuse.

> Generated on 2025-07-28 12:10:56


## Monitoring Kernel Resources


```bash
#!/bin/bash

set -euo pipefail

LOG_DIR="/var/log"
LOG_FILE="$LOG_DIR/system_health_$(date '+%Y-%m-%d_%H-%M-%S').log"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Redirect all output to log file
exec > >(sudo tee -a "$LOG_FILE") 2>&1

echo "=============================="
echo "📊 SYSTEM HEALTH REPORT"
echo "🕒 Generated on: $(date)"
echo "=============================="
echo

# Uptime and Load
echo "🖥️ Uptime and Load Average:"
uptime
echo

# CPU Usage
echo "💻 CPU Usage:"
top -bn1 | grep "Cpu(s)" | awk '{print "User: " $2 ", System: " $4 ", Idle: " $8}'
echo

# Memory Usage
echo "🧠 Memory Usage (MB):"
free -m
echo

# Disk Usage
echo "💾 Disk Usage:"
df -h --exclude-type=tmpfs --exclude-type=devtmpfs
echo

# Network Interfaces and RX/TX stats
echo "🌐 Network Interfaces (RX/TX):"
ip -s link | awk '
  /^[0-9]+: / {gsub(":", "", $2); iface=$2}
  /RX:/ {getline; rx=$1}
  /TX:/ {getline; tx=$1; print iface ": RX=" rx " TX=" tx}
'
echo

# Open listening ports and applications
echo "🔌 Listening Ports and Applications:"
ss -tulnp | awk '
  BEGIN { print "Proto\tLocal Address\t\tPID/Program Name" }
  NR>1 { printf "%s\t%-22s\t%s\n", $1, $5, $NF }
'
echo

# Established external connections
echo "🌍 Active Outbound TCP Connections:"
ss -tanp | awk '
  $1 == "ESTAB" {
    split($5, dest, ":");
    print "🔸 Dest: " dest[1] ":" dest[2] " | PID/Program: " $NF
  }
'
echo

# Top Processes by CPU and Memory
echo "🔥 Top 5 Processes by CPU:"
ps -eo pid,ppid,cmd,%cpu --sort=-%cpu | head -n 6
echo

echo "🔥 Top 5 Processes by Memory:"
ps -eo pid,ppid,cmd,%mem --sort=-%mem | head -n 6
echo

echo "✅ Report saved to: $LOG_FILE"

```

## Automated Backup SCript (file)

```bash
#!/bin/bash
SRC="/var/www/html"
DEST="/backup/"
DATE=$(date +%F)
tar -czf "$DEST/backup-$DATE.tar.gz" "$SRC"
echo "Backup completed!"
``` 

## Automated Backup SCript (DB)
Replace mysqldump by pgdump for postgres.

```bash
#!/bin/bash
DB_NAME="mydatabase"
DB_USER="root"
DEST="/backup/db/"
mysqldump -u "$DB_USER" -p "$DB_NAME" > "$DEST/db_backup_$(date +%F).sql"
echo "Database backup completed!"
``` 

## Automated Postgres Database Backup

Ensure the following tools are installed:

- pg_dump, mysqldump, gzip, date, find


```bash
sudo apt install postgresql-client mysql-client gzip
```


```bash
#!/bin/bash
set -euo pipefail

############################################
# CONFIGURATION
############################################

BACKUP_DIR="/var/backups/postgres"
DATE=$(date +"%Y-%m-%d_%H-%M-%S")
RETENTION_DAYS=7

PG_USER="postgres"
PG_HOST="localhost"     # Change if remote
PG_PORT="5432"

############################################
# PREP
############################################

mkdir -p "$BACKUP_DIR"

echo "📦 Starting PostgreSQL backup at $DATE"
echo "📁 Backup directory: $BACKUP_DIR"
echo

############################################
# GET DATABASE LIST (exclude templates)
############################################

DB_LIST=$(sudo -u "$PG_USER" psql -h "$PG_HOST" -p "$PG_PORT" -At -c "SELECT datname FROM pg_database WHERE datistemplate = false;")

if [[ -z "$DB_LIST" ]]; then
  echo "⚠️ No PostgreSQL databases found or access denied."
  exit 1
fi

############################################
# BACKUP EACH DATABASE
############################################

for db in $DB_LIST; do
  BACKUP_FILE="$BACKUP_DIR/postgres_${db}_$DATE.sql.gz"
  echo "🔄 Backing up database '$db' → $BACKUP_FILE"
  sudo -u "$PG_USER" pg_dump -h "$PG_HOST" -p "$PG_PORT" "$db" | gzip > "$BACKUP_FILE"
done

############################################
# CLEANUP OLD BACKUPS
############################################

echo
echo "🧹 Removing backups older than $RETENTION_DAYS days..."
find "$BACKUP_DIR" -type f -name "*.sql.gz" -mtime +"$RETENTION_DAYS" -exec rm -v {} \;

echo
echo "✅ Backup complete at $(date)"

```

## Encrypt a DB backup or a File and upload it to S3


```bash
#!/bin/bash
set -euo pipefail

# Environment variables expected:
# FILE_TO_ENCRYPT  - file path to encrypt
# GPG_PASSPHRASE  - passphrase for symmetric encryption
# S3_BUCKET       - s3 bucket URL, e.g. s3://mybucket/backups

if [[ -z "${FILE_TO_ENCRYPT:-}" || -z "${GPG_PASSPHRASE:-}" || -z "${S3_BUCKET:-}" ]]; then
  echo "❌ Set FILE_TO_ENCRYPT, GPG_PASSPHRASE, and S3_BUCKET env variables."
  exit 1
fi

if [[ ! -f "$FILE_TO_ENCRYPT" ]]; then
  echo "❌ File '$FILE_TO_ENCRYPT' does not exist."
  exit 2
fi

ENC_FILE="${FILE_TO_ENCRYPT}.gpg"

echo "🔐 Encrypting '$FILE_TO_ENCRYPT' symmetrically with passphrase → '$ENC_FILE' ..."
gpg --batch --yes --passphrase "$GPG_PASSPHRASE" --symmetric --cipher-algo AES256 "$FILE_TO_ENCRYPT"

echo "☁️ Uploading encrypted file to S3 bucket: $S3_BUCKET ..."
aws s3 cp "$ENC_FILE" "$S3_BUCKET/"

echo "🧹 Cleaning up local encrypted file..."
rm -f "$ENC_FILE"

echo "✅ Done."


```


```bash
#!/bin/bash
set -euo pipefail

# Environment variables expected:
# FILE_TO_ENCRYPT  - file path to encrypt
# GPG_RECIPIENT   - public key ID or email of recipient
# S3_BUCKET       - s3 bucket URL, e.g. s3://mybucket/backups

if [[ -z "${FILE_TO_ENCRYPT:-}" || -z "${GPG_RECIPIENT:-}" || -z "${S3_BUCKET:-}" ]]; then
  echo "❌ Set FILE_TO_ENCRYPT, GPG_RECIPIENT, and S3_BUCKET env variables."
  exit 1
fi

if [[ ! -f "$FILE_TO_ENCRYPT" ]]; then
  echo "❌ File '$FILE_TO_ENCRYPT' does not exist."
  exit 2
fi

ENC_FILE="${FILE_TO_ENCRYPT}.gpg"

echo "🔐 Encrypting '$FILE_TO_ENCRYPT' for recipient '$GPG_RECIPIENT' → '$ENC_FILE' ..."
gpg --yes --output "$ENC_FILE" --encrypt --recipient "$GPG_RECIPIENT" "$FILE_TO_ENCRYPT"

echo "☁️ Uploading encrypted file to S3 bucket: $S3_BUCKET ..."
aws s3 cp "$ENC_FILE" "$S3_BUCKET/"

echo "🧹 Cleaning up local encrypted file..."
rm -f "$ENC_FILE"

echo "✅ Done."

```


```bash
export FILE_TO_ENCRYPT="/path/to/backup.sql.gz"
export S3_BUCKET="s3://mybucket/backups"

# For symmetric (your own backup):
export GPG_PASSPHRASE="your-strong-passphrase"
./encrypt_symmetric_and_upload.sh

# For asymmetric (sharing):
export GPG_RECIPIENT="recipient@example.com"
./encrypt_asymmetric_and_upload.sh


```

## User Management Script
```bash
#!/bin/bash
read -p "Enter username: " user
password=$(openssl rand -base64 12)
useradd -m -s /bin/bash "$user"
echo "$user:$password" | chpasswd
echo "User $user created with password: $password"
```

## Automated Log Rotation
```bash
#!/bin/bash
LOG_DIR="/var/log/myapp/"
find "$LOG_DIR" -type f -mtime +7 -exec rm {} \;
echo "Old logs deleted."
```



## Set Up Basic Firewall Rules with UFW


```bash
#!/bin/bash
# === 10. Configure UFW firewall ===
sudo ufw default deny incoming
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
echo "Firewall rules applied on $(date)" >> /var/log/ufw_setup.log

```

## Whitelist an IP for your firewall

```bash
#!/bin/bash
read -p "Enter IP to whitelist: " IP
iptables -A INPUT -s "$IP" -j ACCEPT
echo "IP $IP whitelisted."
```



## Send email alert for specific event that occurs
```bash
#!/bin/bash
THRESHOLD=90
USAGE=$(df -h / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USAGE" -ge "$THRESHOLD" ]; then
    echo "Disk space is critically low: $USAGE%" | mail -s "Disk Space Alert" admin@example.com
fi
```


## Ping a server continuously to check connectivity
```bash
#!/bin/bash
ping -c 5 google.com
```
`
## Automatically Restart a Server if it's not running

```bash
#!/bin/bash
service="nginx"
if ! pgrep -x "$service" > /dev/null; then
    systemctl restart $service
    echo "$service restarted"
fi
```

## Operations on  Files
```bash
#!/bin/bash

# compress large log files
gzip /var/log/*.log

# delete large files over 1GB
find / -type f -size +1G -exec rm -i {} \;

# merge PDF files
pdfunite input1.pdf input2.pdf merged.pdf

# More robust, capable of compression and fine-tuning, page selection, encryption
pdftk file1.pdf file2.pdf cat output combined.pdf

```

Nice tool to know in Python

```python
from PyPDF2 import PdfMerger
merger = PdfMerger()
for pdf in ["file1.pdf", "file2.pdf"]:
    merger.append(pdf)
merger.write("merged.pdf")
merger.close()
```