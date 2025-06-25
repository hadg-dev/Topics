# 🪟 Windows Commands Cheat Sheet

> A practical and structured guide to common Windows commands using Command Prompt (CMD) and PowerShell.

---

## ℹ️ Getting Help

```cmd
help                            # List all available CMD commands
command /?                     # Get help for a specific command
```

```powershell
Get-Help command               # PowerShell help for a command
```

---

## 📁 File and Directory Navigation

### 🔵 CMD
```cmd
cd                             # Show current directory
cd folder\path                 # Change directory
cd ..                          # Move up one directory
cls                            # Clear the screen
dir                            # List contents of current directory
```

### 🟢 PowerShell
```powershell
Get-Location                   # Show current location
Set-Location folder\path       # Navigate to folder
Clear-Host                     # Clear terminal
Get-ChildItem                  # List contents of folder
```

---

## 📂 File Management

> PowerShell offers object-based handling, whereas CMD is text-based.

### 🔵 CMD
```cmd
type file.txt                        # Display contents of a text file
copy file1.txt file2.txt             # Copy file1.txt to file2.txt
move file1.txt folder\              # Move file1.txt to folder\
ren file.txt newname.txt            # Rename file.txt to newname.txt
del file.txt                         # Delete file.txt
mkdir new_folder                     # Create a new folder named 'new_folder'
rmdir folder                         # Remove an empty directory named 'folder'
```

### 🟢 PowerShell
```powershell
Get-Content file.txt                 # Read file content
Copy-Item file1.txt file2.txt        # Copy file
Move-Item file.txt folder\         # Move file
Rename-Item file.txt newname.txt    # Rename file
Remove-Item file.txt                # Delete file
New-Item -ItemType Directory -Name folder  # Create folder
```

---

## 🔐 User and System Info

> CMD shows basics, PowerShell provides structured output.

### 🔵 CMD
```cmd
whoami                               # Display current user
hostname                             # Show the system's hostname
systeminfo                           # Detailed system info (OS, CPU, memory)
```

### 🟢 PowerShell
```powershell
Get-ComputerInfo                     # Full system details (CPU, RAM, BIOS)
Get-WmiObject Win32_UserAccount      # List all local user accounts
```

---

## 🧮 Process & Task Management

### 🔵 CMD
```cmd
tasklist                             # List running processes
taskkill /PID 1234 /F                # Kill process by PID
```

### 🟢 PowerShell
```powershell
Get-Process                          # List running processes
Stop-Process -Id 1234                # Kill process by PID
```

---

## 🌐 Network Tools

### 🔵 CMD
```cmd
ipconfig                             # Network configuration
ping google.com                      # Ping a host
tracert google.com                   # Trace route
netstat -an                          # Show ports and connections
```

### 🟢 PowerShell
```powershell
Test-Connection google.com           # Ping
Get-NetIPConfiguration               # IP config
Get-NetTCPConnection                 # List TCP connections
```

---

## 🔎 File Search

### 🔵 CMD
```cmd
find "text" file.txt                 # Search for text in file
```

### 🟢 PowerShell
```powershell
Select-String -Path file.txt -Pattern "text"  # Grep-like search
```

---

## 📅 Task Scheduling

### 🔵 CMD
```cmd
schtasks /Create /SC DAILY /TN "Backup" /TR "backup.bat" /ST 14:00
schtasks /Run /TN "Backup"
schtasks /Delete /TN "Backup" /F
```

---

## 📦 Installing Packages

### 🟢 PowerShell
```powershell
winget install notepad++            # Install with Winget
choco install git -y                # Install Git via Chocolatey
```

---

## 📑 Environment Variables

### 🔵 CMD
```cmd
set VAR=value                       # Set environment variable
echo %VAR%                          # Display variable
```

### 🟢 PowerShell
```powershell
$env:VAR = "value"                  # Set environment variable
echo $env:VAR                       # Display variable
```

---

## 👤 User Management

### 🔵 CMD
```cmd
net user                             # List users
net user username *                  # Set/change password
net localgroup                       # List groups
net localgroup Administrators username /add  # Add user to admin group
```

### 🟢 PowerShell
```powershell
New-LocalUser "testuser" -Password (ConvertTo-SecureString "P@ssword" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "testuser"
```

---

> ✅ **CMD** is ideal for compatibility and quick tasks.
> ✅ **PowerShell** excels in scripting, automation, and object-oriented management.

