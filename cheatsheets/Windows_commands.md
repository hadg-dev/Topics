<a id="table-of-contents"></a>
# 📚 Table of Contents

- [1 🪟 Windows Commands Cheat Sheet](#windows-commands-cheat-sheet)
  - [1.1 ℹ️ Getting Help](#ℹ-getting-help)
  - [1.2 📁 File and Directory Navigation](#file-and-directory-navigation)
    - [1.2.1 🔵 CMD](#cmd)
    - [1.2.2 🟢 PowerShell](#powershell)
  - [1.3 📂 File Management](#file-management)
    - [1.3.1 🔵 CMD](#cmd)
    - [1.3.2 🟢 PowerShell](#powershell)
  - [1.4 🔐 User and System Info](#user-and-system-info)
    - [1.4.1 🔵 CMD](#cmd)
    - [1.4.2 🟢 PowerShell](#powershell)
  - [1.5 🧮 Process & Task Management](#process--task-management)
    - [1.5.1 🔵 CMD](#cmd)
    - [1.5.2 🟢 PowerShell](#powershell)
  - [1.6 🌐 Network Tools](#network-tools)
    - [1.6.1 🔵 CMD](#cmd)
    - [1.6.2 🟢 PowerShell](#powershell)
  - [1.7 🔎 File Search](#file-search)
    - [1.7.1 🔵 CMD](#cmd)
    - [1.7.2 🟢 PowerShell](#powershell)
  - [1.8 📅 Task Scheduling](#task-scheduling)
    - [1.8.1 🔵 CMD](#cmd)
  - [1.9 📦 Installing Packages](#installing-packages)
    - [1.9.1 🟢 PowerShell](#powershell)
  - [1.10 📑 Environment Variables](#environment-variables)
    - [1.10.1 🔵 CMD](#cmd)
    - [1.10.2 🟢 PowerShell](#powershell)
  - [1.11 👤 User Management](#user-management)
    - [1.11.1 🔵 CMD](#cmd)
    - [1.11.2 🟢 PowerShell](#powershell)

<a id="windows-commands-cheat-sheet"></a>
# 1 🪟 Windows Commands Cheat Sheet [🔝](#table-of-contents)

> A practical and structured guide to common Windows commands using Command Prompt (CMD) and PowerShell.

---

<a id="ℹ-getting-help"></a>
## 1.1 ℹ️ Getting Help [🔝](#table-of-contents)

```cmd
help                            # List all available CMD commands
command /?                     # Get help for a specific command
```

```powershell
Get-Help command               # PowerShell help for a command
```

---

<a id="file-and-directory-navigation"></a>
## 1.2 📁 File and Directory Navigation [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.2.1 🔵 CMD [🔝](#table-of-contents)
```cmd
cd                             # Show current directory
cd folder\path                 # Change directory
cd ..                          # Move up one directory
cls                            # Clear the screen
dir                            # List contents of current directory
```

<a id="powershell"></a>
### 1.2.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
Get-Location                   # Show current location
Set-Location folder\path       # Navigate to folder
Clear-Host                     # Clear terminal
Get-ChildItem                  # List contents of folder
```

---

<a id="file-management"></a>
## 1.3 📂 File Management [🔝](#table-of-contents)

> PowerShell offers object-based handling, whereas CMD is text-based.

<a id="cmd"></a>
### 1.3.1 🔵 CMD [🔝](#table-of-contents)
```cmd
type file.txt                        # Display contents of a text file
copy file1.txt file2.txt             # Copy file1.txt to file2.txt
move file1.txt folder\              # Move file1.txt to folder\
ren file.txt newname.txt            # Rename file.txt to newname.txt
del file.txt                         # Delete file.txt
mkdir new_folder                     # Create a new folder named 'new_folder'
rmdir folder                         # Remove an empty directory named 'folder'
```

<a id="powershell"></a>
### 1.3.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
Get-Content file.txt                 # Read file content
Copy-Item file1.txt file2.txt        # Copy file
Move-Item file.txt folder\         # Move file
Rename-Item file.txt newname.txt    # Rename file
Remove-Item file.txt                # Delete file
New-Item -ItemType Directory -Name folder  # Create folder
```

---

<a id="user-and-system-info"></a>
## 1.4 🔐 User and System Info [🔝](#table-of-contents)

> CMD shows basics, PowerShell provides structured output.

<a id="cmd"></a>
### 1.4.1 🔵 CMD [🔝](#table-of-contents)
```cmd
whoami                               # Display current user
hostname                             # Show the system's hostname
systeminfo                           # Detailed system info (OS, CPU, memory)
```

<a id="powershell"></a>
### 1.4.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
Get-ComputerInfo                     # Full system details (CPU, RAM, BIOS)
Get-WmiObject Win32_UserAccount      # List all local user accounts
```

---

<a id="process--task-management"></a>
## 1.5 🧮 Process & Task Management [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.5.1 🔵 CMD [🔝](#table-of-contents)
```cmd
tasklist                             # List running processes
taskkill /PID 1234 /F                # Kill process by PID
```

<a id="powershell"></a>
### 1.5.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
Get-Process                          # List running processes
Stop-Process -Id 1234                # Kill process by PID
```

---

<a id="network-tools"></a>
## 1.6 🌐 Network Tools [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.6.1 🔵 CMD [🔝](#table-of-contents)
```cmd
ipconfig                             # Network configuration
ping google.com                      # Ping a host
tracert google.com                   # Trace route
netstat -an                          # Show ports and connections
```

<a id="powershell"></a>
### 1.6.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
Test-Connection google.com           # Ping
Get-NetIPConfiguration               # IP config
Get-NetTCPConnection                 # List TCP connections
```

---

<a id="file-search"></a>
## 1.7 🔎 File Search [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.7.1 🔵 CMD [🔝](#table-of-contents)
```cmd
find "text" file.txt                 # Search for text in file
```

<a id="powershell"></a>
### 1.7.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
Select-String -Path file.txt -Pattern "text"  # Grep-like search
```

---

<a id="task-scheduling"></a>
## 1.8 📅 Task Scheduling [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.8.1 🔵 CMD [🔝](#table-of-contents)
```cmd
schtasks /Create /SC DAILY /TN "Backup" /TR "backup.bat" /ST 14:00
schtasks /Run /TN "Backup"
schtasks /Delete /TN "Backup" /F
```

---

<a id="installing-packages"></a>
## 1.9 📦 Installing Packages [🔝](#table-of-contents)

<a id="powershell"></a>
### 1.9.1 🟢 PowerShell [🔝](#table-of-contents)
```powershell
winget install notepad++            # Install with Winget
choco install git -y                # Install Git via Chocolatey
```

---

<a id="environment-variables"></a>
## 1.10 📑 Environment Variables [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.10.1 🔵 CMD [🔝](#table-of-contents)
```cmd
set VAR=value                       # Set environment variable
echo %VAR%                          # Display variable
```

<a id="powershell"></a>
### 1.10.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
$env:VAR = "value"                  # Set environment variable
echo $env:VAR                       # Display variable
```

---

<a id="user-management"></a>
## 1.11 👤 User Management [🔝](#table-of-contents)

<a id="cmd"></a>
### 1.11.1 🔵 CMD [🔝](#table-of-contents)
```cmd
net user                             # List users
net user username *                  # Set/change password
net localgroup                       # List groups
net localgroup Administrators username /add  # Add user to admin group
```

<a id="powershell"></a>
### 1.11.2 🟢 PowerShell [🔝](#table-of-contents)
```powershell
New-LocalUser "testuser" -Password (ConvertTo-SecureString "P@ssword" -AsPlainText -Force)
Add-LocalGroupMember -Group "Administrators" -Member "testuser"
```

---

> ✅ **CMD** is ideal for compatibility and quick tasks.
> ✅ **PowerShell** excels in scripting, automation, and object-oriented management.
