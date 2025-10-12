## Config of the /etc/network/interfaces

```conf
auto lo
iface lo inet loopback
iface enp1s0 auto
iface enp1s0 inet manual

auto vmbr0
iface vmbr0 inet dhcp
        bridge-ports enp1s0
        bridge-stp off
        bridge-fd 0

iface wlp2s0 inet manual

source /etc/network/interfaces.d/*
```

After changing the config according to this, do
```bash
systemctl restart networking.service
ip addr show
ip route show default
ip link show

```


### What is a bridge ?

A **network bridge** is a software-based “virtual switch” that sits between physical and virtual network interfaces, allowing them to act as if they’re on the same Layer-2 network segment. In Linux (and Proxmox), a bridge:

- **Aggregates ports**  
  You add one or more physical NICs (e.g. `enp1s0`) and/or virtual NICs (VMs or containers) to the bridge (e.g. `vmbr0`).

- **Forwards Ethernet frames**  
  It inspects incoming frames’ MAC addresses and forwards them only to the port where the destination MAC lives — or floods them if unknown.

- **Publishes a single IP**  
  The host assigns its own management IP to the bridge device (`vmbr0`), not to the individual physical NICs.

- **Enables VMs/CTs to appear on your LAN**  
  Guests plugged into the bridge get IPs from the same DHCP server or static pool as the host and other physical devices.

#### Why Use a Bridge?
- Lets virtual machines share your LAN without NAT.  
- Simplifies network topology: everything lives on one broadcast domain.  
- Mirrors the behavior of a physical Ethernet switch in software.




## Local Network

Physical interfaces of my home box:

- **Ethernet (enp1s0)** → plugged into your home switch/router via a cable. 

- **Wi-Fi (wlp2s0)** → connects over the air to the same router’s wireless SSID.

- **Bridge (vmbr0)**
Proxmox bridges its VMs/containers onto whichever physical NIC you choose (usually the wired one). That bridge gets an IP just like any other host on your LAN.

**What is a NIC ?** A **network interface card** (NIC) is a hardware component, typically a circuit board or chip, installed on a computer so it can connect to a network (in French, "une carte réseau").

The term network interface card is interchangeable with the terms network interface controller, network adapter and local area network (LAN) adapter.

Regardless of the term used, the NIC's main purpose is to allow a computer to connect to a network. A NIC provides a computer with a dedicated point of connectivity to a network. This network may be a LAN, wide area network (WAN) or even the public internet.

**What is a router ?**

It’s the device (often combined with a modem) that sits at the edge of your LAN and forwards traffic:

- Within your LAN (e.g. between your Proxmox host, laptop, phone, smart TV)
- Between your LAN and the Internet

Its IP on your LAN is called the **default gateway**. In your case, the router's LAN address is given by:

```bash
ip route show default
# Output: default via 192.168.1.254 dev vmbr0
```

My **Local Area Network (LAN)**




DHCP: Dynamic Host Configuration Protocol
**What it does:** the router (or a dedicated DHCP server) hands out IPs automatically.  

**How it works:**

Discover → client (your box) broadcasts “Any DHCP server out there?”

Offer → server replies “Here’s 192.168.1.50 for you, lease for 24 h.”

Request → client asks “Great, please give me that one.”

ACK → server confirms “Done—use it and check back later to renew.”


**Static IP Addresses:**

A static IP is one you assign yourself (in /etc/network/interfaces or your VM’s network config) instead of using DHCP.

Best practice: pick a static outside your DHCP pool. If your router hands out .100–.200, you could safely use .10–.50 or .201–.250 for fixed hosts.

```bash
# 1) Show your IP and prefix
ip addr show dev vmbr0
# e.g. inet 192.168.1.171/24 brd 192.168.1.255 scope global dynamic vmbr0

# 2) Show the route entry for that interface
ip route show dev vmbr0
# e.g. default via 192.168.1.254
# e.g. 192.168.1.0/24 proto kernel scope link src 192.168.1.171

# 3) Show your default gateway (router IP)
ip route show default
# e.g. default via 192.168.1.254 dev vmbr0

```

From the above, you can read:

- Subnet: 192.168.1.0/24

- Network ID: 192.168.1.0

- Broadcast: 192.168.1.255 (the highest address in /24)

- Usable hosts: 192.168.1.1 through 192.168.1.254 (excluding .0 and .255)

```bash
# Show your wireless device name (e.g. wlp2s0)
ip link show

# VERY IMPORTANT: See your current IP, subnet, and gateway (router IP)
ip addr show
ip route show

```

On a typical home LAN (192.168.1.0/24):

- Network:

    - Network ID – 192.168.1.0

    - Usable host range – 192.168.1.1 through 192.168.1.254

    - Broadcast – 192.168.1.255


```bash
root@hadg-dev:~# ip route
# default via 192.168.1.254 dev vmbr0
# 192.168.1.0/24 dev vmbr0 proto kernel scope link src 192.168.1.171
```

### Find free IPs on my LAN
```bash
nmap -sn 192.168.1.0/24 | grep 'Nmap scan report for'
# Nmap scan report for Bbox-TV-001.lan (192.168.1.23)
# Nmap scan report for Host-001.lan (192.168.1.57)
# Nmap scan report for Repeteur-Bbox-Wi-Fi-6-5E68.lan (192.168.1.65)
# Nmap scan report for MBPdeShaghayegh.lan (192.168.1.89)
# Nmap scan report for Host-002.lan (192.168.1.91)
# Nmap scan report for FR-L5492964.lan (192.168.1.119)
# Nmap scan report for bbox.lan (192.168.1.254)
# Nmap scan report for hadg-dev.lan (192.168.1.171)

```



| Hostname                       | IP Address    | Description                                           |
| ------------------------------ | ------------- | ----------------------------------------------------- |
| Bbox-TV-001.lan                | 192.168.1.23  | ISP’s set-top TV box                                  |
| Host-001.lan                   | 192.168.1.57  | Generic device (e.g. PC, IoT device)                  |
| Repeteur-Bbox-Wi-Fi-6-5E68.lan | 192.168.1.65  | Wi-Fi repeater/extender                               |
| MBPdeShaghayegh.lan            | 192.168.1.89  | MacBook Pro belonging to “Shaghayegh”                 |
| Host-002.lan                   | 192.168.1.91  | Generic device (e.g. second PC or IoT device)         |
| FR-L5492964.lan                | 192.168.1.119 | Likely a network printer or another FR-branded device |
| bbox.lan                       | 192.168.1.254 | Home router / DHCP server (default gateway)           |
| hadg-dev.lan                   | 192.168.1.171 | Your Proxmox server (vmbr0 management interface)      |



 Each device that is connected to the LAN is assigned an IP address in the 192.168.1.0/24 so from 192.168.1.1 through 192.168.1.254

 This IP address for each device in the LAN is assigned by the DHCP protocol:


Your LAN uses the network **192.168.1.0/24**, which means:

- **Network ID**: `192.168.1.0`  
- **Usable host range**: `192.168.1.1` – `192.168.1.254` (254 addresses)  
- **Broadcast**: `192.168.1.255`  

---

### 1. DHCP (Dynamic Host Configuration Protocol)

1. **DHCP Server**  
   - Typically your router, e.g. `192.168.1.254`  
   - Maintains a _pool_ of addresses, e.g. `192.168.1.100`–`192.168.1.200`

2. **4-Step Handshake**  
   ```text
   1. Discover  – Client broadcasts “Any DHCP server out there?”
   2. Offer     – Server replies “Here’s 192.168.1.X for you.”
   3. Request   – Client says “I’ll take 192.168.1.X.”
   4. ACK       – Server confirms “You have it for 24 h.”


3. Lease Renewal

    - Client automatically renews halfway through the lease period.

4. Reservations (optional)  

    - You can bind a device’s MAC address to a fixed IP in your router so it always gets the same address.

### Static IP assigment
- Choose an IP outside the DHCP pool to avoid conflicts
- No lease timer—address remains until you change it

You can do it manually or by a Address Reservation on the Settings of you router's Web UI (http://192.168.1.254)
Add a reservation, that is:
- MAC addressof the device
- static IP address (eg. 192.168.1.50) outside of your DHCP pool

#### How to find MAC addresses of your devices on your LAN ?
First, find the LAN subnet
```bash
# find your LAN's subnet
ip route

# scan you subnet using your selected connexion type ethernet/wifi
 arp-scan --interface=en1ps0 192.168.1.0/24

root@hadg-dev:~# arp-scan --interface=vmbr0 192.168.1.0/24
# Interface: vmbr0, type: EN10MB, MAC: 68:1d:ef:31:fa:0e, IPv4: 192.168.1.171
# Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
# 192.168.1.23    d0:5a:00:a6:74:2c       Technicolor CH USA Inc.
# 192.168.1.57    70:ee:50:ba:40:62       Netatmo
# 192.168.1.65    84:1e:a3:e2:5e:68       Sagemcom Broadband SAS
# 192.168.1.119   d4:54:8b:e2:df:06       Intel Corporate
# 192.168.1.254   48:29:52:d3:3d:95       Sagemcom Broadband SAS
# 192.168.1.91    ac:fa:e4:ec:bb:da       (Unknown)
# 192.168.1.166   52:32:f8:22:18:cb       (Unknown: locally administered)
```

#### Why `arp-scan` on Ethernet Only Sees Wired Hosts ?

`arp-scan` works at **Layer 2** (Ethernet) and only discovers devices that reply to ARP on the same physical segment.  If your access point is isolating wireless clients or not bridging ARP to the wired side, you won’t see your Wi-Fi devices with:

```bash
sudo arp-scan --interface=vmbr0 192.168.1.0/24
```
Notice your printer (on Wi-Fi) doesn’t show up here. To do so, you need to scan via a wifi-interface like
```bash
arp-scan --interface=wlan0 192.168.1.0/24
```

```bash
root@hadg-dev:~# nmap -sn 192.168.1.0/24
# Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-11 13:34 CEST
# Nmap scan report for Bbox-TV-001.lan (192.168.1.23)
# Host is up (0.0015s latency).
# MAC Address: D0:5A:00:A6:74:2C (Technicolor CH USA)
# Nmap scan report for Host-001.lan (192.168.1.57)
# Host is up (0.017s latency).
# MAC Address: 70:EE:50:BA:40:62 (Netatmo)
# Nmap scan report for Repeteur-Bbox-Wi-Fi-6-5E68.lan (192.168.1.65)
# Host is up (0.014s latency).
# MAC Address: 84:1E:A3:E2:5E:68 (Sagemcom Broadband SAS)
# Nmap scan report for Host-002.lan (192.168.1.91)
# Host is up (0.20s latency).
# MAC Address: AC:FA:E4:EC:BB:DA (Unknown)
# Nmap scan report for FR-L5492964.lan (192.168.1.119)
# Host is up (0.11s latency).
# MAC Address: D4:54:8B:E2:DF:06 (Intel Corporate)
# Nmap scan report for Host-003.lan (192.168.1.166)
# Host is up (0.12s latency).
# MAC Address: 52:32:F8:22:18:CB (Unknown)
# Nmap scan report for bbox.lan (192.168.1.254)
# Host is up (0.00061s latency).
# MAC Address: 48:29:52:D3:3D:95 (Sagemcom Broadband SAS)
# Nmap scan report for hadg-dev.lan (192.168.1.171)
# Host is up.
# Nmap done: 256 IP addresses (8 hosts up) scanned in 3.25 seconds``` 
``` 

| Hostname                         | IP Address       | MAC Address            | Description                                |
|----------------------------------|------------------|------------------------|--------------------------------------------|
| Bbox-TV-001.lan                  | 192.168.1.23     | D0:5A:00:A6:74:2C      | ISP’s set-top TV box                       |
| Host-001.lan                     | 192.168.1.57     | 70:EE:50:BA:40:62      | Netatmo IoT device (e.g. weather station)  |
| Repeteur-Bbox-Wi-Fi-6-5E68.lan   | 192.168.1.65     | 84:1E:A3:E2:5E:68      | Wi-Fi repeater/extender                    |
| Host-002.lan                     | 192.168.1.91     | AC:FA:E4:EC:BB:DA      | Unknown wired client                       |
| FR-L5492964.lan                  | 192.168.1.119    | D4:54:8B:E2:DF:06      | Intel-based device (PC/laptop)             |
| Host-003.lan                     | 192.168.1.166    | 52:32:F8:22:18:CB      | Unknown device (locally administered MAC)  |
| bbox.lan                         | 192.168.1.254    | 48:29:52:D3:3D:95      | Home router / DHCP server                  |
| hadg-dev.lan                     | 192.168.1.171    | 68:1D:EF:31:FA:0E      | Your Proxmox VE host (vmbr0 management IP) |



#### Another solution: check your routers UI
Most home routers show all attached clients—wired and wireless—in their web UI under DHCP leases or Connected Devices. That is often the easiest way to see every device, including printers on Wi-Fi.



### Find your DHCP pool range

In a browser, go to your gateway IP (from $ ip route default):
```
http://192.168.1.254
```



### Find your DNS Server(s) IP address
```bash
cat /etc/resolv.conf
# domain lan
# search lan
# nameserver 192.168.1.254
```
you can add DNS servers like 9.9.9.9 or Google



# Storage


