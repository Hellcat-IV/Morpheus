# Code:Morpheus — Cybersecurity Lab by Forensick

**Morpheus** is an open-source cybersecurity laboratory project imagined by **Forensick**.

Everything, as much as we can 🙂, developed as part of the lab — from research papers to automation scripts — will be open-sourced.

---

## 🚀 Project Objectives

- 🌐 **Web Hosting**  
- 🧪 **Pentest Labs**  
- 🐞 **Vulnerability Research**
- 🔎 **Forensic/CTI Analysis**
- </> **Cyber R&D**

---

### 🔧 Hardware Components

#### **Storage & File Hosting**
- **NAS:** QNAP TS-412U  
  - 4 × 4TB Western Digital Red (WD40EFRX)

#### **Compute Node**
- **Server:** Intel R1208WFTYS  
  - 2 × Intel Xeon Gold 6138  
  - 8 × 16GB DDR3 RAM  
  - 2 × 480GB Intel S4600 SSD (SAS)  
  - 6 × 1TB HDDs (Mixed brands)

#### **Networking**
- **Switch:** Cisco Catalyst C2960S-48  
  - 48-port managed switch for internal lab segmentation
- **Router:** Freebox Delta  
  - Used as the main internet gateway
- **VPN**: Wireguard
  - Wireguard has been chosen because of it's simplicity of deployment into a personal environment.

---

## 🧭 Roadmap

![image](https://github.com/user-attachments/assets/a470b283-8635-4f7b-9875-a31885080228)

Short-term Roadmap:
1. Restrict SSH connections on lab for root with key + 2FA Proxmox + Create last users ✅
2. Install OS on Raspberry + Setup routing & basics firewall rules
3. Reset NAS software + create users ✅
4. Uptime checker + alerting for server (cloud-based server)

---

## 🧑‍💻 Contributing

Morpheus is open to contributions. If you’re interested about dev, infrastructure administration, or offensive/defensive security — you're welcome here. We will soon post the contribution guidelines.

---

## 📜 License

This project will be released under an open-source license (GPLv3).

---
