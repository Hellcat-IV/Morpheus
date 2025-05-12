# Active directory setup on Proxmox VM

1. Installation
- Using microsoft website, we can download directly the iso file (https://www.microsoft.com/fr-fr/evalcenter/download-windows-server-2022)
- During the install, we need to choose the desktop (GUI) install or CLI install. To begin and for simplicity, we choose Desktop version.
- For the activation, we followed the note of Bramada (https://gist.github.com/bramada/51c7a78c12e8970822fe5a5e7b1250fc)
- Then, basics services (with active directory domain services to manage users and computers of the domain) need to be activated : https://www.ittsystems.com/active-directory-setup-guide/.

2. Information
- Domain: ad-forensick.local
