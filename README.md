# nginx

- Debian 12/11.
- Ubuntu 24.04/22.04.
- AlmaLinux 9/8.

Debian/Ubuntu.
```bash
apt update; apt-get -y upgrade; apt-get -y install wget apt-transport-https ca-certificates gnupg2 sudo
echo "deb [arch=amd64 trusted=yes] https://repo.raweb.al/ $(cat /etc/os-release | grep VERSION_CODENAME= | cut -d= -f2) main" | sudo tee /etc/apt/sources.list.d/raweb.list
sudo apt update; sudo apt install -y raweb-webserver

```

AlmaLinux 9.
```bash
dnf -y update; dnf install -y wget ca-certificates gnupg2 epel-release sudo

sudo tee /etc/yum.repos.d/raweb.repo << 'EOF'
[raweb-alma9]
name=Raweb Panel Repository for AlmaLinux 9
baseurl=https://repo.raweb.al/rpm/alma9/x86_64
enabled=1
gpgcheck=0
EOF

# Install
sudo dnf makecache; sudo dnf -y install raweb-webserver
```

AlmaLinux 8.
```bash
dnf -y update; dnf install -y wget ca-certificates gnupg2 epel-release sudo

sudo tee /etc/yum.repos.d/raweb.repo << 'EOF'
[raweb-alma8]
name=Raweb Panel Repository for AlmaLinux 8
baseurl=https://repo.raweb.al/rpm/alma8/x86_64
enabled=1
gpgcheck=0
EOF

# Install
sudo dnf makecache; sudo dnf -y install raweb-webserver
```

---
