#!/bin/bash
# Runs RIGHT BEFORE LightDM starts — ensures koppa user + password exist
id koppa 2>/dev/null || useradd -m -u 1000 -s /bin/bash -G sudo,audio,video,cdrom,plugdev,netdev koppa
echo "koppa:koppa" | chpasswd
echo "root:koppa"  | chpasswd
mkdir -p /home/koppa
chown koppa:koppa /home/koppa
chmod 700 /home/koppa
