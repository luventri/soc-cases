# OLA1-LNX-001 Evidence — soc-linux-endpoint (2026-03-03)

## VM metadata
- VM name: `soc-linux-endpoint`
- Hypervisor: VMware
- OS: Ubuntu 24.04.4 LTS
- Kernel after update/reboot: `6.8.0-101-generic`
- Hostname: `soc-linux-endpoint`
- NIC: `ens33`
- IPv4: `192.168.242.130/24` (VMnet8 NAT)
- Gateway: `192.168.242.2`

## Executed commands (sanitized)
```bash
# Connectivity checks
ping 192.168.242.128
ping 192.168.242.129

# Patch/update
sudo apt update
sudo apt upgrade -y
sudo reboot

# Post-reboot validation
hostnamectl
ip -4 a
ip r
timedatectl status
systemctl status systemd-timesyncd --no-pager

# SSH and host security posture
sudo grep -E '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
sudo ufw status verbose
sudo systemctl is-enabled apparmor
sudo aa-status
sudo systemctl status ssh --no-pager

# Lab hardening adjustment
sudo tee /etc/ssh/sshd_config.d/99-lab-root-login.conf >/dev/null <<'EOC'
PermitRootLogin no
EOC
sudo sshd -t
sudo systemctl reload ssh
```

## Validation results
- Reachability to `soc-core` (`192.168.242.128`): PASS (0% packet loss)
- Reachability to `soc-backup` (`192.168.242.129`): PASS (0% packet loss)
- Package updates: PASS (upgrade completed)
- Reboot into updated kernel: PASS (`6.8.0-101-generic`)
- Time sync: PASS (`System clock synchronized: yes`, `NTP service: active`)
- AppArmor: PASS (enabled and enforcing profiles)
- SSH service: PASS (running)
- `PermitRootLogin no`: PASS (set via override file)
- `PasswordAuthentication`: LAB-EXCEPTION (kept enabled)
- Host firewall (`ufw`): LAB-EXCEPTION (inactive by decision)

## Remaining risks
1. Password-based SSH increases brute-force risk if network exposure grows.
2. Inactive host firewall reduces host-level filtering/segmentation.
3. IP assignment currently dynamic; reservation is recommended for stable operations.

## Conclusion
`OLA1-LNX-001` is complete in **Lab mode**:
- VM provisioned
- Base hardening applied
- Time sync and core validations passed
- Exceptions documented for later tightening
