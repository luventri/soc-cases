# OLA1-LNX-001 — Linux Endpoint Provisioning Baseline

## Objective
Provision and harden a Linux endpoint VM (`soc-linux-endpoint`) as Wave 1 telemetry source for Wazuh.

## Scope
- VM provisioning on VMware (VMnet8 NAT segment `192.168.242.0/24`)
- OS baseline and package updates
- Minimal hardening suitable for home SOC lab
- Evidence artifact generation

## Target architecture (minimum)
- VM name: `soc-linux-endpoint`
- OS: Ubuntu Server 24.04.4 LTS
- Kernel: `6.8.0-101-generic`
- Network: `VMnet8` (NAT)
- Current endpoint IP: `192.168.242.130/24` (dynamic)
- Default gateway: `192.168.242.2`

## Build and hardening steps
1. Provision VM in VMware with one NIC in `VMnet8`.
2. Confirm L3 reachability to SOC nodes:
   - `ping 192.168.242.128` (soc-core)
   - `ping 192.168.242.129` (soc-backup)
3. Apply OS updates:
   - `sudo apt update`
   - `sudo apt upgrade -y`
4. Reboot after upgrade:
   - `sudo reboot`
5. Validate host identity and network:
   - `hostnamectl`
   - `ip -4 a`
   - `ip r`
6. Validate time sync:
   - `timedatectl status`
   - `systemctl status systemd-timesyncd --no-pager`
7. SSH root login hardening (lab-safe minimum):
   - enforce `PermitRootLogin no`
   - keep password auth enabled for lab operations

## Validation checklist
- VM reachable in SOC segment (`192.168.242.0/24`): PASS
- OS fully upgraded and rebooted into updated kernel: PASS
- Time synchronization active: PASS
- Root SSH login disabled: PASS
- Password auth disabled: N/A (kept enabled by lab decision)
- Host firewall strict mode: N/A (kept inactive by lab decision)

## Lab-mode exception (documented)
For this lab endpoint, the following controls are intentionally deferred:
- `PasswordAuthentication` remains enabled.
- Host firewall (`ufw`) remains inactive.

Rationale:
- Endpoint is dedicated to telemetry generation in isolated home SOC lab.
- Simpler operator access while attack/testing scenarios are developed.

Compensating controls:
- `PermitRootLogin no` enforced.
- VM isolated inside VMware NAT segment.
- No production workload/data hosted on endpoint.

## Rollback (basic)
If SSH access is lost after hardening change:
1. Use VM console in VMware.
2. Remove/adjust file under `/etc/ssh/sshd_config.d/`.
3. Validate and reload SSH:
   - `sudo sshd -t`
   - `sudo systemctl reload ssh`

## Next step
Proceed to `OLA1-LNX-002`: install and enroll Wazuh agent, then validate telemetry arrival.
