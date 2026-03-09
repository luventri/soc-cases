# OLA1-NET-001 Evidence — pfSense Perimeter Baseline (2026-03-09)

## Infrastructure metadata
- Firewall VM: `soc-fw` (pfSense CE)
- Version: `2.8.1-RELEASE (amd64)`
- Hypervisor: VMware Virtual Machine
- WAN (`em0`): `192.168.242.131/24` (VMnet8 NAT)
- LAN (`em1`): `192.168.114.254/24` (VMnet1 Host-only)
- LAN client validated: `soc-linux-endpoint` (`192.168.114.130/24`)

## Executed steps and checks (sanitized)
```text
1) pfSense installed and interfaces assigned:
   - WAN -> em0
   - LAN -> em1

2) Resolved initial management access issue:
   - Collision detected when LAN was 192.168.114.1 (same subnet as host adapter)
   - LAN updated to 192.168.114.254

3) VMware adjustment:
   - VMnet1 kept as Host-only
   - VMware local DHCP on VMnet1 disabled

4) Endpoint networking validation:
   ip -4 a
   ip r
   ping -c 4 192.168.114.254
   ping -c 4 8.8.8.8
   ping -c 4 192.168.242.128

5) Endpoint DNS validation:
   resolvectl status | sed -n '/ens33/,+8p'
   ping -c 3 google.com
   curl -I http://example.com

6) pfSense telemetry validation:
   - Diagnostics > States filtered by 192.168.114.130
   - Status > System Logs > Firewall > Normal View (LAN pass entries)
```

## Validation results
- LAN gateway reachability (`192.168.114.254`): PASS
- Internet egress (`8.8.8.8`): PASS
- Reachability to SOC core (`192.168.242.128`): PASS
- DNS via pfSense (`Current DNS Server: 192.168.114.254`): PASS
- FQDN resolution (`google.com`): PASS
- HTTP egress test (`example.com`): PASS
- pfSense state table:
  - LAN state for `192.168.114.130:56186 -> 192.168.242.128:1514`: PASS
  - WAN translated state `192.168.242.131:34382 -> 192.168.242.128:1514`: PASS
- pfSense firewall logs (`LAN pass` entries): PASS
  - `192.168.114.130 -> 8.8.8.8` (ICMP)
  - `192.168.114.130 -> 192.168.114.254:53` (DNS)
  - `192.168.114.130:53768 -> 104.18.26.120:80` (HTTP)

## Notable findings
1. `sudo dhclient` is not present on the Linux endpoint image, but not required after network stabilized.
2. "Summary View" can show high `block` ratio and still be healthy; authoritative check is `Normal View` plus `States`.
3. Successful NAT and LAN pass logging confirm endpoint traffic is traversing pfSense as designed.

## Residual risks
1. Lab management path is host-only; hardening of mgmt plane exposure is pending future phases.
2. DNS upstream choice is lab-oriented and should be reviewed if policy requires specific providers/logging.

## Conclusion
`OLA1-NET-001` is complete:
- pfSense perimeter deployed
- WAN/LAN segmentation operational
- endpoint traffic routed through firewall with validated DNS, egress, SOC reachability, NAT and pass logs
