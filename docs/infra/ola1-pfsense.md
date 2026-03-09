# OLA1-NET-001 — pfSense Perimeter Baseline (WAN/LAN Segmentation)

## Objective
Deploy pfSense as perimeter firewall/router for Wave 1 and place lab endpoint traffic behind LAN with validated egress and SOC reachability.

## Scope
- pfSense CE VM provisioning in VMware
- WAN/LAN interface segmentation
- Basic routing/NAT and LAN firewall baseline
- Validation from Linux endpoint behind pfSense
- Evidence artifact generation

## Minimum architecture
- Firewall VM: `soc-fw` (pfSense CE 2.8.1)
- WAN interface: VMware `VMnet8` (NAT `192.168.242.0/24`)
- LAN interface: VMware `VMnet1` (Host-only `192.168.114.0/24`)
- pfSense WAN IPv4 (DHCP): `192.168.242.131/24`
- pfSense LAN IPv4: `192.168.114.254/24`
- Linux endpoint moved to LAN segment:
  - IP: `192.168.114.130/24`
  - Gateway: `192.168.114.254`
  - DNS: `192.168.114.254`

## Provisioning and baseline configuration
1. Create pfSense VM with two NICs:
   - `em0` -> `VMnet8` (WAN)
   - `em1` -> `VMnet1` (LAN)
2. Complete console assignment and verify interfaces.
3. Resolve LAN IP collision with host adapter by changing pfSense LAN from `192.168.114.1` to `192.168.114.254`.
4. Run setup wizard:
   - Hostname: `soc-fw`
   - Domain: `home.arpa`
   - Timezone: `Etc/UTC`
   - WAN type: `DHCP`
   - DNS configured (lab): `1.1.1.1`, `9.9.9.9`
5. VMware network adjustment:
   - Keep `VMnet1` as Host-only
   - Disable VMware DHCP service on `VMnet1` (avoid DHCP conflict with pfSense)
6. Confirm LAN rules include IPv4 allow LAN-to-any rule and enable rule logging for validation.
7. Move Linux endpoint NIC to `VMnet1` and renew/verify lease from pfSense DHCP.

## Validation commands (endpoint)
```bash
ip -4 a
ip r
ping -c 4 192.168.114.254
ping -c 4 8.8.8.8
ping -c 4 192.168.242.128
resolvectl status | sed -n '/ens33/,+8p'
ping -c 3 google.com
curl -I http://example.com
```

## Validation checklist
- Endpoint receives LAN address from pfSense DHCP: PASS
- Default route via pfSense LAN gateway (`192.168.114.254`): PASS
- Internet connectivity from LAN client: PASS
- Reachability to SOC core (`192.168.242.128`) through pfSense: PASS
- DNS resolution through pfSense resolver/forwarder: PASS
- pfSense firewall logs show `pass` entries for endpoint traffic: PASS
- pfSense state table shows LAN and translated WAN states: PASS

## Lab notes and decisions
- LAN gateway was intentionally set to `.254` to avoid collision with VMware host adapter IP on `VMnet1`.
- WAN private/bogon defaults were adapted for lab NAT topology during setup.
- Management remains from host-only network; public exposure is out of scope for this phase.

## Basic rollback
If endpoint loses connectivity after changes:
1. Verify VMware NIC mappings for pfSense and endpoint.
2. Ensure `VMnet1` DHCP from VMware remains disabled.
3. In pfSense, confirm LAN IP/gateway/DHCP range and LAN allow rule.
4. Rebind endpoint lease (`netplan apply` or interface restart), then retest route and DNS.

## Next step
Proceed with `OLA1-NET-002`: export pfSense telemetry/logs to SIEM and validate parsing.
