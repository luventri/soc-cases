# pfSense network DQ gate

- Generated (UTC): 2026-03-09 17:03 UTC
- Window: now-180m .. now
- Source IP: 192.168.242.131
- Total matched events: 66

## Checks
- N1 recent ingest from source (192.168.242.131): PASS
- N2 filterlog presence: PASS
- N3 key fields parse (action/proto/src/dst/ports): PASS
- N4 dhcp/system auxiliary signal: PASS

## Parsed sample (filterlog)
- action: pass
- proto: udp
- srcip: 192.168.114.128
- dstip: 192.168.114.254
- srcport: 46346
- dstport: 53

## Samples
- 2026-03-09T16:34:17.051Z | 192.168.242.131 | Mar  9 16:34:17 filterlog[7007]: 86,,,100000101,em1,match,pass,in,4,0x0,,64,11953,0,none,17,udp,99,192.168.114.128,192.168.114.254,46346,53,79
- 2026-03-09T16:34:17.050Z | 192.168.242.131 | Mar  9 16:34:17 filterlog[7007]: 86,,,100000101,em1,match,pass,in,4,0x0,,64,24250,0,none,17,udp,89,192.168.114.128,192.168.114.254,41618,53,69
- 2026-03-09T16:34:17.050Z | 192.168.242.131 | Mar  9 16:34:17 filterlog[7007]: 86,,,100000101,em1,match,pass,in,4,0x0,,64,36186,0,none,17,udp,89,192.168.114.128,192.168.114.254,42168,53,69
- 2026-03-09T16:34:00.689Z | 192.168.242.131 | Mar  9 16:34:00 filterlog[7007]: 86,,,100000101,em1,match,pass,in,4,0x0,,64,62044,0,none,17,udp,68,192.168.114.128,192.168.114.254,39524,53,48
- 2026-03-09T16:34:00.689Z | 192.168.242.131 | Mar  9 16:34:00 filterlog[7007]: 86,,,100000101,em1,match,pass,in,4,0x0,,64,4965,0,none,17,udp,68,192.168.114.128,192.168.114.254,44942,53,48

## Result
**PASS**
