# OLA1-LNX-002 Install Evidence (2026-03-03)

## Endpoint
- Host: `soc-linux-endpoint`
- OS: Ubuntu 24.04.4 LTS
- Agent package target: `wazuh-agent 4.9.2-1`
- Manager target: `192.168.242.128`

## Execution summary
Installation and enrollment were completed on endpoint host using the documented runbook sequence.

Executed stages:
1. Connectivity pre-checks to manager ports.
2. Wazuh repository setup and package installation.
3. Version alignment to manager (`4.9.2`).
4. Agent configuration update with manager address.
5. `agent-auth` enrollment with agent name `soc-linux-endpoint`.
6. Service enable/start and local log verification.

## Notable findings during install
- Initial version mismatch (newer agent vs manager `4.9.2`) required version alignment.
- Configuration cleanup was required before final successful start.
- Final state after corrections: service active, enrollment successful.

## Security handling
- No secrets were printed or committed.
- Enrollment key exchange handled via `agent-auth` channel.

## Conclusion
**PASS** — agent installed and enrolled on Linux endpoint.
