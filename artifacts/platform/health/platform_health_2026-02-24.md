# Platform Health — Wazuh single-node Docker (P0)

- Date/time (local): 2026-02-24 11:42 UTC
- Host: soc-core
- Compose file path: /home/socadmin/wazuh-docker/single-node/docker-compose.yml
- Dashboard URL used: https://192.168.242.128:443

## 1) docker compose ps
Command:
- docker compose -f '/home/socadmin/wazuh-docker/single-node/docker-compose.yml' ps

Output:
```text
time="2026-02-24T11:42:14Z" level=warning msg="/home/socadmin/wazuh-docker/single-node/docker-compose.yml: the attribute `version` is obsolete, it will be ignored, please remove it to avoid potential confusion"
NAME                            IMAGE                         COMMAND                  SERVICE           CREATED       STATUS       PORTS
single-node-wazuh.dashboard-1   wazuh/wazuh-dashboard:4.9.2   "/entrypoint.sh"         wazuh.dashboard   2 weeks ago   Up 12 days   443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp
single-node-wazuh.indexer-1     wazuh/wazuh-indexer:4.9.2     "/entrypoint.sh open…"   wazuh.indexer     2 weeks ago   Up 12 days   0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp
single-node-wazuh.manager-1     wazuh/wazuh-manager:4.9.2     "/init"                  wazuh.manager     2 weeks ago   Up 12 days   0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp
```

## 2) docker ps (table)
Command:
- docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

Output:
```text
NAMES                           STATUS       PORTS
single-node-wazuh.dashboard-1   Up 12 days   443/tcp, 0.0.0.0:443->5601/tcp, [::]:443->5601/tcp
single-node-wazuh.manager-1     Up 12 days   0.0.0.0:1514-1515->1514-1515/tcp, [::]:1514-1515->1514-1515/tcp, 0.0.0.0:514->514/udp, [::]:514->514/udp, 0.0.0.0:55000->55000/tcp, [::]:55000->55000/tcp, 1516/tcp
single-node-wazuh.indexer-1     Up 12 days   0.0.0.0:9200->9200/tcp, [::]:9200->9200/tcp
```

## 3) Dashboard reachability (headers only)
Command:
- curl -skI "https://192.168.242.128:443" | egrep -vi '^set-cookie:' | head -n 10

Output:
```text
HTTP/1.1 302 Found
location: /app/login?
osd-name: wazuh.dashboard
x-frame-options: sameorigin
cache-control: private, no-cache, no-store, must-revalidate
content-length: 0
Date: Tue, 24 Feb 2026 11:42:15 GMT
Connection: keep-alive
Keep-Alive: timeout=120

```

## 4) Indexer container status (docker inspect)
Command:
- docker inspect --format='{{.Name}}  health={{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}  status={{.State.Status}}  started={{.State.StartedAt}}' 'single-node-wazuh.indexer-1'

Output:
```text
/single-node-wazuh.indexer-1  health=n/a  status=running  started=2026-02-12T10:27:30.376695727Z
```

## 4.1) Indexer cluster health (auth)
Source:
- https://127.0.0.1:9200/_cluster/health
Credentials:
- Loaded from environment (WAZUH_INDEXER_USER/WAZUH_INDEXER_PASS); not printed

Output (summary):
```text
HTTP=200 BYTES=447
status: green
cluster_name: opensearch
number_of_nodes: 1
active_shards_percent_as_number: 100.0
unassigned_shards: 0
timed_out: False
```

## 5) Listener exposure check (local)
Command:
- ss -lntp | egrep '(:443|:9200|:55000)\b' || true

Output:
```text
LISTEN 0      4096         0.0.0.0:55000      0.0.0.0:*          
LISTEN 0      4096         0.0.0.0:443        0.0.0.0:*          
LISTEN 0      4096         0.0.0.0:9200       0.0.0.0:*          
LISTEN 0      4096            [::]:55000         [::]:*          
LISTEN 0      4096            [::]:443           [::]:*          
LISTEN 0      4096            [::]:9200          [::]:*          
```

## Conclusion
- If containers are Up and dashboard returns an HTTP response (commonly 302 to /app/login), the SIEM stack is operational.
- Indexer health is strongest when cluster health returns status=green/yellow and expected node count.
- If any service is down/unreachable, investigate with: docker compose -f /home/socadmin/wazuh-docker/single-node/docker-compose.yml logs --tail 200 <service>
- Security note: if listeners bind to 0.0.0.0/[::], restrict by firewall or bind addresses as needed for your environment.
