docker ps --format "{{.Ports}}" | awk -F '->' '{print $1}'
docker ps --format "{{.Image}} {{.Ports}}" | awk -F '->' '{print $1}'