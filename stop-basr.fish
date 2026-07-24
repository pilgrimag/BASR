#!/usr/bin/env fish

echo "Stopping BASR Fabric containers..."

for container in \
    (docker ps \
      --format '{{.Names}}' \
      | grep -E \
      '^(peer0\.org1\.example\.com|peer0\.org2\.example\.com|orderer\.example\.com|ca_org1|ca_org2|ca_orderer|dev-peer)')

    echo "Stopping $container"
    docker stop $container
end

if docker ps \
    --format '{{.Names}}' \
    | grep -qx ipfs

    echo "Stopping ipfs"
    docker stop ipfs
end

echo "BASR services stopped. Docker volumes and ledger state are preserved."