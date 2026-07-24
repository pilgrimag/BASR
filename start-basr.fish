#!/usr/bin/env fish

echo "Starting IPFS..."

if docker ps -a \
    --format '{{.Names}}' \
    | grep -qx ipfs

    docker start ipfs
end

echo "Starting Fabric CA and Orderer..."

for container in \
    ca_orderer \
    ca_org1 \
    ca_org2 \
    orderer.example.com

    if docker ps -a \
        --format '{{.Names}}' \
        | grep -qx $container

        docker start $container
    end
end

echo "Starting Fabric peers..."

for container in \
    peer0.org1.example.com \
    peer0.org2.example.com

    if docker ps -a \
        --format '{{.Names}}' \
        | grep -qx $container

        docker start $container
    end
end

sleep 8

echo "Starting BASR chaincode containers..."

for container in \
    (docker ps -a \
      --format '{{.Names}}' \
      | grep -E '^dev-peer.*-basr_')

    docker start $container
end

sleep 5

echo
echo "Current BASR services:"
docker ps \
  --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
  | grep -E \
  'ipfs|peer0\.org1|peer0\.org2|orderer\.example|ca_org|ca_orderer|dev-peer'