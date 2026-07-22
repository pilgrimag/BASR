# BASR

BASR 是一个基于 Java、Hyperledger Fabric 和 IPFS/Kubo 的完整原型实现，用于验证以下端到端流程：

1. 系统公共参数初始化；
2. 设备生成 secp256k1 密钥对；
3. 设备生成并提交 Schnorr Proof of Possession $POP$；
4. Fabric Chaincode 验证 POP，并维护链上设备注册表  
   $\mathcal{L}=\{(ID_i,pk_i)\}$；
5. DR 生成 X25519 恢复密钥；
6. 设备对公开数据$\beta=0$或敏感数据$\beta=1$执行报告封装和签名；
7. 聚合器验证设备注册关系与单条签名，完成去重和聚合；
8. 批次包 `Pkg` 被确定性编码并上传至 IPFS；
9. 链上写入  
   $BRec=(bid,t,\sigma_{agg},\mu,cid)$；
10. 服务端从 Fabric 读取 `BRec`，根据 `cid` 从 IPFS 下载 `Pkg`；
11. 执行聚合签名验证；
12. DR 使用恢复密钥恢复公开报告或解密敏感报告。

当前仓库已包含真实密码算法、真实 Fabric Chaincode、真实 Fabric Gateway 客户端、真实 IPFS 客户端、应用服务层以及正向/负向端到端测试。

---

## 1. 当前实现范围

| BASR 阶段 | 实现位置 | 状态 |
|---|---|---|
| `Setup` | `com.basr.algorithm.Setup` | 已实现 |
| 设备密钥生成 | `Registration.generateDevice` | 已实现 |
| Schnorr POP 生成 | `Registration.createRequest` | 已实现 |
| POP 链上验证 | `BasrContract.RegisterDevice` | 已实现 |
| Fabric 设备注册表 | `FabricDeviceRegistry` | 已实现 |
| `RecKeyGen` | `com.basr.algorithm.RecKeyGen` | 已实现 |
| 公开报告签名（$\beta=0$） | `Sign.sign` | 已实现 |
| 敏感报告加密与签名（$\beta=1$） | `Sign.sign` | 已实现 |
| 单条签名验证 | `SigVerify.verify` | 已实现 |
| 报告去重与聚合 | `Aggregate.aggregate` | 已实现 |
| 聚合签名验证 | `AggVerify.verify` | 已实现 |
| 批次包编码/解码 | `PackageCodec` | 已实现 |
| IPFS `put/get` | `KuboHttpIpfsClient` | 已实现 |
| 链上批记录 | `CreateBatchRecord` / `ReadBatchRecord` | 已实现 |
| 报告恢复 | `Recovery.recover` | 已实现 |
| 应用服务层 | `BasrWorkflowService` | 已实现 |
| 正向真实 E2E | `BasrFabricEndToEndTest` | 已通过 |
| 三项负向真实测试 | `BasrFabricEndToEndTest` | 已通过 |

对于当前定义的 BASR 算法流程，本仓库已经能够完成全流程执行。

---

## 2. 项目结构

```text
BASR/
├── pom.xml
├── src/
│   ├── main/java/com/basr/
│   │   ├── algorithm/       # Setup、Registration、Sign、Aggregate、AggVerify、Recovery
│   │   ├── app/             # BasrWorkflowService
│   │   ├── crypto/          # secp256k1、哈希、编码、X25519、HKDF、AES-GCM
│   │   ├── entity/          # Device、Report、SignedReport、BatchRecord 等实体
│   │   ├── fabric/          # FabricGatewayClient
│   │   ├── ipfs/            # IpfsClient、KuboHttpIpfsClient
│   │   ├── persistence/     # PackageCodec、DTO
│   │   └── registry/        # DeviceRegistry、FabricDeviceRegistry
│   └── test/java/com/basr/
│       ├── BasrFabricEndToEndTest.java
│       └── ...
└── chaincode/
    ├── build.gradle
    ├── gradlew
    ├── libs/
    │   └── basr-algorithm-1.0-SNAPSHOT.jar
    └── src/
        ├── main/java/com/basr/chaincode/
        │   ├── BasrContract.java
        │   ├── DeviceAsset.java
        │   └── BatchRecordAsset.java
        └── test/java/com/basr/chaincode/
            └── BasrContractTest.java
```

---

## 3. 已验证环境

当前原型在以下环境完成验证：

```text
操作系统：WSL2 Ubuntu 24.04.1 LTS x86_64
Java：21.0.11
Maven：3.9.11
Gradle Wrapper：9.1.0
Docker：29.6.1
Docker Compose：5.3.0
Kubo/IPFS：0.42.0
Hyperledger Fabric Peer/Orderer/Tools：2.5.16
Hyperledger Fabric CA：1.5.17
Fabric Gateway Java：1.10.0
gRPC：1.76.0
Protobuf Java：4.33.0
Bouncy Castle：1.84
```

Fabric 网络配置：

```text
Channel：basrchannel
Chaincode name：basr
Contract name：basr
Organizations：Org1MSP、Org2MSP
Orderer：Raft
State database：LevelDB
CA mode：enabled
```

---

## 4. 前置条件

需要预先安装：

- Git
- Java 21
- Maven 3.9+
- Docker
- Docker Compose
- Hyperledger Fabric 2.5.x 二进制工具
- `fabric-samples`
- `jq`
- `curl`

验证版本：

```bash
java -version
mvn -version
docker --version
docker compose version
peer version
orderer version
configtxlator version
jq --version
curl --version
```

---

## 5. 获取代码

```bash
git clone https://github.com/pilgrimag/BASR.git
cd BASR
```

检查当前分支：

```bash
git branch --show-current
git log -1 --oneline
```

---

## 6. 构建算法与客户端工程

在仓库根目录执行：

```bash
mvn clean test-compile
```

运行普通单元测试：

```bash
mvn test -Dbasr.fabric.e2e=false
```

说明：

- `BasrFabricEndToEndTest` 由系统属性 `basr.fabric.e2e` 控制；
- 默认普通测试不会写入 Fabric，也不会执行真实链上 E2E；
- 真实 E2E 需要显式指定 `-Dbasr.fabric.e2e=true`。

构建 JAR：

```bash
mvn clean package
```

生成：

```text
target/basr-algorithm-1.0-SNAPSHOT.jar
```

---

## 7. 启动 Kubo/IPFS

### 7.1 已存在容器

```bash
docker start ipfs
```

确认状态：

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' | grep ipfs
```

### 7.2 首次创建容器

```bash
docker volume create ipfs_staging
docker volume create ipfs_data

docker run -d \
  --name ipfs \
  --restart unless-stopped \
  -v ipfs_staging:/export \
  -v ipfs_data:/data/ipfs \
  -p 4001:4001 \
  -p 127.0.0.1:5001:5001 \
  -p 8080:8080 \
  ipfs/kubo:v0.42.0
```

### 7.3 验证 RPC

```bash
curl -sS -X POST \
  http://127.0.0.1:5001/api/v0/version

echo
```

预期返回包含：

```json
{
  "Version": "0.42.0"
}
```

---

## 8. 准备 Hyperledger Fabric 测试网络

本 README 假设 Fabric Samples 位于：

```text
~/basr/blockchain/fabric-samples
```

Fabric 配置文件位于：

```text
~/basr/blockchain/config
```

进入测试网络：

```bash
cd ~/basr/blockchain/fabric-samples/test-network
```

### 8.1 新建网络和通道

首次部署或希望清空账本时：

```bash
./network.sh down
```

启动双组织、CA 和 Raft 网络，并创建 `basrchannel`：

```bash
./network.sh up createChannel \
  -ca \
  -c basrchannel
```

检查容器：

```bash
docker ps --format \
  'table {{.Names}}\t{{.Status}}\t{{.Ports}}' \
  | grep -E \
  'peer0\.org1|peer0\.org2|orderer\.example|ca_org'
```

---

## 9. 设置 Anchor Peer

Fabric Gateway 需要通过 Discovery/Gossip 找到能够满足背书策略的 Peer。创建通道后，显式设置两个组织的 Anchor Peer：

```bash
cd ~/basr/blockchain/fabric-samples/test-network

./scripts/setAnchorPeer.sh 1 basrchannel
./scripts/setAnchorPeer.sh 2 basrchannel
```

等待 Gossip 更新：

```bash
sleep 10
```

验证 Anchor Peer：

```bash
set -gx ORDERER_CA \
  $PWD/organizations/ordererOrganizations/example.com/tlsca/tlsca.example.com-cert.pem
```

Fish Shell：

```fish
peer channel fetch config \
  /tmp/basrchannel_config.pb \
  -o localhost:7050 \
  --ordererTLSHostnameOverride orderer.example.com \
  -c basrchannel \
  --tls \
  --cafile $ORDERER_CA

configtxlator proto_decode \
  --input /tmp/basrchannel_config.pb \
  --type common.Block \
  --output /tmp/basrchannel_config.json

jq '{
  Org1MSP:
    .data.data[0].payload.data.config.channel_group
    .groups.Application.groups.Org1MSP
    .values.AnchorPeers.value.anchor_peers,

  Org2MSP:
    .data.data[0].payload.data.config.channel_group
    .groups.Application.groups.Org2MSP
    .values.AnchorPeers.value.anchor_peers
}' /tmp/basrchannel_config.json
```

正确结果：

```json
{
  "Org1MSP": [
    {
      "host": "peer0.org1.example.com",
      "port": 7051
    }
  ],
  "Org2MSP": [
    {
      "host": "peer0.org2.example.com",
      "port": 9051
    }
  ]
}
```

---

## 10. 构建 Chaincode

进入仓库 Chaincode 工程：

```bash
cd ~/basr/basr-java/basr-algorithm/chaincode
```

对于直接克隆本仓库的用户，也可以将该路径替换为实际 `BASR/chaincode`。

执行：

```bash
./gradlew clean test installDist
```

预期 Chaincode 单元测试通过：

```text
Tests run: 8
Failures: 0
Errors: 0
Skipped: 0
```

Chaincode 通过以下内置依赖使用已经验证的算法核心：

```text
chaincode/libs/basr-algorithm-1.0-SNAPSHOT.jar
```

---

## 11. 部署 Chaincode

### 11.1 全新通道首次部署

对全新 `basrchannel`，使用 Sequence 1：

```fish
cd ~/basr/blockchain/fabric-samples/test-network

set -gx CHAINCODE_PATH \
  $HOME/BASR/chaincode
```

根据实际仓库路径调整 `CHAINCODE_PATH`。

执行：

```fish
./network.sh deployCC \
  -c basrchannel \
  -ccn basr \
  -ccp $CHAINCODE_PATH \
  -ccl java \
  -ccv 1.1 \
  -ccs 1
```

### 11.2 已经部署过旧定义时升级

当前验证环境已从 Sequence 1 升级到 Sequence 2：

```fish
./network.sh deployCC \
  -c basrchannel \
  -ccn basr \
  -ccp $CHAINCODE_PATH \
  -ccl java \
  -ccv 1.1 \
  -ccs 2
```

部署后检查：

```fish
peer lifecycle chaincode querycommitted \
  --channelID basrchannel \
  --name basr
```

当前已验证环境预期：

```text
Name: basr
Version: 1.1
Sequence: 2
Approvals: [Org1MSP: true, Org2MSP: true]
```

对全新网络，Sequence 应为 1。

---

## 12. 配置 Fabric CLI 环境

以下命令针对 Fish Shell，并以 Org1 Admin 身份连接 `peer0.org1.example.com`：

```fish
cd ~/basr/blockchain/fabric-samples/test-network

set -gx FABRIC_CFG_PATH \
  $HOME/basr/blockchain/config

set -gx CORE_PEER_TLS_ENABLED true

set -gx CORE_PEER_LOCALMSPID \
  Org1MSP

set -gx CORE_PEER_TLS_ROOTCERT_FILE \
  $PWD/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt

set -gx CORE_PEER_MSPCONFIGPATH \
  $PWD/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp

set -gx CORE_PEER_ADDRESS \
  localhost:7051
```

检查通道：

```fish
peer channel list
```

预期：

```text
Channels peers has joined:
basrchannel
```

---

## 13. 手动验证 Chaincode 接口

### 13.1 `DeviceExists`

```fish
set -gx DEVICE_ID \
  '实际已注册设备ID'

peer chaincode query \
  -C basrchannel \
  -n basr \
  -c "{\"Args\":[\"basr:DeviceExists\",\"$DEVICE_ID\"]}"
```

预期：

```text
true
```

### 13.2 `ReadDevice`

```fish
peer chaincode query \
  -C basrchannel \
  -n basr \
  -c "{\"Args\":[\"basr:ReadDevice\",\"$DEVICE_ID\"]}" \
  | jq
```

返回：

```json
{
  "deviceId": "...",
  "publicKeyHex": "02..."
}
```

### 13.3 `PublicKeyExists`

从 `ReadDevice` 自动提取公钥：

```fish
set -gx PUBLIC_KEY_HEX \
  (peer chaincode query \
    -C basrchannel \
    -n basr \
    -c "{\"Args\":[\"basr:ReadDevice\",\"$DEVICE_ID\"]}" \
    | jq -r '.publicKeyHex')
```

查询：

```fish
peer chaincode query \
  -C basrchannel \
  -n basr \
  -c "{\"Args\":[\"basr:PublicKeyExists\",\"$PUBLIC_KEY_HEX\"]}"
```

预期：

```text
true
```

### 13.4 `IsRegisteredDevice`

```fish
peer chaincode query \
  -C basrchannel \
  -n basr \
  -c "{\"Args\":[\"basr:IsRegisteredDevice\",\"$DEVICE_ID\",\"$PUBLIC_KEY_HEX\"]}"
```

预期：

```text
true
```

### 13.5 `GetAllDevices`

```fish
peer chaincode query \
  -C basrchannel \
  -n basr \
  -c '{"Args":["basr:GetAllDevices"]}' \
  | jq
```

### 13.6 `ReadBatchRecord`

```fish
set -gx BATCH_ID \
  '实际批次ID'

peer chaincode query \
  -C basrchannel \
  -n basr \
  -c "{\"Args\":[\"basr:ReadBatchRecord\",\"$BATCH_ID\"]}" \
  | jq
```

---

## 14. 运行真实应用层 E2E

确认以下组件均在运行：

```bash
docker ps --format \
  'table {{.Names}}\t{{.Status}}' \
  | grep -E \
  'ipfs|peer0\.org1|peer0\.org2|orderer\.example|dev-peer.*basr'
```

返回 BASR 根工程：

```bash
cd ~/basr/basr-java/basr-algorithm
```

或进入实际克隆的仓库目录。

执行：

```bash
mvn \
  -Dbasr.fabric.e2e=true \
  -Dtest=BasrFabricEndToEndTest \
  test
```

当前测试类包含：

1. 应用服务层真实正向 E2E；
2. 未注册设备报告拒绝；
3. 正确设备 ID 与错误公钥组合拒绝；
4. Gateway 关闭后失败关闭。

预期统计：

```text
Tests run: 4
Failures: 0
Errors: 0
Skipped: 0

BUILD SUCCESS
```

正向测试输出类似：

```text
========== BASR Application E2E ==========
publicDeviceId    = service-public-...
sensitiveDeviceId = service-sensitive-...
batchId           = service-batch-...
cid               = bafkrei...
packageBytes      = ...
AggVerify         = PASS
publicRecovery    = temperature=23.7;run=...
sensitiveRecovery = confidential-pressure=82.2;run=...
==========================================
```

所有 ID、签名、CID、批记录和恢复结果都由本次真实运行产生。

---

## 15. 验证 IPFS 内容

从 E2E 输出复制 CID：

```fish
set -gx CID \
  '实际CID'
```

下载：

```fish
curl -sS -X POST \
  "http://127.0.0.1:5001/api/v0/cat?arg=$CID" \
  --output /tmp/basr-package.bin
```

检查文件大小：

```fish
wc -c /tmp/basr-package.bin
```

检查固定状态：

```fish
docker exec ipfs \
  ipfs pin ls "$CID"
```

---

## 16. 应用服务层调用顺序

核心入口：

```java
BasrWorkflowService service =
        new BasrWorkflowService(
                pp,
                gateway,
                ipfs);
```

典型流程：

```java
Device publicDevice =
        service.registerDevice(publicDeviceId);

Device sensitiveDevice =
        service.registerDevice(sensitiveDeviceId);

RecoveryKey recoveryKey =
        service.generateRecoveryKey();

SignedReport publicReport =
        service.signPublicReport(
                publicDevice,
                recoveryKey,
                publicPlaintext,
                batchId,
                timestamp);

SignedReport sensitiveReport =
        service.signSensitiveReport(
                sensitiveDevice,
                recoveryKey,
                sensitivePlaintext,
                batchId,
                timestamp);

BasrWorkflowService.PublishedBatch published =
        service.aggregateAndPublish(
                List.of(
                        publicReport,
                        sensitiveReport),
                batchId,
                timestamp);

BasrWorkflowService.VerifiedBatch verified =
        service.verifyPublishedBatch(batchId);

byte[] recoveredPublic =
        service.recoverReport(
                recoveryKey,
                verified,
                publicDeviceId,
                publicReport.getSignature().getR());

byte[] recoveredSensitive =
        service.recoverReport(
                recoveryKey,
                verified,
                sensitiveDeviceId,
                sensitiveReport.getSignature().getR());
```

---

## 17. 常见问题

### 17.1 Protobuf 运行时错误

错误：

```text
NoClassDefFoundError:
com/google/protobuf/RuntimeVersion$RuntimeDomain
```

确认：

```bash
mvn dependency:tree \
  -Dverbose \
  '-Dincludes=com.google.protobuf:*,org.hyperledger.fabric:fabric-protos,io.grpc:*'
```

必须实际解析：

```text
com.google.protobuf:protobuf-java:jar:4.33.0
```

不能只出现：

```text
com.google.protobuf:protobuf-java:pom:4.33.0:import
```

### 17.2 无法满足背书策略

错误：

```text
no combination of peers can be derived which satisfy the endorsement policy
```

检查并重新设置 Anchor Peer：

```bash
cd ~/basr/blockchain/fabric-samples/test-network

./scripts/setAnchorPeer.sh 1 basrchannel
./scripts/setAnchorPeer.sh 2 basrchannel

sleep 10
```

### 17.3 `peer channel list` 超时或找不到配置

确认：

```fish
set -gx FABRIC_CFG_PATH \
  $HOME/basr/blockchain/config
```

并设置 Org1 TLS、MSP 和 Peer 地址变量。

### 17.4 Chaincode Sequence 错误

错误：

```text
new definition must be sequence N
```

查询当前定义：

```fish
peer lifecycle chaincode querycommitted \
  --channelID basrchannel \
  --name basr
```

升级时将 `-ccs` 设置为当前 Sequence 加 1。

### 17.5 Kubo 不可用

检查：

```bash
docker ps | grep ipfs

curl -sS -X POST \
  http://127.0.0.1:5001/api/v0/version
```

必要时：

```bash
docker restart ipfs
```

### 17.6 E2E 重复运行

测试每次自动生成唯一设备 ID 和批次 ID，因此允许重复运行。每次正向执行都会向 Fabric 世界状态写入：

- 两条新设备注册记录；
- 一条新批记录；
- 一个新的 IPFS 批次包。

---

## 18. 停止与重启

停止 Fabric 测试网络并清除账本：

```bash
cd ~/basr/blockchain/fabric-samples/test-network
./network.sh down
```

注意：该操作会删除当前测试网络状态。之后需要重新：

1. 创建网络与通道；
2. 设置 Anchor Peer；
3. 部署 Chaincode；
4. 再运行 E2E。

停止 IPFS：

```bash
docker stop ipfs
```

重新启动 IPFS：

```bash
docker start ipfs
```

---

## 19. 实验测试入口

当前实现已经可以进入实验数据采集阶段。建议后续分别测量：

- `Setup`
- `Registration.createRequest`
- Chaincode `RegisterDevice`
- `RecKeyGen`
- `Sign`（$\beta=0$ 与 $\beta=1$）
- `SigVerify`
- `Aggregate`
- `PackageCodec.encode`
- IPFS `put`
- Fabric `CreateBatchRecord`
- `AggVerify`
- `Recovery`
- 总体端到端时间
- 不同设备数量和敏感报告比例下的计算、通信与存储开销

正式性能实验应使用独立 benchmark，不应直接以 JUnit E2E 总时长作为算法性能结果。

---

## 20. 当前里程碑

当前代码已经完成：

```text
BASR 密码算法
+ Fabric 设备注册表
+ POP 链上验证
+ IPFS 批次存储
+ BRec 链上记录
+ Fabric Gateway
+ FabricDeviceRegistry
+ BasrWorkflowService
+ 正向真实 E2E
+ 三项负向真实测试
```

因此，当前仓库已经具备执行 BASR 算法全流程和进入实验评估阶段的条件。
