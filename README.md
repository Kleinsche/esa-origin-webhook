# ESA 回源更新 Webhook（阿里云 ESA 边缘函数）

<table><tr>
<td align="center">
  <a href="https://esa.console.aliyun.com/edge/pages/creation"><img src="https://img.shields.io/badge/%E9%83%A8%E7%BD%B2%E5%88%B0-ESA%20Pages%20%C2%B7%20%E4%B8%AD%E5%9B%BD%E7%AB%99-FF6A00?style=for-the-badge&logo=alibabacloud&logoColor=white" alt="部署到 ESA Pages（中国站）" height="32"></a><br>
  <sub>中国站</sub>
</td>
<td align="center">
  <a href="https://esa.console.alibabacloud.com/edge/pages/creation"><img src="https://img.shields.io/badge/Deploy%20to-ESA%20Pages%20%C2%B7%20Intl-0B4C8C?style=for-the-badge&logo=alibabacloud&logoColor=white" alt="部署到 ESA Pages（国际站）" height="32"></a><br>
  <sub>国际站</sub>
</td>
</tr></table>

按你的账号所在站点点任意一个按钮，会跳转到 ESA「函数和 Pages」的创建流程，下面这些字段需手填：

| 字段 | 预填值 |
| --- | --- |
| 部署来源 | GitHub 仓库 `https://github.com/Kleinsche/esa-origin-webhook` |
| 项目名称 | `esa-origin-webhook` |
| 生产分支 | `main` |
| 根目录 | `/`（若与 EdgeOne 版本同仓，改填 `/esa-origin-webhook`） |
| 安装命令 | `npm install` |
| 构建命令 / 静态资源目录 | 均留空（本项目只有边缘函数，无静态产物） |
| 函数入口 | `esa.js`（由仓库根目录的 `esa.jsonc` 提供，优先级高于控制台填写） |
| 环境变量清单 | `ESA_ACCESS_KEY_ID`、`ESA_ACCESS_KEY_SECRET`、`ESA_SITE_ID`、`WEBHOOK_TOKEN` |

环境变量的**取值**仍需自己补齐：AccessKey 到 RAM 控制台获取（[中国站](https://ram.console.aliyun.com/manage/ak) / [国际站](https://ram.console.alibabacloud.com/manage/ak)，建议只授予文末《最小权限 RAM 策略》里的那几个 Action）；`ESA_SITE_ID` 填纯数字的 ESA 站点 ID；`WEBHOOK_TOKEN` 填一个高强度随机串。其余变量属于可选加固或调优项，需要时按下方 [环境变量](#环境变量) 表格自行添加。

一个部署在**阿里云 ESA（边缘安全加速）边缘函数**上的小服务：通过 HTTP Webhook 更新 ESA 加速域名的**回源地址**与 **HTTP/HTTPS 回源端口**。

本项目由 `edgeone-origin-webhook`（腾讯云 EdgeOne 版本）迁移而来，把平台从 EdgeOne 换成阿里云 ESA，接口风格与调用方式保持一致：

| | EdgeOne 版 | ESA 版（本项目） |
| --- | --- | --- |
| 站点标识 | `zoneId`（ZoneId） | `siteId`（ESA 站点 ID，纯数字） |
| 域名对象 | 加速域名 `ModifyAccelerationDomain` | 站点下的记录（加速域名）`ListRecords` / `UpdateRecord` |
| 回源地址 | `OriginInfo.Origin` 等 | 源地址池 `UpdateOriginPool`，或记录值 `UpdateRecord` |
| 回源端口 | `OriginInfo.OriginPort/BackupOriginPort` | 回源规则 `UpdateOriginRule`（`OriginHttpPort` / `OriginHttpsPort` / `OriginScheme`） |
| 回源协议 | `OriginProtocol` | `OriginScheme`（`http` / `https` / `follow`） |
| 签名 | TC3-HMAC-SHA256 | ACS3-HMAC-SHA256 |

## 接口

### `POST /update-origin`

请求体（JSON）：

```jsonc
{
  "secret": "你的令牌",        // 必填，若配置了 WEBHOOK_TOKEN
  "domain": "www.example.com",  // 必填：站点下的记录名（加速域名）
  "ip": "1.2.3.4",              // 必填：新回源地址，也支持 origin / origins / value；多源站用逗号分隔
  "siteId": 1234567890123,      // 可选，缺省用环境变量 ESA_SITE_ID
  "originPoolId": 12345,        // 可选，显式指定写入哪个源地址池
  "httpPort": 80,               // 可选：HTTP 回源端口
  "httpsPort": 443,             // 可选：HTTPS 回源端口
  "originProtocol": "follow",   // 可选：http / https / follow（等价于 ESA 的 OriginScheme）
  "dryRun": "true"              // 可选：只回显 before/after，不写 API
}
```

响应（成功）：

```jsonc
{
  "ok": true,
  "dryRun": false,
  "message": "origin updated, http port=80, https port=443",
  "requestId": "A1B2C3D4-...",        // ESA API 返回的 RequestId
  "domain": "www.example.com",
  "siteId": 1234567890123,
  "writeTo": "originPool",             // originPool = 写源地址池；record = 写记录值
  "before": { "originPool": { "id": 12345, "name": "default-pool", "origins": [{ "address": "9.9.9.9", "enabled": true, "weight": 100 }] } },
  "after":  { "originPool": { "id": 12345, "name": "default-pool", "origins": [{ "address": "1.2.3.4", "enabled": true, "weight": 100 }] } },
  "notes": ["回源地址写入源地址池「default-pool」（Id: 12345）"]
}
```

### `GET /update-origin`（默认关闭）

- `?domain=www.example.com` → 查询当前回源（需 `ESA_ALLOW_DESCRIBE=true`）
- `?domain=www.example.com&ip=1.2.3.4` → 直接更新（需 `ESA_ALLOW_GET_UPDATE=true`，仅建议内网/调试使用）

其它路径返回 `404`，`OPTIONS` 返回 `204`（CORS 预检）。

## 回源写入位置的判定逻辑

ESA 中「回源地址」可能落在两个位置，脚本按以下顺序决定写哪里：

1. 请求传了 `originPoolId`（或环境变量 `ESA_ORIGIN_POOL_ID`）→ 写该**源地址池**；
2. 记录的 `RecordSourceType = OP`（源地址池源站）→ 自动查该记录引用的**源地址池**并写入；
3. 其余情况（普通域名源站的 CNAME、代理加速的 A/AAAA 记录）→ 直接改**记录值** `Data.Value`。
   - CNAME 记录若传入 IP 会返回 `400`，请改用源地址池；
   - A/AAAA 记录传入域名会返回 `400`。

> `UpdateOriginPool` 的 `Origins` 是**全量覆盖**：脚本会按位置复用原有条目的 `Name / Type / Enabled / Weight / Header`，只替换 `Address`，不会把多源站配置压成一条。

**回源端口/协议**属于站点级「回源规则」，只有在请求显式传了 `httpPort` / `httpsPort` / `originProtocol` 时才修改：

- 先找 `Rule` 中 `http.host eq "<domain>"` 的规则；
- 没有则回退到全局配置（`ConfigType=global`）；
- 都没有则新建一条按该域名匹配的规则（可设置 `ESA_ALLOW_CREATE_ORIGIN_RULE=false` 禁止）。

## 环境变量

在 ESA 控制台（Pages → 项目 → 环境变量 / 密钥）中配置：

| 变量 | 必填 | 说明 |
| --- | --- | --- |
| `ESA_ACCESS_KEY_ID` | ✅ | RAM 用户的 AccessKey ID（兼容 `ALIBABA_CLOUD_ACCESS_KEY_ID`） |
| `ESA_ACCESS_KEY_SECRET` | ✅ | AccessKey Secret（兼容 `ALIBABA_CLOUD_ACCESS_KEY_SECRET`） |
| `ESA_SECURITY_TOKEN` | ➖ | STS 临时凭证时填写 |
| `ESA_SITE_ID` | ✅ | 默认 ESA 站点 ID（纯数字，ESA 控制台 → 站点概览） |
| `ESA_API_ENDPOINT` | ➖ | 默认 `https://esa.cn-hangzhou.aliyuncs.com`；国际站用 `https://esa.ap-southeast-1.aliyuncs.com` |
| `ESA_API_TIMEOUT_MS` | ➖ | 单个 API 超时，默认 `15000` |
| `WEBHOOK_TOKEN` | 建议 | 调用令牌，`secret` 不匹配返回 `401` |
| `ESA_ALLOWED_DOMAINS` | ➖ | 域名白名单，逗号分隔 |
| `ESA_CORS_ORIGIN` | ➖ | CORS 来源，默认 `*` |
| `ESA_ALLOW_GET_UPDATE` | ➖ | 允许 GET 触发更新，默认 `false` |
| `ESA_ALLOW_DESCRIBE` | ➖ | 允许 GET 查询，默认 `false` |
| `ESA_ORIGIN_SEPARATOR` | ➖ | 多源站分隔符，默认 `,` |
| `ESA_ORIGIN_WEIGHT` | ➖ | 新建源站条目默认权重，默认 `100` |
| `ESA_ORIGIN_POOL_ID` | ➖ | 缺省写入的源地址池 |
| `ESA_ALLOW_CREATE_ORIGIN_RULE` | ➖ | 置为 `false` 时禁止自动创建回源规则 |
| `ESA_DRY_RUN` | ➖ | 置为 `true` 时全局演练，不写 API |

## 部署（ESA Pages + 边缘函数）

1. 把本目录推到一个 Git 仓库（若与 EdgeOne 项目同仓，请把 Pages 项目的「根目录」设为 `esa-origin-webhook`）。
2. ESA 控制台 → **边缘计算和 AI → 函数和 Pages** → 创建 → 导入 Github 仓库 → 连接该仓库；也可以直接点文档顶部的部署按钮，仓库与构建参数会自动带上。ESA 会读取根目录的 `esa.jsonc`（`entry: "esa.js"`）作为边缘函数入口。
3. 在项目设置中添加上表的环境变量（密钥类变量建议用「加密变量」）。
4. 部署完成后访问 `https://<你的 Pages 域名>/update-origin` 调用。

### 本地调试（可选）

```bash
cd esa-origin-webhook
cp .env.example .env   # 填入真实凭证与 ESA_SITE_ID
npm run dev            # http://localhost:8787/update-origin
```

`dev-server.mjs` 只是把 Node 的 HTTP 请求转成 Web 标准 `Request`，逻辑与线上完全一致。

## 调用示例

```bash
curl -X POST "https://<你的域名>/update-origin" \
  -H "Content-Type: application/json" \
  -d '{"secret":"你的令牌","domain":"www.example.com","ip":"1.2.3.4","httpPort":8080,"httpsPort":8443,"originProtocol":"follow"}'
```

DDNS 场景（只改 IP，不改端口）：

```bash
curl -X POST "https://<你的域名>/update-origin" \
  -H "Content-Type: application/json" \
  -d '{"secret":"你的令牌","domain":"home.example.com","ip":"203.0.113.10"}'
```

演练（不写 API）：

```bash
curl -X POST "https://<你的域名>/update-origin" \
  -H "Content-Type: application/json" \
  -d '{"secret":"你的令牌","domain":"www.example.com","ip":"1.2.3.4","dryRun":"true"}'
```

## 最小权限 RAM 策略

为 AccessKey 对应的 RAM 用户授予刚好够用的权限（把 `esa:*` 换成下列 Action 更安全）：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "esa:ListRecords",
        "esa:GetRecord",
        "esa:UpdateRecord",
        "esa:ListOriginPools",
        "esa:UpdateOriginPool",
        "esa:ListOriginRules",
        "esa:CreateOriginRule",
        "esa:UpdateOriginRule"
      ],
      "Resource": "*"
    }
  ]
}
```

不需要改回源端口时，可去掉 `esa:ListOriginRules` / `esa:CreateOriginRule` / `esa:UpdateOriginRule`；
不需要写记录值时，可去掉 `esa:UpdateRecord`。

## 注意事项

- **签名**：使用 ACS3-HMAC-SHA256（RPC 风格，参数放 QueryString、空请求体），签名密钥即 AccessKeySecret，不额外拼接字符；时间取 UTC（`x-acs-date`）。
- **HTTP 方法**：ESA 网关按接口校验方法，`List*` / `Get*` 只能用 `GET`，写入接口（`Update*` / `Create*`）只能用 `POST`，用错会返回 `UnsupportedHTTPMethod`。
- **全量覆盖**：`UpdateOriginPool` 的 `Origins` 会覆盖原列表，脚本仅在同位置替换地址；如需完全不同的多源站配置，请先用 `dryRun` 确认。
- **全局回源规则**：`ConfigType=global` 的规则只能改端口与协议，脚本不会回传 `RuleName / Rule / RuleEnable / Sequence`，避免触发 `CanNotSet*` 错误。
- **CNAME 不能写 IP**：ESA 要求 CNAME 记录值为域名；IP 回源请使用源地址池。
- **站点 ID**：ESA 站点 ID 是纯数字（如 `216558609793952`），不是域名。
- 建议配合 `WEBHOOK_TOKEN` 与 `ESA_ALLOWED_DOMAINS` 使用，避免接口被滥用。

## 目录结构

```
esa-origin-webhook/
├─ esa.jsonc            # ESA Pages 项目配置（entry: esa.js）
├─ esa.js               # 边缘函数入口：路由、鉴权、参数校验、更新与回读
├─ lib/esa-client.js    # ACS3 签名 + ESA OpenAPI 封装
├─ dev-server.mjs       # 本地调试服务器（可选）
├─ .env.example
├─ package.json
└─ LICENSE
```

## License

AGPL-3.0（与 EdgeOne 版本一致），详见 [LICENSE](./LICENSE)。
