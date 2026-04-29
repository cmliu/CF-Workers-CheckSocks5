# CF-Workers-CheckSocks5

![demo](./demo.png)

一个基于 Cloudflare Workers 的代理可用性检测工具。项目以单个 `_worker.js` 运行为核心，支持 SOCKS5、HTTP、HTTPS、TURN、SSTP 代理检测，提供网页端单条/批量检测、域名解析、出口 IP 信息展示、地图定位、结果筛选与导出。

> 当前源码没有内置 `TOKEN` 鉴权。部署到公开域名后，任何访问者都可以使用检测接口；如果需要私有使用，请在 Cloudflare 侧增加访问控制或自行扩展鉴权逻辑。

## 功能特性

- 支持 `socks5://`、`http://`、`https://`、`turn://`、`sstp://` 五类代理协议。
- 支持无认证代理、`username:password` 认证代理，以及 IPv4、域名、方括号 IPv6 地址。
- TURN 检测使用 TCP Allocation / CONNECT / ConnectionBind 流程，支持无认证 TURN 服务器和长期凭据认证。
- SSTP 检测使用 HTTPS SSTP 握手、PPP / IPCP 建链，并通过 PPP 内 TCP 连接读取出口信息。
- 支持单条检测和批量检测；批量模式会自动去重、解析域名并并发验证。
- 支持域名解析为 A / AAAA 记录，优先使用 Cloudflare DoH，失败后回退到 Google DoH。
- 支持代理出口信息展示，包括出口 IP、地区、ASN、运营商、风险标签、响应耗时等。
- 支持 Leaflet / OpenStreetMap 地图展示出口位置。
- 支持结果筛选，并可将有效结果复制到剪贴板或导出为 TXT / CSV。
- 支持深浅色主题、历史记录、访问人数显示和自定义页脚备案内容。

## 在线体验

Demo: <https://check.socks5.cmliussss.net>

## 部署方式

### Cloudflare Workers

1. 在 Cloudflare 控制台创建一个 Worker。
2. 将 [_worker.js](./_worker.js) 的全部内容复制到 Worker 编辑器中。
3. 保存并部署。
4. 访问 Worker 域名即可打开检测页面。

### Cloudflare Pages

如果使用 Pages，可将仓库连接到 Cloudflare Pages，并确保部署产物根目录包含 `_worker.js`。该文件会作为 Pages 的 Worker 入口处理请求。

项目没有额外构建步骤，也不依赖 `package.json`。

## 环境变量

当前源码只读取以下环境变量：

| 变量名 | 说明 | 示例 | 必需 |
| --- | --- | --- | --- |
| `BEIAN` | 自定义页面页脚 HTML。未设置时使用默认页脚，包含项目链接、访问人数和维护者链接。 | `© 2026 Example.com · ICP 备案号` | 否 |

## 支持的代理格式

```text
socks5://host:1080
socks5://username:password@host:1080
socks5://username:password@[2001:db8::1]:1080
http://host:80
http://username:password@host:80
https://host:443
https://username:password@host:443
turn://host:3478
turn://username:password@host:3478
sstp://host:443
sstp://username:password@host:443
```

网页端输入缺少协议头时，会默认按 `socks5://` 处理。端口缺省值分别为：

| 协议 | 默认端口 |
| --- | --- |
| `socks5` | `1080` |
| `http` | `80` |
| `https` | `443` |
| `turn` | `3478` |
| `sstp` | `443` |

### TURN 支持说明

`turn://` 目标会被当作 TURN over TCP 服务器检测。Worker 会先连接 TURN 服务器，再通过 TURN TCP 中继访问 `api.ipapi.is:443`，最后读取出口 IP 信息。

当前 TURN 实现有以下边界：

- 支持 RFC 6062 风格的 TCP Allocation、CreatePermission、CONNECT 和 ConnectionBind。
- 支持无认证服务器；如果服务端返回 `401` 认证挑战，并且链接中提供了 `username:password`，会使用长期凭据认证继续握手。
- 目标出口检测地址会解析为 IPv4 后发起 TURN CONNECT；当前不走 TURN UDP relay，也不支持 `turns://`。
- `turn://` 中的主机可以是 IP 或域名，端口未填写时默认使用 `3478`。

### SSTP 支持说明

`sstp://` 目标会被当作 SSTP over TLS 服务器检测。Worker 会先建立 SSTP HTTP 隧道，再完成 PPP / IPCP 协商，随后在 PPP 内构造 TCP 连接访问 `api.ipapi.is:443`，最后读取出口 IP 信息。

当前 SSTP 实现有以下边界：

- 支持无认证 SSTP 服务器；如果 PPP 协商要求认证，仅支持 PAP，并使用链接中提供的 `username:password`。
- 目标出口检测地址会解析为 IPv4 后建立 PPP 内 TCP 连接；当前 SSTP 检测依赖服务端分配 IPv4 地址。
- `sstp://` 中的主机可以是 IP 或域名，端口未填写时默认使用 `443`。

## API

所有 JSON 接口都带有 CORS 响应头，并支持 `OPTIONS` 预检请求。

### `GET /check`

检测单个代理是否可用。Worker 会通过代理建立到 `api.ipapi.is` 的连接，并读取该服务返回的出口 IP 信息。

请求参数支持以下写法：

```text
/check?socks5=proxy.example.com:1080
/check?http=proxy.example.com:80
/check?https=proxy.example.com:443
/check?turn=turn.example.com:3478
/check?sstp=vpn:vpn@vpn205396913.opengw.net:1922

/check?proxy=socks5://user:pass@proxy.example.com:1080
/check?proxy=http://proxy.example.com:80
/check?proxy=https://proxy.example.com:443
/check?proxy=turn://user:pass@turn.example.com:3478
/check?proxy=sstp://vpn:vpn@vpn890321947.opengw.net:1630
/check/proxy=socks5://proxy.example.com:1080
```

响应示例：

```json
{
  "candidate": "proxy.example.com:1080",
  "type": "socks5",
  "username": null,
  "password": null,
  "hostname": "proxy.example.com",
  "port": 1080,
  "link": "socks5://proxy.example.com:1080",
  "success": true,
  "responseTime": 523,
  "exit": {
    "ip": "203.0.113.10",
    "rir": "APNIC",
    "is_datacenter": true,
    "is_proxy": false,
    "is_vpn": false,
    "asn": {
      "asn": 64500,
      "org": "Example Network"
    },
    "location": {
      "country": "Japan",
      "country_code": "JP",
      "city": "Tokyo",
      "latitude": 35.6895,
      "longitude": 139.6917
    }
  }
}
```

失败时会返回 `success: false` 和 `error` 字段。

### `GET /resolve`

将域名或代理链接解析为可检测的 `host:port` 列表。

参数别名：

- `proxyip`
- `target`
- `host`

示例：

```bash
curl "https://your-worker.example.workers.dev/resolve?proxyip=socks5://proxy.example.com:1080"
```

响应示例：

```json
[
  "198.51.100.10:1080",
  "[2001:db8::10]:1080"
]
```

解析规则：

- 输入已经是 IPv4 或 IPv6 时，直接返回原目标和端口。
- 输入是域名时，解析 A / AAAA 记录。
- 未提供端口时，解析接口默认使用 `443`。

### `POST /resolve-batch`

批量解析目标。单次最多 `50` 个。

请求体支持 `targets` 或 `proxyips`：

```json
{
  "targets": [
    "socks5://proxy-a.example.com:1080",
    "proxy-b.example.com:1080"
  ]
}
```

响应示例：

```json
{
  "results": [
    {
      "input": "proxy-b.example.com:1080",
      "targets": [
        "198.51.100.20:1080"
      ]
    }
  ]
}
```

## 网页端使用

1. 打开部署后的 Worker 域名。
2. 在输入框中填写代理链接、`IP:端口`、`域名:端口` 或带认证的代理地址。
3. 如需批量检测，打开「批量检测」并粘贴多行目标。
4. 点击「开始检测」。
5. 检测完成后，可按全部/有效/失败/风控评级、协议和国家地区筛选，并导出有效结果。

也可以直接通过路径触发单条检测：

```text
https://your-worker.example.workers.dev/socks5://proxy.example.com:1080
```

## 运行参数

源码中的主要限制和超时：

| 参数 | 当前值 | 说明 |
| --- | --- | --- |
| `CHECK_TIMEOUT_MS` | `12000` | 单次代理检测总超时 |
| `CONNECT_TIMEOUT_MS` | `9999` | 代理连接和握手超时 |
| `READ_TIMEOUT_MS` | `8000` | 读取远端响应超时 |
| `MAX_RESPONSE_BYTES` | `96 KiB` | 读取出口信息响应的最大字节数 |
| `RESOLVE_BATCH_LIMIT` | `50` | 批量解析接口单次最大目标数 |
| 前端检测并发 | `32` | 网页端批量检测的并发数 |

## 注意事项

- Cloudflare Workers 的 TCP Socket 能力由 `cloudflare:sockets` 提供，请确保部署环境支持 Workers TCP 出站连接。
- 检测逻辑会把代理作为隧道访问 `api.ipapi.is`，因此结果反映的是该代理访问该目标服务时的可用性和出口信息。
- TURN 检测依赖 TURN 服务器支持 TCP relay / CONNECT；只支持 UDP relay 的 TURN 服务会检测失败。
- SSTP 检测依赖服务端支持 SSTP over TLS、PPP / IPCP 和 IPv4 分配；仅支持 PAP 认证，不支持 MS-CHAP 等其他 PPP 认证方式。
- 公开部署时请谨慎使用真实代理账号密码；当前页面和接口没有访问令牌保护。
- 大批量检测可能受到 Cloudflare Workers 执行时长、并发和外部 DNS/API 可用性的影响。

## 许可证

本项目基于 [GNU General Public License v3.0](./LICENSE) 发布。

## 致谢
- [@Alexandre_Kojeve](https://t.me/Enkelte_notif/821)
- [Cloudflare Workers](https://workers.cloudflare.com/)
- [ipapi.is](https://ipapi.is/)
- [Cloudflare DNS](https://cloudflare-dns.com/)
- [OpenStreetMap](https://www.openstreetmap.org/)
- [Leaflet](https://leafletjs.com/)
