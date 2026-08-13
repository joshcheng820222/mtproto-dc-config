# mtproto-dc-config

Telegram MTProto DC 配置文件，兼容 Surge [MTProto Proxy Server](https://manual.nssurge.com/features/mtproto.html) 的 JSON 格式。

- `mtproto-dc-config-ipv4.json` — 仅 IPv4（IPv6 路由差的网络避免 Surge 优先试 v6 导致卡顿）
- `mtproto-dc-config.json` — IPv4 + IPv6（IPv6 已按 RFC 5952 规范化）

GitHub Actions 每日自动构建更新。

## 使用方法

Surge 配置文件 `[MTProto]` Section 下新增：

```ini
dc-config-url = https://raw.githubusercontent.com/joshcheng820222/mtproto-dc-config/main/mtproto-dc-config-ipv4.json
```

## 与 Surge 官方 MTProtoDCConfigGenerator 的区别

- CI 每日自动构建
- 修复官方版 IPv6 未 normalize 导致的重复 DC 配置项 bug（同一地址的全展开与压缩写法并存）
- 额外提供 IPv4-only 版本
- 输出 Surge 新版要求的 encoded options 字符串格式（`[N]{flags:int,...}` + CSV 行），而非旧的 JSON 数组

数据源（与 [SukkaW/Surge](https://github.com/SukkaW/Surge) 相同）：

1. `help.getConfig` MTProto 直连（telethon，免登录）
2. 备用端点：DNS TXT `apv3.stel.com`、Firebase RTDB、Firestore、AppEngine
3. 静态 bootstrap 列表（DC1–5）

## 本地运行

```bash
pip install telethon pycryptodome
python generate.py
```
