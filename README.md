# 🚀 NodeHarvester (Tizi1) - 代理节点深度采集与云端多协议测活引擎

[![Actions Status](https://github.com/luyuandong6b/tizi1/actions/workflows/collect.yml/badge.svg)](https://github.com/luyuandong6b/tizi1/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Protocols](https://img.shields.io/badge/Protocols-Hy2%20%7C%20VLESS%20%7C%20VMess%20%7C%20HTTPS-blue)](RULES.md)
[![Execution Mode](https://img.shields.io/badge/Trigger-Manual%20Dispatch%20Only-brightgreen)](RULES.md)

基于 **GitHub Actions 云端高并发执行 + 本地 GitHub Token 按需手动控制** 的全自动化代理节点采集与测活引擎。

---

## 📌 订阅直链 (Direct Subscription URLs)

| 订阅名称 | 内容说明 | 原始订阅链接 |
| :--- | :--- | :--- |
| **高精存活池 (推荐)** | 经 250 并发测活 + **单物理 IP 绝对唯一去重** 的纯净可用节点 | `https://raw.githubusercontent.com/luyuandong6b/tizi1/main/valid_proxies.txt` |
| **全量候选池** | 汇总全网 50+ 个源、经协议白名单与 TLS 辨识后的全量节点池 | `https://raw.githubusercontent.com/luyuandong6b/tizi1/main/all_proxies.txt` |

> 💡 **客户端支持**：兼容 sing-box、Clash Meta / Mihomo、v2rayN、Shadowrocket 等主流客户端。

---

## 🌟 核心特性与 7 大执行铁律

本项目严格遵循 [RULES.md](RULES.md) 规定的 7 大执行铁律：

1. **协议头标准化规范**：统一将非标准的 `hy2://` 重写为 sing-box 标准的 `hysteria2://`，并自动补齐 `insecure=1` 与 `sni`。
2. **单物理 IP 绝对唯一去重**：静态初筛 + 测活时通过 Socket 底层 `peername` 获取真实物理出口 IP，**相同的物理 IP 绝不重复出现**，彻底消灭换皮套壳节点。
3. **超低关注度小众宝藏源聚合**：
   - 覆盖 5 个 1~20 Stars 的高频防封宝藏源（`ProxyRift`, `vless-subscriptions`, `vless-sub-hub`, `FlareFeed`, `proxy-and-vless-collector`），防封锁、不拥堵。
   - 覆盖 29 个中立专线订阅与 13 个 GitHub 动态目录树项目。
   - 智能解析引擎：自适应单行明文、全文 Base64、逐行 Base64、Clash YAML。
4. **均衡防误杀初筛**：仅剔除 `.ir` 等无大陆路由的绝对死域，零误杀。
5. **云端原生异步并发测活**：`asyncio` 250 独立网络握手，逐点探测，零批次连坐。
6. **协议白名单聚焦**：仅保留 `hysteria2`、`vless` (Reality/TLS)、`vmess` (TLS)、`https` 四大加密协议，其余一律抛弃。
7. **多协议 TLS 针对性辨识**：针对各协议底层特征精准判定 TLS 真伪，100% 拦截裸明文。
8. **纯手动触发模式**：移除自动定时任务，仅保留 `workflow_dispatch`，杜绝不必要的免费时长消耗，完全通过本地控制器按需启动。

---

## 🛠️ 仓库文件架构

```text
├── .github/
│   └── workflows/
│       └── collect.yml      # GitHub Actions 工作流 (纯手动控制触发)
├── collector.py             # 云端核心采集、清洗与 250 并发测活引擎
├── RULES.md                 # 7 大执行铁律规范说明文档
├── requirements.txt         # 运行依赖 (标准库零依赖)
├── .gitignore               # Git 忽略配置
├── all_proxies.txt          # 全网采集汇总后的候选节点池
├── valid_proxies.txt        # 测活通过且单物理 IP 唯一的最终可用池
└── seen_hashes.txt          # 节点特征指纹去重记录
```

---

## 🎮 手动控制方式

在本地电脑上，使用配套的控制台 `控制云端采集.py` 或双击 `一键触发云端采集.bat`，即可使用 GitHub Token 一键远程下发采集测活指令，任务完成后自动下载最新结果到本地。

---

## ⚖️ 免责声明 (Disclaimer)

本项目仅用于网络安全研究、协议连通性测试与分布式系统学习，所有节点数据均来自于互联网公开中立项目。请使用者遵守当地法律法规，严禁用于任何非法用途。
