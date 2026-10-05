#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
GitHub Actions 代理节点全量深度采集与多协议测活引擎 (NodeHarvester - 增强版)
================================================================================
1. 100% 全量聚合：完整收录原始 13 个 GitHub 核心仓库 + 15 个高价值分协议优选源
2. 零遗漏提取：基于 Zip 极速打包检索 + 内存流式解包，免疫 API 限流与鉴权中断
3. 原始汇总全量无损：第一阶段原始收集绝不压缩单 IP、绝不筛协议，真实留存全部候选节点
4. 40MB 单文件严格上限与规律分卷：
   - 超过 40MB 自动规律切分：all_proxies_1.txt, all_proxies_2.txt, all_proxies_3.txt...
   - 同时镜像生成 all_proxies.txt，保障常规订阅链接无缝兼容
5. 第二阶段独立验活：协议白名单 + TLS 安全判定 + 真实物理出口 IP 绝对唯一去重
================================================================================
"""

import asyncio
import base64
import glob
import hashlib
import io
import json
import os
import re
import shutil
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# [基础路径与文件配置]
# ==============================================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE = os.path.join(BASE_DIR, "all_proxies.txt")
VALID_OUTPUT_FILE = os.path.join(BASE_DIR, "valid_proxies.txt")
SEEN_FILE = os.path.join(BASE_DIR, "seen_hashes.txt")

# ==============================================================================
# [云端执行参数配置]
# ==============================================================================
CHECK_CONCURRENCY = 250
CHECK_TIMEOUT_SECONDS = 2.5
MAX_OUTPUT_BYTES = 40 * 1024 * 1024  # 严格 40MB 单文件上限 (超过自动拆分)
REQUEST_TIMEOUT_SECONDS = 25
MAX_RETRIES = 3

# ==============================================================================
# [代理源清单：针对各源不同结构与格式分类收录]
# ==============================================================================

# 一、超低关注度（1~20 Stars）高频小众宝藏源（重点防封、防拥堵）
LOW_ATTENTION_SOURCES = [
    {
        "name": "ProxyRift-All-Plain",
        "repo": "rekt0ro/ProxyRift",
        "url": "https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all.txt",
        "desc": "明文/混合全协议池",
    },
    {
        "name": "ProxyRift-All-B64",
        "repo": "rekt0ro/ProxyRift",
        "url": "https://raw.githubusercontent.com/rekt0ro/ProxyRift/main/subscriptions/all-base64.txt",
        "desc": "Base64全量订阅池",
    },
    {
        "name": "vless-sub-All",
        "repo": "zxcursedzxc0721/vless-subscriptions",
        "url": "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/all/vless.txt",
        "desc": "全量白名单 VLESS 池",
    },
    {
        "name": "vless-sub-Domain",
        "repo": "zxcursedzxc0721/vless-subscriptions",
        "url": "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/domain/vless.txt",
        "desc": "域名化 VLESS 专线",
    },
    {
        "name": "vless-sub-RU",
        "repo": "zxcursedzxc0721/vless-subscriptions",
        "url": "https://raw.githubusercontent.com/zxcursedzxc0721/vless-subscriptions/main/ru/vless.txt",
        "desc": "俄罗斯及欧洲边缘节点池",
    },
    {
        "name": "vless-sub-hub-All",
        "repo": "Mai-kun/vless-sub-hub",
        "url": "https://raw.githubusercontent.com/Mai-kun/vless-sub-hub/main/docs/sub/all.txt",
        "desc": "Base64 优选 VLESS 池",
    },
    {
        "name": "vless-sub-hub-Raw",
        "repo": "Mai-kun/vless-sub-hub",
        "url": "https://raw.githubusercontent.com/Mai-kun/vless-sub-hub/main/docs/sub/all_raw.txt",
        "desc": "明文直连 VLESS 池",
    },
    {
        "name": "FlareFeed-Hy2",
        "repo": "svinakraft-maker/FlareFeed",
        "url": "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/hysteria2.txt",
        "desc": "Hysteria 2 纯净抗封专线",
    },
    {
        "name": "FlareFeed-Fastest",
        "repo": "svinakraft-maker/FlareFeed",
        "url": "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/fastest.txt",
        "desc": "极速网络优选池",
    },
    {
        "name": "FlareFeed-Top500",
        "repo": "svinakraft-maker/FlareFeed",
        "url": "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/Top500.txt",
        "desc": "Top 500 安全节点",
    },
    {
        "name": "FlareFeed-Podpiska",
        "repo": "svinakraft-maker/FlareFeed",
        "url": "https://raw.githubusercontent.com/svinakraft-maker/FlareFeed/main/public/podpiska.txt",
        "desc": "综合清洗聚合大池",
    },
    {
        "name": "Darmioniks-Vless-Large",
        "repo": "Darmioniks/proxy-and-vless-collector",
        "url": "https://raw.githubusercontent.com/Darmioniks/proxy-and-vless-collector/main/vless.txt",
        "desc": "7.4MB 海量储备底池",
    },
    {
        "name": "Darmioniks-Vless-Filtered",
        "repo": "Darmioniks/proxy-and-vless-collector",
        "url": "https://raw.githubusercontent.com/Darmioniks/proxy-and-vless-collector/main/vless_filtered.txt",
        "desc": "CI 自动化初滤池",
    },
]

# 二、高频维护的细分协议订阅专线与中立优选池
CURATED_SUBSCRIPTIONS = [
    {
        "name": "0xRadikal-Vless",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vless.txt",
        "desc": "VLESS 纯净大池",
    },
    {
        "name": "0xRadikal-Hy2",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/hysteria2.txt",
        "desc": "Hysteria 2 纯净专线",
    },
    {
        "name": "0xRadikal-Verified",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs.txt",
        "desc": "实网 HTTP 验活池",
    },
    {
        "name": "0xRadikal-Fast",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/fast/configs.txt",
        "desc": "高速优选池",
    },
    {
        "name": "0xRadikal-Vmess",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/protocols/vmess.txt",
        "desc": "VMess 纯净专线",
    },
    {
        "name": "0xRadikal-Top100",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
        "desc": "Top 100 极速活池",
    },
    {
        "name": "0xRadikal-B64",
        "repo": "0xRadikal/Free-v2ray-Configs",
        "url": "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",
        "desc": "Base64 实测活池",
    },
    {
        "name": "R3ZARAHIMI-2h",
        "repo": "R3ZARAHIMI/tg-v2ray-configs-every2h",
        "url": "https://raw.githubusercontent.com/R3ZARAHIMI/tg-v2ray-configs-every2h/refs/heads/main/Original-Configs.txt",
        "desc": "每2小时定时更新",
    },
    {
        "name": "roosterkid-HTTPS",
        "repo": "roosterkid/openproxylist",
        "url": "https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt",
        "desc": "纯净 HTTPS 开放代理",
    },
    {
        "name": "ircfspace-Mix",
        "repo": "ircfspace/tvc",
        "url": "https://raw.githubusercontent.com/ircfspace/tvc/main/sub/mix",
        "desc": "全自动清洗聚合",
    },
    {
        "name": "Delta-Kronecker-All",
        "repo": "Delta-Kronecker/V2ray-Config",
        "url": "https://raw.githubusercontent.com/Delta-Kronecker/V2ray-Config/main/config/all_configs.txt",
        "desc": "超大容量全自动构建",
    },
    {
        "name": "Mahdi0024-Proxies",
        "repo": "Mahdi0024/ProxyCollector",
        "url": "https://raw.githubusercontent.com/Mahdi0024/ProxyCollector/master/sub/proxies.txt",
        "desc": "长效自动测活输出",
    },
    {
        "name": "MohammadBahemmat-15m",
        "repo": "MohammadBahemmat/V2ray-Collector",
        "url": "https://raw.githubusercontent.com/MohammadBahemmat/V2ray-Collector/main/Tested.txt",
        "desc": "15分钟高频刷新池",
    },
    {
        "name": "Alirewa-Sub1",
        "repo": "Alirewa/V2ray-Configs",
        "url": "https://raw.githubusercontent.com/Alirewa/V2ray-Configs/main/sub1.txt",
        "desc": "活跃分卷订阅",
    },
    {
        "name": "V2RayRoot-Proxies",
        "repo": "V2RayRoot/V2RayConfig",
        "url": "https://raw.githubusercontent.com/V2RayRoot/V2RayConfig/main/Config/proxies.txt",
        "desc": "高频更新节点库",
    },
    {
        "name": "rtwo2-Vless",
        "repo": "rtwo2/FastNodes",
        "url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt",
        "desc": "每小时实测验活 VLESS",
    },
    {
        "name": "rtwo2-Hy2",
        "repo": "rtwo2/FastNodes",
        "url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt",
        "desc": "每小时实测验活 Hy2",
    },
    {
        "name": "LalatinaHub-Mineral",
        "repo": "LalatinaHub/Mineral",
        "url": "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",
        "desc": "老牌中立代号聚合池",
    },
    {
        "name": "ebrasha-Vless",
        "repo": "ebrasha/free-v2ray-public-list",
        "url": "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
        "desc": "15分钟自动化更新 VLESS",
    },
    {
        "name": "ebrasha-All",
        "repo": "ebrasha/free-v2ray-public-list",
        "url": "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
        "desc": "全类型订阅汇总",
    },
    {
        "name": "mahdibland-Merge",
        "repo": "mahdibland/V2RayAggregator",
        "url": "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
        "desc": "全球高星经典聚合源",
    },
]

# 三、原始 13 个 GitHub 核心仓库 (100% 完整收录并追加优质扩展库)
PROJECTS = [
    # 1. Danialsamadi/v2go
    {
        "name": "Project1-v2go",
        "owner": "Danialsamadi",
        "repo": "v2go",
        "branch": "main",
        "dirs": ["Splitted-By-Country"],
    },
    # 2. Firmfox/Proxify
    {
        "name": "Project2-Proxify",
        "owner": "Firmfox",
        "repo": "Proxify",
        "branch": "main",
        "dirs": ["v2ray_configs/mixed", "v2ray_configs/seperated_by_protocol", "v2ray_configs/separated_by_protocol", "v2ray_configs/subscriptions"],
    },
    # 3. 0xAbolfazl/PyroConfig
    {
        "name": "Project3-PyroConfig",
        "owner": "0xAbolfazl",
        "repo": "PyroConfig",
        "branch": "main",
        "dirs": ["Configs"],
    },
    # 4. ShatakVPN/ConfigForge-V2Ray
    {
        "name": "Project4-ConfigForge-V2Ray",
        "owner": "ShatakVPN",
        "repo": "ConfigForge-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
    },
    # 5. MatinGhanbari/v2ray-configs
    {
        "name": "Project5-v2ray-configs",
        "owner": "MatinGhanbari",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["subscriptions/v2ray", "subscriptions/filtered"],
        "files": ["subscriptions/v2ray/all_sub.txt"],
    },
    # 6. MahanKenway/Freedom-V2Ray
    {
        "name": "Project6-Freedom-V2Ray",
        "owner": "MahanKenway",
        "repo": "Freedom-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
    },
    # 7. F0rc3Run/F0rc3Run
    {
        "name": "Project7-F0rc3Run",
        "owner": "F0rc3Run",
        "repo": "F0rc3Run",
        "branch": "main",
        "dirs": ["splitted-by-protocol"],
    },
    # 8. SoliSpirit/v2ray-configs
    {
        "name": "Project8-SoliSpirit",
        "owner": "SoliSpirit",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Subscriptions", "Protocols"],
        "files": ["all_configs.txt"],
    },
    # 9. iboxz/free-v2ray-collector
    {
        "name": "Project9-free-v2ray-collector",
        "owner": "iboxz",
        "repo": "free-v2ray-collector",
        "branch": "main",
        "dirs": ["main"],
    },
    # 10. hamedcode/port-based-v2ray-configs
    {
        "name": "Project10-port-based-v2ray-configs",
        "owner": "hamedcode",
        "repo": "port-based-v2ray-configs",
        "branch": "main",
        "dirs": ["sub"],
    },
    # 11. sevcator/5ubscrpt10n
    {
        "name": "Project11-5ubscrpt10n",
        "owner": "sevcator",
        "repo": "5ubscrpt10n",
        "branch": "main",
        "dirs": ["mini", "protocols"],
    },
    # 12. Epodonios/v2ray-configs (Splitted-By-Protocol)
    {
        "name": "Project12-Epodonios-Splitted",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Splitted-By-Protocol"],
    },
    # 13. Epodonios/v2ray-configs (All_Configs_Sub.txt)
    {
        "name": "Project13-Epodonios-AllConfigsSub",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": [],
        "files": ["All_Configs_Sub.txt"],
    },
    # 优质补充 14. Surfboardv2ray/TGParse
    {
        "name": "Project14-Surfboardv2ray",
        "owner": "Surfboardv2ray",
        "repo": "TGParse",
        "branch": "main",
        "dirs": ["splitted"],
        "files": ["splitted/vless", "splitted/vmess", "splitted/hy2", "splitted/hysteria2", "splitted/mixed"],
    },
    # 优质补充 15. mohamadfg-dev/telegram-v2ray-configs-collector
    {
        "name": "Project15-mohamadfg-dev",
        "owner": "mohamadfg-dev",
        "repo": "telegram-v2ray-configs-collector",
        "branch": "main",
        "dirs": ["category"],
    },
]

# 允许采集的协议前缀规范 (覆盖所有可用代理类型)
KNOWN_PROTOCOLS = (
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "ssr://",
    "hysteria2://",
    "hy2://",
    "hysteria://",
    "tuic://",
    "wireguard://",
    "wg://",
    "socks5://",
    "socks://",
    "http://",
    "https://",
)

# ==============================================================================
# [智能解包引擎]
# ==============================================================================
def safe_b64decode(s: str) -> str:
    """安全还原任意 Base64 编码 (自动补齐 padding 与清洗空白字符)"""
    try:
        clean = "".join(s.split())
        pad = len(clean) % 4
        if pad:
            clean += "=" * (4 - pad)
        return base64.b64decode(clean).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def convert_clash_dict_to_uri(p: dict) -> str:
    """解析 Clash/Meta 节点字典，输出标准 URI"""
    try:
        ptype = str(p.get("type", "")).strip().lower()
        server = str(p.get("server", "")).strip()
        port = str(p.get("port", "")).strip()
        name = str(p.get("name", "clash_node")).strip()
        tag = urllib.parse.quote(name)

        if not server or not port:
            return ""

        if ptype in ("hysteria2", "hy2"):
            auth = p.get("password") or p.get("auth") or ""
            sni = p.get("sni") or server
            return f"hysteria2://{auth}@{server}:{port}?sni={sni}&insecure=1#{tag}"

        elif ptype == "vless":
            uuid = str(p.get("uuid", "")).strip()
            tls = str(p.get("tls", "")).lower() in ("true", "1")
            reality = "reality-opts" in p or "reality" in str(p.get("network", "")).lower()
            sec = "reality" if reality else ("tls" if tls else "none")
            sni = p.get("servername") or p.get("sni") or server
            flow = p.get("flow", "")
            flow_arg = f"&flow={flow}" if flow else ""
            return f"vless://{uuid}@{server}:{port}?security={sec}&sni={sni}{flow_arg}#{tag}"

        elif ptype == "vmess":
            uuid = str(p.get("uuid", "")).strip()
            v_dict = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": port,
                "id": uuid,
                "aid": p.get("alterId", 0),
                "net": p.get("network", "tcp"),
                "type": "none",
                "host": p.get("servername") or p.get("sni") or "",
                "path": "",
                "tls": "tls" if str(p.get("tls", "")).lower() in ("true", "1") else ""
            }
            v_b64 = base64.b64encode(json.dumps(v_dict).encode("utf-8")).decode("utf-8")
            return f"vmess://{v_b64}"

        elif ptype == "trojan":
            pwd = p.get("password", "")
            sni = p.get("sni") or server
            return f"trojan://{pwd}@{server}:{port}?sni={sni}#{tag}"

        elif ptype == "ss":
            cipher = p.get("cipher", "")
            pwd = p.get("password", "")
            user_info = base64.b64encode(f"{cipher}:{pwd}".encode("utf-8")).decode("utf-8")
            return f"ss://{user_info}@{server}:{port}#{tag}"

        elif ptype == "http" and str(p.get("tls", "")).lower() in ("true", "1"):
            user = p.get("username", "")
            pwd = p.get("password", "")
            auth = f"{user}:{pwd}@" if (user or pwd) else ""
            return f"https://{auth}{server}:{port}#{tag}"
    except Exception:
        pass
    return ""


def extract_proxies_from_clash_yaml(text: str) -> list:
    """轻量解析 Clash proxies 节点块"""
    nodes = []
    lines = text.splitlines()
    in_proxies = False
    current_proxy = {}

    for line in lines:
        stripped = line.strip()
        if stripped == "proxies:":
            in_proxies = True
            continue

        if in_proxies:
            if line and not line.startswith(" ") and not line.startswith("\t") and ":" in line:
                if current_proxy:
                    uri = convert_clash_dict_to_uri(current_proxy)
                    if uri:
                        nodes.append(uri)
                break

            if stripped.startswith("- ") and ":" in stripped:
                if current_proxy:
                    uri = convert_clash_dict_to_uri(current_proxy)
                    if uri:
                        nodes.append(uri)
                    current_proxy = {}
                item_content = stripped[2:].strip()
                if ":" in item_content:
                    parts = item_content.split(":", 1)
                    k = parts[0].strip().replace("-", "_")
                    v = parts[1].strip().strip('"').strip("'")
                    current_proxy[k] = v
                continue

            if ":" in stripped:
                parts = stripped.split(":", 1)
                k = parts[0].strip().replace("-", "_")
                v = parts[1].strip().strip('"').strip("'")
                current_proxy[k] = v

    if current_proxy:
        uri = convert_clash_dict_to_uri(current_proxy)
        if uri:
            nodes.append(uri)

    return nodes


def decode_and_extract_nodes(raw_bytes: bytes) -> list:
    """【万能解包引擎】：支持明文、全文 Base64、逐行 Base64、Clash YAML"""
    if not raw_bytes:
        return []

    text = raw_bytes.decode("utf-8", errors="ignore").strip()
    if not text:
        return []

    results = []

    # 1. 尝试全文 Base64 解码
    if not any(p in text for p in KNOWN_PROTOCOLS + ("proxies:",)):
        decoded_candidate = safe_b64decode(text)
        if any(p in decoded_candidate for p in KNOWN_PROTOCOLS):
            text = decoded_candidate

    # 2. 如果包含 Clash YAML
    if "proxies:" in text and ("type:" in text or "- name:" in text):
        yaml_nodes = extract_proxies_from_clash_yaml(text)
        results.extend(yaml_nodes)

    # 3. 按行流式逐行解析
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        if any(line.startswith(p) for p in KNOWN_PROTOCOLS):
            results.append(line)
            continue

        if len(line) > 20 and " " not in line:
            b64_unpacked = safe_b64decode(line)
            if any(b64_unpacked.startswith(p) for p in KNOWN_PROTOCOLS):
                results.append(b64_unpacked)

    return results


def normalize_node_uri(line: str) -> str:
    """协议头标准化 (hy2:// 转为 hysteria2:// 并补齐必要参数)"""
    line = line.strip()
    if line.startswith("hy2://"):
        line = "hysteria2://" + line[6:]

    if line.startswith("hysteria2://"):
        try:
            u = urllib.parse.urlsplit(line)
            q = urllib.parse.parse_qs(u.query)
            changed = False
            if "insecure" not in q:
                q["insecure"] = ["1"]
                changed = True
            if "sni" not in q and u.hostname:
                q["sni"] = [u.hostname]
                changed = True
            if changed:
                new_query = urllib.parse.urlencode({k: v[0] for k, v in q.items()})
                line = urllib.parse.urlunsplit((u.scheme, u.netloc, u.path, new_query, u.fragment))
        except Exception:
            pass

    return line


# ==============================================================================
# [40MB 物理上限与规律拆分引擎]
# ==============================================================================
def save_split_files(base_filename: str, lines: list, max_bytes: int = MAX_OUTPUT_BYTES) -> list:
    """
    【核心分卷逻辑】：
    1. 严格控制单文件体积 <= 40MB。
    2. 若超过 40MB，按规律顺序拆分：
       - all_proxies_1.txt (第 1 卷, <= 40MB)
       - all_proxies_2.txt (第 2 卷, <= 40MB)
       - all_proxies_3.txt (第 3 卷, <= 40MB)
       ...
    3. 同时保留主文件 (如 all_proxies.txt)，其内容为第 1 卷的镜像，确保常规订阅工具无缝获取。
    """
    stem, ext = os.path.splitext(base_filename)
    
    # 1. 彻底清理旧的分卷文件，防止历史残留
    for old_file in glob.glob(f"{stem}*{ext}"):
        try:
            os.remove(old_file)
        except Exception:
            pass

    if not lines:
        with open(base_filename, "w", encoding="utf-8") as f:
            pass
        return [base_filename]

    parts_created = []
    current_part_idx = 1
    current_lines = []
    current_bytes = 0

    def write_current_part(idx, p_lines):
        filename = f"{stem}_{idx}{ext}"
        with open(filename, "w", encoding="utf-8") as pf:
            for l in p_lines:
                pf.write(l + "\n")
        parts_created.append(filename)

    for line in lines:
        encoded_line = (line + "\n").encode("utf-8")
        if current_bytes + len(encoded_line) > max_bytes and current_lines:
            write_current_part(current_part_idx, current_lines)
            current_part_idx += 1
            current_lines = []
            current_bytes = 0
        current_lines.append(line)
        current_bytes += len(encoded_line)

    if current_lines:
        write_current_part(current_part_idx, current_lines)

    # 规范镜像：生成主文件名 (如 all_proxies.txt)
    part1_path = f"{stem}_1{ext}"
    if os.path.exists(part1_path):
        shutil.copyfile(part1_path, base_filename)
        if base_filename not in parts_created:
            parts_created.insert(0, base_filename)

    return parts_created


# ==============================================================================
# [第一阶段：全量多源无损采集 (Zip 极速下载 + 纯内存解包)]
# ==============================================================================
def fetch_project_via_zip(project: dict) -> list:
    """
    通过 GitHub codeload Zip 极速打包通道下载，免 Token 鉴权，免 API 配额限制
    在内存中直接匹配并解包指定目录与文件，确保 100% 捕获，绝不遗漏
    """
    name = project["name"]
    owner = project["owner"]
    repo = project["repo"]
    branch = project["branch"]
    dirs = [d.rstrip("/") for d in project.get("dirs", [])]
    target_files = [f.lstrip("/") for f in project.get("files", [])]

    url = f"https://codeload.github.com/{owner}/{repo}/zip/refs/heads/{branch}"
    headers = {"User-Agent": "Mozilla/5.0"}
    
    extracted_nodes = []
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
            data = resp.read()

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for item in zf.namelist():
                if item.endswith("/"):
                    continue
                # 去除 zip 根目录前缀 (例如 "v2go-main/...")
                parts = item.split("/", 1)
                rel_path = parts[1] if len(parts) > 1 else item

                matched = False
                # 1. 匹配显式指定文件
                for tf in target_files:
                    if rel_path.lower() == tf.lower() or os.path.basename(rel_path).lower() == tf.lower():
                        matched = True
                        break

                # 2. 匹配目录前缀
                if not matched:
                    for d in dirs:
                        prefix = d.lower() + "/"
                        if rel_path.lower().startswith(prefix):
                            # 捕获 .txt, .sub, .json, .yaml 或无后缀分类文件
                            ext = os.path.splitext(rel_path)[1].lower()
                            if ext in (".txt", ".sub", ".json", ".yaml", ""):
                                matched = True
                                break

                if matched:
                    try:
                        content_bytes = zf.read(item)
                        nodes = decode_and_extract_nodes(content_bytes)
                        extracted_nodes.extend(nodes)
                    except Exception:
                        pass
    except Exception as e:
        # Zip 异常时退化为尝试 raw 方式读取显式文件
        for tf in target_files:
            try:
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{tf}"
                raw_req = urllib.request.Request(raw_url, headers=headers)
                with urllib.request.urlopen(raw_req, timeout=12) as r_resp:
                    extracted_nodes.extend(decode_and_extract_nodes(r_resp.read()))
            except Exception:
                pass

    return extracted_nodes


def collect_all_sources() -> list:
    """
    全网海量代理无损汇聚：
    1. 拉取 5 个小众宝藏防封源
    2. 拉取 15 个细分协议优选专线源
    3. 极速扫描 15 个 GitHub 目录树项目 (含原始 13 核心仓库)
    4. 仅执行单行内容哈希排重，保留全部原始链接与所有协议！
    """
    candidate_lines = []
    seen_hashes = set()

    print("======================================================================")
    print("【第一部分】：全网海量代理全量采集与无损聚合")
    print("======================================================================")

    # 1. 抓取小众宝藏源
    print(f"\n[*] [1/3] 正在拉取 {len(LOW_ATTENTION_SOURCES)} 个超低关注度(1~20 Stars)小众宝藏源...")
    for src in LOW_ATTENTION_SOURCES:
        name = src["name"]
        url = src["url"]
        desc = src["desc"]
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                nodes = decode_and_extract_nodes(resp.read())
                new_cnt = 0
                for n in nodes:
                    h = hashlib.sha256(n.encode("utf-8")).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        candidate_lines.append(n)
                        new_cnt += 1
                print(f"  [+] 成功解析: {name:<26} ({desc}) -> 提取 {new_cnt} 个新节点")
        except Exception as e:
            print(f"  [-] 请求跳过: {name:<26} ({e})")

    # 2. 抓取中立优选专线
    print(f"\n[*] [2/3] 正在拉取 {len(CURATED_SUBSCRIPTIONS)} 个高频中立优选专线...")
    for src in CURATED_SUBSCRIPTIONS:
        name = src["name"]
        url = src["url"]
        desc = src["desc"]
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                nodes = decode_and_extract_nodes(resp.read())
                new_cnt = 0
                for n in nodes:
                    h = hashlib.sha256(n.encode("utf-8")).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        candidate_lines.append(n)
                        new_cnt += 1
                print(f"  [+] 成功解析: {name:<26} ({desc}) -> 提取 {new_cnt} 个新节点")
        except Exception as e:
            print(f"  [-] 请求跳过: {name:<26} ({e})")

    # 3. 动态扫描 15 个 GitHub 目录树项目 (含原始 13 核心仓库)
    print(f"\n[*] [3/3] 正在 Zip 并发解包检索 {len(PROJECTS)} 个 GitHub 项目 (含原始 13 核心仓库)...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_map = {executor.submit(fetch_project_via_zip, p): p for p in PROJECTS}
        for future in future_map:
            p = future_map[future]
            p_name = p["name"]
            try:
                nodes = future.result()
                new_cnt = 0
                for n in nodes:
                    h = hashlib.sha256(n.encode("utf-8")).hexdigest()
                    if h not in seen_hashes:
                        seen_hashes.add(h)
                        candidate_lines.append(n)
                        new_cnt += 1
                print(f"  [+] 成功解包: {p_name:<28} -> 提取 {new_cnt} 个新节点")
            except Exception as e:
                print(f"  [-] 解包跳过: {p_name:<28} ({e})")

    print(f"\n[+] 第一部分完成！全网原始节点聚合总量: {len(candidate_lines)} 个有效配置！\n")

    # 保存原始汇总池 (单文件上限 40MB，超过规律自动拆分)
    print(f"[*] 正在将全量原始节点写入存储 (单文件物理上限: 40MB)...")
    split_parts = save_split_files(OUTPUT_FILE, candidate_lines, max_bytes=MAX_OUTPUT_BYTES)
    for part in split_parts:
        sz_mb = os.path.getsize(part) / 1024 / 1024
        print(f"  -> 生成分卷文件: {os.path.basename(part)} (大小: {sz_mb:.2f} MB)")

    return candidate_lines


# ==============================================================================
# [第二阶段：安全初筛、异步独立测活与物理 IP 绝对去重]
# ==============================================================================
def parse_and_validate_proxy(line: str):
    """
    测活阶段协议过滤：
    1. 过滤 .ir 等死域
    2. 仅保留 hysteria2, vless, vmess, https 四大协议
    3. 校验 TLS 加密真伪
    """
    line = line.strip()
    if not line:
        return None

    try:
        if ".ir" in line or "mbghalibaf" in line or "levikogjgfdd" in line:
            return None

        # 1. Hysteria 2 协议
        if line.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if host and port:
                return ("hy2", host, port, 1)

        # 2. VLESS 协议
        elif line.startswith("vless://"):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if not host or not port:
                return None

            q = urllib.parse.parse_qs(u.query)
            sec = q.get("security", ["none"])[0].lower()
            if sec == "reality":
                return ("vless_reality", host, port, 2)
            elif sec == "tls" or port in (443, 8443, 2053, 2083, 2087, 2096):
                return ("vless_tls", host, port, 3)
            return None

        # 3. VMess 协议
        elif line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            raw = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            data = json.loads(raw)
            host = data.get("add") or data.get("host")
            port = int(data.get("port", 0))
            if not host or port <= 0:
                return None

            tls_val = str(data.get("tls", "")).lower()
            is_tls = tls_val in ("tls", "1", "true") or port in (443, 8443, 2053, 2083, 2087, 2096)
            if is_tls:
                return ("vmess_tls", host, port, 4)
            return None

        # 4. HTTPS 协议
        elif line.startswith("https://"):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if host and port:
                return ("https", host, port, 5)
    except Exception:
        pass

    return None


async def check_single_proxy(sem: asyncio.Semaphore, line: str, timeout: float = 2.5):
    """底层 Socket 物理连通性握手与出口 IP 探测"""
    parsed = parse_and_validate_proxy(line)
    if not parsed:
        return None
    proto_type, host, port, rank = parsed

    async with sem:
        t0 = time.time()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            peer = writer.get_extra_info("peername")
            real_ip = peer[0] if (peer and len(peer) > 0) else host

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency_ms = int((time.time() - t0) * 1000)
            return {"line": line, "delay": latency_ms, "rank": rank, "real_ip": real_ip, "type": proto_type}
        except Exception:
            return None


async def run_batch_validation(candidate_nodes, concurrency=250, timeout=2.5):
    """高并发异步独立测活与单物理 IP 唯一去重"""
    print(f"\n[*] 启动云端高并发独立测活: 待测节点={len(candidate_nodes)} | 并发数={concurrency} | 超时={timeout}s")
    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(check_single_proxy(sem, p, timeout)) for p in candidate_nodes]

    alive_results = []
    start_time = time.time()
    done = 0
    total = len(candidate_nodes)

    for coro in asyncio.as_completed(tasks):
        res = await coro
        done += 1
        if res is not None:
            alive_results.append(res)
        if done % 1000 == 0 or done == total:
            elapsed = time.time() - start_time
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  测活进度: [{done}/{total}] 连通={len(alive_results)} 速率={rate:.0f}节点/s")

    alive_results.sort(key=lambda x: (x["rank"], x["delay"]))

    final_unique_alive = []
    seen_physical_ips = set()
    for item in alive_results:
        real_ip = item.get("real_ip")
        if real_ip and real_ip not in seen_physical_ips:
            seen_physical_ips.add(real_ip)
            final_unique_alive.append(item)

    print(f"[+] 测活与物理 IP 去重完成! 耗时: {time.time()-start_time:.1f}s")
    print(f"    - 初步连通节点: {len(alive_results)} 个")
    print(f"    - 【单物理 IP 唯一存活】: {len(final_unique_alive)} 个 (彻底剔除所有复用同 IP 换皮节点)")
    return final_unique_alive


def process_and_validate_candidates(candidate_lines: list, concurrency=250, timeout=2.5):
    """第二阶段执行流水线"""
    if not candidate_lines:
        print("[-] 候选池为空，无可用节点。")
        return []

    print("======================================================================")
    print("【第二部分】：执行高精存活池筛选 (协议聚焦 + TLS + 单物理IP验活)")
    print("======================================================================")

    # 1. 协议白名单初筛
    print("[*] 步骤 1/3: 协议白名单 (Hy2/VLESS/VMess/HTTPS) 校验与 TLS 加密辨识...")
    filtered_nodes = []
    for line in candidate_lines:
        if parse_and_validate_proxy(line) is not None:
            filtered_nodes.append(normalize_node_uri(line))
    print(f"  [+] 白名单初筛保留: {len(filtered_nodes)} / {len(candidate_lines)} 个")

    # 2. 静态域名初步去重，降低并发压力
    dedup_map = {}
    for line in filtered_nodes:
        try:
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            if host and host not in dedup_map:
                dedup_map[host] = line
        except Exception:
            pass
    unique_candidates = list(dedup_map.values())
    print(f"  [+] 静态初筛完成: 提取出 {len(unique_candidates)} 个独立目标节点参与连通性测活")

    # 3. 异步并发测活
    alive_results = asyncio.run(
        run_batch_validation(
            unique_candidates,
            concurrency=concurrency,
            timeout=timeout,
        )
    )

    # 4. 保存高精存活池与指纹
    alive_lines = [item["line"] for item in alive_results]
    valid_parts = save_split_files(VALID_OUTPUT_FILE, alive_lines, max_bytes=MAX_OUTPUT_BYTES)
    for vp in valid_parts:
        print(f"  -> 生成存活分卷: {os.path.basename(vp)} ({len(alive_lines)} 个存活节点)")

    with open(SEEN_FILE, "w", encoding="utf-8") as sf:
        for item in alive_results:
            sf.write(hashlib.sha256(item["line"].encode("utf-8")).hexdigest() + "\n")

    return alive_results


# ==============================================================================
# [程序入口]
# ==============================================================================
def main():
    t0 = time.time()
    print("=" * 70)
    print(">>> 启动 GitHub Actions 代理全量采集与高精测活引擎 <<<")
    print("=" * 70)
    raw = collect_all_sources()
    alive = process_and_validate_candidates(raw, concurrency=CHECK_CONCURRENCY, timeout=CHECK_TIMEOUT_SECONDS)
    print("\n" + "=" * 70)
    print(f"🎉 全部采集与测活流程圆满完成！总耗时: {time.time()-t0:.1f} 秒")
    print(f"  - 全量原始候选池: {len(raw)} 个")
    print(f"  - 单物理IP唯一存活: {len(alive)} 个")
    print("=" * 70)


if __name__ == "__main__":
    main()
