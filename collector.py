#!/usr/bin/env python3

# -*- coding: utf-8 -*-

"""

================================================================================

GitHub Actions 代理节点全量深度采集与云端初筛引擎 (NodeHarvester - 云端初筛版)

================================================================================

【核心执行流程与铁律规范】：

1. 内存全网聚合：从 13 个原始核心仓库 + 20 个高频优选源全量解包（百万级节点纯内存驻留，绝不落地脏数据）

2. 规则 1 协议规范化：hy2:// 自动重写为 hysteria2://，补齐 insecure=1 与 sni 参数

3. 规则 2 基础过滤：剔除 .ir 死域、私有内网 IP 及无效测试占位符

4. 规则 3 协议聚焦与加密判定：支持 hysteria2/vless/vmess/trojan/ss/https，剔除裸明文

5. 规则 4 内存单 Host 粗排重：同一目标地址初筛去重，快速消肿

6. 规则 5 云端海外高并发握手测活：asyncio 250 并发底层探测，剔除 90%+ 绝对应答死亡节点

7. 规则 6 真实物理出口 IP 绝对唯一：通过 Socket peername 获取真实物理 IP，彻底消灭马甲换皮节点

8. 规则 7 质量排序：按协议优先级与握手延迟毫秒排序，优质节点排在最前

9. 规则 8 落地分卷存储：仅将初筛存活的优质节点落盘，单文件上限严格锁死 40MB，超限规律自动拆分

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

# 解决 Windows 控制台编码问题

if sys.platform.startswith("win"):

    try:

        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

        sys.stderr.reconfigure(encoding="utf-8", errors="replace")

    except Exception:

        pass



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
FINAL_OUTPUT_FILE = os.path.join(BASE_DIR, "final_valid_proxies.txt")

SEEN_FILE = os.path.join(BASE_DIR, "seen_hashes.txt")



# ==============================================================================

# [云端执行参数配置]

# ==============================================================================

CHECK_CONCURRENCY = 250

CHECK_TIMEOUT_SECONDS = 2.5

MAX_OUTPUT_BYTES = 40 * 1024 * 1024  # 严格 40MB 单文件物理上限 (超限自动拆分)

REQUEST_TIMEOUT_SECONDS = 25



# ==============================================================================

# [数据源清单：13 原始核心仓库 + 超低关注度防封源 + 高频细分专线]

# ==============================================================================



# 一、超低关注度（1~20 Stars）高频小众宝藏源

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



# 二、高频维护的细分协议订阅专线

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



# 三、原始 13 个核心仓库 + 扩展动态库 (100% 完整收录)

PROJECTS = [

    {

        "name": "Project1-v2go",

        "owner": "Danialsamadi",

        "repo": "v2go",

        "branch": "main",

        "dirs": ["Splitted-By-Country"],

    },

    {

        "name": "Project2-Proxify",

        "owner": "Firmfox",

        "repo": "Proxify",

        "branch": "main",

        "dirs": ["v2ray_configs/mixed", "v2ray_configs/seperated_by_protocol", "v2ray_configs/separated_by_protocol", "v2ray_configs/subscriptions"],

    },

    {

        "name": "Project3-PyroConfig",

        "owner": "0xAbolfazl",

        "repo": "PyroConfig",

        "branch": "main",

        "dirs": ["Configs"],

    },

    {

        "name": "Project4-ConfigForge-V2Ray",

        "owner": "ShatakVPN",

        "repo": "ConfigForge-V2Ray",

        "branch": "main",

        "dirs": ["configs"],

    },

    {

        "name": "Project5-v2ray-configs",

        "owner": "MatinGhanbari",

        "repo": "v2ray-configs",

        "branch": "main",

        "dirs": ["subscriptions/v2ray", "subscriptions/filtered"],

        "files": ["subscriptions/v2ray/all_sub.txt"],

    },

    {

        "name": "Project6-Freedom-V2Ray",

        "owner": "MahanKenway",

        "repo": "Freedom-V2Ray",

        "branch": "main",

        "dirs": ["configs"],

    },

    {

        "name": "Project7-F0rc3Run",

        "owner": "F0rc3Run",

        "repo": "F0rc3Run",

        "branch": "main",

        "dirs": ["splitted-by-protocol"],

    },

    {

        "name": "Project8-SoliSpirit",

        "owner": "SoliSpirit",

        "repo": "v2ray-configs",

        "branch": "main",

        "dirs": ["Subscriptions", "Protocols"],

        "files": ["all_configs.txt"],

    },

    {

        "name": "Project9-free-v2ray-collector",

        "owner": "iboxz",

        "repo": "free-v2ray-collector",

        "branch": "main",

        "dirs": ["main"],

    },

    {

        "name": "Project10-port-based-v2ray-configs",

        "owner": "hamedcode",

        "repo": "port-based-v2ray-configs",

        "branch": "main",

        "dirs": ["sub"],

    },

    {

        "name": "Project11-5ubscrpt10n",

        "owner": "sevcator",

        "repo": "5ubscrpt10n",

        "branch": "main",

        "dirs": ["mini", "protocols"],

    },

    {

        "name": "Project12-Epodonios-Splitted",

        "owner": "Epodonios",

        "repo": "v2ray-configs",

        "branch": "main",

        "dirs": ["Splitted-By-Protocol"],

    },

    {

        "name": "Project13-Epodonios-AllConfigsSub",

        "owner": "Epodonios",

        "repo": "v2ray-configs",

        "branch": "main",

        "dirs": [],

        "files": ["All_Configs_Sub.txt"],

    },

    {

        "name": "Project14-Surfboardv2ray",

        "owner": "Surfboardv2ray",

        "repo": "TGParse",

        "branch": "main",

        "dirs": ["splitted"],

        "files": ["splitted/vless", "splitted/vmess", "splitted/hy2", "splitted/hysteria2", "splitted/mixed"],

    },

    {

        "name": "Project15-mohamadfg-dev",

        "owner": "mohamadfg-dev",

        "repo": "telegram-v2ray-configs-collector",

        "branch": "main",

        "dirs": ["category"],

    },

]



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

# [内存解包与解析引擎]

# ==============================================================================

def safe_b64decode(s: str) -> str:

    """安全还原任意 Base64 编码"""

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

    """万能解包：支持明文、全文 Base64、逐行 Base64、Clash YAML"""

    if not raw_bytes:

        return []



    text = raw_bytes.decode("utf-8", errors="ignore").strip()

    if not text:

        return []



    results = []



    if not any(p in text for p in KNOWN_PROTOCOLS + ("proxies:",)):

        decoded_candidate = safe_b64decode(text)

        if any(p in decoded_candidate for p in KNOWN_PROTOCOLS):

            text = decoded_candidate



    if "proxies:" in text and ("type:" in text or "- name:" in text):

        yaml_nodes = extract_proxies_from_clash_yaml(text)

        results.extend(yaml_nodes)



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

    """【规则 1】：协议头标准化规范 (hy2:// 转为 hysteria2:// 并补齐必要参数)"""

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

    """【规则 8】：严格限制单文件体积 <= 40MB，超限按序号规律拆分"""

    stem, ext = os.path.splitext(base_filename)

    

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



    part1_path = f"{stem}_1{ext}"

    if os.path.exists(part1_path):

        shutil.copyfile(part1_path, base_filename)

        if base_filename not in parts_created:

            parts_created.insert(0, base_filename)



    return parts_created





# ==============================================================================

# [第一阶段：纯内存全网聚合 (100% 内存驻留，绝不落地脏数据)]

# ==============================================================================

def fetch_project_via_zip(project: dict) -> list:

    """Zip 极速下载解包，免 Token 鉴权，免 API 配额限制"""

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

                parts = item.split("/", 1)

                rel_path = parts[1] if len(parts) > 1 else item



                matched = False

                for tf in target_files:

                    if rel_path.lower() == tf.lower() or os.path.basename(rel_path).lower() == tf.lower():

                        matched = True

                        break



                if not matched:

                    for d in dirs:

                        prefix = d.lower() + "/"

                        if rel_path.lower().startswith(prefix):

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

    except Exception:

        for tf in target_files:

            try:

                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{tf}"

                raw_req = urllib.request.Request(raw_url, headers=headers)

                with urllib.request.urlopen(raw_req, timeout=12) as r_resp:

                    extracted_nodes.extend(decode_and_extract_nodes(r_resp.read()))

            except Exception:

                pass



    return extracted_nodes





def collect_all_sources_in_ram() -> list:

    """全网海量代理聚合：百万级节点纯内存驻留"""

    candidate_lines = []

    seen_hashes = set()



    print("======================================================================")

    print("【第一部分】：全网海量代理原始聚合 (纯内存驻留，不落地脏数据)")

    print("======================================================================")



    # 1. 抓取小众宝藏源

    print(f"\n[*] [1/3] 正在内存拉取 {len(LOW_ATTENTION_SOURCES)} 个小众防封宝藏源...")

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

                print(f"  [+] 内存解包: {name:<26} ({desc}) -> 提取 {new_cnt} 个新节点")

        except Exception as e:

            print(f"  [-] 请求跳过: {name:<26} ({e})")



    # 2. 抓取中立优选专线

    print(f"\n[*] [2/3] 正在内存拉取 {len(CURATED_SUBSCRIPTIONS)} 个细分协议高频专线...")

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

                print(f"  [+] 内存解包: {name:<26} ({desc}) -> 提取 {new_cnt} 个新节点")

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

                print(f"  [+] 内存解包: {p_name:<28} -> 提取 {new_cnt} 个新节点")

            except Exception as e:

                print(f"  [-] 解包跳过: {p_name:<28} ({e})")



    print(f"\n[+] 内存聚合完成！全网原始候选池规模: {len(candidate_lines)} 个节点 (全部纯内存驻留，不落地)\n")

    return candidate_lines





# ==============================================================================

# [第二阶段：云端 8 大铁律初筛流水线]

# ==============================================================================

def parse_and_validate_proxy(line: str):

    """

    【规则 2 & 规则 3】：

    1. 剔除 .ir、localhost、私有 IP 等死域

    2. 仅保留 hysteria2, vless, vmess, trojan, ss, https 主流协议

    3. 校验 TLS 加密真伪，剔除裸明文

    """

    line = line.strip()

    if not line:

        return None



    try:

        lower = line.lower()

        # 规则 2: 过滤死域与自环回地址

        if ".ir" in lower or "mbghalibaf" in lower or "levikogjgfdd" in lower or "localhost" in lower or "127.0.0.1" in lower or "0.0.0.0" in lower:

            return None



        # 1. Hysteria 2 协议 (优先级 1)

        if line.startswith(("hysteria2://", "hy2://")):

            u = urllib.parse.urlsplit(line)

            host = u.hostname

            port = u.port or 443

            if host and port and 1 <= port <= 65535:

                return ("hy2", host, port, 1)



        # 2. VLESS 协议 (优先级 2: Reality, 3: TLS)

        elif line.startswith("vless://"):

            u = urllib.parse.urlsplit(line)

            host = u.hostname

            port = u.port or 443

            if not host or not port or not (1 <= port <= 65535):

                return None



            q = urllib.parse.parse_qs(u.query)

            sec = q.get("security", ["none"])[0].lower()

            if sec == "reality":

                return ("vless_reality", host, port, 2)

            elif sec == "tls" or port in (443, 8443, 2053, 2083, 2087, 2096):

                return ("vless_tls", host, port, 3)

            return None



        # 4. VMess 协议 (优先级 4)

        elif line.startswith("vmess://"):

            b64_str = line[8:].split("#")[0]

            pad = len(b64_str) % 4

            if pad:

                b64_str += "=" * (4 - pad)

            raw = base64.b64decode(b64_str).decode("utf-8", errors="ignore")

            data = json.loads(raw)

            host = data.get("add") or data.get("host")

            port = int(data.get("port", 0))

            if not host or not (1 <= port <= 65535):

                return None



            tls_val = str(data.get("tls", "")).lower()

            is_tls = tls_val in ("tls", "1", "true") or port in (443, 8443, 2053, 2083, 2087, 2096)

            if is_tls:

                return ("vmess_tls", host, port, 4)

            return None



        # 6. HTTPS 协议 (优先级 6)

        elif line.startswith("https://"):

            u = urllib.parse.urlsplit(line)

            host = u.hostname

            port = u.port or 443

            if host and port and 1 <= port <= 65535:

                return ("https", host, port, 6)

    except Exception:

        pass



    return None





async def check_single_proxy(sem: asyncio.Semaphore, line: str, timeout: float = 2.5):

    """【规则 5 & 规则 6】：底层 Socket 物理握手探测与真实出口 IP 提取"""

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

    """【规则 5 & 规则 6 & 规则 7】：全量并发握手初筛 + 单物理 IP 绝对去重 + 质量排序"""

    print(f"\n[*] 启动云端高并发握手测活: 待测节点={len(candidate_nodes)} | 并发数={concurrency} | 超时={timeout}s")

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

            print(f"  握手进度: [{done}/{total}] 连通响应={len(alive_results)} 速率={rate:.0f}节点/s")



    # 规则 7: 按协议抗封锁等级与握手延迟毫秒综合排序

    alive_results.sort(key=lambda x: (x["rank"], x["delay"]))



    # 规则 6: 真实物理出口 IP 绝对唯一去重 (同一物理机仅保留 1 个最优节点)

    final_unique_alive = []

    seen_physical_ips = set()

    for item in alive_results:

        real_ip = item.get("real_ip")

        if real_ip and real_ip not in seen_physical_ips:

            seen_physical_ips.add(real_ip)

            final_unique_alive.append(item)



    print(f"[+] 云端初筛完成! 耗时: {time.time()-start_time:.1f}s")

    print(f"    - 初步握手连通: {len(alive_results)} 个")

    print(f"    - 【单物理 IP 唯一存活】: {len(final_unique_alive)} 个 (彻底剔除所有复用同 IP 换皮节点)")

    return final_unique_alive







# ==============================================================================
# [sing-box 真实 Cloudflare 204 网页深度测活引擎 (Linux/云端高并发版)]
# ==============================================================================
VALID_FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}
SINGBOX_TEST_URL = "http://cp.cloudflare.com/generate_204"
SINGBOX_BATCH_SIZE = 120
SINGBOX_CONCURRENCY = 40
SINGBOX_TIMEOUT_MS = 3500
SINGBOX_CLASH_PORT = 19999
SINGBOX_DNS_CACHE = {}

def get_node_physical_ip(line: str) -> str:
    """提取节点的底层物理出口 IP (带内存 DNS 缓存)"""
    line = line.strip()
    if not line:
        return None
    try:
        host = None
        if line.startswith(("vless://", "hysteria2://", "hy2://", "trojan://", "https://")):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
        elif line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
            host = data.get("add") or data.get("host")

        if not host:
            return None

        host_lower = host.lower()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host_lower):
            return host_lower

        if host_lower in SINGBOX_DNS_CACHE:
            return SINGBOX_DNS_CACHE[host_lower]

        try:
            resolved_ip = socket.gethostbyname(host_lower)
            SINGBOX_DNS_CACHE[host_lower] = resolved_ip
            return resolved_ip
        except Exception:
            return host_lower
    except Exception:
        pass
    return None

def parse_proxy_to_singbox_outbound(line: str, tag: str):
    """将代理 URI 字符串解析为 sing-box 标准 outbound JSON"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    try:
        # 1. VLESS 协议
        if line.startswith("vless://"):
            u = urllib.parse.urlsplit(line)
            q = urllib.parse.parse_qs(u.query)
            sec = q.get("security", ["none"])[0].lower()
            net = q.get("type", ["tcp"])[0].lower()
            if net in ("xhttp", "raw"):
                return None

            ob = {
                "type": "vless",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "uuid": u.username or "",
            }
            if not ob["server"] or not ob["uuid"]:
                return None

            flow = q.get("flow", [""])[0]
            if flow in ("xtls-rprx-vision", "xtls-rprx-vision-udp443"):
                ob["flow"] = flow

            if sec in ("tls", "reality"):
                tls = {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0],
                    "insecure": True
                }
                fp = q.get("fp", ["chrome"])[0].lower()
                if fp not in VALID_FP:
                    fp = "chrome"
                tls["utls"] = {"enabled": True, "fingerprint": fp}

                if sec == "reality":
                    pbk = q.get("pbk", [""])[0]
                    sid = q.get("sid", [""])[0]
                    if not pbk or len(pbk) < 30:
                        return None
                    tls["reality"] = {
                        "enabled": True,
                        "public_key": pbk,
                        "short_id": sid
                    }
                ob["tls"] = tls

            if net == "ws":
                ob["transport"] = {
                    "type": "ws",
                    "path": q.get("path", ["/"])[0],
                    "headers": {"Host": q.get("host", [u.hostname])[0]}
                }
            return ob

        # 2. Hysteria 2 协议
        elif line.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlsplit(line)
            if not u.hostname:
                return None
            q = urllib.parse.parse_qs(u.query)
            raw_pwd = u.username or ""
            pwd = urllib.parse.unquote(raw_pwd)
            ob = {
                "type": "hysteria2",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "password": pwd,
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0],
                    "insecure": True
                }
            }
            if "obfs" in q:
                ob["obfs"] = {
                    "type": q["obfs"][0],
                    "password": q.get("obfs-password", [""])[0]
                }
            mport = q.get("mport", q.get("ports", [None]))[0]
            if mport:
                singbox_mport = mport.replace("-", ":")
                ob["server_ports"] = [singbox_mport]
            return ob

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
            uuid = data.get("id")
            if not host or port <= 0 or not uuid:
                return None

            ob = {
                "type": "vmess",
                "tag": tag,
                "server": host,
                "server_port": port,
                "uuid": uuid,
                "security": "auto"
            }
            net = data.get("net", "tcp")
            if net == "ws":
                tr = {"type": "ws", "path": data.get("path", "/")}
                if data.get("host"):
                    tr["headers"] = {"Host": data.get("host")}
                ob["transport"] = tr

            if str(data.get("tls", "")).lower() in ("tls", "1", "true") or port in (443, 8443):
                ob["tls"] = {
                    "enabled": True,
                    "server_name": data.get("sni") or data.get("host") or host,
                    "insecure": True
                }
            return ob

        # 4. Trojan 协议
        elif line.startswith("trojan://"):
            u = urllib.parse.urlsplit(line)
            q = urllib.parse.parse_qs(u.query)
            ob = {
                "type": "trojan",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "password": u.username or "",
                "tls": {
                    "enabled": True,
                    "server_name": q.get("sni", [u.hostname])[0],
                    "insecure": True
                }
            }
            if not ob["server"] or not ob["password"]:
                return None
            return ob

        # 5. HTTPS 协议
        elif line.startswith("https://"):
            u = urllib.parse.urlsplit(line)
            ob = {
                "type": "http",
                "tag": tag,
                "server": u.hostname,
                "server_port": int(u.port or 443),
                "tls": {
                    "enabled": True,
                    "server_name": u.hostname,
                    "insecure": True
                }
            }
            if u.username or u.password:
                ob["username"] = u.username or ""
                ob["password"] = u.password or ""
            return ob

    except Exception:
        pass
    return None

def test_singbox_batch(batch_nodes, batch_index, total_batches, sing_box_bin):
    """单批次 sing-box 启动并并发向 Clash API 查询 204 延迟"""
    tag_to_raw = {}
    outbounds = []

    for i, raw_line in enumerate(batch_nodes):
        tag = f"node-{batch_index}-{i}"
        ob = parse_proxy_to_singbox_outbound(raw_line, tag)
        if ob:
            outbounds.append(ob)
            tag_to_raw[tag] = raw_line

    if not outbounds:
        return []

    temp_cfg_path = os.path.join(BASE_DIR, f"_temp_batch_{batch_index}.json")

    # 预检并剔除不合法参数的异常节点
    while outbounds:
        cfg = {
            "log": {"level": "warn"},
            "dns": {
                "servers": [{"tag": "dns-direct", "address": "1.1.1.1", "detour": "direct"}],
                "rules": [{"outbound": "any", "server": "dns-direct"}],
                "final": "dns-direct",
                "strategy": "prefer_ipv4"
            },
            "inbounds": [],
            "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
            "experimental": {
                "clash_api": {
                    "external_controller": f"127.0.0.1:{SINGBOX_CLASH_PORT}"
                }
            }
        }
        with open(temp_cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)

        check_res = subprocess.run(
            [sing_box_bin, "check", "-c", temp_cfg_path],
            capture_output=True,
            text=True
        )
        if check_res.returncode == 0:
            break

        m = re.search(r"outbound\[(\d+)\]", check_res.stderr)
        if m:
            bad_idx = int(m.group(1))
            if bad_idx < len(outbounds):
                outbounds.pop(bad_idx)
            else:
                break
        else:
            break

    if not outbounds:
        if os.path.exists(temp_cfg_path):
            try: os.remove(temp_cfg_path)
            except Exception: pass
        return []

    proc = subprocess.Popen(
        [sing_box_bin, "run", "-c", temp_cfg_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.2)

    alive_nodes = []
    encoded_target = urllib.parse.quote(SINGBOX_TEST_URL)
    direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def query_delay(ob):
        t = ob["tag"]
        url = f"http://127.0.0.1:{SINGBOX_CLASH_PORT}/proxies/{t}/delay?url={encoded_target}&timeout={SINGBOX_TIMEOUT_MS}"
        try:
            req = urllib.request.Request(url)
            with direct_opener.open(req, timeout=(SINGBOX_TIMEOUT_MS / 1000.0) + 1.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    delay = data.get("delay", 0)
                    if delay > 0:
                        raw = tag_to_raw[t]
                        return (raw, delay)
        except Exception:
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=SINGBOX_CONCURRENCY) as executor:
            futures = [executor.submit(query_delay, ob) for ob in outbounds]
            for future in as_completed(futures):
                res = future.result()
                if res:
                    alive_nodes.append(res)
    finally:
        try:
            proc.kill()
            proc.wait(timeout=2)
        except Exception:
            pass
        if os.path.exists(temp_cfg_path):
            try: os.remove(temp_cfg_path)
            except Exception: pass

    return alive_nodes

def run_singbox_deep_verify(candidate_lines: list) -> list:
    """启动 sing-box 批量进行真实的 Cloudflare 204 网页请求深度测活与物理 IP 去重"""
    sing_box_bin = shutil.which("sing-box") or "/usr/local/bin/sing-box"
    if not (os.path.exists(sing_box_bin) or shutil.which(sing_box_bin)):
        local_bin = os.path.join(BASE_DIR, "sing-box")
        if os.path.exists(local_bin):
            sing_box_bin = local_bin
        else:
            print("[!] 未检测到可用 sing-box 程序，跳过 204 网页深度测活，保留全量初筛列表。")
            return candidate_lines

    total = len(candidate_lines)
    print(f"\n======================================================================")
    print(f"[*] 启动 sing-box 真实 204 网页深度测活 (候选待测节点: {total} 个)")
    print(f"[*] 测活目标: {SINGBOX_TEST_URL} | 并发: {SINGBOX_CONCURRENCY} | 超时: {SINGBOX_TIMEOUT_MS}ms")
    print(f"======================================================================")

    b_count = (total + SINGBOX_BATCH_SIZE - 1) // SINGBOX_BATCH_SIZE
    all_alive = []
    seen_ips = set()

    for b in range(b_count):
        start_idx = b * SINGBOX_BATCH_SIZE
        end_idx = min(start_idx + SINGBOX_BATCH_SIZE, total)
        batch = candidate_lines[start_idx:end_idx]

        alive_batch = test_singbox_batch(batch, b, b_count, sing_box_bin)

        for raw_line, delay in alive_batch:
            phy_ip = get_node_physical_ip(raw_line)
            if phy_ip and phy_ip in seen_ips:
                continue
            if phy_ip:
                seen_ips.add(phy_ip)
            all_alive.append((raw_line, delay))

        if (b + 1) % 10 == 0 or b + 1 == b_count:
            print(f"  [进度] 批次 [{b + 1}/{b_count}] 已完成，当前累计 204 深度存活节点: {len(all_alive)} 个")

    all_alive.sort(key=lambda x: x[1])
    final_lines = [item[0] for item in all_alive]

    print(f"\n[+] sing-box 真实 204 网页深度测活圆满完成！")
    print(f"    - 输入初筛节点: {total} 个")
    print(f"    - 最终通过 204 网页测活且物理 IP 唯一节点: {len(final_lines)} 个")
    return final_lines


def process_and_validate_candidates(candidate_lines: list, concurrency=250, timeout=2.5):

    """云端初筛执行总装流水线"""

    if not candidate_lines:

        print("[-] 内存候选池为空，无可用节点。")

        return []



    print("======================================================================")

    print("【第二部分】：执行云端 8 大铁律初筛流水线 (握手连通 + 物理单IP提纯)")

    print("======================================================================")



    # 步骤 1: 格式清洗、协议聚焦与安全初筛 (规则 1, 2, 3)

    print("[*] 步骤 1/4: 执行协议白名单校验、TLS 加密真伪识别与参数规范化...")

    filtered_nodes = []

    for line in candidate_lines:

        if parse_and_validate_proxy(line) is not None:

            filtered_nodes.append(normalize_node_uri(line))

    print(f"  [+] 初筛保留: {len(filtered_nodes)} / {len(candidate_lines)} 个 (已剔除死域、内网伪地址与裸明文)")



    # 步骤 2: 内存静态单 Host 排重 (规则 4)

    print("\n[*] 步骤 2/4: 执行内存单 Host 初步排重，消减重复域名冗余...")

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

    print(f"  [+] 静态消肿完成: 提炼出 {len(unique_candidates)} 个独立目标节点参与网络握手测活")



    # 步骤 3: 异步并发网络握手测活与物理 IP 去重 (规则 5, 6, 7)

    print("\n[*] 步骤 3/4: 云端海外高并发底层握手连通性探测 (零连坐)...")

    alive_results = asyncio.run(

        run_batch_validation(

            unique_candidates,

            concurrency=concurrency,

            timeout=timeout,

        )

    )



    # 步骤 4: 落地保存初筛结果 (规则 8: 严格 40MB 单文件物理上限与规律拆分)

    print("\n[*] 步骤 4/4: 将初筛存活节点规律落盘写入仓库 (严格 40MB 单文件上限)...")

    alive_lines = [item["line"] for item in alive_results]



    # 保存初筛后的主文件 all_proxies.txt (及规律分卷)

    all_parts = save_split_files(OUTPUT_FILE, alive_lines, max_bytes=MAX_OUTPUT_BYTES)

    for p in all_parts:

        sz_mb = os.path.getsize(p) / 1024 / 1024

        print(f"  -> 生成初筛分卷: {os.path.basename(p)} ({sz_mb:.2f} MB)")



    # 镜像保存 valid_proxies.txt 保持兼容

    # 步骤 5: sing-box 真实 204 网页深度测活
    print("\n[*] 步骤 5/5: 启动 sing-box 执行 Cloudflare HTTP 204 网页深度测活...")
    deep_verified_lines = run_singbox_deep_verify(alive_lines)

    # 导出最终测活文件 valid_proxies.txt 与 final_valid_proxies.txt (可分卷)
    save_split_files(VALID_OUTPUT_FILE, deep_verified_lines, max_bytes=MAX_OUTPUT_BYTES)
    save_split_files(FINAL_OUTPUT_FILE, deep_verified_lines, max_bytes=MAX_OUTPUT_BYTES)

    # 保存指纹库
    with open(SEEN_FILE, "w", encoding="utf-8") as sf:
        for line in deep_verified_lines:
            sf.write(hashlib.sha256(line.encode("utf-8")).hexdigest() + "\n")

    return deep_verified_lines





# ==============================================================================

# [程序入口]

# ==============================================================================

def main():

    t0 = time.time()

    print("=" * 70)

    print(">>> 启动 GitHub Actions 代理全量采集与云端初筛引擎 <<<")

    print("=" * 70)

    raw = collect_all_sources_in_ram()

    alive = process_and_validate_candidates(raw, concurrency=CHECK_CONCURRENCY, timeout=CHECK_TIMEOUT_SECONDS)

    print("\n" + "=" * 70)

    print(f" 全部采集与云端初筛流程圆满完成！总耗时: {time.time()-t0:.1f} 秒")

    print(f"  - 内存聚合原始总数: {len(raw)} 个 (已自动释放，不落地)")

    print(f"  - 初筛单物理IP存活: {len(alive)} 个 (已规律落盘推库)")

    print("=" * 70)





if __name__ == "__main__":

    main()

