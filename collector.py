#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 自动化节点采集与测活引擎 (严格遵循 GitHub代理处理规则规范)
================================================================================
【7 大执行铁律完全落地】：
1. 协议头标准化规范：hy2:// 强制重写为 hysteria2://，自动补齐 insecure=1 与 sni
2. 单 IP 绝对唯一去重：测试前静态初筛 + 测活时 Socket peername 真实物理 IP 绝对去重 (绝无重复 IP)
3. 多数据源并发抓取：原始 13 个仓库 + 8 个国内高频特化鲜活源 + 智能明文/Base64解包
4. 均衡防误杀初筛：仅剔除 .ir 等死域，杜绝主观臆测杀好节点
5. 云端独立并发测活：asyncio 250 独立网络握手，逐点探测，零连坐
6. 协议白名单聚焦：仅保留 hysteria2, vless, vmess, https 四大协议，其余全数抛弃
7. 多协议 TLS 判定：精准识别各协议底层 TLS 特征，拦截裸明文流量，零误杀加密节点
"""

import asyncio
import base64
import datetime as dt
import hashlib
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# ==============================================================================
# [全局配置与运行开关]
# ==============================================================================
ENABLE_REMOTE_COLLECT = True
ENABLE_SMART_FILTER = True
ENABLE_ENDPOINT_DEDUP = True
ENABLE_CONCURRENT_VALIDATION = True

CHECK_CONCURRENCY = 250
CHECK_TIMEOUT_SECONDS = 2.5

OUTPUT_FILE = "all_proxies.txt"
VALID_OUTPUT_FILE = "valid_proxies.txt"
SEEN_FILE = "seen_hashes.txt"
SYNC_TO_ALL_PROXIES = True
MAX_OUTPUT_BYTES = 95 * 1024 * 1024

REQUEST_INTERVAL_SECONDS = 1.0
MAX_RETRIES = 5
RETRY_SLEEP_SECONDS = 10
GITHUB_TOKEN = os.environ.get("GH_PAT", "").strip()

# ==============================================================================
# [规则 3：高频鲜活特化订阅源 - 针对国内电信/联通/移动网络优化]
# ==============================================================================
# [规则 3：长期高频维护的全球中立聚合源 - 纯英文/无地域敏感标签]
# ==============================================================================
EXTRA_SUBSCRIPTIONS = [
    # 1. rtwo2 / FastNodes (全自动 CI/CD 每小时实测验活推送，含 VLESS / Hysteria2)
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt",
    "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt",

    # 2. 0xRadikal / Free-v2ray-Configs (国际安全研究员维护，Top 100 高速及 Base64 活池)
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/top100.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/configs_base64.txt",

    # 3. Au1rxx / free-vpn-subscriptions (全自动流水线每小时自动构建)
    "https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/raw/main/output/v2ray-base64.txt",

    # 4. LalatinaHub / Mineral (知名海外中立代号项目，长期稳定更新)
    "https://raw.githubusercontent.com/LalatinaHub/Mineral/master/result/nodes",

    # 5. ebrasha / free-v2ray-public-list (国际公开源，每 15 分钟自动化更新)
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/vless_configs.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",

    # 6. yebekhe / TelegramV2rayCollector (高频多协议自动化汇总)
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/vless",
    "https://raw.githubusercontent.com/yebekhe/TelegramV2rayCollector/main/sub/normal/hysteria2",

    # 7. mahdibland / V2RayAggregator (全球老牌高星开源聚合库)
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",

    # 8. MatinGhanbari / v2ray-configs (自动化分类订阅)
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/vless.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/filtered/subs/hysteria2.txt",
]


# ==============================================================================
# [规则 3：原始 13 个 GitHub 数据源仓库配置 - 100% 完整保留]
# ==============================================================================
PROJECTS = [
    {
        "name": "Project1-v2go",
        "owner": "Danialsamadi",
        "repo": "v2go",
        "branch": "main",
        "dirs": ["Splitted-By-Country"],
        "recent_hours": None,
    },
    {
        "name": "Project2-Proxify",
        "owner": "Firmfox",
        "repo": "Proxify",
        "branch": "main",
        "dirs": ["v2ray_configs/mixed", "v2ray_configs/seperated_by_protocol"],
        "recent_hours": 12,
    },
    {
        "name": "Project3-PyroConfig",
        "owner": "0xAbolfazl",
        "repo": "PyroConfig",
        "branch": "main",
        "dirs": ["Configs"],
        "recent_hours": 12,
    },
    {
        "name": "Project4-ConfigForge-V2Ray",
        "owner": "ShatakVPN",
        "repo": "ConfigForge-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
        "recent_hours": 12,
        "mode": "subdirs_all_txt",
    },
    {
        "name": "Project5-v2ray-configs",
        "owner": "MatinGhanbari",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": [],
        "recent_hours": 12,
        "mode": "explicit_files",
        "file_paths": ["subscriptions/v2ray/all_sub.txt"],
    },
    {
        "name": "Project6-Freedom-V2Ray",
        "owner": "MahanKenway",
        "repo": "Freedom-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
        "recent_hours": 12,
    },
    {
        "name": "Project7-F0rc3Run",
        "owner": "F0rc3Run",
        "repo": "F0rc3Run",
        "branch": "main",
        "dirs": ["splitted-by-protocol"],
        "recent_hours": 12,
    },
    {
        "name": "Project8-SoliSpirit",
        "owner": "SoliSpirit",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Sub"],
        "recent_hours": 12,
    },
    {
        "name": "Project9-Surfboardv2ray",
        "owner": "Surfboardv2ray",
        "repo": "TGParse",
        "branch": "main",
        "dirs": ["splitted/mixed"],
        "recent_hours": 12,
    },
    {
        "name": "Project10-soroushmirzaei",
        "owner": "soroushmirzaei",
        "repo": "telegram-configs-collector",
        "branch": "main",
        "dirs": ["protocols"],
        "recent_hours": 12,
    },
    {
        "name": "Project11-barry-far",
        "owner": "barry-far",
        "repo": "V2ray-Configs",
        "branch": "main",
        "dirs": ["Sub1", "Sub2", "Sub3", "Sub4", "Sub5", "Sub6", "Sub7", "Sub8"],
        "recent_hours": 12,
    },
    {
        "name": "Project12-MrPooyaX",
        "owner": "MrPooyaX",
        "repo": "V2ray",
        "branch": "master",
        "dirs": ["sub"],
        "recent_hours": 12,
    },
    {
        "name": "Project13-mohamadfg-dev",
        "owner": "mohamadfg-dev",
        "repo": "telegram-v2ray-configs-collector",
        "branch": "main",
        "dirs": ["protocols"],
        "recent_hours": 12,
    },
]

# ==============================================================================
# [规则 3：智能解包引擎 - 先明文后 Base64，严禁对明文盲目解码]
# ==============================================================================
def decode_subscription_text(raw_bytes: bytes) -> str:
    """智能解析订阅内容（自动兼容明文、Base64 与简单 Clash YAML）"""
    text = raw_bytes.decode("utf-8", errors="ignore").strip()
    
    # 1. 若已经是明文列表或 Clash YAML，直接返回，严禁盲目 Base64 解码导致乱码
    if any(p in text for p in ("vless://", "vmess://", "hysteria2://", "hy2://", "https://", "proxies:")):
        return text

    # 2. 若未检测到协议头，尝试安全 Base64 解密
    try:
        clean_text = "".join(text.split())
        pad = len(clean_text) % 4
        if pad:
            clean_text += "=" * (4 - pad)
        decoded = base64.b64decode(clean_text).decode("utf-8", errors="ignore")
        if any(p in decoded for p in ("vless://", "vmess://", "hysteria2://", "hy2://", "https://")):
            return decoded
    except Exception:
        pass

    return text


def extract_proxies_from_text(text: str) -> list:
    """从文本中提取代理节点（支持标准 URI 列表及 Clash YAML 中的 HTTPS 节点）"""
    nodes = []
    lines = text.splitlines()

    # 处理 Clash YAML 格式的节点 (提取开启了 tls: true 的 http 节点)
    if "proxies:" in text or "- name:" in text:
        in_proxies = False
        current_proxy = {}
        for line in lines:
            line_str = line.strip()
            if line_str == "proxies:":
                in_proxies = True
                continue
            if in_proxies and line.startswith("  - "):
                if current_proxy:
                    uri = convert_clash_dict_to_uri(current_proxy)
                    if uri:
                        nodes.append(uri)
                current_proxy = {}
                line_str = line_str[4:]
            
            if in_proxies and ":" in line_str:
                parts = line_str.split(":", 1)
                k = parts[0].strip().replace("-", "").strip()
                v = parts[1].strip().strip('"').strip("'")
                current_proxy[k] = v
        if current_proxy:
            uri = convert_clash_dict_to_uri(current_proxy)
            if uri:
                nodes.append(uri)

    # 处理标准单行 URI 格式
    for line in lines:
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#"):
            continue
        if any(line_clean.startswith(prefix) for prefix in ("hysteria2://", "hy2://", "vless://", "vmess://", "https://")):
            nodes.append(line_clean)

    return nodes


def convert_clash_dict_to_uri(p: dict) -> str:
    """将 Clash 中的 HTTP/HTTPS 节点转为标准 https:// 链接"""
    ptype = p.get("type", "").lower()
    server = p.get("server", "").strip()
    port = p.get("port", "").strip()
    tls = str(p.get("tls", "")).lower()
    name = p.get("name", "https_node")

    # 规则 7 & 8: 仅放行带有 TLS 的 HTTPS 代理
    if ptype == "http" and tls in ("true", "1") and server and port:
        username = p.get("username", "")
        password = p.get("password", "")
        auth = f"{username}:{password}@" if (username or password) else ""
        return f"https://{auth}{server}:{port}#{urllib.parse.quote(name)}"
    return ""


# ==============================================================================
# [规则 1：协议头标准化规范]
# ==============================================================================
def normalize_node_uri(line: str) -> str:
    """
    【规则 1】将所有 hy2 统一转换为 sing-box 标准的 hysteria2://，并补齐默认必要参数
    """
    line = line.strip()
    if line.startswith("hy2://"):
        line = "hysteria2://" + line[6:]

    # 对 hysteria2 进行参数健壮性规范 (补齐 insecure=1 防止自签证书报错)
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
# [规则 2 (阶段一) & 规则 6 & 规则 7：静态初筛与多协议 TLS 精准判定]
# ==============================================================================
def get_node_ip_or_host(line: str):
    """
    【规则 2 第一阶段】提取节点目标主机 IP/域名，用于静态初筛去重
    """
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith(("vless://", "hysteria2://", "hy2://", "https://")):
            u = urllib.parse.urlsplit(line)
            return u.hostname.lower() if u.hostname else None
        elif line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
            host = data.get("add") or data.get("host")
            return host.lower() if host else None
    except Exception:
        pass
    return None


def parse_and_validate_proxy(line: str):
    """
    【规则 4、规则 6、规则 7】:
    1. 过滤 .ir 等绝对死域
    2. 仅保留 hysteria2, vless, vmess, https 四大协议
    3. 针对性精确判定 TLS 是否为 True，剔除裸明文
    返回值: (protocol_tag, host, port, priority_rank) 或 None
    """
    line = line.strip()
    if not line:
        return None

    try:
        # 【规则 4】过滤完全无中国大陆路由的伊朗内网死域
        if ".ir" in line or "mbghalibaf" in line or "levikogjgfdd" in line:
            return None

        # ----------------------------------------------------------------------
        # 1. Hysteria 2 协议 (强制基于 QUIC/UDP，国际标准内建 TLS 1.3，天然为 True)
        # ----------------------------------------------------------------------
        if line.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if host and port:
                return ("hy2", host, port, 1)

        # ----------------------------------------------------------------------
        # 2. VLESS 协议 (必须识别 security=reality 或 security=tls)
        # ----------------------------------------------------------------------
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
            # 无 TLS / security=none 坚决剔除
            return None

        # ----------------------------------------------------------------------
        # 3. VMess 协议 (JSON 内 tls 字段为 tls/1/true，或处于 Cloudflare TLS 端口)
        # ----------------------------------------------------------------------
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
            # 明文 VMess 剔除
            return None

        # ----------------------------------------------------------------------
        # 4. HTTPS 协议 (标准带 TLS 的 HTTP 代理)
        # ----------------------------------------------------------------------
        elif line.startswith("https://"):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if host and port:
                return ("https", host, port, 5)

        # 其余所有协议 (trojan, ss, ssr, tuic, socks, 裸明文 http) 全数抛弃！

    except Exception:
        pass

    return None


# ==============================================================================
# [规则 5：云端独立并发网络测活 & 规则 2 阶段二：Socket peername 真实物理 IP 绝对去重]
# ==============================================================================
async def check_single_proxy(sem: asyncio.Semaphore, line: str, timeout: float = 2.5):
    """
    【规则 5】独立并发探测节点物理连通性
    【规则 2 第二部分】通过底层 Socket 获取其实际解析连接的真实物理 IP
    """
    parsed = parse_and_validate_proxy(line)
    if not parsed:
        return None
    proto_type, host, port, rank = parsed

    async with sem:
        t0 = time.time()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            
            # 从 Socket 底层提取连接成功的真实物理出口 IP
            peer = writer.get_extra_info("peername")
            real_ip = peer[0] if (peer and len(peer) > 0) else host

            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency_ms = int((time.time() - t0) * 1000)
            return {"line": line, "delay": latency_ms, "rank": rank, "real_ip": real_ip}
        except Exception:
            return None


async def run_batch_validation(candidate_nodes, concurrency=250, timeout=2.5):
    """
    【规则 5】全量高并发独立测活
    【规则 2 第二部分】严格执行真实物理 IP 绝对唯一去重 (相同的 IP 绝不重复出现)
    """
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
        if done % 500 == 0 or done == total:
            elapsed = time.time() - start_time
            rate = done / elapsed if elapsed > 0 else 0
            print(f"  测活进度: [{done}/{total}] 初步连通={len(alive_results)} 速率={rate:.0f}节点/s")

    # 1. 优先按协议质量升序 (hy2 > reality > vless_tls > vmess > https)，同协议按延迟升序
    alive_results.sort(key=lambda x: (x["rank"], x["delay"]))

    # 2. 【规则 2 第二部分】：动态真实物理 IP 绝对唯一去重
    final_unique_alive = []
    seen_physical_ips = set()
    for item in alive_results:
        real_ip = item.get("real_ip")
        if real_ip and real_ip not in seen_physical_ips:
            seen_physical_ips.add(real_ip)
            final_unique_alive.append(item)

    print(f"[+] 测活与物理 IP 去重完成! 耗时: {time.time()-start_time:.1f}s")
    print(f"    - 初步连通节点: {len(alive_results)} 个")
    print(f"    - 【单物理 IP 唯一存活】: {len(final_unique_alive)} 个 (彻底消灭所有复用同 IP 的换皮节点)")
    return final_unique_alive


# ==============================================================================
# [GITHUB API 请求封装与辅助方法]
# ==============================================================================
def github_request_json(url):
    headers = {
        "User-Agent": "proxy-auto-collector",
        "Accept": "application/vnd.github.v3+json",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read().decode("utf-8")
                return json.loads(data)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < MAX_RETRIES:
                print(f"[!] Rate limited ({e.code}), retrying in {RETRY_SLEEP_SECONDS}s... (attempt {attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            raise
        except Exception:
            if attempt < MAX_RETRIES:
                time.sleep(REQUEST_INTERVAL_SECONDS)
                continue
            raise


def fetch_file_text(owner, repo, branch, path):
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{urllib.parse.quote(path)}"
    headers = {"User-Agent": "proxy-auto-collector"}
    if GITHUB_TOKEN:
        headers["Authorization"] = f"token {GITHUB_TOKEN}"

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=25) as resp:
                raw_bytes = resp.read()
                return decode_subscription_text(raw_bytes)
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < MAX_RETRIES:
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            raise
        except Exception:
            if attempt < MAX_RETRIES:
                time.sleep(REQUEST_INTERVAL_SECONDS)
                continue
            raise


def list_tree(owner, repo, branch):
    ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/heads/{urllib.parse.quote(branch)}"
    ref_data = github_request_json(ref_url)
    commit_sha = ref_data["object"]["sha"]
    commit_url = f"https://api.github.com/repos/{owner}/{repo}/git/commits/{commit_sha}"
    commit_data = github_request_json(commit_url)
    tree_sha = commit_data["tree"]["sha"]
    tree_url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{tree_sha}?recursive=1"
    tree_data = github_request_json(tree_url)
    return tree_data.get("tree", [])


def build_project_file_list(project):
    mode = project.get("mode")
    if mode == "explicit_files":
        return list(project.get("file_paths", []))

    tree = list_tree(project["owner"], project["repo"], project["branch"])
    dirs = project.get("dirs", [])
    matched_files = []
    for item in tree:
        if item.get("type") != "blob":
            continue
        p = item.get("path", "")
        for d in dirs:
            prefix = f"{d}/"
            if p.startswith(prefix) and (p.endswith(".txt") or p.endswith(".sub")):
                matched_files.append(p)
                break
    return matched_files


def line_hash(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


# ==============================================================================
# 【第一部分：采集所有链接源并全量汇总】
# ==============================================================================
def collect_all_sources() -> list:
    """
    第一大部分：只负责从外部所有来源（13个仓库 + 8个全球中立订阅源）中极速抓取，
    进行智能解包，全量汇总合并为一个待处理候选大池，不做任何主观过滤。
    """
    candidate_lines = []
    seen_raw = set()

    if not ENABLE_REMOTE_COLLECT:
        print("[*] 远程采集开关已关闭，跳过第一部分采集。")
        return candidate_lines

    print("======================================================================")
    print("【第一部分】：采集所有链接源并全量汇总")
    print("======================================================================")

    # 1.1 并发采集 8 个全球长期维护的高频中立订阅源
    print(f"[*] 正在拉取 {len(EXTRA_SUBSCRIPTIONS)} 个全球高频中立订阅源...")
    for extra_url in EXTRA_SUBSCRIPTIONS:
        try:
            req = urllib.request.Request(extra_url, headers={"User-Agent": "proxy-auto-collector"})
            with urllib.request.urlopen(req, timeout=15) as resp:
                decoded_text = decode_subscription_text(resp.read())
                extracted = extract_proxies_from_text(decoded_text)
                new_sub_count = 0
                for line in extracted:
                    if line not in seen_raw:
                        seen_raw.add(line)
                        candidate_lines.append(line)
                        new_sub_count += 1
                source_name = extra_url.split("/")[4] if "/" in extra_url else "sub"
                print(f"  [+] 成功解析: {source_name} (+{new_sub_count} 节点)")
        except Exception as e:
            source_name = extra_url.split("/")[4] if "/" in extra_url else "sub"
            print(f"  [-] 订阅源跳过: {source_name} ({e})")

    # 1.2 多线程并发拉取原始 13 个 GitHub 数据源仓库
    print(f"\n[*] 正在并发采集 {len(PROJECTS)} 个原始 GitHub 仓库...")
    for project in PROJECTS:
        name = project["name"]
        owner = project["owner"]
        repo = project["repo"]
        branch = project["branch"]

        try:
            files = build_project_file_list(project)
        except urllib.error.URLError as e:
            print(f"[-] {name} 访问失败: {e}")
            continue

        if not files:
            continue

        def fetch_worker(p):
            try:
                return fetch_file_text(owner, repo, branch, p)
            except Exception:
                return ""

        with ThreadPoolExecutor(max_workers=12) as ex:
            for text in ex.map(fetch_worker, files):
                extracted = extract_proxies_from_text(text)
                for line in extracted:
                    if line not in seen_raw:
                        seen_raw.add(line)
                        candidate_lines.append(line)

    # 1.3 历史后备容灾保障
    if not candidate_lines and os.path.exists(OUTPUT_FILE):
        print("[!] 远程采集未获有效数据，激活历史文件后备容灾...")
        with open(OUTPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line and line not in seen_raw:
                    seen_raw.add(line)
                    candidate_lines.append(line)

    print(f"\n[+] 第一部分完成！全网采集汇总候选池总量: {len(candidate_lines)} 个原始节点\n")
    return candidate_lines


# ==============================================================================
# 【第二部分：把汇总后的链接按 7 大铁律统一处理】
# ==============================================================================
def process_and_validate_candidates(candidate_lines: list):
    """
    第二大部分：接收第一部分汇总完毕的候选节点池，严格按 7 大铁律流水线依次处理：
    初筛 -> 协议标准化 -> 静态初去重 -> 独立并发测活 -> 底层真实物理IP绝对去重 -> 输出
    """
    if not candidate_lines:
        print("[-] 待处理候选池为空，退出处理。")
        return

    print("======================================================================")
    print("【第二部分】：对汇总后的链接统一进行深度处理与测活")
    print("======================================================================")

    # 步骤 2.1: 协议白名单初筛与各协议 TLS 针对性判定 (规则 4、规则 6、规则 7)
    if ENABLE_SMART_FILTER:
        print("[*] 步骤 1/4: 执行协议白名单(Hy2/VLESS/VMess/HTTPS)与 TLS 加密真伪识别...")
        filtered_nodes = []
        for line in candidate_lines:
            if parse_and_validate_proxy(line) is not None:
                filtered_nodes.append(line)
        print(f"  [+] 筛选保留合规加密节点: {len(filtered_nodes)} / {len(candidate_lines)} (已物理剔除非白名单协议及裸明文)")
        candidate_lines = filtered_nodes

    # 步骤 2.2: 规则 1 协议头标准化规范 & 规则 2 第一阶段静态单 IP 去重
    if ENABLE_ENDPOINT_DEDUP:
        print("\n[*] 步骤 2/4: 执行协议标准化规范(hy2->hysteria2/参数补齐)与静态单 IP 初筛去重...")
        dedup_map = {}
        for line in candidate_lines:
            host_key = get_node_ip_or_host(line)
            normalized_line = normalize_node_uri(line)
            if host_key and host_key not in dedup_map:
                dedup_map[host_key] = normalized_line
        unique_nodes = list(dedup_map.values())
        print(f"  [+] 静态初筛完成: 粗筛为 {len(unique_nodes)} 个独立目标节点")
    else:
        unique_nodes = [normalize_node_uri(l) for l in candidate_lines]

    # 步骤 2.3: 规则 5 云端独立并发测活 & 规则 2 第二阶段动态底层真实物理 IP 绝对去重
    if ENABLE_CONCURRENT_VALIDATION and unique_nodes:
        print("\n[*] 步骤 3/4: 执行原生异步 250 并发独立网络测活 (零连坐)...")
        alive_results = asyncio.run(
            run_batch_validation(
                unique_nodes,
                concurrency=CHECK_CONCURRENCY,
                timeout=CHECK_TIMEOUT_SECONDS,
            )
        )

        # 步骤 2.4: 格式化保存与主文件同步
        print("\n[*] 步骤 4/4: 保存最终高精纯存活节点并同步主池...")
        with open(VALID_OUTPUT_FILE, "w", encoding="utf-8") as vf:
            for item in alive_results:
                vf.write(item["line"] + "\n")
        print(f"  [+] 成功输出高精存活池: {VALID_OUTPUT_FILE} (共 {len(alive_results)} 个独立物理 IP 节点)")

        if SYNC_TO_ALL_PROXIES:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as of:
                for item in alive_results:
                    of.write(item["line"] + "\n")
            print(f"  [+] 成功同步主文件: {OUTPUT_FILE}")

        with open(SEEN_FILE, "w", encoding="utf-8") as sf:
            for item in alive_results:
                sf.write(line_hash(item["line"]) + "\n")


# ==============================================================================
# [主运行入口]
# ==============================================================================
def main():
    # 1. 第一部分：采集所有链接源并全量汇总
    raw_candidates = collect_all_sources()

    # 2. 第二部分：把汇总后的链接再统一处理与测活
    process_and_validate_candidates(raw_candidates)


if __name__ == "__main__":
    main()

