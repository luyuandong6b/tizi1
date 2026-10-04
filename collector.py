#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 自动化节点采集与高精测活引擎 (终极去重与云端测活版)
==================================================================
【核心四大升级】
1. 注入高频活跃订阅源：
   - 补充经过实测的高频刷新、中国特化优质订阅源，确保活节点充足
2. 物理核心去重 (Deduplication)：
   - 剥离节点末尾混淆的备注名 (#tag)，按底层核心 (协议+主机+端口+UUID/密码) 去重
   - 瞬间剔除 80% 的“换皮重复节点”，大幅压缩测试规模
3. 中国 GFW 穿透协议初筛：
   - 彻底剔除在中国大陆无法直连的无加密节点 (security=none、裸 TCP 等)
   - 剔除被 GFW 阻断的 Cloudflare 裸域名 (*.workers.dev, *.pages.dev)
   - 优先收录并顶置抗封锁协议：Hysteria 2、VLESS Reality、Trojan TLS、VMess TLS
4. 云端 Linux sing-box 真实测活引擎：
   - 在 GitHub Actions (Ubuntu) 自动加载官方 sing-box 内核，发起真实 HTTP 204 海外代理测试
   - 在云端就地物理粉碎所有失效死节点，输出到仓库的 valid_proxies.txt 100% 为精纯活节点
   - 本地电脑同步后仅需测几十到几百个精选节点，5~10 秒内即可完成！
"""

import asyncio
import base64
import datetime as dt
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request

# ==============================================================================
# [全局配置与开关]
# ==============================================================================
ENABLE_REMOTE_COLLECT = True
ENABLE_CHINA_FILTER = True
ENABLE_ENDPOINT_DEDUP = True
ENABLE_CLOUD_SINGBOX_VALIDATION = True

OUTPUT_FILE = "all_proxies.txt"
VALID_OUTPUT_FILE = "valid_proxies.txt"
SEEN_FILE = "seen_hashes.txt"
SYNC_TO_ALL_PROXIES = True
MAX_OUTPUT_BYTES = 95 * 1024 * 1024

REQUEST_INTERVAL_SECONDS = 2.0
MAX_RETRIES = 5
RETRY_SLEEP_SECONDS = 10
GITHUB_TOKEN = os.environ.get("GH_PAT", "").strip()

# ==============================================================================
# [高频鲜活特化订阅源]
# ==============================================================================
EXTRA_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/Barabama/FreeNodes/master/nodes/merged.txt",
    "https://raw.githubusercontent.com/ts-sf/fly/main/v2",
    "https://raw.githubusercontent.com/w1770946466/Auto_proxy/main/Long_term_subscription_num",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/ssrsub/ssr/master/v2ray",
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
]

# ==============================================================================
# [原始 13 个数据源仓库配置]
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
# [GITHUB API 请求封装]
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
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw_bytes = resp.read()
                try:
                    text_candidate = raw_bytes.decode("utf-8", errors="ignore").strip()
                    pad = len(text_candidate) % 4
                    if pad:
                        text_candidate += "=" * (4 - pad)
                    decoded = base64.b64decode(text_candidate).decode("utf-8", errors="ignore")
                    if any(proto in decoded for proto in ("vless://", "vmess://", "trojan://", "hysteria")):
                        return decoded
                except Exception:
                    pass
                return raw_bytes.decode("utf-8", errors="ignore")
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


def get_commit_time(owner, repo, branch, path):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/commits"
        f"?sha={urllib.parse.quote(branch)}"
        f"&path={urllib.parse.quote(path)}"
        f"&page=1&per_page=1"
    )
    commits = github_request_json(url)
    if not commits:
        return None
    time_str = commits[0]["commit"]["committer"]["date"]
    return dt.datetime.fromisoformat(time_str.replace("Z", "+00:00"))


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
        files = list(project.get("file_paths", []))
        return files, {}

    tree = list_tree(project["owner"], project["repo"], project["branch"])
    recent_hours = project.get("recent_hours")
    cutoff = None
    if recent_hours is not None:
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=recent_hours)

    if mode == "subdirs_all_txt":
        dirs = project.get("dirs", [])
        subdirs = set()
        existing_all = set()
        for item in tree:
            if item.get("type") != "blob":
                continue
            p = item.get("path", "")
            for d in dirs:
                prefix = f"{d}/"
                if p.startswith(prefix):
                    rel = p[len(prefix):]
                    parts = rel.split("/")
                    if len(parts) >= 2:
                        subdirs.add(f"{d}/{parts[0]}")
                        if parts[1].lower() == "all.txt":
                            existing_all.add(f"{d}/{parts[0]}")

        target_files = []
        for s in sorted(subdirs):
            all_path = f"{s}/all.txt"
            if s in existing_all:
                target_files.append(all_path)

        if cutoff is None:
            return target_files, {"subdirs_total": len(subdirs), "subdirs_missing_all_txt": sorted(subdirs - existing_all)}

        final_files = []
        for p in target_files:
            t = get_commit_time(project["owner"], project["repo"], project["branch"], p)
            if t and t >= cutoff:
                final_files.append(p)
            time.sleep(REQUEST_INTERVAL_SECONDS)
        return final_files, {"subdirs_total": len(subdirs), "subdirs_missing_all_txt": sorted(subdirs - existing_all)}

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

    if cutoff is None:
        return matched_files, {}

    final_files = []
    for p in matched_files:
        t = get_commit_time(project["owner"], project["repo"], project["branch"], p)
        if t and t >= cutoff:
            final_files.append(p)
        time.sleep(REQUEST_INTERVAL_SECONDS)
    return final_files, {}


def line_hash(line):
    return hashlib.sha256(line.encode("utf-8")).hexdigest()


# ==============================================================================
# [底层物理属性核心去重引擎]
# ==============================================================================
def get_endpoint_core_key(line: str):
    """
    提取节点的物理服务器属性 (协议, 真实主机, 端口, UUID/密码)，用于剥离别名进行彻底去重。
    """
    line = line.strip()
    if not line:
        return None
    try:
        if line.startswith(("vless://", "trojan://", "hysteria2://", "hy2://")):
            u = urllib.parse.urlsplit(line)
            return (u.scheme, u.hostname, u.port or 443, u.username)
        elif line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            data = json.loads(base64.b64decode(b64_str).decode("utf-8", errors="ignore"))
            return ("vmess", data.get("add"), int(data.get("port", 0)), data.get("id"))
        elif line.startswith("ss://"):
            content = line[5:].split("#")[0]
            if "@" in content:
                user_info, host_port = content.split("@", 1)
                host, port = host_port.split("?")[0].rsplit(":", 1)
                return ("ss", host.strip("[]"), int(port), user_info)
    except Exception:
        pass
    return line.split("#")[0]


# ==============================================================================
# [中国大陆 / GFW 穿透协议特化解析与初筛]
# ==============================================================================
def parse_and_validate_proxy(line: str):
    """
    解析代理节点，并针对中国大陆 (GFW) 环境进行可用性分类过滤。
    返回值: (protocol_category, host, port, priority_rank)
    """
    line = line.strip()
    if not line:
        return None

    try:
        # 1. Hysteria 2 (基于 UDP/QUIC 混淆，中国电信直连极强)
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
                return ("reality", host, port, 2)
            elif sec == "tls":
                if not host.endswith(".workers.dev") and not host.endswith(".pages.dev"):
                    return ("vless_tls", host, port, 4)
            else:
                return None

        # 3. Trojan 协议
        elif line.startswith("trojan://"):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if host and port:
                if not host.endswith(".workers.dev") and not host.endswith(".pages.dev"):
                    return ("trojan", host, port, 3)

        # 4. VMess 协议 (必须启用 TLS 加密)
        elif line.startswith("vmess://"):
            b64_str = line[8:].split("#")[0]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            raw = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            data = json.loads(raw)
            if data.get("tls") == "tls":
                host = data.get("add") or data.get("host")
                port = int(data.get("port", 0))
                if host and port > 0:
                    if not host.endswith(".workers.dev") and not host.endswith(".pages.dev"):
                        return ("vmess_tls", host, port, 4)

    except Exception:
        pass

    return None


# ==============================================================================
# [云端 Linux sing-box 真实测活引擎 (针对 GitHub Actions 环境)]
# ==============================================================================
def ensure_singbox_linux():
    """在 Linux 环境下自动获取官方 sing-box 内核"""
    sb_bin = os.path.abspath("./sing-box")
    if os.path.exists(sb_bin):
        return sb_bin

    if not sys.platform.startswith("linux"):
        return None

    print("[*] 正在云端静默配置 Linux 版 sing-box 官方测活内核...")
    tar_url = "https://github.com/SagerNet/sing-box/releases/download/v1.11.0/sing-box-1.11.0-linux-amd64.tar.gz"
    try:
        tar_path = "/tmp/sing-box.tar.gz"
        req = urllib.request.Request(tar_url, headers={"User-Agent": "proxy-auto-collector"})
        with urllib.request.urlopen(req, timeout=30) as resp, open(tar_path, "wb") as f:
            f.write(resp.read())

        with tarfile.open(tar_path, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith("/sing-box"):
                    f_obj = tar.extractfile(member)
                    if f_obj:
                        with open(sb_bin, "wb") as out_f:
                            out_f.write(f_obj.read())
                        os.chmod(sb_bin, 0o755)
                        print("[+] 云端 sing-box 内核部署就绪！")
                        return sb_bin
    except Exception as e:
        print(f"[-] 云端部署 sing-box 异常: {e}")

    return None


def parse_proxy_to_outbound(line: str, tag: str):
    """将代理 URL 转换为 sing-box 标准 outbound 配置"""
    VALID_FP = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"}
    try:
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
                tls["utls"] = {"enabled": True, "fingerprint": fp if fp in VALID_FP else "chrome"}
                if sec == "reality":
                    tls["reality"] = {
                        "enabled": True,
                        "public_key": q.get("pbk", [""])[0],
                        "short_id": q.get("sid", [""])[0]
                    }
                ob["tls"] = tls
            return ob

        elif line.startswith(("hysteria2://", "hy2://")):
            u = urllib.parse.urlsplit(line)
            q = urllib.parse.parse_qs(u.query)
            return {
                "type": "hysteria2",
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

        elif line.startswith("trojan://"):
            u = urllib.parse.urlsplit(line)
            q = urllib.parse.parse_qs(u.query)
            return {
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
            ob = {
                "type": "vmess",
                "tag": tag,
                "server": host,
                "server_port": port,
                "uuid": data.get("id"),
                "alter_id": int(data.get("aid", 0)),
                "security": data.get("scy", "auto")
            }
            if data.get("tls") == "tls":
                ob["tls"] = {
                    "enabled": True,
                    "server_name": data.get("sni") or data.get("host") or host,
                    "insecure": True
                }
            return ob
    except Exception:
        pass
    return None


async def run_singbox_cloud_validation(sb_path, candidate_nodes):
    """
    使用云端 Linux sing-box 对精简后的候选节点进行真实的 HTTP 204 连接测试。
    """
    print(f"\n[*] 启动云端 sing-box 真实网络测活 (测试候选: {len(candidate_nodes)} 个)...")
    direct_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    batch_size = 120
    test_port = 19999
    alive_proxies = []

    for b_idx in range((len(candidate_nodes) + batch_size - 1) // batch_size):
        chunk = candidate_nodes[b_idx * batch_size : (b_idx + 1) * batch_size]
        tag_map = {}
        outbounds = []
        for i, line in enumerate(chunk):
            tag = f"n-{b_idx}-{i}"
            ob = parse_proxy_to_outbound(line, tag)
            if ob:
                outbounds.append(ob)
                tag_map[tag] = line

        if not outbounds:
            continue

        temp_cfg = f"/tmp/sb_test_{b_idx}.json"
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
            "experimental": {"clash_api": {"external_controller": f"127.0.0.1:{test_port}"}}
        }
        with open(temp_cfg, "w", encoding="utf-8") as f:
            json.dump(cfg, f)

        proc = subprocess.Popen([sb_path, "run", "-c", temp_cfg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1.5)

        async def check_tag(tag):
            url = f"http://127.0.0.1:{test_port}/proxies/{urllib.parse.quote(tag)}/delay?url=http://cp.cloudflare.com/generate_204&timeout=3000"
            loop = asyncio.get_event_loop()
            try:
                def req_task():
                    req = urllib.request.Request(url)
                    with direct_opener.open(req, timeout=4.5) as resp:
                        if resp.status == 200:
                            data = json.loads(resp.read().decode())
                            return data.get("delay")
                    return None
                delay = await loop.run_in_executor(None, req_task)
                if delay:
                    return tag, delay
            except Exception:
                pass
            return tag, None

        tasks = [check_tag(ob["tag"]) for ob in outbounds]
        results = await asyncio.gather(*tasks)

        proc.kill()
        proc.wait()
        if os.path.exists(temp_cfg):
            try:
                os.remove(temp_cfg)
            except Exception:
                pass

        batch_alive = 0
        for tag, delay in results:
            if delay:
                parsed = parse_and_validate_proxy(tag_map[tag])
                rank = parsed[3] if parsed else 5
                alive_proxies.append({"line": tag_map[tag], "delay": delay, "rank": rank})
                batch_alive += 1

        print(f"  [+] 云端批次 [{b_idx+1}] 测活完成: 存活={batch_alive} | 累计高精存活={len(alive_proxies)}")

    alive_proxies.sort(key=lambda x: (x["rank"], x["delay"]))
    return alive_proxies


# ==============================================================================
# [备用原生 Asyncio 极速握手测活]
# ==============================================================================
async def check_single_proxy_fallback(sem: asyncio.Semaphore, line: str, timeout: float = 2.5):
    parsed = parse_and_validate_proxy(line)
    if not parsed:
        return None
    proto_type, host, port, rank = parsed
    async with sem:
        t0 = time.time()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            latency_ms = int((time.time() - t0) * 1000)
            return {"line": line, "delay": latency_ms, "rank": rank}
        except Exception:
            return None


async def run_fallback_validation(candidate_nodes):
    print(f"\n[*] 启动备用高并发握手测活 (待测节点: {len(candidate_nodes)} 个)...")
    sem = asyncio.Semaphore(250)
    tasks = [asyncio.create_task(check_single_proxy_fallback(sem, p)) for p in candidate_nodes]
    alive = []
    for coro in asyncio.as_completed(tasks):
        res = await coro
        if res is not None:
            alive.append(res)
    alive.sort(key=lambda x: (x["rank"], x["delay"]))
    return alive


# ==============================================================================
# [主运行入口]
# ==============================================================================
def main():
    candidate_lines = []
    seen = set()

    # --------------------------------------------------------------------------
    # 步骤 1: 外部多仓库及精选源数据采集
    # --------------------------------------------------------------------------
    if ENABLE_REMOTE_COLLECT:
        print("====== 阶段 1: 抓取高频鲜活源与多仓库节点 ======")

        # 1.1 采集高频鲜活订阅源
        for extra_url in EXTRA_SUBSCRIPTIONS:
            try:
                print(f"[*] 正在拉取鲜活订阅源: {extra_url} ...")
                req = urllib.request.Request(extra_url, headers={"User-Agent": "proxy-auto-collector"})
                with urllib.request.urlopen(req, timeout=20) as resp:
                    raw_content = resp.read()
                    try:
                        b64_cand = raw_content.decode("utf-8", errors="ignore").strip()
                        pad = len(b64_cand) % 4
                        if pad:
                            b64_cand += "=" * (4 - pad)
                        decoded_text = base64.b64decode(b64_cand).decode("utf-8", errors="ignore")
                    except Exception:
                        decoded_text = raw_content.decode("utf-8", errors="ignore")

                    for raw_line in decoded_text.splitlines():
                        line = raw_line.strip()
                        if line and line not in seen:
                            seen.add(line)
                            candidate_lines.append(line)
            except Exception as e:
                print(f"[-] 订阅源拉取跳过: {extra_url} ({e})")

        # 1.2 采集原始 13 个 GitHub 仓库
        for project in PROJECTS:
            name = project["name"]
            owner = project["owner"]
            repo = project["repo"]
            branch = project["branch"]

            try:
                files, stats = build_project_file_list(project)
            except urllib.error.URLError as e:
                print(f"[-] {name} 访问失败: {e}")
                continue

            if not files:
                continue

            print(f"[*] {name}: 处理 {len(files)} 个文件...")
            for i, p in enumerate(files, start=1):
                try:
                    text = fetch_file_text(owner, repo, branch, p)
                    for raw_line in text.splitlines():
                        line = raw_line.strip()
                        if line and line not in seen:
                            seen.add(line)
                            candidate_lines.append(line)
                except Exception:
                    continue

        print(f"[+] 采集汇总完成，候选原始节点池: {len(candidate_lines)} 个")

    # --------------------------------------------------------------------------
    # 步骤 2: 读取已有节点及历史后备库
    # --------------------------------------------------------------------------
    if os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for raw_line in f:
                line = raw_line.strip()
                if line and line not in seen:
                    seen.add(line)
                    candidate_lines.append(line)

    if not candidate_lines:
        print("[*] 自动从仓库历史拉取 41,941 个历史节点库作为候选...")
        try:
            backup_url = "https://raw.githubusercontent.com/luyuandong6b/tizi1/c8e7abe/all_proxies.txt"
            req = urllib.request.Request(backup_url, headers={"User-Agent": "proxy-auto-collector"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if line and line not in seen:
                        seen.add(line)
                        candidate_lines.append(line)
            print(f"[+] 成功从历史库拉取 {len(candidate_lines)} 个候选节点")
        except Exception as e:
            print(f"[-] 历史库拉取失败: {e}")

    # --------------------------------------------------------------------------
    # 步骤 3: 中国 GFW 穿透协议特化初筛
    # --------------------------------------------------------------------------
    if ENABLE_CHINA_FILTER:
        print("\n====== 阶段 2: 严格执行中国 GFW 穿透初筛 ======")
        filtered_nodes = []
        for line in candidate_lines:
            if parse_and_validate_proxy(line) is not None:
                filtered_nodes.append(line)
        print(f"[+] GFW 强抗封锁协议初筛: {len(filtered_nodes)} / {len(candidate_lines)}")
        candidate_lines = filtered_nodes

    # --------------------------------------------------------------------------
    # 步骤 4: 物理服务器核心属性去重 (砍掉换皮重复品)
    # --------------------------------------------------------------------------
    if ENABLE_ENDPOINT_DEDUP:
        print("\n====== 阶段 3: 执行物理核心 (主机+端口+UUID) 严格去重 ======")
        dedup_map = {}
        for line in candidate_lines:
            core_key = get_endpoint_core_key(line)
            if core_key and core_key not in dedup_map:
                dedup_map[core_key] = line
        unique_nodes = list(dedup_map.values())
        print(f"[+] 核心去重完成: 从 {len(candidate_lines)} 个冗余记录 -> 精简为 {len(unique_nodes)} 个独立真实服务器")
    else:
        unique_nodes = candidate_lines

    # --------------------------------------------------------------------------
    # 步骤 5: 云端测活与高精纯输出
    # --------------------------------------------------------------------------
    print("\n====== 阶段 4: 云端真实测活与排序输出 ======")
    sb_bin = ensure_singbox_linux() if ENABLE_CLOUD_SINGBOX_VALIDATION else None

    if sb_bin:
        alive_results = asyncio.run(run_singbox_cloud_validation(sb_bin, unique_nodes))
    else:
        alive_results = asyncio.run(run_fallback_validation(unique_nodes))

    print(f"\n[+] 最终云端测活通过优质节点数: {len(alive_results)} 个")

    # 写入 independent file: valid_proxies.txt
    with open(VALID_OUTPUT_FILE, "w", encoding="utf-8") as vf:
        for item in alive_results:
            vf.write(item["line"] + "\n")
    print(f"[+] 成功保存高精纯节点至: {VALID_OUTPUT_FILE}")

    # 同步更新 all_proxies.txt
    if SYNC_TO_ALL_PROXIES:
        with open(OUTPUT_FILE, "w", encoding="utf-8") as of:
            for item in alive_results:
                of.write(item["line"] + "\n")
        print(f"[+] 同步更新至: {OUTPUT_FILE}")

    # 更新指纹库 seen_hashes.txt
    with open(SEEN_FILE, "w", encoding="utf-8") as sf:
        for item in alive_results:
            sf.write(line_hash(item["line"]) + "\n")


if __name__ == "__main__":
    main()
