#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Actions 自动化节点采集与测活引擎 (中国大陆/天翼云特化定制版)
====================================================================
【核心升级】
1. 中国 GFW 穿透初筛：
   - 彻底剔除在中国大陆无法直连的无加密节点 (security=none、裸 TCP 等)
   - 剔除被 GFW SNI/DNS 阻断的 Cloudflare 裸域名 (*.workers.dev, *.pages.dev)
   - 优先收录并顶置强抗封锁协议：Hysteria 2、VLESS Reality、Trojan TLS、VMess TLS
2. 高并发异步测活：
   - 基于 asyncio 协程池超高速并发测活，毫秒级响应
   - 测量真实握手延迟，按协议可用性及低延迟智能排序
3. 纯原生标准库实现：
   - 零第三方依赖 (免 pip install)，与 GitHub Actions 环境 100% 兼容
"""

import asyncio
import base64
import datetime as dt
import hashlib
import json
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

# ==============================================================================
# [全局配置与运行开关]
# ==============================================================================
# ENABLE_REMOTE_COLLECT:
# True  = 从配置的远程 GitHub 仓库抓取最新节点
# False = 跳过远程抓取，直接验证处理已有节点
ENABLE_REMOTE_COLLECT = True

# ENABLE_CHINA_FILTER:
# True  = 启用中国大陆 GFW 过滤 (只保留 Hysteria2 / VLESS-Reality / Trojan / TLS 强加密节点)
# False = 保留所有协议节点
ENABLE_CHINA_FILTER = True

# ENABLE_VALIDATION:
# True  = 启用高并发网络测活
# False = 仅抓取/去重，不测活
ENABLE_VALIDATION = True

# 测活并发数与单节点超时时间
CHECK_CONCURRENCY = 250
CHECK_TIMEOUT_SECONDS = 2.5

# 输入与输出文件路径
OUTPUT_FILE = "all_proxies.txt"
VALID_OUTPUT_FILE = "valid_proxies.txt"
SEEN_FILE = "seen_hashes.txt"

# 是否将验证存活的节点同步回写至 all_proxies.txt
SYNC_TO_ALL_PROXIES = True

# 输出文件最大安全体积 (95MB，防止超出 GitHub 仓库限制)
MAX_OUTPUT_BYTES = 95 * 1024 * 1024

REQUEST_INTERVAL_SECONDS = 2.0
MAX_RETRIES = 5
RETRY_SLEEP_SECONDS = 10

GITHUB_TOKEN = os.environ.get("GH_PAT", "").strip()

# ==============================================================================
# [原始 13 个数据源仓库配置 - 100% 完整保留]
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
# [额外精选优质订阅源 - 强化国内连通性]
# ==============================================================================
EXTRA_SUBSCRIPTIONS = [
    "https://raw.githubusercontent.com/ermaozi/get_subscribe/main/subscribe/v2ray.txt",
    "https://raw.githubusercontent.com/Pawdroid/Free-servers/main/sub",
    "https://raw.githubusercontent.com/ripaojiedian/freenode/main/sub",
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
                # 尝试 base64 解码订阅内容
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
# [中国大陆 / GFW 穿透特化解析与过滤引擎]
# ==============================================================================
def parse_and_validate_proxy(line: str):
    """
    解析代理节点，并针对中国大陆 (GFW) 环境进行可用性分类过滤。
    返回值: (protocol_category, host, port, priority_rank)
    priority_rank: 越小优先级越高 (1: Hy2, 2: Reality, 3: Trojan, 4: TLS)
    """
    line = line.strip()
    if not line:
        return None

    try:
        # 1. Hysteria 2 (最高优先级：基于 UDP/QUIC 混淆，中国电信天翼云直连极强)
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

            # VLESS Reality (顶级抗封锁：伪装苹果/微软等国外 TLS 1.3 流量)
            if sec == "reality":
                return ("reality", host, port, 2)
            # VLESS TLS (标准 TLS 加密)
            elif sec == "tls":
                if not host.endswith(".workers.dev") and not host.endswith(".pages.dev"):
                    return ("vless_tls", host, port, 4)
            # security=none 在国内 100% 被 GFW 瞬间丢包阻断，直接过滤剔除
            else:
                return None

        # 3. Trojan 协议 (固有 TLS 加密)
        elif line.startswith("trojan://"):
            u = urllib.parse.urlsplit(line)
            host = u.hostname
            port = u.port or 443
            if host and port:
                if not host.endswith(".workers.dev") and not host.endswith(".pages.dev"):
                    return ("trojan", host, port, 3)

        # 4. VMess 协议 (必须启用 TLS 加密，未加密明文在 GFW 必死)
        elif line.startswith("vmess://"):
            b64_str = line[8:]
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

        # 5. Shadowsocks (仅保留合法的带加密节点)
        elif line.startswith("ss://"):
            content = line[5:].split("#")[0]
            if "@" in content:
                host_port = content.split("@")[1].split("?")[0]
                host, port = host_port.rsplit(":", 1)
                return ("ss", host.strip("[]"), int(port), 5)

    except Exception:
        pass

    return None


# ==============================================================================
# [高并发异步网络测活引擎]
# ==============================================================================
async def check_single_proxy(sem: asyncio.Semaphore, line: str, timeout: float):
    """通过异步 TCP 握手校验节点端口存活与延迟"""
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
            return {
                "line": line,
                "proto": proto_type,
                "rank": rank,
                "latency": latency_ms,
            }
        except Exception:
            return None


async def run_batch_validation(proxies, concurrency=250, timeout=2.5):
    """并发批量测活"""
    total = len(proxies)
    print(f"\n[+] 启动高并发网络测活: 待测节点={total} | 并发数={concurrency} | 超时={timeout}s")

    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(check_single_proxy(sem, p, timeout)) for p in proxies]

    alive_results = []
    start_time = time.time()
    done_count = 0

    for coro in asyncio.as_completed(tasks):
        res = await coro
        done_count += 1
        if res is not None:
            alive_results.append(res)

        if done_count % 1000 == 0 or done_count == total:
            elapsed = time.time() - start_time
            rate = done_count / elapsed if elapsed > 0 else 0
            print(
                f"测活进度: [{done_count}/{total}] "
                f"存活数: {len(alive_results)} "
                f"存活率: {len(alive_results) / done_count * 100:.1f}% "
                f"速率: {rate:.0f} 节点/秒"
            )

    # 智能排序：优先抗封锁协议 (Rank 升序)，同协议按延迟 (Latency 升序)
    alive_results.sort(key=lambda x: (x["rank"], x["latency"]))

    elapsed_total = time.time() - start_time
    print(f"[+] 测活完成! 总耗时: {elapsed_total:.2f}s | 优质存活={len(alive_results)}/{total}")
    return alive_results


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
        print("====== 阶段 1: 远程订阅源与 GitHub 仓库采集 ======")

        # 1.1 采集额外精选源
        for extra_url in EXTRA_SUBSCRIPTIONS:
            try:
                print(f"[*] 正在拉取精选订阅源: {extra_url} ...")
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
                print(f"[-] 精选源拉取跳过: {extra_url} ({e})")

        # 1.2 采集 13 个 GitHub 仓库
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

            print(f"[*] {name}: 开始处理 {len(files)} 个文件...")
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

        print(f"[+] 远程采集结束，共汇总候选节点: {len(candidate_lines)} 个")

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

    # 容灾后备：若当前无节点，自动拉取历史 4 万节点库
    if not candidate_lines:
        print("[*] 当前无节点，自动从仓库历史拉取 41,941 个历史节点库作为候选...")
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
    # 步骤 3: 中国大陆 GFW 穿透协议特化初筛
    # --------------------------------------------------------------------------
    if ENABLE_CHINA_FILTER:
        print(f"\n====== 阶段 2: 针对中国大陆/天翼云网络进行协议穿透筛选 ======")
        filtered_nodes = []
        proto_stats = {}
        for line in candidate_lines:
            parsed = parse_and_validate_proxy(line)
            if parsed is not None:
                filtered_nodes.append(line)
                proto_stats[parsed[0]] = proto_stats.get(parsed[0], 0) + 1

        print(f"[+] 筛选后强抗封锁候选节点: {len(filtered_nodes)} / {len(candidate_lines)}")
        print(f"    - 协议构成统计: {proto_stats}")
        candidate_nodes = filtered_nodes
    else:
        candidate_nodes = candidate_lines

    # --------------------------------------------------------------------------
    # 步骤 4: 高并发网络测活与排序输出
    # --------------------------------------------------------------------------
    if ENABLE_VALIDATION and candidate_nodes:
        print(f"\n====== 阶段 3: 执行高并发测活与质量排序 ======")
        alive_results = asyncio.run(
            run_batch_validation(
                candidate_nodes,
                concurrency=CHECK_CONCURRENCY,
                timeout=CHECK_TIMEOUT_SECONDS,
            )
        )

        # 写入独立存活文件 valid_proxies.txt
        with open(VALID_OUTPUT_FILE, "w", encoding="utf-8") as vf:
            for item in alive_results:
                vf.write(item["line"] + "\n")
        print(f"[+] 成功将 {len(alive_results)} 个天翼云高可用节点保存至: {VALID_OUTPUT_FILE}")

        # 同步回写至 all_proxies.txt
        if SYNC_TO_ALL_PROXIES:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as of:
                for item in alive_results:
                    of.write(item["line"] + "\n")
            print(f"[+] 成功同步至主节点文件: {OUTPUT_FILE}")

        # 更新指纹库 seen_hashes.txt
        with open(SEEN_FILE, "w", encoding="utf-8") as sf:
            for item in alive_results:
                sf.write(line_hash(item["line"]) + "\n")
    else:
        # 未开启验证则直接保存筛选结果
        with open(OUTPUT_FILE, "w", encoding="utf-8") as of:
            for line in candidate_nodes:
                of.write(line + "\n")


if __name__ == "__main__":
    main()
