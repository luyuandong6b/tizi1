#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
# [RUN CONFIGURATION & SWITCHES]
# ==============================================================================
# ENABLE_REMOTE_COLLECT:
# True  = Fetch new proxies from 13 external GitHub repos (original behavior)
# False = [CURRENT MODE] Skip external fetching, directly validate existing proxies
ENABLE_REMOTE_COLLECT = False

# ENABLE_VALIDATION:
# True  = Enable high-concurrency TCP handshake validation (filter out dead nodes)
# False = Disable validation
ENABLE_VALIDATION = True

# Concurrency level (200 - 300 recommended for GitHub Actions runner)
CHECK_CONCURRENCY = 250

# Connection timeout per node in seconds (2.0 - 3.0s recommended)
CHECK_TIMEOUT_SECONDS = 2.5

# Input and output file paths
OUTPUT_FILE = "all_proxies.txt"
VALID_OUTPUT_FILE = "valid_proxies.txt"
SEEN_FILE = "seen_hashes.txt"

# Sync validated alive proxies back to all_proxies.txt
SYNC_TO_ALL_PROXIES = True

# Maximum output file size (95MB limit to prevent GitHub push errors)
MAX_OUTPUT_BYTES = 95 * 1024 * 1024

REQUEST_INTERVAL_SECONDS = 2.5
MAX_RETRIES = 5
RETRY_SLEEP_SECONDS = 12

GITHUB_TOKEN = os.environ.get("GH_PAT", "").strip()

# ==============================================================================
# [ORIGINAL REPOSITORIES CONFIGURATION - 100% PRESERVED]
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
        "dirs": ["Subscriptions", "Protocols"],
        "recent_hours": 12,
    },
    {
        "name": "Project9-free-v2ray-collector",
        "owner": "iboxz",
        "repo": "free-v2ray-collector",
        "branch": "main",
        "dirs": ["main"],
        "recent_hours": 12,
    },
    {
        "name": "Project10-port-based-v2ray-configs",
        "owner": "hamedcode",
        "repo": "port-based-v2ray-configs",
        "branch": "main",
        "dirs": ["sub"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "Project11-5ubscrpt10n",
        "owner": "sevcator",
        "repo": "5ubscrpt10n",
        "branch": "main",
        "dirs": ["mini", "protocols"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "Project12-Epodonios-Splitted",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Splitted-By-Protocol"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "Project13-Epodonios-AllConfigsSub",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": [],
        "recent_hours": None,
        "mode": "explicit_files",
        "file_paths": ["All_Configs_Sub.txt"],
    },
]


# ==============================================================================
# [ORIGINAL FETCHING FUNCTIONS - 100% PRESERVED]
# ==============================================================================
def _headers(api=True):
    h = {"User-Agent": "proxy-auto-collector"}
    if api:
        h["Accept"] = "application/vnd.github+json"
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


def _request_json(url: str):
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        time.sleep(REQUEST_INTERVAL_SECONDS)
        req = urllib.request.Request(url, headers=_headers(api=True))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            last_err = e
            if attempt < MAX_RETRIES:
                print(f"Request failed, retrying in {RETRY_SLEEP_SECONDS}s ({attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            raise
    raise last_err


def _request_text(url: str):
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        time.sleep(REQUEST_INTERVAL_SECONDS)
        req = urllib.request.Request(url, headers=_headers(api=False))
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except (urllib.error.HTTPError, urllib.error.URLError) as e:
            last_err = e
            if attempt < MAX_RETRIES:
                print(f"Download failed, retrying in {RETRY_SLEEP_SECONDS}s ({attempt}/{MAX_RETRIES})")
                time.sleep(RETRY_SLEEP_SECONDS)
                continue
            raise
    raise last_err


def list_text_files(owner, repo, branch, path):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{urllib.parse.quote(path)}?ref={branch}"
    )
    items = _request_json(url)
    files = []
    for item in items:
        t = item.get("type")
        p = item.get("path", "")
        n = item.get("name", "")
        if t == "dir":
            files.extend(list_text_files(owner, repo, branch, p))
        elif t == "file" and n.lower().endswith(".txt"):
            files.append(p)
    return files


def list_top_text_files(owner, repo, branch, path):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{urllib.parse.quote(path)}?ref={branch}"
    )
    items = _request_json(url)
    return sorted(
        [
            i.get("path", "")
            for i in items
            if i.get("type") == "file" and i.get("name", "").lower().endswith(".txt")
        ]
    )


def list_subdir_all_txt_files(owner, repo, branch, path):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{urllib.parse.quote(path)}?ref={branch}"
    )
    items = _request_json(url)
    subdirs = [i for i in items if i.get("type") == "dir"]
    files = []
    missing = []
    for sub in subdirs:
        sp = sub.get("path", "")
        sn = sub.get("name", "")
        target = f"{sp}/all.txt"
        u = (
            f"https://api.github.com/repos/{owner}/{repo}/contents/"
            f"{urllib.parse.quote(target)}?ref={branch}"
        )
        try:
            d = _request_json(u)
            if d.get("type") == "file":
                files.append(target)
            else:
                missing.append(sn)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                missing.append(sn)
            else:
                raise
    return sorted(files), sorted(missing), len(subdirs)


def get_last_commit_time(owner, repo, branch, path):
    url = (
        f"https://api.github.com/repos/{owner}/{repo}/commits?"
        f"path={urllib.parse.quote(path)}&sha={branch}&per_page=1"
    )
    data = _request_json(url)
    if not data:
        return None
    s = data[0]["commit"]["committer"]["date"]
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.timezone.utc)


def fetch_file_text(owner, repo, branch, path):
    u = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{urllib.parse.quote(path)}?ref={branch}"
    )
    data = _request_json(u)
    if data.get("encoding") == "base64":
        return base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
    dl = data.get("download_url")
    if not dl:
        return ""
    return _request_text(dl)


def build_project_file_list(project):
    owner = project["owner"]
    repo = project["repo"]
    branch = project["branch"]
    mode = project.get("mode", "all_txt_recursive")
    stats = {
        "subdirs_total": 0,
        "subdirs_missing_all_txt": [],
    }
    files = []
    if mode == "explicit_files":
        files.extend(project.get("file_paths", []))
    else:
        for d in project["dirs"]:
            if mode == "subdirs_all_txt":
                f, m, c = list_subdir_all_txt_files(owner, repo, branch, d)
                files.extend(f)
                stats["subdirs_total"] += c
                stats["subdirs_missing_all_txt"].extend(m)
            elif mode == "top_txt_only":
                files.extend(list_top_text_files(owner, repo, branch, d))
            else:
                files.extend(list_text_files(owner, repo, branch, d))

    files = sorted(set(files))
    hours = project.get("recent_hours")
    if hours is None:
        return files, stats

    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    selected = []
    for p in files:
        t = get_last_commit_time(owner, repo, branch, p)
        if t is not None and t >= cutoff:
            selected.append(p)
    return sorted(selected), stats


def line_hash(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def write_unique_lines(text, out_f, seen_f, seen_set, output_bytes):
    new_count = 0
    dup_count = 0
    size_skip_count = 0
    wrote_any = False

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        h = line_hash(line)
        if h in seen_set:
            dup_count += 1
            continue

        encoded = (line + "\n").encode("utf-8")
        if output_bytes + len(encoded) > MAX_OUTPUT_BYTES:
            size_skip_count += 1
            continue

        out_f.write(line + "\n")
        seen_f.write(h + "\n")
        seen_set.add(h)
        output_bytes += len(encoded)
        new_count += 1
        wrote_any = True

    if wrote_any:
        blank = "\n".encode("utf-8")
        if output_bytes + len(blank) <= MAX_OUTPUT_BYTES:
            out_f.write("\n")
            output_bytes += len(blank)

    out_f.flush()
    seen_f.flush()
    os.fsync(out_f.fileno())
    os.fsync(seen_f.fileno())

    return new_count, dup_count, size_skip_count, output_bytes


# ==============================================================================
# [HIGH-CONCURRENCY VALIDATION ENGINE]
# ==============================================================================
def parse_proxy(line: str):
    """
    Parse server host and port from various proxy URI protocols.
    Supports: vmess, vless, trojan, ss, ssr, hysteria, hysteria2, hy2, tuic
    """
    line = line.strip()
    if not line:
        return None

    try:
        # VMess protocol (Base64 JSON)
        if line.startswith("vmess://"):
            b64_str = line[8:]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            raw = base64.b64decode(b64_str).decode("utf-8", errors="ignore")
            data = json.loads(raw)
            host = data.get("add") or data.get("host")
            port = int(data.get("port", 0))
            if host and port > 0:
                return host, port

        # VLESS / Trojan / Hysteria / Hysteria2 / TUIC
        elif line.startswith(("vless://", "trojan://", "hysteria://", "hysteria2://", "hy2://", "tuic://")):
            u = urllib.parse.urlsplit(line)
            if u.hostname and u.port:
                return u.hostname, int(u.port)

        # Shadowsocks (ss://)
        elif line.startswith("ss://"):
            content = line[5:].split("#")[0]
            if "@" in content:
                host_port = content.split("@")[1].split("?")[0]
                host, port = host_port.rsplit(":", 1)
                return host.strip("[]"), int(port)
            else:
                pad = len(content) % 4
                if pad:
                    content += "=" * (4 - pad)
                decoded = base64.b64decode(content).decode("utf-8", errors="ignore")
                if "@" in decoded:
                    host_port = decoded.split("@")[1].split("?")[0]
                    host, port = host_port.rsplit(":", 1)
                    return host.strip("[]"), int(port)

        # SSR (ssr://)
        elif line.startswith("ssr://"):
            b64_str = line[6:]
            pad = len(b64_str) % 4
            if pad:
                b64_str += "=" * (4 - pad)
            decoded = base64.urlsafe_b64decode(b64_str).decode("utf-8", errors="ignore")
            parts = decoded.split(":")
            if len(parts) >= 2:
                return parts[0], int(parts[1])

    except Exception:
        pass

    return None


async def check_single_proxy(sem: asyncio.Semaphore, line: str, timeout: float):
    """Asynchronous TCP handshake validation for a single proxy node."""
    parsed = parse_proxy(line)
    if not parsed:
        return None

    host, port = parsed
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
            return (line, latency_ms)
        except Exception:
            return None


async def run_batch_validation(proxies, concurrency=250, timeout=2.5):
    """Validate list of proxy strings concurrently using asyncio."""
    total = len(proxies)
    print(f"\n[+] Starting High-Concurrency Validation: Total={total} | Concurrency={concurrency} | Timeout={timeout}s")

    sem = asyncio.Semaphore(concurrency)
    tasks = [asyncio.create_task(check_single_proxy(sem, p, timeout)) for p in proxies]

    alive_proxies = []
    start_time = time.time()
    done_count = 0

    for coro in asyncio.as_completed(tasks):
        res = await coro
        done_count += 1
        if res is not None:
            alive_proxies.append(res)

        if done_count % 500 == 0 or done_count == total:
            elapsed = time.time() - start_time
            rate = done_count / elapsed if elapsed > 0 else 0
            print(
                f"Progress: [{done_count}/{total}] "
                f"Alive: {len(alive_proxies)} "
                f"AliveRate: {len(alive_proxies) / done_count * 100:.1f}% "
                f"Speed: {rate:.0f} nodes/sec"
            )

    elapsed_total = time.time() - start_time
    print(f"[+] Validation Completed in {elapsed_total:.2f}s | Alive={len(alive_proxies)}/{total}")
    return alive_proxies


# ==============================================================================
# [MAIN ENTRY POINT]
# ==============================================================================
def main():
    seen = set()
    total_new = 0
    total_dup = 0
    total_size_skip = 0
    output_bytes = 0

    # --------------------------------------------------------------------------
    # Stage 1: External Repositories Collection (Toggled by ENABLE_REMOTE_COLLECT)
    # --------------------------------------------------------------------------
    if ENABLE_REMOTE_COLLECT:
        print("====== MODE: Remote GitHub Repositories Fetching Enabled ======")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f, open(SEEN_FILE, "w", encoding="utf-8") as seen_f:
            for project in PROJECTS:
                name = project["name"]
                owner = project["owner"]
                repo = project["repo"]
                branch = project["branch"]

                try:
                    files, stats = build_project_file_list(project)
                except urllib.error.URLError as e:
                    print(f"{name} Access failed: {e}")
                    continue

                if project.get("mode") == "subdirs_all_txt":
                    missing_count = len(stats["subdirs_missing_all_txt"])
                    exists_count = stats["subdirs_total"] - missing_count
                    print(
                        f"{name} Subdirs={stats['subdirs_total']}, "
                        f"Existing all.txt={exists_count}, "
                        f"Missing all.txt={missing_count}"
                    )

                if not files:
                    print(f"{name} No matching files found")
                    continue

                if project.get("recent_hours") is None:
                    print(f"{name} Processing {len(files)} files...")
                else:
                    print(f"{name} Processing {len(files)} files updated in past {project['recent_hours']}h...")

                for i, p in enumerate(files, start=1):
                    fn = p.rsplit("/", 1)[-1]
                    try:
                        text = fetch_file_text(owner, repo, branch, p)
                    except urllib.error.URLError as e:
                        print(f"{name} [{i}/{len(files)}] Skipped {fn}, download error: {e}")
                        continue

                    n, d, s, output_bytes = write_unique_lines(
                        text=text,
                        out_f=out_f,
                        seen_f=seen_f,
                        seen_set=seen,
                        output_bytes=output_bytes,
                    )
                    total_new += n
                    total_dup += d
                    total_size_skip += s

        print(f"Collection complete: Added {total_new}, Duplicate {total_dup}")
    else:
        print("====== MODE: Skipped Remote Fetching -> Directly Validating Existing Proxies ======")

    # --------------------------------------------------------------------------
    # Stage 2: Read Existing Proxies and Run High-Concurrency Validation
    # --------------------------------------------------------------------------
    if ENABLE_VALIDATION:
        unique_nodes = []
        node_seen = set()

        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
                raw_lines = [line.strip() for line in f if line.strip()]
            for line in raw_lines:
                if line not in node_seen and parse_proxy(line) is not None:
                    node_seen.add(line)
                    unique_nodes.append(line)

        # Smart Fallback: If all_proxies.txt in current branch is empty, pull the 41,941 historical collected proxies!
        if not unique_nodes:
            print(f"[*] {OUTPUT_FILE} is currently empty. Fetching previously collected 41,941 nodes from repository history...")
            try:
                backup_url = "https://raw.githubusercontent.com/luyuandong6b/tizi1/c8e7abe/all_proxies.txt"
                req = urllib.request.Request(backup_url, headers={"User-Agent": "proxy-auto-collector"})
                with urllib.request.urlopen(req, timeout=30) as resp:
                    content = resp.read().decode("utf-8", errors="ignore")
                    for line in content.splitlines():
                        line = line.strip()
                        if line and line not in node_seen and parse_proxy(line) is not None:
                            node_seen.add(line)
                            unique_nodes.append(line)
                print(f"[+] Successfully fetched {len(unique_nodes)} candidate nodes from history!")
            except Exception as e:
                print(f"[-] Failed to fetch historical proxies: {e}")

        if not unique_nodes:
            print(f"[-] No valid proxy URLs found in {OUTPUT_FILE} (file may be empty).")
            return

        print(f"[+] Ready to test {len(unique_nodes)} unique candidate nodes")

        # Run concurrent async validation
        alive_results = asyncio.run(
            run_batch_validation(
                unique_nodes,
                concurrency=CHECK_CONCURRENCY,
                timeout=CHECK_TIMEOUT_SECONDS,
            )
        )

        # Write alive proxies to independent file: valid_proxies.txt
        with open(VALID_OUTPUT_FILE, "w", encoding="utf-8") as vf:
            for item in alive_results:
                vf.write(item[0] + "\n")
        print(f"[+] Saved {len(alive_results)} alive proxies to independent file: {VALID_OUTPUT_FILE}")

        # Synchronize back to all_proxies.txt
        if SYNC_TO_ALL_PROXIES:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as of:
                for item in alive_results:
                    of.write(item[0] + "\n")
            print(f"[+] Synchronized {len(alive_results)} alive proxies to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
