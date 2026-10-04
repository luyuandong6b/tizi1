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
# 銆愯繍琛屾帶鍒跺紑鍏炽€?# ==============================================================================
# 鏄惁浠庡叾浠?GitHub 浠撳簱鎷夊彇鏂拌妭鐐癸細
# True  = 鎵ц鍘熺増閲囬泦閫昏緫锛堟姄鍙栧閮?13 涓」鐩級
# False = 銆愬綋鍓嶆ā寮忋€戣烦杩囧閮ㄦ姄鍙栵紝鐩存帴瀵逛粨搴撳唴宸茬粡鏀堕泦濂界殑浠ｇ悊杩涜楂樺苟鍙戦獙璇?ENABLE_REMOTE_COLLECT = False

# 鏄惁寮€鍚珮骞跺彂鏈夋晥鎬ч獙璇侊紙娴嬫椿锛夛細
# True  = 寮€鍚珮骞跺彂娴嬫椿锛屽墧闄ゆ鑺傜偣锛屼粎淇濈暀鍙敤鑺傜偣
# False = 涓嶆祴娲?ENABLE_VALIDATION = True

# 娴嬫椿骞跺彂鏁帮紙GitHub Actions 鍏嶈垂杩愯鍣ㄦ帹鑽?200 ~ 300锛?CHECK_CONCURRENCY = 250

# 鍗曚釜鑺傜偣杩炴帴瓒呮椂鏃堕棿锛堢锛屽缓璁?2.0 ~ 3.0 绉掞紝瓒呮椂鍗冲垽瀹氫负姝昏妭鐐癸級
CHECK_TIMEOUT_SECONDS = 2.5

# 杈撳叆涓庤緭鍑烘枃浠堕厤缃?OUTPUT_FILE = "all_proxies.txt"
VALID_OUTPUT_FILE = "valid_proxies.txt"
SEEN_FILE = "seen_hashes.txt"

# 鏄惁灏嗘祴娲婚€氳繃鐨勬湁鏁堣妭鐐瑰悓姝ュ洖鍐欏埌 all_proxies.txt
SYNC_TO_ALL_PROXIES = True

# GitHub 鍗曟枃浠剁‖闄愬埗鏄?100MB锛岃繖閲屾帶鍒跺湪 95MB 宸﹀彸锛岄伩鍏?push 澶辫触
MAX_OUTPUT_BYTES = 95 * 1024 * 1024

REQUEST_INTERVAL_SECONDS = 2.5
MAX_RETRIES = 5
RETRY_SLEEP_SECONDS = 12

GITHUB_TOKEN = os.environ.get("GH_PAT", "").strip()

# ==============================================================================
# 銆愬師鐗堥噰闆嗘暟鎹簮閰嶇疆 - 瀹屾暣淇濈暀锛屾湭鍋氫换浣曞垹闄ゃ€?# ==============================================================================
PROJECTS = [
    {
        "name": "椤圭洰1-v2go",
        "owner": "Danialsamadi",
        "repo": "v2go",
        "branch": "main",
        "dirs": ["Splitted-By-Country"],
        "recent_hours": None,
    },
    {
        "name": "椤圭洰2-Proxify",
        "owner": "Firmfox",
        "repo": "Proxify",
        "branch": "main",
        "dirs": ["v2ray_configs/mixed", "v2ray_configs/seperated_by_protocol"],
        "recent_hours": 12,
    },
    {
        "name": "椤圭洰3-PyroConfig",
        "owner": "0xAbolfazl",
        "repo": "PyroConfig",
        "branch": "main",
        "dirs": ["Configs"],
        "recent_hours": 12,
    },
    {
        "name": "椤圭洰4-ConfigForge-V2Ray",
        "owner": "ShatakVPN",
        "repo": "ConfigForge-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
        "recent_hours": 12,
        "mode": "subdirs_all_txt",
    },
    {
        "name": "椤圭洰5-v2ray-configs",
        "owner": "MatinGhanbari",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": [],
        "recent_hours": 12,
        "mode": "explicit_files",
        "file_paths": ["subscriptions/v2ray/all_sub.txt"],
    },
    {
        "name": "椤圭洰6-Freedom-V2Ray",
        "owner": "MahanKenway",
        "repo": "Freedom-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
        "recent_hours": 12,
    },
    {
        "name": "椤圭洰7-F0rc3Run",
        "owner": "F0rc3Run",
        "repo": "F0rc3Run",
        "branch": "main",
        "dirs": ["splitted-by-protocol"],
        "recent_hours": 12,
    },
    {
        "name": "椤圭洰8-SoliSpirit",
        "owner": "SoliSpirit",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Subscriptions", "Protocols"],
        "recent_hours": 12,
    },
    {
        "name": "椤圭洰9-free-v2ray-collector",
        "owner": "iboxz",
        "repo": "free-v2ray-collector",
        "branch": "main",
        "dirs": ["main"],
        "recent_hours": 12,
    },
    {
        "name": "椤圭洰10-port-based-v2ray-configs",
        "owner": "hamedcode",
        "repo": "port-based-v2ray-configs",
        "branch": "main",
        "dirs": ["sub"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "椤圭洰11-5ubscrpt10n",
        "owner": "sevcator",
        "repo": "5ubscrpt10n",
        "branch": "main",
        "dirs": ["mini", "protocols"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "椤圭洰12-Epodonios-Splitted",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Splitted-By-Protocol"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "椤圭洰13-Epodonios-AllConfigsSub",
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
# 銆愬師鐗堢綉缁滄媺鍙栧嚱鏁?- 瀹屾暣淇濈暀銆?# ==============================================================================
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
                print(f"璇锋眰澶辫触锛寋RETRY_SLEEP_SECONDS}绉掑悗閲嶈瘯({attempt}/{MAX_RETRIES})")
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
                print(f"涓嬭浇澶辫触锛寋RETRY_SLEEP_SECONDS}绉掑悗閲嶈瘯({attempt}/{MAX_RETRIES})")
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
# 銆愭柊澧炴ā鍧楋細楂樺苟鍙戜唬鐞嗘湁鏁堟€ф祴璇曞紩鎿庛€?# ==============================================================================
def parse_proxy(line: str):
    """
    閫氱敤浠ｇ悊鍗忚瑙ｆ瀽鍣細瑙ｆ瀽鎻愬彇鐩爣鏈嶅姟鍣?IP/鍩熷悕 涓?绔彛
    鏀寔鍗忚锛歷mess, vless, trojan, ss, ssr, hysteria, hysteria2, hy2, tuic
    """
    line = line.strip()
    if not line:
        return None

    try:
        # VMess 鍗忚 (Base64 JSON)
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
    """寮傛鍗曡妭鐐?TCP 鎻℃墜娴嬫椿"""
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
    """澶氬崗绋嬮珮骞跺彂鎵归噺楠岃瘉鑺傜偣"""
    total = len(proxies)
    print(f"\n馃殌 寮€濮嬮珮骞跺彂娴嬫椿: 寰呮祴璇曡妭鐐?{total} 涓?| 骞跺彂鏁? {concurrency} | 瓒呮椂: {timeout}s")

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
                f"杩涘害: [{done_count}/{total}] "
                f"宸插瓨娲? {len(alive_proxies)} "
                f"瀛樻椿鐜? {len(alive_proxies) / done_count * 100:.1f}% "
                f"閫熷害: {rate:.0f} 涓?绉?
            )

    elapsed_total = time.time() - start_time
    print(f"鉁?娴嬫椿瀹屾垚! 鑰楁椂: {elapsed_total:.2f} 绉?| 瀛樻椿: {len(alive_proxies)} / {total}")
    return alive_proxies


# ==============================================================================
# 銆愪富鎵ц娴佺▼銆?# ==============================================================================
def main():
    seen = set()
    total_new = 0
    total_dup = 0
    total_size_skip = 0
    output_bytes = 0

    # --------------------------------------------------------------------------
    # 绗竴闃舵锛氳法浠撳簱閲囬泦锛堟牴鎹紑鍏冲喅瀹氭槸鍚︽墽琛岋紝浠ｇ爜瀹屾暣淇濈暀锛?    # --------------------------------------------------------------------------
    if ENABLE_REMOTE_COLLECT:
        print("====== 妯″紡: 鎵ц鍘熺増澶氶」鐩繙绋嬫姄鍙?======")
        with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f, open(SEEN_FILE, "w", encoding="utf-8") as seen_f:
            for project in PROJECTS:
                name = project["name"]
                owner = project["owner"]
                repo = project["repo"]
                branch = project["branch"]

                try:
                    files, stats = build_project_file_list(project)
                except urllib.error.URLError as e:
                    print(f"{name} 璁块棶澶辫触: {e}")
                    continue

                if project.get("mode") == "subdirs_all_txt":
                    missing_count = len(stats["subdirs_missing_all_txt"])
                    exists_count = stats["subdirs_total"] - missing_count
                    print(
                        f"{name} 瀛愭枃浠跺す鎬绘暟: {stats['subdirs_total']}锛?
                        f"瀛樺湪 all.txt: {exists_count}锛?
                        f"缂哄皯 all.txt: {missing_count}"
                    )

                if not files:
                    print(f"{name} 娌℃湁绗﹀悎鏉′欢鐨勬枃妗?)
                    continue

                if project.get("recent_hours") is None:
                    print(f"{name} 鍏?{len(files)} 涓枃妗ｏ紝寮€濮嬪啓鍏?)
                else:
                    print(f"{name} 鏈€杩?{project['recent_hours']} 灏忔椂鍐呭叡 {len(files)} 涓枃妗ｏ紝寮€濮嬪啓鍏?)

                for i, p in enumerate(files, start=1):
                    fn = p.rsplit("/", 1)[-1]
                    try:
                        text = fetch_file_text(owner, repo, branch, p)
                    except urllib.error.URLError as e:
                        print(f"{name} [{i}/{len(files)}] 璺宠繃 {fn}锛屼笅杞藉け璐? {e}")
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

        print(f"閲囬泦瀹屾垚: 鏂板 {total_new} 琛岋紝璺宠繃閲嶅 {total_dup} 琛?)
    else:
        print("====== 妯″紡: 璺宠繃澶栭儴鎶撳彇锛岀洿鎺ラ獙璇佸綋鍓嶅凡鏀堕泦鐨勪唬鐞?======")

    # --------------------------------------------------------------------------
    # 绗簩闃舵锛氳鍙栧綋鍓嶈妭鐐规睜骞舵墽琛岄珮骞跺彂娴嬫椿
    # --------------------------------------------------------------------------
    if ENABLE_VALIDATION:
        if not os.path.exists(OUTPUT_FILE):
            print(f"鏈壘鍒拌緭鍏ユ枃浠?{OUTPUT_FILE}锛岃鍏堢‘淇濆凡鏈夐噰闆嗗埌鐨勪唬鐞嗘枃浠躲€?)
            return

        with open(OUTPUT_FILE, "r", encoding="utf-8", errors="ignore") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

        # 鍘婚噸涓斿彧鎻愬彇鏈夋剰涔夌殑浠ｇ悊閾炬帴
        unique_nodes = []
        node_seen = set()
        for line in raw_lines:
            if line not in node_seen and parse_proxy(line) is not None:
                node_seen.add(line)
                unique_nodes.append(line)

        if not unique_nodes:
            print(f"{OUTPUT_FILE} 涓病鏈夋彁鍙栧埌鍚堟硶鐨勪唬鐞嗛摼鎺ワ紙鎴栬€呮枃浠朵负绌猴級銆?)
            return

        print(f"浠?{OUTPUT_FILE} 涓彁鍙栧埌 {len(unique_nodes)} 涓緟娴嬩唬鐞嗚妭鐐?)

        # 鍚姩寮傛楂樺苟鍙戞祴娲?        alive_results = asyncio.run(
            run_batch_validation(
                unique_nodes,
                concurrency=CHECK_CONCURRENCY,
                timeout=CHECK_TIMEOUT_SECONDS,
            )
        )

        # 鍐欏叆娴嬫椿鍚庣殑鏈夋晥鏂囦欢 valid_proxies.txt
        with open(VALID_OUTPUT_FILE, "w", encoding="utf-8") as vf:
            for item in alive_results:
                vf.write(item[0] + "\n")
        print(f"馃帀 鏈夋晥鑺傜偣宸蹭繚瀛樿嚦: {VALID_OUTPUT_FILE} (鍏?{len(alive_results)} 鏉?")

        # 鍚屾鏇存柊 all_proxies.txt
        if SYNC_TO_ALL_PROXIES:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as of:
                for item in alive_results:
                    of.write(item[0] + "\n")
            print(f"馃攧 宸插悓姝ユ洿鏂? {OUTPUT_FILE} (鍏?{len(alive_results)} 鏉?")


if __name__ == "__main__":
    main()
