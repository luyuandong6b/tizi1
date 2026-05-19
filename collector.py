#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import datetime as dt
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request


OUTPUT_FILE = "all_proxies.txt"
SEEN_FILE = "seen_hashes.txt"

# GitHub 单文件硬限制是 100MB，这里控制在 95MB 左右，避免 push 失败
MAX_OUTPUT_BYTES = 95 * 1024 * 1024

REQUEST_INTERVAL_SECONDS = 2.5
MAX_RETRIES = 5
RETRY_SLEEP_SECONDS = 12

GITHUB_TOKEN = os.environ.get("GH_PAT", "").strip()

PROJECTS = [
    {
        "name": "项目1-v2go",
        "owner": "Danialsamadi",
        "repo": "v2go",
        "branch": "main",
        "dirs": ["Splitted-By-Country"],
        "recent_hours": None,
    },
    {
        "name": "项目2-Proxify",
        "owner": "Firmfox",
        "repo": "Proxify",
        "branch": "main",
        "dirs": ["v2ray_configs/mixed", "v2ray_configs/seperated_by_protocol"],
        "recent_hours": 12,
    },
    {
        "name": "项目3-PyroConfig",
        "owner": "0xAbolfazl",
        "repo": "PyroConfig",
        "branch": "main",
        "dirs": ["Configs"],
        "recent_hours": 12,
    },
    {
        "name": "项目4-ConfigForge-V2Ray",
        "owner": "ShatakVPN",
        "repo": "ConfigForge-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
        "recent_hours": 12,
        "mode": "subdirs_all_txt",
    },
    {
        "name": "项目5-v2ray-configs",
        "owner": "MatinGhanbari",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": [],
        "recent_hours": 12,
        "mode": "explicit_files",
        "file_paths": ["subscriptions/v2ray/all_sub.txt"],
    },
    {
        "name": "项目6-Freedom-V2Ray",
        "owner": "MahanKenway",
        "repo": "Freedom-V2Ray",
        "branch": "main",
        "dirs": ["configs"],
        "recent_hours": 12,
    },
    {
        "name": "项目7-F0rc3Run",
        "owner": "F0rc3Run",
        "repo": "F0rc3Run",
        "branch": "main",
        "dirs": ["splitted-by-protocol"],
        "recent_hours": 12,
    },
    {
        "name": "项目8-SoliSpirit",
        "owner": "SoliSpirit",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Subscriptions", "Protocols"],
        "recent_hours": 12,
    },
    {
        "name": "项目9-free-v2ray-collector",
        "owner": "iboxz",
        "repo": "free-v2ray-collector",
        "branch": "main",
        "dirs": ["main"],
        "recent_hours": 12,
    },
    {
        "name": "项目10-port-based-v2ray-configs",
        "owner": "hamedcode",
        "repo": "port-based-v2ray-configs",
        "branch": "main",
        "dirs": ["sub"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "项目11-5ubscrpt10n",
        "owner": "sevcator",
        "repo": "5ubscrpt10n",
        "branch": "main",
        "dirs": ["mini", "protocols"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "项目12-Epodonios-Splitted",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": ["Splitted-By-Protocol"],
        "recent_hours": 12,
        "mode": "top_txt_only",
    },
    {
        "name": "项目13-Epodonios-AllConfigsSub",
        "owner": "Epodonios",
        "repo": "v2ray-configs",
        "branch": "main",
        "dirs": [],
        "recent_hours": None,
        "mode": "explicit_files",
        "file_paths": ["All_Configs_Sub.txt"],
    },
]


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
                print(f"请求失败，{RETRY_SLEEP_SECONDS}秒后重试({attempt}/{MAX_RETRIES})")
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
                print(f"下载失败，{RETRY_SLEEP_SECONDS}秒后重试({attempt}/{MAX_RETRIES})")
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
            if i.get("type") == "file"
            and i.get("name", "").lower().endswith(".txt")
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

    return dt.datetime.strptime(
        s,
        "%Y-%m-%dT%H:%M:%SZ"
    ).replace(tzinfo=dt.timezone.utc)


def fetch_file_text(owner, repo, branch, path):
    u = (
        f"https://api.github.com/repos/{owner}/{repo}/contents/"
        f"{urllib.parse.quote(path)}?ref={branch}"
    )

    data = _request_json(u)

    if data.get("encoding") == "base64":
        return base64.b64decode(
            data.get("content", "")
        ).decode("utf-8", errors="replace")

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


def main():
    # 关键修改 1：
    # 每次运行都从空集合开始，只做“本轮去重”
    # 不再读取旧 seen_hashes.txt
    seen = set()

    total_new = 0
    total_dup = 0
    total_size_skip = 0
    output_bytes = 0

    # 关键修改 2：
    # "w" = 覆盖写入
    # 每次运行都会清空 all_proxies.txt 和 seen_hashes.txt，然后重新生成
    with open(OUTPUT_FILE, "w", encoding="utf-8") as out_f, open(SEEN_FILE, "w", encoding="utf-8") as seen_f:
        for project in PROJECTS:
            name = project["name"]
            owner = project["owner"]
            repo = project["repo"]
            branch = project["branch"]

            try:
                files, stats = build_project_file_list(project)

            except urllib.error.URLError as e:
                print(f"{name} 访问失败: {e}")
                continue

            if project.get("mode") == "subdirs_all_txt":
                missing_count = len(stats["subdirs_missing_all_txt"])
                exists_count = stats["subdirs_total"] - missing_count

                print(
                    f"{name} 子文件夹总数: {stats['subdirs_total']}，"
                    f"存在 all.txt: {exists_count}，"
                    f"缺少 all.txt: {missing_count}"
                )

            if not files:
                print(f"{name} 没有符合条件的文档")
                continue

            if project.get("recent_hours") is None:
                print(f"{name} 共 {len(files)} 个文档，开始写入")
            else:
                print(f"{name} 最近 {project['recent_hours']} 小时内共 {len(files)} 个文档，开始写入")

            for i, p in enumerate(files, start=1):
                fn = p.rsplit("/", 1)[-1]

                try:
                    text = fetch_file_text(owner, repo, branch, p)

                except urllib.error.URLError as e:
                    print(f"{name} [{i}/{len(files)}] 跳过 {fn}，下载失败: {e}")
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

                print(
                    f"{name} [{i}/{len(files)}] 已处理: {fn} | "
                    f"新增 {n} 行 | "
                    f"重复 {d} 行 | "
                    f"因大小限制跳过 {s} 行 | "
                    f"当前输出大小 {output_bytes / 1024 / 1024:.2f} MB"
                )

                if output_bytes >= MAX_OUTPUT_BYTES:
                    print(
                        f"输出文件已达到大小上限 "
                        f"{MAX_OUTPUT_BYTES / 1024 / 1024:.2f} MB，"
                        f"后续新内容会被跳过。"
                    )

    print(
        f"完成: 新增 {total_new} 行，"
        f"跳过重复 {total_dup} 行，"
        f"因大小限制跳过 {total_size_skip} 行，"
        f"输出 {OUTPUT_FILE}，"
        f"最终大小 {output_bytes / 1024 / 1024:.2f} MB"
    )


if __name__ == "__main__":
    main()
