#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
rlv - Rancher Logs Viewer
=========================
A k9s-style terminal UI for browsing and analysing the output of the Rancher
logs-collector (rancher2_logs_collector.sh) completely offline.

    python3 rlv.py <bundle-dir | bundle.tar.gz | dir-with-many-tarballs>
    python3 rlv.py <bundle> --summary
    python3 rlv.py <bundle> --issues
    python3 rlv.py <bundle> -c "get pods -A | grep -i crash" -c "grep -i x509"

Pure Python 3.8+ standard library (curses: Linux/macOS; on Windows `pip install windows-curses`).

Inside the TUI press  :  to run a command, ?  for help.
"""
import argparse
import atexit
import bisect
import calendar
import curses
import fnmatch
import gzip
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field

VERSION = "0.1.0"
MAX_HITS_PER_RULE = 300
MAX_HITS_PER_FILE_RULE = 40
MAX_GREP_HITS = 5000
ARCHIVE_EXT = (".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")


class Quit(Exception):
    pass


# --------------------------------------------------------------------------- #
# small helpers
# --------------------------------------------------------------------------- #
ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
CTRL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def clean(s):
    return CTRL_RE.sub("", ANSI_RE.sub("", s))


REDACT = [False]
_TRIVIAL = re.compile(r"(?i)^(null|none|nil|true|false|undefined|redacted|<.*>|\$.*|\{\{.*|\*+|\.\.\.)$")
SECRET_PATTERNS = [   # (type, regex, has_prefix_group_to_keep)
    ("password/token/secret keyword", re.compile(
        r"((?:token|password|passwd|secret|api[_-]?key|apikey|access[_-]?key|client[_-]?secret|authorization|bearer)"
        r"[\"']?\s*[:=]\s*[\"']?(?:Bearer\s+)?)[^\s\"',}]+", re.I), True),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"), False),
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), False),
    ("RKE2/K3s join token", re.compile(r"K10[0-9a-f]{20,}::\w+:\S+"), False),
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), False),
    ("URL with credentials", re.compile(r"(://[^/\s:@]+:)[^/\s@]{3,}(?=@)"), True),
    ("kubeconfig client key", re.compile(r"(client-key-data[\"']?\s*[:=]\s*[\"']?)[A-Za-z0-9+/=]{20,}"), True),
]
SECRET_PREFILTER = re.compile(r"token|passw|secret|api[_-]?key|access[_-]?key|authorization|bearer|eyJ|PRIVATE KEY|K10|AKIA|://|client-key-data", re.I)
B64_VALUE = re.compile(r'^\s*[^:\s][^:]*:\s+"?[A-Za-z0-9+/]{8,}={0,2}"?,?\s*$')
SECRET_KIND = re.compile(r'^\s*kind:\s*Secret\s*$|"kind":\s*"Secret"')


def _entropy(v):
    from math import log2
    c, n = Counter(v), len(v)
    return -sum(k / n * log2(k / n) for k in c.values())


_NAME_RE = re.compile(r"^[a-z0-9]([a-z0-9._:/-]*[a-z0-9])?$")


def classify_value(keyword, v):
    """(confidence, shape) from what the VALUE looks like. HIGH = random secret material, MEDIUM = verify,
    LOW = name / path / placeholder (e.g. secret=cattle-system/my-secret is a reference, not a secret)."""
    v = v.strip("\"'`,;)")
    if not v or re.search(r"[<>$]|\{\{|%[sdvq]|\.\.\.", v) or v.startswith("{"):
        return "LOW", "placeholder/template"
    if len(v) >= 20 and re.fullmatch(r"[0-9a-fA-F]+", v):
        return "HIGH", "hex, %d chars" % len(v)
    name_like = bool(_NAME_RE.match(v)) and bool(re.search(r"[-/._:]", v)) and \
        sum(ch.isalpha() for ch in v) / len(v) >= 0.75
    classes = sum(bool(re.search(pt, v)) for pt in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    ent = _entropy(v)
    if not name_like:
        if len(v) >= 20 and ent >= 3.5 and classes >= 2:
            return "HIGH", "random-looking, %d chars, entropy %.1f" % (len(v), ent)
        if len(v) >= 32 and re.fullmatch(r"[A-Za-z0-9+/=_-]+", v):
            return "HIGH", "token/base64-like, %d chars" % len(v)
    if "://" in v and "@" not in v:
        return "LOW", "url without credentials"
    if keyword == "secret" and (name_like or len(v) < 8):
        return "LOW", "name/path reference"
    if len(v) < 4:
        return "LOW", "too short"
    return "MEDIUM", ("word/name-like" if name_like else "password-like") + " value, %d chars - verify" % len(v)


def _match_info(name, m, pre):
    """(keyword, value, confidence|None, shape) for one regex match; confidence None = ignore (placeholder)."""
    if not pre:
        return "", m.group(0), "HIGH", "secret-format string"
    kw = re.match(r"[A-Za-z_-]+", m.group(1))
    kw = kw.group(0).lower() if kw else ""
    v = m.group(0)[len(m.group(1)):]
    if name == "kubeconfig client key":
        return kw, v, "HIGH", "embedded private key data"
    if name == "URL with credentials":
        kw = "password"
    if _TRIVIAL.match(v):
        return kw, v, None, ""
    conf, shape = classify_value(kw, v)
    return kw, v, conf, shape


def mask_line(s):
    if not SECRET_PREFILTER.search(s):
        return s
    for name, rx, pre in SECRET_PATTERNS:
        def sub(m, name=name, pre=pre):
            _, _, conf, _ = _match_info(name, m, pre)
            if pre and conf in (None, "LOW"):
                return m.group(0)
            return (m.group(1) if pre else "") + "<redacted>"
        s = rx.sub(sub, s)
    return s


def secret_matches(s):
    """[(type, keyword, value, confidence, shape)] for credential-like strings in one line."""
    out = []
    if not SECRET_PREFILTER.search(s):
        return out
    for name, rx, pre in SECRET_PATTERNS:
        for m in rx.finditer(s):
            kw, v, conf, shape = _match_info(name, m, pre)
            if conf:
                out.append((name, kw, v, conf, shape))
    return out


def rd(s):
    """Mask credentials in what is displayed / saved / piped when --redact is on (files on disk are NOT changed)."""
    return mask_line(s) if REDACT[0] else s


def human(n):
    for unit in ("B", "K", "M", "G"):
        if n < 1024:
            return "%d%s" % (n, unit) if unit == "B" else "%.1f%s" % (n, unit)
        n /= 1024.0
    return "%.1fT" % n


def smart_re(pat, cs=None, literal=False):
    """Compile pattern; case-insensitive unless it contains an uppercase letter."""
    src = re.escape(pat) if literal else pat
    if cs is None:
        cs = any(c.isupper() for c in re.sub(r"\\.", "", pat))
    flags = 0 if cs else re.I
    try:
        return re.compile(src, flags)
    except re.error:
        return re.compile(re.escape(pat), flags)


def sortkey(s):
    m = re.fullmatch(r"(-?\d+(?:\.\d+)?)([BKMGT]?)", s.strip())
    if m:
        mult = {"": 1, "B": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[m.group(2)]
        return (1, float(m.group(1)) * mult, "")
    m = re.match(r"(\d+)", s)
    if m:
        return (1, float(m.group(1)), s.lower())
    return (0, 0, s.lower())


def is_binary(path):
    try:
        with open(path, "rb") as f:
            return b"\0" in f.read(4096)
    except OSError:
        return True


def open_text(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def read_lines(path, limit=3000000):
    if not path.endswith(".gz") and is_binary(path):
        return ["[binary file, %s]" % human(os.path.getsize(path))]
    out = []
    try:
        with open_text(path) as fh:
            for i, line in enumerate(fh):
                if i >= limit:
                    out.append("... truncated at %d lines ..." % limit)
                    break
                out.append(line.rstrip("\r\n").expandtabs(4))
    except (OSError, EOFError, gzip.BadGzipFile) as e:
        out.append("[cannot read: %s]" % e)
    return out


ERR_RE = re.compile(
    r"\b(?:error|errors|fatal|panic|critical|exception|failed|failure|crit)\b"
    r'|^\s*[EF]\d{4}\s|\blevel=(?:error|fatal)|"level":\s*"(?:error|fatal|panic)"', re.I)
WARN_RE = re.compile(r'\bwarn(?:ing)?\b|^\s*W\d{4}\s|\blevel=warn|"level":\s*"warn', re.I)


def line_level(s):
    if ERR_RE.search(s):
        return 2
    if WARN_RE.search(s):
        return 1
    return 0


# --------------------------------------------------------------------------- #
# timestamps (timezone-less stamps are assumed to be UTC)
# --------------------------------------------------------------------------- #
BUNDLE_END = [time.time()]
MONTHS = {m: i + 1 for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split())}
TS_ISO = re.compile(r"(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:[.,]\d+)?(Z|[+-]\d{2}:?\d{2})?")
TS_SLASH = re.compile(r"(\d{4})/(\d{2})/(\d{2}) (\d{2}):(\d{2}):(\d{2})")
TS_KLOG = re.compile(r"^[IWEF](\d{2})(\d{2}) (\d{2}):(\d{2}):(\d{2})")
TS_SYS = re.compile(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")


def _epoch(y, mo, d, h, mi, s):
    try:
        return calendar.timegm((y, mo, d, h, mi, s, 0, 0, 0))
    except (ValueError, OverflowError):
        return None


def _yearless(mo, d, h, mi, s):
    end = BUNDLE_END[0]
    y = time.gmtime(end).tm_year
    t = _epoch(y, mo, d, h, mi, s)
    if t is not None and t > end + 86400:
        t = _epoch(y - 1, mo, d, h, mi, s)
    return t


def parse_ts(line):
    """Epoch seconds from ISO / 2026/01/01 / klog (E0101) / syslog (Jan  1) stamps, else None."""
    s = line[:120]
    m = TS_ISO.search(s)
    if m:
        t = _epoch(*[int(x) for x in m.groups()[:6]])
        z = m.group(7)
        if t is not None and z and z != "Z":
            sign = 1 if z[0] == "+" else -1
            z = z[1:].replace(":", "")
            t -= sign * (int(z[:2]) * 3600 + int(z[2:]) * 60)
        return t
    m = TS_SLASH.search(s)
    if m:
        return _epoch(*[int(x) for x in m.groups()])
    m = TS_KLOG.match(s)
    if m:
        return _yearless(*[int(x) for x in m.groups()])
    m = TS_SYS.match(s)
    if m:
        return _yearless(MONTHS[m.group(1)], *[int(x) for x in m.groups()[1:]])
    return None


def fmt_ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t))


def parse_user_time(s):
    m = re.fullmatch(r"(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?Z?", s.strip())
    return _epoch(*[int(x) if x else 0 for x in m.groups()]) if m else None


def parse_dur(s):
    m = re.fullmatch(r"(\d+)([smhd]?)", s.strip())
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)] if m else 120


# --------------------------------------------------------------------------- #
# kubectl table parsing
# --------------------------------------------------------------------------- #
HDR_TOK = re.compile(r"\S+(?: \S+)*")


def parse_table(text):
    """Parse `kubectl get` text output using the header's column offsets."""
    lines = text.splitlines()
    i = 0
    while i < len(lines) and not lines[i].strip():
        i += 1
    if i >= len(lines):
        return None
    toks = list(HDR_TOK.finditer(lines[i]))
    if len(toks) < 2:
        return None
    names = [m.group(0) for m in toks]
    if not all(re.fullmatch(r"[A-Z][A-Z0-9 /_.%\-]*", n) for n in names):
        return None
    starts = [m.start() for m in toks]
    rows = []
    for ln in lines[i + 1:]:
        if not ln.strip():
            continue
        cells = []
        for j, s in enumerate(starts):
            e = starts[j + 1] if j + 1 < len(starts) else len(ln)
            cells.append(ln[s:e].strip())
        rows.append(cells)
    return names, rows


def format_grid(headers, rows):
    w = [len(h) for h in headers]
    for r in rows:
        for i, c in enumerate(r):
            w[i] = max(w[i], len(c))
    out = ["   ".join(h.ljust(w[i]) for i, h in enumerate(headers)).rstrip()]
    for r in rows:
        out.append("   ".join(c.ljust(w[i]) for i, c in enumerate(r)).rstrip())
    return out


class Table:
    def __init__(self, name, headers, rows, src, raw=None):
        self.name, self.headers, self.rows, self.src, self.raw = name, headers, rows, src, raw

    def idx(self, *names):
        up = [h.upper() for h in self.headers]
        for n in names:
            if n in up:
                return up.index(n)
        return -1


def _g(d, *path, default=""):
    for p in path:
        if not isinstance(d, dict):
            return default
        d = d.get(p)
        if d is None:
            return default
    return d


def structured_to_table(items, src, stem):
    """Turn a kubectl -o json/yaml item list (Node/Pod/Event/other) into a Table; raw items are kept."""
    if not items:
        return None
    kind = items[0].get("kind", "")
    rows = []
    if kind == "Node":
        headers = ["NAME", "STATUS", "ROLES", "CREATED", "VERSION", "INTERNAL-IP", "CPU", "MEMORY", "PRESSURE"]
        for n in items:
            conds = {c.get("type"): c for c in _g(n, "status", "conditions", default=[])}
            rd = conds.get("Ready", {}).get("status")
            status = "Ready" if rd == "True" else ("NotReady" if rd == "False" else "Unknown")
            if _g(n, "spec", "unschedulable", default=False):
                status += ",SchedulingDisabled"
            roles = ",".join(sorted(k.split("/", 1)[1] for k in _g(n, "metadata", "labels", default={})
                                    if k.startswith("node-role.kubernetes.io/"))) or "<none>"
            ip = next((a.get("address", "") for a in _g(n, "status", "addresses", default=[])
                       if a.get("type") == "InternalIP"), "")
            pressure = ",".join(t for t, c in conds.items() if t != "Ready" and c.get("status") == "True") or "-"
            al = _g(n, "status", "allocatable", default={})
            rows.append([str(x) for x in (_g(n, "metadata", "name"), status, roles,
                                          _g(n, "metadata", "creationTimestamp"),
                                          _g(n, "status", "nodeInfo", "kubeletVersion"), ip,
                                          al.get("cpu", ""), al.get("memory", ""), pressure)])
    elif kind == "Pod":
        headers = ["NAMESPACE", "NAME", "READY", "STATUS", "RESTARTS", "NODE", "CREATED"]
        for p in items:
            cs = _g(p, "status", "containerStatuses", default=[])
            total = len(_g(p, "spec", "containers", default=[])) or len(cs)
            status = _g(p, "status", "phase")
            if _g(p, "metadata", "deletionTimestamp"):
                status = "Terminating"
            else:
                for c in cs:
                    w = _g(c, "state", "waiting", default={})
                    t = _g(c, "state", "terminated", default={})
                    if w.get("reason"):
                        status = w["reason"]
                        break
                    if t.get("reason") and t["reason"] != "Completed":
                        status = t["reason"]
                        break
                if _g(p, "status", "reason"):
                    status = p["status"]["reason"]
            rows.append([str(x) for x in (_g(p, "metadata", "namespace"), _g(p, "metadata", "name"),
                                          "%d/%d" % (sum(1 for c in cs if c.get("ready")), total), status,
                                          sum(c.get("restartCount", 0) for c in cs), _g(p, "spec", "nodeName"),
                                          _g(p, "metadata", "creationTimestamp"))])
    elif kind == "Event":
        headers = ["NAMESPACE", "LAST SEEN", "TYPE", "REASON", "OBJECT", "COUNT", "MESSAGE"]
        for e in items:
            io = e.get("involvedObject", {})
            rows.append([str(x) for x in (_g(e, "metadata", "namespace"),
                                          e.get("lastTimestamp") or e.get("eventTime") or
                                          _g(e, "metadata", "creationTimestamp"),
                                          e.get("type", ""), e.get("reason", ""),
                                          "%s/%s" % (io.get("kind", "").lower(), io.get("name", "")),
                                          e.get("count", ""), (e.get("message") or "").replace("\n", " "))])
    else:
        headers = ["NAMESPACE", "NAME", "KIND", "CREATED"]
        rows = [[str(x) for x in (_g(i, "metadata", "namespace"), _g(i, "metadata", "name"), i.get("kind", ""),
                                  _g(i, "metadata", "creationTimestamp"))] for i in items]
    return Table(stem, headers, rows, src, raw=items)


ALIASES = {
    "po": "pods", "pod": "pods", "no": "nodes", "node": "nodes", "ev": "events", "event": "events",
    "deploy": "deployments", "deployment": "deployments", "ds": "daemonsets", "daemonset": "daemonsets",
    "sts": "statefulsets", "statefulset": "statefulsets", "svc": "services", "service": "services",
    "namespace": "namespaces", "cm": "configmaps", "configmap": "configmaps", "pv": "persistentvolumes",
    "pvc": "persistentvolumeclaims", "ing": "ingresses", "ingress": "ingresses", "rs": "replicasets",
    "replicaset": "replicasets", "job": "jobs", "cronjob": "cronjobs", "cj": "cronjobs",
    "ep": "endpoints", "containers": "crictl-psa", "ps": "crictl-psa", "psa": "crictl-psa",
    "crictl": "crictl-psa", "sandboxes": "crictl-pods", "cpods": "crictl-pods", "stats": "crictl-statsa", "crd": "customresourcedefinitions", "crds": "customresourcedefinitions",
}


def canon(n):
    n = n.lower()
    return ALIASES.get(n, n)


# --------------------------------------------------------------------------- #
# bundle loading / indexing
# --------------------------------------------------------------------------- #
def is_archive(p):
    return p.lower().endswith(ARCHIVE_EXT)


def strip_ext(p):
    for e in ARCHIVE_EXT:
        if p.lower().endswith(e):
            return p[: -len(e)]
    return p


def safe_extract(archive, dest):
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(archive, "r:*") as tf:
        base = os.path.realpath(dest)
        members = []
        for m in tf.getmembers():
            target = os.path.realpath(os.path.join(dest, m.name))
            if not (target == base or target.startswith(base + os.sep)):
                continue
            if m.issym() or m.islnk() or m.isdev():
                continue
            members.append(m)
        try:
            tf.extractall(dest, members=members, filter="data")
        except TypeError:
            tf.extractall(dest, members=members)


@dataclass
class FileEntry:
    rel: str
    path: str
    size: int
    kind: str


def classify(rel):
    low = rel.lower()
    parts = low.split("/")
    base = parts[-1]
    dirs = parts[:-1]
    if "kubectl" in dirs:
        return "kubectl"
    if "crictl" in dirs:
        return "crictl"
    if any(p in ("podlogs", "containerlogs", "pod-logs", "pod_logs") for p in dirs) \
            or re.search(r"(^|/)var/log/(pods|containers)/", low):
        return "podlog"
    if any(p in ("systemlogs", "journald", "journal", "agent-logs") for p in dirs) \
            or base.endswith((".log", ".log.gz", ".journal")) \
            or base in ("syslog", "messages", "dmesg", "kern.log"):
        return "syslog"
    return "other"


@dataclass
class Finding:
    sev: str
    cat: str
    title: str
    count: int = 1
    where: str = ""
    hits: list = field(default_factory=list)
    ref: tuple = None
    pat: object = None


SEV_ORDER = {"ERROR": 0, "WARN": 1, "INFO": 2}


class Bundle:
    def __init__(self, path):
        self.tmp = None
        path = os.path.abspath(path)
        if os.path.isfile(path) and is_archive(path):
            self.tmp = tempfile.mkdtemp(prefix="rlv-")
            atexit.register(shutil.rmtree, self.tmp, True)
            root = os.path.join(self.tmp, os.path.basename(strip_ext(path)))
            print("Extracting %s ..." % path, file=sys.stderr)
            safe_extract(path, root)
        elif os.path.isdir(path):
            root = path
            names = os.listdir(path)
            arcs = [n for n in names if is_archive(n)]
            if arcs and not any(os.path.isdir(os.path.join(path, n)) for n in names):
                self.tmp = tempfile.mkdtemp(prefix="rlv-")
                atexit.register(shutil.rmtree, self.tmp, True)
                for a in sorted(arcs):
                    print("Extracting %s ..." % a, file=sys.stderr)
                    safe_extract(os.path.join(path, a), os.path.join(self.tmp, strip_ext(a)))
                root = self.tmp
        else:
            raise SystemExit("not a directory or tar archive: %s" % path)
        self.root = root
        self.files = []
        self.resources = {}   # key -> [Table]
        self.describes = {}   # key -> [path]
        self._dcache = {}
        self.notes = []
        self._jent = None
        self._index()
        if self.files:
            BUNDLE_END[0] = max(os.path.getmtime(f.path) for f in self.files)
        self._load_resources()
        self._load_listeners()

    def _index(self):
        for dp, dn, fn in os.walk(self.root):
            dn[:] = sorted(d for d in dn if d != ".git")
            for f in sorted(fn):
                p = os.path.join(dp, f)
                try:
                    sz = os.path.getsize(p)
                except OSError:
                    continue
                rel = os.path.relpath(p, self.root).replace(os.sep, "/")
                self.files.append(FileEntry(rel, p, sz, classify(rel)))

    def _load_resources(self):
        for f in self.files:
            if f.kind not in ("kubectl", "crictl") or f.size > 80 * 1024 * 1024:
                continue
            low = re.sub(r"\.(txt|out|log)$", "", os.path.basename(f.rel).lower())
            parent = os.path.basename(os.path.dirname(f.rel)).lower()
            if f.kind == "kubectl" and "describe" in parent:          # kubectl/poddescribe/<file>
                self.describes.setdefault(re.sub(r"describe", "", parent).strip("-_."), []).append(f.path)
                continue
            if "describe" in low:                                     # kubectl/nodesdescribe
                self.describes.setdefault(re.sub(r"describe", "", low).strip("-_."), []).append(f.path)
                continue
            stem, ext = os.path.splitext(low)
            if ext in (".json", ".yaml", ".yml"):
                self._load_structured(f, stem, ext)
                continue
            try:
                with open(f.path, "r", errors="replace") as fh:
                    parsed = parse_table(fh.read())
            except OSError:
                continue
            if parsed and parsed[1]:
                key = low if f.kind == "kubectl" else "crictl-" + low
                self.resources.setdefault(key, []).append(Table(key, parsed[0], parsed[1], f.rel))

    def _load_structured(self, f, stem, ext):
        try:
            if ext == ".json":
                docs = [json.load(open(f.path, "r", errors="replace"))]
            else:
                try:
                    import yaml
                except ImportError:
                    if "yaml" not in " ".join(self.notes):
                        self.notes.append("PyYAML not installed: .yaml resource dumps not parsed (pip install pyyaml)")
                    return
                docs = list(yaml.safe_load_all(open(f.path, "r", errors="replace")))
        except Exception:
            return
        items = []
        for d in docs:
            if isinstance(d, dict) and isinstance(d.get("items"), list):
                lk = d.get("kind", "")
                for it in d["items"]:
                    if isinstance(it, dict):
                        it.setdefault("kind", lk[:-4] if lk.endswith("List") else lk)
                        items.append(it)
            elif isinstance(d, dict) and d.get("kind") and d.get("metadata"):
                items.append(d)
        t = structured_to_table(items, f.rel, stem)
        if t:
            self.resources.setdefault(stem, []).append(t)

    def net_files(self):
        for f in self.files:
            parts = f.rel.lower().split("/")
            if f.kind == "other" and f.size < 8 << 20 and ("networking" in parts[:-1] or "systeminfo" in parts[:-1]):
                yield f

    def _load_listeners(self):
        rows, seen = [], set()
        for f in self.net_files():
            if not re.search(r"(^|[-_.])(ss|netstat|listen\w*|sockets?|ports?)([-_.]|$)", os.path.basename(f.rel).lower()):
                continue
            try:
                txt = open(f.path, "r", errors="replace").read()
            except OSError:
                continue
            for ln in txt.splitlines():
                if "LISTEN" not in ln and not re.match(r"^udp", ln):
                    continue
                m = re.search(r"(?:^|\s)(\S+):(\d+)\s+\S+:(?:\*|\d+)", ln)
                if not m:
                    continue
                proc = re.search(r'users:\(\("([^"]+)"', ln) or re.search(r"\s\d+/(\S+)\s*$", ln)
                proto = "udp" if ln.startswith("udp") else ("tcp6" if "tcp6" in ln else "tcp")
                row = [m.group(2), m.group(1), proto, proc.group(1) if proc else "-"]
                if tuple(row) not in seen:
                    seen.add(tuple(row))
                    rows.append(row + [f.rel])
        if rows:
            rows.sort(key=lambda r: int(r[0]))
            self.resources["listeners"] = [Table("listeners", ["PORT", "ADDRESS", "PROTO", "PROCESS", "SRC"], rows, "networking")]

    def find_key(self, name):
        c = canon(name)
        if c in self.resources:
            return c
        for k in self.resources:
            if k.split("-")[-1] == c or k.endswith(c):
                return k
        cands = [k for k in self.resources if k.startswith(c)]
        return cands[0] if len(cands) == 1 else None

    def describe_blocks(self, name):
        """name -> text; namespaced objects are keyed 'ns/name'. Handles one-file and one-file-per-object dumps."""
        key = canon(name)
        if key in self._dcache:
            return self._dcache[key]
        out = {}
        for k, paths in self.describes.items():
            if canon(k) != key:
                continue
            for p in paths:
                try:
                    txt = open(p, "r", errors="replace").read()
                except OSError:
                    continue
                ms = list(re.finditer(r"^Name:\s+(\S+)", txt, re.M))
                if not ms:
                    out[os.path.basename(p)] = txt
                    continue
                for i, m in enumerate(ms):
                    end = ms[i + 1].start() if i + 1 < len(ms) else len(txt)
                    block = txt[m.start():end]
                    mns = re.search(r"^Namespace:\s+(\S+)", block, re.M)
                    out["%s/%s" % (mns.group(1), m.group(1)) if mns else m.group(1)] = block
        self._dcache[key] = out
        return out

    def pod_logs(self, ns, pod, prev=False):
        res = []
        for f in self.files:
            if f.kind != "podlog":
                continue
            isprev = bool(re.search(r"previous", f.rel, re.I))
            if isprev != prev:
                continue
            stem = re.sub(r"\.(log|txt|gz)$", "", os.path.basename(f.rel))
            stem = re.sub(r"[-_.]?previous$", "", stem, flags=re.I)
            score = None
            if ns and stem == "%s-%s" % (ns, pod):
                score = 0
            elif ns and ("%s-%s" % (ns, pod) in stem or "/%s_%s_" % (ns, pod) in "/" + f.rel):
                score = 1
            elif pod in stem or pod in f.rel:
                score = 3
            if score is not None:
                res.append((score, f))
        if not res:
            return []
        best = min(s for s, _ in res)
        return sorted((f for s, f in res if s == best), key=lambda f: f.rel)


# --------------------------------------------------------------------------- #
# background log scanner (pattern rules)
# --------------------------------------------------------------------------- #
RULES = [
    ("ERROR", "etcd", "etcd leader / heartbeat problems",
     r"failed to send out heartbeat|etcdserver: leader changed|lost leader|no leader"),
    ("ERROR", "etcd", "etcd request timeouts / overload",
     r"etcdserver: request timed out|etcdserver: too many requests"),
    ("ERROR", "etcd", "etcd database space exceeded", r"mvcc: database space exceeded"),
    ("WARN", "etcd", "etcd slow requests / slow disk",
     r"apply request took too long|slow fdatasync|waiting for ReadIndex response took too long"),
    ("ERROR", "certs", "Expired / not-yet-valid certificates",
     r"x509: certificate has expired|certificate has expired or is not yet valid|expired certificate"),
    ("ERROR", "certs", "Unknown CA / certificate mismatch",
     r"x509: certificate signed by unknown authority|x509: certificate is valid for|tls: bad certificate"),
    ("ERROR", "memory", "OOM kills",
     r"Out of memory: Kill|oom-kill|OOMKilled|oom_reaper|invoked oom-killer"),
    ("ERROR", "disk", "Disk full / disk pressure",
     r"no space left on device|DiskPressure|failed to garbage collect required amount of images"),
    ("ERROR", "crash", "Panics / fatal errors",
     r"\bpanic:|fatal error:|segmentation fault|SIGSEGV|goroutine \d+ \[running\]"),
    ("ERROR", "workload", "Crash loops", r"CrashLoopBackOff|Back-off restarting failed container"),
    ("ERROR", "control-plane", "API server unavailable / throttled",
     r"server is currently unable to handle the request|apiserver not ready|connection to the server \S+ was refused"),
    ("WARN", "control-plane", "Leader election problems",
     r"leaderelection lost|failed to renew lease|error retrieving resource lock"),
    ("WARN", "kubelet", "Kubelet PLEG / runtime unhealthy",
     r"PLEG is not healthy|container runtime is down|container runtime network not ready"),
    ("WARN", "kubelet", "Probe failures", r"(?:Liveness|Readiness|Startup) probe failed"),
    ("WARN", "images", "Image pull failures",
     r"ErrImagePull|ImagePullBackOff|Failed to pull image|manifest unknown|toomanyrequests"),
    ("WARN", "storage", "Volume mount / attach failures",
     r"FailedMount|FailedAttachVolume|MountVolume\.\w+ failed|Unable to attach or mount volumes"),
    ("WARN", "network", "Connection refused", r"connection refused"),
    ("WARN", "network", "Timeouts",
     r"i/o timeout|TLS handshake timeout|Client\.Timeout exceeded|context deadline exceeded"),
    ("WARN", "network", "No route / DNS failures",
     r"no route to host|no such host|server misbehaving|network is unreachable|Temporary failure in name resolution"),
    ("WARN", "rancher", "Rancher agent / tunnel disconnects",
     r"websocket: close|cluster agent disconnected|Failed to connect to peer|tunnel disconnected|"
     r"waiting for cluster agent|Cluster agent is not ready|remotedialer"),
    ("WARN", "admission", "Admission webhook failures", r"failed calling webhook|admission webhook \S+ denied"),
    ("ERROR", "network", "conntrack table full (packets dropped)", r"nf_conntrack: table full"),
    ("WARN", "network", "CNI / pod network setup failures",
     r"NetworkPluginNotReady|cni plugin not initialized|failed to setup network for sandbox|cni config uninitialized"),
    ("WARN", "host", "Too many open files / inotify exhaustion",
     r"too many open files|inotify_init|failed to create fsnotify watcher"),
    ("INFO", "auth", "Forbidden / unauthorized", r"is forbidden:|\bUnauthorized\b"),
]
COMBINED = re.compile("|".join("(?P<r%d>%s)" % (i, r[3]) for i, r in enumerate(RULES)), re.I)


class Scanner(threading.Thread):
    def __init__(self, bundle):
        super().__init__(daemon=True)
        self.b = bundle
        self.lock = threading.Lock()
        self.counts = Counter()
        self.hits = defaultdict(list)
        self.rule_files = defaultdict(Counter)
        self.file_stats = {}
        self.done = False
        self.started = False
        self.total = 0
        self.n = 0

    def start(self):
        self.started = True
        super().start()

    def run(self):
        todo = [f for f in self.b.files if f.kind not in ("kubectl", "crictl") and f.size < 2 << 30
                and not (not f.path.endswith(".gz") and is_binary(f.path))]
        self.total = len(todo)
        for f in todo:
            counts, hits, st, per = Counter(), defaultdict(list), [0, 0, 0], Counter()
            try:
                with open_text(f.path) as fh:
                    for ln, line in enumerate(fh, 1):
                        st[2] += 1
                        m = COMBINED.search(line)
                        if m:
                            i = int(m.lastgroup[1:])
                            counts[i] += 1
                            per[i] += 1
                            if per[i] <= MAX_HITS_PER_FILE_RULE:
                                hits[i].append((f.rel, ln, line.rstrip()[:400], parse_ts(line)))
                        if ERR_RE.search(line):
                            st[0] += 1
                        elif WARN_RE.search(line):
                            st[1] += 1
            except (OSError, EOFError, gzip.BadGzipFile):
                pass
            with self.lock:
                self.file_stats[f.rel] = tuple(st)
                for i, c in counts.items():
                    self.counts[i] += c
                    self.rule_files[i][f.rel] += c
                    room = MAX_HITS_PER_RULE - len(self.hits[i])
                    if room > 0:
                        self.hits[i].extend(hits[i][:room])
            self.n += 1
        self.done = True

    def progress(self):
        if self.done:
            return "scan: done"
        if not self.started:
            return "scan: off"
        return "scan: %d%%" % (100 * self.n // max(1, self.total))


def extra_findings(b):
    out = []
    # crictl: containers whose latest attempt is not running / restarted a lot (works without kubectl)
    t = (b.resources.get("crictl-psa") or [None])[0]
    if t:
        si, ni, ai, pi, nsi = t.idx("STATE"), t.idx("NAME"), t.idx("ATTEMPT"), t.idx("POD"), t.idx("NAMESPACE")
        if si >= 0 and ni >= 0:
            latest = {}
            for r in t.rows:
                att = int(r[ai]) if ai >= 0 and r[ai].isdigit() else 0
                k = (r[pi] if pi >= 0 else "", r[ni], r[nsi] if nsi >= 0 else "")
                if k not in latest or att >= latest[k][0]:
                    latest[k] = (att, r[si])
            for (pod, cname, ns), (att, st) in latest.items():
                if st == "Running":
                    if att >= 5:
                        out.append(Finding("WARN", "container", "%s/%s container %s restarted %d times" % (ns, pod, cname, att),
                                           1, t.src, ref=("pod", ns, pod)))
                elif st != "Created" and (att >= 2 or st == "Unknown"):
                    out.append(Finding("ERROR" if att >= 3 else "WARN", "container",
                                       "%s/%s container %s is %s (attempt %d)" % (ns, pod, cname, st, att),
                                       1, t.src, ref=("pod", ns, pod)))
    # pod describe: last termination reason + warning events
    for k, txt in b.describe_blocks("pods").items():
        ns, _, name = k.rpartition("/")
        m = re.search(r"Last State:\s+Terminated\s+Reason:\s+(\S+)", txt)
        if m and m.group(1) != "Completed":
            code = re.search(r"Last State:[\s\S]*?Exit Code:\s+(\d+)", txt)
            out.append(Finding("ERROR" if m.group(1) == "OOMKilled" else "WARN", "pod",
                               "%s: last termination %s (exit %s)" % (k, m.group(1), code.group(1) if code else "?"),
                               1, "pod describe", ref=("pod", ns, name)))
        warns = Counter(re.findall(r"^\s+Warning\s+(\w+)", txt, re.M))
        if warns:
            out.append(Finding("WARN", "pod", "%s: warning events %s" % (k, ", ".join("%s x%d" % kv for kv in warns.items())),
                               sum(warns.values()), "pod describe", ref=("pod", ns, name)))
    # nodes from JSON (only when there is no describe output to use)
    if not b.describe_blocks("nodes"):
        for t in b.resources.get("nodes", []):
            for it in (t.raw or []):
                name = _g(it, "metadata", "name")
                for c in _g(it, "status", "conditions", default=[]):
                    ty, st = c.get("type"), c.get("status")
                    if (ty == "Ready" and st != "True") or (ty in ("MemoryPressure", "DiskPressure", "PIDPressure",
                                                                  "NetworkUnavailable") and st == "True"):
                        out.append(Finding("ERROR", "node", "node %s: %s=%s %s" % (name, ty, st, (c.get("message") or "")[:70]),
                                           1, t.src, ref=("node", name)))
    out += net_findings(b)
    # host facts from systeminfo/: disk, inodes, memory, load
    for f in b.files:
        parts = f.rel.lower().split("/")
        if "systeminfo" not in parts[:-1] or f.size > 5 << 20:
            continue
        base = parts[-1]
        try:
            txt = open(f.path, "r", errors="replace").read()
        except OSError:
            continue
        if base.startswith("df"):
            inode = base.endswith("i") or "inode" in base
            for ln in txt.splitlines():
                if re.match(r"(tmpfs|overlay|shm|devtmpfs|udev|none|cgroup)", ln):
                    continue
                m = re.search(r"\s(\d{1,3})%\s+(/\S*)\s*$", ln)
                if m and int(m.group(1)) >= 80:
                    out.append(Finding("ERROR" if int(m.group(1)) >= 90 else "WARN", "host",
                                       "%s usage %s%% on %s" % ("inode" if inode else "disk", m.group(1), m.group(2)),
                                       1, f.rel))
        elif base.startswith("free"):
            m = re.search(r"^Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", txt, re.M)
            if m and int(m.group(1)) and int(m.group(6)) / int(m.group(1)) < 0.10:
                out.append(Finding("WARN", "host", "low available memory: %d%% of total" %
                                   (100 * int(m.group(6)) / int(m.group(1))), 1, f.rel))
        elif base == "uptime":
            m = re.search(r"load average:\s*([\d.]+)[, ]+([\d.]+)[, ]+([\d.]+)", txt)
            cpus = None
            for g in b.files:
                if g.rel.lower().endswith(("systeminfo/nproc",)):
                    try:
                        cpus = int(open(g.path).read().split()[0])
                    except (OSError, ValueError, IndexError):
                        pass
            if m and cpus and float(m.group(3)) > cpus * 1.5:
                out.append(Finding("WARN", "host", "15-min load %s on %d CPUs" % (m.group(3), cpus), 1, f.rel))
    return out


def net_findings(b):
    out, ifaces, conn = [], {}, {}
    for f in b.net_files():
        base = os.path.basename(f.rel).lower()
        try:
            txt = open(f.path, "r", errors="replace").read()
        except OSError:
            continue
        for ln in txt.splitlines():
            m = re.match(r"^\d+:\s+([^\s:@]+)(?:@\S+)?:\s+<([^>]*)>.*?\bmtu\s+(\d+)", ln)
            if m:
                st = re.search(r"\bstate\s+(\w+)", ln)
                ifaces[m.group(1)] = (int(m.group(3)), st.group(1) if st else "", f.rel)
        for key, rx in (("count", r"nf_conntrack_count\s*[=:]\s*(\d+)"), ("max", r"nf_conntrack_max\s*[=:]\s*(\d+)")):
            m = re.search(rx, txt)
            if m:
                conn[key] = int(m.group(1))
        if re.search(r"net\.ipv4\.ip_forward\s*=\s*0\b", txt):
            out.append(Finding("ERROR", "network", "net.ipv4.ip_forward=0 (pod networking will not work)", 1, f.rel))
        if re.search(r"net\.bridge\.bridge-nf-call-iptables\s*=\s*0\b", txt):
            out.append(Finding("WARN", "network", "bridge-nf-call-iptables=0 (service routing may break)", 1, f.rel))
        m = re.search(r"fs\.inotify\.max_user_instances\s*=\s*(\d+)", txt)
        if m and int(m.group(1)) < 512:
            out.append(Finding("WARN", "host", "fs.inotify.max_user_instances=%s is low" % m.group(1), 1, f.rel))
        if "route" in base and len(txt.splitlines()) >= 2 and not re.search(r"^default\b", txt, re.M):
            out.append(Finding("WARN", "network", "routing table has no default route", 1, f.rel))
        if base.startswith("resolv") and not re.search(r"^nameserver\s+\S+", txt, re.M):
            out.append(Finding("ERROR", "network", "resolv.conf has no nameserver", 1, f.rel))
        if "iptables" in base and re.search(r"^(-A |Chain )", txt, re.M) and "KUBE-SERVICES" not in txt:
            out.append(Finding("INFO", "network", "no KUBE-SERVICES chain in %s (ignore if kube-proxy replacement / other table)" % base,
                               1, f.rel))
    if conn.get("max") and conn.get("count", 0) / conn["max"] > 0.8:
        out.append(Finding("WARN", "network", "conntrack table %d%% full (%d/%d)" %
                           (100 * conn["count"] / conn["max"], conn["count"], conn["max"]), 1, "networking"))
    under = [v[0] for k, v in ifaces.items() if re.match(r"(eth|ens|eno|enp|bond|em)", k)]
    for k, (mtu, st, rel) in ifaces.items():
        if under and re.match(r"(flannel\.\d+|vxlan\.calico|cilium_vxlan)$", k) and mtu > max(under) - 50:
            out.append(Finding("WARN", "network", "overlay %s MTU %d too large for underlay MTU %d (needs <= %d)" %
                               (k, mtu, max(under), max(under) - 50), 1, rel))
        if re.match(r"(flannel|cni0|vxlan|cilium_host|cilium_vxlan)", k) and st == "DOWN":
            out.append(Finding("WARN", "network", "interface %s is DOWN" % k, 1, rel))
    lt = (b.resources.get("listeners") or [None])[0]
    if lt and "10250" not in {r[0] for r in lt.rows}:
        out.append(Finding("WARN", "network", "nothing listening on kubelet port 10250 (per ss/netstat)", 1, lt.rows[0][4]))
    return out


def json_entries(b):
    """Timeline entries (ts, sev, cat, src, line, text) from absolute timestamps in -o json/yaml dumps."""
    if b._jent is not None:
        return b._jent
    ents = []
    bad_reasons = ("OOMKilling", "SystemOOM", "NodeNotReady", "Evicted", "FailedMount", "BackOff", "Failed")
    for tabs in b.resources.values():
        for t in tabs:
            for it in (t.raw or []):
                kind, md = it.get("kind"), it.get("metadata", {})
                nm = ("%s/%s" % (md.get("namespace"), md.get("name"))) if md.get("namespace") else md.get("name", "")
                if kind == "Event" and it.get("type") == "Warning":
                    ts = parse_ts(it.get("lastTimestamp") or it.get("eventTime") or md.get("creationTimestamp") or "")
                    io = it.get("involvedObject", {})
                    if ts:
                        ents.append((ts, "ERROR" if it.get("reason") in bad_reasons else "WARN", "event", "k8s events", 0,
                                     "%s %s/%s: %s" % (it.get("reason"), io.get("kind", "").lower(), io.get("name"),
                                                       (it.get("message") or "")[:250])))
                elif kind == "Pod":
                    for c in _g(it, "status", "containerStatuses", default=[]):
                        term = _g(c, "lastState", "terminated", default={})
                        ts = parse_ts(term.get("finishedAt", "")) if term else None
                        if ts:
                            ents.append((ts, "ERROR" if term.get("reason") != "Completed" else "INFO", "pod", "pod status", 0,
                                         "%s container %s terminated: %s exit=%s (restarts=%s)" %
                                         (nm, c.get("name"), term.get("reason"), term.get("exitCode"), c.get("restartCount"))))
                elif kind == "Node":
                    for c in _g(it, "status", "conditions", default=[]):
                        ty, st = c.get("type"), c.get("status")
                        if (ty == "Ready" and st != "True") or (ty != "Ready" and st == "True"):
                            ts = parse_ts(c.get("lastTransitionTime", ""))
                            if ts:
                                ents.append((ts, "ERROR", "node", "node conditions", 0,
                                             "node %s: %s=%s %s" % (nm, ty, st, (c.get("message") or "")[:150])))
    b._jent = ents
    return ents


def build_findings(b, sc):
    out = []
    # --- pods
    t = (b.resources.get("pods") or [None])[0]
    if t:
        ci = {h.upper(): i for i, h in enumerate(t.headers)}
        for r in t.rows:
            g = lambda k: r[ci[k]] if k in ci and ci[k] < len(r) else ""
            name, ns, st, rd, rs = g("NAME"), g("NAMESPACE"), g("STATUS"), g("READY"), g("RESTARTS")
            m = re.match(r"(\d+)", rs)
            rn = int(m.group(1)) if m else 0
            sev, why = None, []
            if st and not re.fullmatch(r"Running|Completed|Succeeded", st):
                sev = "WARN" if re.search(r"Pending|Terminating|Init|ContainerCreating", st) else "ERROR"
                why.append(st)
            m = re.fullmatch(r"(\d+)/(\d+)", rd)
            if m and m.group(1) != m.group(2) and st == "Running":
                sev = sev or "WARN"
                why.append("ready " + rd)
            if rn >= 5:
                sev = sev or "WARN"
                why.append("restarts %d" % rn)
            if sev:
                out.append(Finding(sev, "pod", "%s/%s: %s" % (ns or "-", name, ", ".join(why)),
                                   1, t.src, ref=("pod", ns, name)))
    # --- nodes
    t = (b.resources.get("nodes") or [None])[0]
    if t:
        si, ni = t.idx("STATUS"), t.idx("NAME")
        for r in t.rows:
            st = r[si] if si >= 0 else ""
            if st and not st.startswith("Ready"):
                out.append(Finding("ERROR", "node", "node %s is %s" % (r[ni], st), 1, t.src, ref=("node", r[ni])))
            elif "SchedulingDisabled" in st:
                out.append(Finding("WARN", "node", "node %s is cordoned" % r[ni], 1, t.src, ref=("node", r[ni])))
    for name, txt in b.describe_blocks("nodes").items():
        m = re.search(r"^Conditions:\s*\n((?:[ \t]+.*\n?)+)", txt, re.M)
        if m:
            for ln in m.group(1).splitlines():
                p = ln.split()
                if len(p) >= 2 and p[0] in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable") \
                        and p[1] == "True":
                    out.append(Finding("ERROR", "node", "node %s: %s" % (name, p[0]), 1, "nodes describe",
                                       ref=("node", name)))
                if len(p) >= 2 and p[0] == "Ready" and p[1] != "True":
                    out.append(Finding("ERROR", "node", "node %s: Ready=%s" % (name, p[1]), 1, "nodes describe",
                                       ref=("node", name)))
        for res in ("cpu", "memory"):
            m = re.search(r"^\s+%s\s+(\S+)\s+\((\d+)%%\)\s+(\S+)\s+\((\d+)%%\)" % res, txt, re.M)
            if m and int(m.group(2)) >= 90:
                out.append(Finding("WARN", "node", "node %s: %s requests at %s%%" % (name, res, m.group(2)),
                                   1, "nodes describe", ref=("node", name)))
    # --- events
    t = (b.resources.get("events") or [None])[0]
    if t:
        ti, ri, oi, mi = t.idx("TYPE"), t.idx("REASON"), t.idx("OBJECT", "INVOLVED OBJECT"), t.idx("MESSAGE")
        groups = defaultdict(list)
        for r in t.rows:
            if ti >= 0 and r[ti] == "Warning":
                groups[r[ri] if ri >= 0 else "?"].append(r)
        for reason, rows in groups.items():
            sev = "ERROR" if reason in ("OOMKilling", "SystemOOM", "NodeNotReady", "Evicted", "FailedMount",
                                        "FailedCreatePodSandBox", "BackOff") else "WARN"
            objs = Counter(r[oi] for r in rows if oi >= 0)
            msg = rows[0][mi] if mi >= 0 else ""
            out.append(Finding(sev, "event", "Warning event %s: %s" % (reason, msg[:110]), len(rows),
                               ", ".join(o for o, _ in objs.most_common(3)), ref=("events", reason)))
    # --- log patterns
    with sc.lock:
        counts, hits, rf = dict(sc.counts), {k: list(v) for k, v in sc.hits.items()}, \
            {k: v.most_common(3) for k, v in sc.rule_files.items()}
    for i, n in counts.items():
        sev, cat, title, _ = RULES[i]
        out.append(Finding(sev, cat, title, n, ", ".join("%s (%d)" % x for x in rf[i]), hits[i],
                           pat=re.compile(RULES[i][3], re.I)))
    out += extra_findings(b)
    out.sort(key=lambda f: (SEV_ORDER[f.sev], -f.count))
    return out


class Snapshot:
    """A second bundle (baseline) + its background scanner, used by `diff`."""
    def __init__(self, bundle):
        self.b, self.sc = bundle, Scanner(bundle)


def norm_rel(rel):
    first, _, rest = rel.partition("/")
    first = re.sub(r"[-_.]?\d{4}[-_]?\d{2}[-_]?\d{2}.*$", "", first)
    return first + "/" + rest


def compute_diff(nb, nsc, ob, osc):
    """Rows (chg, category, item, detail): what changed in `nb` (current) relative to `ob` (baseline)."""
    rows = []
    norm = lambda t: re.sub(r"\d+", "#", t)
    fn = {(f.cat, norm(f.title)): f for f in build_findings(nb, nsc)}
    fo = {(f.cat, norm(f.title)): f for f in build_findings(ob, osc)}
    for k in sorted(fn.keys() - fo.keys()):
        rows.append(("+", "finding", "[%s] %s" % (fn[k].sev, fn[k].title), "NEW (count %d) %s" % (fn[k].count, fn[k].where[:80])))
    for k in sorted(fo.keys() - fn.keys()):
        rows.append(("-", "finding", "[%s] %s" % (fo[k].sev, fo[k].title), "gone since baseline"))
    for k in sorted(fn.keys() & fo.keys()):
        a, c = fo[k].count, fn[k].count
        if a != c and k[0] not in ("pod", "container"):
            rows.append(("~", "finding", fn[k].title, "count %d -> %d (%+d)" % (a, c, c - a)))
    # resources
    def idf(t):
        ni, ns = t.idx("NAME"), t.idx("NAMESPACE")
        return None if ni < 0 else (lambda r: (r[ns] + "/" if ns >= 0 else "") + r[ni])
    for key in sorted(set(nb.resources) & set(ob.resources)):
        if key in ("events", "api-resources", "listeners") or key.startswith("crictl-"):
            continue
        tn, to = nb.resources[key][0], ob.resources[key][0]
        fi, fo_ = idf(tn), idf(to)
        if not fi or not fo_:
            continue
        mn, mo = {fi(r): r for r in tn.rows}, {fo_(r): r for r in to.rows}
        for tag, ids in (("+", sorted(mn.keys() - mo.keys())), ("-", sorted(mo.keys() - mn.keys()))):
            for k in ids[:40]:
                rows.append((tag, key, k, "added since baseline" if tag == "+" else "removed since baseline"))
            if len(ids) > 40:
                rows.append((tag, key, "... %d more" % (len(ids) - 40), ""))
        for k in sorted(mn.keys() & mo.keys()):
            for c in ("STATUS", "READY", "RESTARTS", "VERSION", "AVAILABLE", "UP-TO-DATE"):
                i1, i2 = tn.idx(c), to.idx(c)
                if i1 >= 0 and i2 >= 0 and mn[k][i1] != mo[k][i2]:
                    rows.append(("~", key, k, "%s: %s -> %s" % (c, mo[k][i2], mn[k][i1])))
    # log error volume per file
    old = {norm_rel(r): v for r, v in osc.file_stats.items()}
    cand = []
    for r, v in nsc.file_stats.items():
        o = old.get(norm_rel(r))
        d = v[0] - (o[0] if o else 0)
        if d >= 10 or (o is None and v[0] > 0):
            cand.append((d, r, o[0] if o else None, v[0]))
    for d, r, o, n in sorted(cand, reverse=True)[:25]:
        rows.append(("+" if o is None else "~", "log errors", r, ("new file with %d error lines" % n) if o is None
                     else "ERR lines %d -> %d (%+d)" % (o, n, d)))
    # versions file
    import difflib
    def vers(b):
        f = next((x for x in b.files if os.path.basename(x.rel) == "versions" and x.rel.count("/") <= 2), None)
        return read_lines(f.path, 400) if f else []
    for ln in difflib.ndiff(vers(ob), vers(nb)):
        if ln[:2] in ("+ ", "- "):
            rows.append((ln[0], "versions", ln[2:].strip()[:120], "changed"))
    return rows


def scan_secrets(b, cap=5000):
    """Heuristic credential scan. Returns [(rel, line, type, masked_context)] - values are never included."""
    hits = []
    for f in b.files:
        if len(hits) >= cap:
            break
        if not f.path.endswith(".gz") and is_binary(f.path):
            continue
        kind_ln, b64 = 0, False
        try:
            with open_text(f.path) as fh:
                for ln, line in enumerate(fh, 1):
                    if not kind_ln and SECRET_KIND.search(line):
                        kind_ln = ln
                    if kind_ln and not b64 and B64_VALUE.search(line):
                        b64 = True
                    for t, kw, val, conf, shape in secret_matches(line):
                        hits.append((f.rel, ln, t, mask_line(line.rstrip())[:200], conf, shape, val, kw))
                        if len(hits) >= cap:
                            break
                    if len(hits) >= cap:
                        break
        except (OSError, EOFError, gzip.BadGzipFile):
            continue
        if kind_ln and b64:    # a Secret object that still carries (base64) values
            hits.append((f.rel, kind_ln, "Kubernetes Secret object", "kind: Secret", "MEDIUM",
                         "contains base64 data values", "", "secret"))
    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    hits.sort(key=lambda h: (rank[h[4]], h[0], h[1]))
    return hits


def sanitize_bundle(b, out):
    """Write a redacted copy of the bundle to `out`. Original files are untouched."""
    out = os.path.abspath(out)
    if os.path.exists(out) and os.listdir(out):
        raise SystemExit("refusing to write into non-empty directory: %s" % out)
    changed, files_changed, skipped = 0, 0, []
    for f in b.files:
        dest = os.path.join(out, f.rel)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        st = os.stat(f.path)
        if not f.path.endswith(".gz") and is_binary(f.path):
            shutil.copy2(f.path, dest)
            if f.size and f.kind != "crictl":
                skipped.append(f.rel)
            continue
        try:
            with open_text(f.path) as fh:
                lines = fh.read().split("\n")
        except (OSError, EOFError, gzip.BadGzipFile):
            shutil.copy2(f.path, dest)
            skipped.append(f.rel)
            continue
        is_secret = any(SECRET_KIND.search(l) for l in lines)
        in_data, ind, n = False, 0, 0
        for i, l in enumerate(lines):
            new = mask_line(l)
            if is_secret:
                lead = len(l) - len(l.lstrip())
                if re.match(r"^\s*(data|stringData):\s*$", l):
                    in_data, ind = True, lead
                elif in_data and l.strip() and lead <= ind:
                    in_data = False
                elif in_data:
                    new = re.sub(r"^(\s*[^:\s][^:]*:\s*).+$", r"\1<redacted>", l)
                if re.match(r'^\s*"[^"]+":\s*"[A-Za-z0-9+/=]{16,}",?$', l):
                    new = re.sub(r'(:\s*)"[A-Za-z0-9+/=]{16,}"', r'\1"<redacted>"', l)
            if new != l:
                lines[i] = new
                n += 1
        opener = gzip.open if dest.endswith(".gz") else open
        with opener(dest, "wt") as fh:
            fh.write("\n".join(lines))
        os.utime(dest, (st.st_atime, st.st_mtime))
        if n:
            changed += n
            files_changed += 1
    rep = ["rlv sanitize report", "source: %s" % b.root, "lines masked: %d in %d files" % (changed, files_changed), "",
           "NOT sanitised (binary/unreadable files copied as-is - review manually):"] + ["  " + r for r in skipped]
    open(os.path.join(out, "SANITIZE-REPORT.txt"), "w").write("\n".join(rep) + "\n")
    return changed, files_changed, len(skipped)


# --------------------------------------------------------------------------- #
# curses plumbing
# --------------------------------------------------------------------------- #
C_HDR, C_SEL, C_RED, C_YEL, C_GRN, C_DIM, C_HIT, C_COL = range(1, 9)


def init_colors():
    try:
        curses.start_color()
        curses.use_default_colors()
    except curses.error:
        return
    spec = {C_HDR: (curses.COLOR_WHITE, curses.COLOR_BLUE), C_SEL: (curses.COLOR_BLACK, curses.COLOR_CYAN),
            C_RED: (curses.COLOR_RED, -1), C_YEL: (curses.COLOR_YELLOW, -1), C_GRN: (curses.COLOR_GREEN, -1),
            C_DIM: (curses.COLOR_CYAN, -1), C_HIT: (curses.COLOR_BLACK, curses.COLOR_YELLOW),
            C_COL: (curses.COLOR_BLACK, curses.COLOR_WHITE)}
    for k, (f, b) in spec.items():
        curses.init_pair(k, f, b)


def cp(n):
    return curses.color_pair(n)


def put(scr, y, x, s, attr=0):
    h, w = scr.getmaxyx()
    if y < 0 or y >= h or x >= w - 1:
        return
    try:
        scr.addstr(y, x, clean(s)[: max(0, w - x - 1)], attr)
    except curses.error:
        pass


def color_pod(headers, row):
    try:
        st = row[headers.index("STATUS")]
    except ValueError:
        return 0
    if st in ("Running", "Completed", "Succeeded"):
        m = re.fullmatch(r"(\d+)/(\d+)", row[headers.index("READY")]) if "READY" in headers else None
        return cp(C_YEL) if m and m.group(1) != m.group(2) and st == "Running" else cp(C_GRN)
    if re.search(r"Pending|Init|Terminating|ContainerCreating", st):
        return cp(C_YEL)
    return cp(C_RED)


def color_node(headers, row):
    try:
        st = row[headers.index("STATUS")]
    except ValueError:
        return 0
    return cp(C_GRN) if st.startswith("Ready") and "Scheduling" not in st else (
        cp(C_YEL) if st.startswith("Ready") else cp(C_RED))


def color_event(headers, row):
    try:
        t = row[headers.index("TYPE")]
    except ValueError:
        return 0
    return cp(C_YEL) if t == "Warning" else 0


def color_sev(headers, row):
    sev = next((c for c in row[:2] if c in ("ERROR", "WARN", "INFO")), "")
    return {"ERROR": cp(C_RED), "WARN": cp(C_YEL)}.get(sev, cp(C_DIM))


def color_state(headers, row):
    try:
        st = row[headers.index("STATE")]
    except ValueError:
        return 0
    return cp(C_GRN) if st in ("Running", "Ready") else (cp(C_YEL) if st in ("Exited", "Created") else cp(C_RED))


# --------------------------------------------------------------------------- #
# views
# --------------------------------------------------------------------------- #
class TableView:
    def __init__(self, app, title, headers, rows, payloads=None, enter=None, colorfn=None,
                 keys=None, filt="", ns=None, sortcol=None, rev=False, hint="", raw=None):
        self.app, self.title, self.headers, self.rows = app, title, headers, rows
        self.payloads, self.enter, self.colorfn = payloads, enter, colorfn
        self.keys, self.filt, self.ns, self.hint = keys or {}, filt, ns, hint
        self.raw = raw
        self.sortcol, self.rev = sortcol, rev
        self.sel = self.top = self.hs = 0
        self.nsidx = next((i for i, h in enumerate(headers) if h.upper() == "NAMESPACE"), -1)
        self.widths = [len(h) + 2 for h in headers]
        for r in rows[:5000]:
            for i, c in enumerate(r):
                self.widths[i] = max(self.widths[i], len(c))
        self.widths = [min(w, 60) for w in self.widths[:-1]] + [min(self.widths[-1], 400)]
        self.view = []
        self.refresh()

    def refresh(self):
        ns = self.app.ns if self.ns is None else self.ns
        pat = smart_re(self.filt) if self.filt else None
        idx = []
        for i, r in enumerate(self.rows):
            if ns and self.nsidx >= 0 and r[self.nsidx] != ns:
                continue
            if pat and not pat.search(" ".join(r)):
                continue
            idx.append(i)
        if self.sortcol is not None:
            c = self.sortcol
            idx.sort(key=lambda i: sortkey(self.rows[i][c]), reverse=self.rev)
        self.view = idx
        self.sel = min(self.sel, max(0, len(idx) - 1))

    def payload(self, vi):
        i = self.view[vi]
        return self.payloads[i] if self.payloads is not None else self.rows[i]

    def current(self):
        return self.payload(self.sel) if self.view else None

    def current_raw(self):
        if self.raw is None or not self.view:
            return None
        return self.raw[self.view[self.sel]]

    def cell(self, row, name):
        up = [h.upper() for h in self.headers]
        return row[up.index(name)] if name in up and up.index(name) < len(row) else ""

    def as_lines(self):
        return format_grid(self.headers, [[rd(c) for c in self.rows[i]] for i in self.view])

    def status(self):
        ns = self.app.ns if self.ns is None else self.ns
        s = "%d/%d rows" % (len(self.view), len(self.rows))
        if self.filt:
            s += "  filter: /%s" % self.filt
        if ns and self.nsidx >= 0:
            s += "  ns: %s" % ns
        if self.sortcol is not None:
            s += "  sort: %s%s" % (self.headers[self.sortcol], " desc" if self.rev else " asc")
        return s + ("  | " + self.hint if self.hint else "")

    def hints(self):
        return "/ filter  s sort  r reverse  Enter open  : command  ? help  Esc back" + \
            "".join("  %s %s" % (k, v[1]) for k, v in self.keys.items() if len(v) > 1)

    def draw(self, y0, h, w):
        scr = self.app.scr
        rh = h - 1
        if self.sel < self.top:
            self.top = self.sel
        if self.sel >= self.top + rh:
            self.top = self.sel - rh + 1
        names = list(self.headers)
        if self.sortcol is not None:
            names[self.sortcol] += " v" if self.rev else " ^"
        fmt = lambda cells: "  ".join(clean(rd(c))[:wd].ljust(wd) for c, wd in zip(cells, self.widths))
        put(scr, y0, 0, fmt(names)[self.hs:].ljust(w), cp(C_COL) | curses.A_BOLD)
        for r in range(rh):
            p = self.top + r
            if p >= len(self.view):
                break
            row = self.rows[self.view[p]]
            line = fmt(row)[self.hs:]
            if p == self.sel:
                put(scr, y0 + 1 + r, 0, line.ljust(w), cp(C_SEL) | curses.A_BOLD)
            else:
                put(scr, y0 + 1 + r, 0, line, self.colorfn(self.headers, row) if self.colorfn else 0)

    def key(self, k):
        n, page = len(self.view), self.app.page
        if k in ("j", curses.KEY_DOWN):
            self.sel = min(n - 1, self.sel + 1)
        elif k in ("k", curses.KEY_UP):
            self.sel = max(0, self.sel - 1)
        elif k == curses.KEY_NPAGE:
            self.sel = min(n - 1, self.sel + page)
        elif k == curses.KEY_PPAGE:
            self.sel = max(0, self.sel - page)
        elif k in ("g", curses.KEY_HOME):
            self.sel = 0
        elif k in ("G", curses.KEY_END):
            self.sel = max(0, n - 1)
        elif k == curses.KEY_LEFT:
            self.hs = max(0, self.hs - 8)
        elif k == curses.KEY_RIGHT:
            self.hs += 8
        elif k == "0":
            self.hs = 0
        elif k == "/":
            s = self.app.prompt("/", self.filt)
            if s is not None:
                self.filt = s
                self.refresh()
        elif k == "s":
            nxt = 0 if self.sortcol is None else self.sortcol + 1
            self.sortcol = nxt if nxt < len(self.headers) else None
            self.refresh()
        elif k == "r":
            self.rev = not self.rev
            self.refresh()
        elif k in (10, 13, curses.KEY_ENTER):
            if n and self.enter:
                self.enter(self, self.current())
        elif k == 27:
            if self.filt:
                self.filt = ""
                self.refresh()
            else:
                self.app.pop()
        elif k in self.keys and n:
            self.keys[k][0](self, self.current())
        elif k in self.keys and k in ("]", "[", "R"):
            self.keys[k][0](self, None)
        else:
            return False
        return True


class Pager:
    def __init__(self, app, title, lines, line=None, pat=None, path=None):
        self.app, self.title, self.lines, self.path = app, title, lines, path
        self.vis = range(len(lines))
        self.cur = self.top = self.hs = 0
        self.filt, self.level = "", 0
        self.search, self.search_s = None, ""
        self._lv = None
        if pat is not None:
            self.search = pat
            self.search_s = pat.pattern
        if line:
            self.goto(line - 1)
            self.top = max(0, self.cur - 8)

    def as_lines(self):
        return [rd(self.lines[i]) for i in self.vis]

    def levels(self):
        if self._lv is None:
            self._lv = bytearray(line_level(l) for l in self.lines)
        return self._lv

    def recompute(self):
        keep = self.vis[self.cur] if len(self.vis) else 0
        if not self.filt and self.level == 0:
            self.vis = range(len(self.lines))
        else:
            pat = smart_re(self.filt) if self.filt else None
            lv = self.levels() if self.level else None
            self.vis = [i for i, l in enumerate(self.lines)
                        if (not pat or pat.search(l)) and (not lv or lv[i] >= self.level)]
        self.goto(keep)

    def goto(self, idx):
        p = bisect.bisect_left(self.vis, idx)
        self.cur = max(0, min(p, len(self.vis) - 1))

    def find(self, step, test, inclusive=False):
        n = len(self.vis)
        if not n:
            return False
        p = self.cur if inclusive else self.cur + step
        for _ in range(n):
            p %= n
            if test(self.vis[p]):
                self.cur = p
                return True
            p += step
        return False

    def status(self):
        s = "%d/%d" % (self.cur + 1 if len(self.vis) else 0, len(self.vis))
        if len(self.vis) != len(self.lines):
            s += " (of %d)" % len(self.lines)
        if self.filt:
            s += "  filter: %s" % self.filt
        if self.level:
            s += "  level>=%s" % ("WARN", "ERROR")[self.level - 1]
        if self.search_s:
            s += "  search: %s" % self.search_s
        return s + ("  | " + self.path if self.path else "")

    def hints(self):
        return "/ search  n/N next  f filter  e/E error  v level  T timeline  s save  : command  ? help  Esc back"

    def draw(self, y0, h, w):
        scr = self.app.scr
        n = len(self.vis)
        if self.cur < self.top:
            self.top = self.cur
        if self.cur >= self.top + h:
            self.top = self.cur - h + 1
        gw = len(str(max(1, len(self.lines)))) + 1
        bw = max(1, w - gw - 2)
        for r in range(h):
            p = self.top + r
            if p >= n:
                break
            li = self.vis[p]
            body = rd(clean(self.lines[li]))
            seg = body[self.hs:self.hs + bw]
            lv = line_level(body)
            attr = cp(C_RED) if lv == 2 else (cp(C_YEL) if lv == 1 else 0)
            if p == self.cur:
                attr |= curses.A_REVERSE
            put(scr, y0 + r, 0, ("%*d " % (gw, li + 1)), cp(C_DIM))
            put(scr, y0 + r, gw + 1, seg, attr)
            if self.search:
                for m in self.search.finditer(body):
                    s, e = m.span()
                    s, e = s - self.hs, e - self.hs
                    if e > s and e > 0 and s < len(seg):
                        s0 = max(s, 0)
                        put(scr, y0 + r, gw + 1 + s0, seg[s0:e], cp(C_HIT))

    def key(self, k):
        n, page = len(self.vis), self.app.page
        if k in ("j", curses.KEY_DOWN):
            self.cur = min(n - 1, self.cur + 1)
        elif k in ("k", curses.KEY_UP):
            self.cur = max(0, self.cur - 1)
        elif k in (curses.KEY_NPAGE, " "):
            self.cur = min(n - 1, self.cur + page)
        elif k in (curses.KEY_PPAGE, "b"):
            self.cur = max(0, self.cur - page)
        elif k in ("g", curses.KEY_HOME):
            self.cur = 0
        elif k in ("G", curses.KEY_END, "t"):
            self.cur = max(0, n - 1)
        elif k == curses.KEY_LEFT:
            self.hs = max(0, self.hs - 8)
        elif k == curses.KEY_RIGHT:
            self.hs += 8
        elif k == "0":
            self.hs = 0
        elif k == "/":
            s = self.app.prompt("/", self.search_s)
            if s is not None:
                self.search_s = s
                self.search = smart_re(s) if s else None
                if self.search and not self.find(1, lambda i: self.search.search(self.lines[i]), True):
                    self.app.msg = "pattern not found"
        elif k in ("n", "N") and self.search:
            if not self.find(1 if k == "n" else -1, lambda i: self.search.search(self.lines[i])):
                self.app.msg = "pattern not found"
        elif k == "f":
            s = self.app.prompt("filter/", self.filt)
            if s is not None:
                self.filt = s
                self.recompute()
        elif k in ("e", "E"):
            lv = self.levels()
            if not self.find(1 if k == "e" else -1, lambda i: lv[i] == 2):
                self.app.msg = "no error lines"
        elif k == "v":
            self.level = (self.level + 1) % 3
            self.recompute()
        elif k == "T":
            ts, li = None, self.vis[self.cur] if len(self.vis) else None
            if li is not None:
                for j in range(li, max(-1, li - 300), -1):
                    ts = parse_ts(self.lines[j])
                    if ts:
                        break
            if ts:
                self.app.go(self.app.timeline_around(ts, 120, 2))
            else:
                self.app.msg = "no timestamp found near this line"
        elif k == "s":
            fn = "rlv-out-%s.txt" % time.strftime("%Y%m%d-%H%M%S")
            with open(fn, "w") as fh:
                fh.write("\n".join(self.as_lines()) + "\n")
            self.app.msg = "saved %d lines to %s" % (len(self.vis), os.path.abspath(fn))
        elif k == 27:
            if self.filt or self.level:
                self.filt, self.level = "", 0
                self.recompute()
            elif self.search:
                self.search, self.search_s = None, ""
            else:
                self.app.pop()
        else:
            return False
        return True


# --------------------------------------------------------------------------- #
# application / command interpreter
# --------------------------------------------------------------------------- #
HELP = """\
rlv - Rancher Logs Viewer  (offline k9s-style browser for logs-collector bundles)

NAVIGATION   j/k or arrows move   g/G top/bottom   PgUp/PgDn   left/right scroll sideways (0 resets)
TABLE VIEWS  /  filter (regex, smart-case)   s  cycle sort column   r  reverse   Enter  open row
             pods:  Enter/l logs   p previous logs   d describe   e events for the pod
             nodes: Enter/d describe   e events        ] [  switch between multiple source files
LOG VIEWER   /  search   n/N next/prev match   f  filter lines (grep)   e/E next/prev error line
             v  level filter (all > warn+ > error)   s  save visible lines to file   t  tail
GENERAL      :  command prompt   ?  help   Esc  clear filter / go back   q  back (quit at top)

COMMANDS (press :)  - kubectl-like and shell-like, everything can be piped
  pods | po | nodes | events | deploy | svc ...      open any parsed kubectl table from the bundle
  get <res> [name] [-n ns | -A]                      same, with namespace / name filter
  describe <node|pod|res> <name>                     show the matching describe block
  logs <pod> [-n ns] [-p] [--tail N]                 pod log (-p previous container)
  logs | sys                                         list pod logs / system logs with ERR/WARN counts
  grep [-s] [-F] <regex> [path-substring|glob]       search ALL files in the bundle (smart-case)
  cat <path-substring>   ls|find [regex]             open a file / browse all files
  issues                                             auto-detected problems (pods, nodes, events, log patterns)
  summary                                            bundle overview
  ns [name|all]                                      set namespace filter (no arg: list namespaces)
  !<shell command>                                   run a real shell command in the bundle directory
  <cmd> | grep [-v] pat | head N | tail N | wc | sort [-rn] | uniq [-c] | <any shell tool>
     e.g.  get pods -A | grep -v Running        logs coredns | grep -i timeout | tail 20
           grep -i "x509|expired" | wc          !grep -ril oom . | head
  timeline [time] [-w 5m] [-l error|warn|all] [pattern]
                                                     chronological incident view across ALL logs + k8s events
        timeline                       key events/errors: pattern hits, warning events, container terminations
        timeline "2026-11-17 10:32" -w 10m     what errored within +-10 minutes of that moment
        timeline oom                   every line matching 'oom', oldest first
        (inside a log: press T for +-2 min around the selected line; stamps without a timezone = UTC)
  secrets [all] [reveal]                             credential scan scored HIGH/MEDIUM/LOW by value shape; 'all' adds LOW,\n                                                     'reveal' shows values (local screen only)
  diff                                               what changed vs the baseline bundle (start with --baseline OLD)
  net | listeners                                    listening ports parsed from ss/netstat in networking/
  containers | sandboxes | stats | images            crictl tables (ps -a / pods / stats / images); Enter opens pod log
  sysinfo                                            browse systeminfo/, networking/ and versions
  q | quit                                           exit
"""


class App:
    def __init__(self, bundle, scr=None):
        self.b, self.scr = bundle, scr
        self.stack, self.ns, self.msg, self.history = [], None, "", []
        self.page = 20
        self.scanner = Scanner(bundle)
        self.base = None

    # ---- stack
    def push(self, v):
        if v is not None:
            self.stack.append(v)

    def pop(self):
        if len(self.stack) > 1:
            self.stack.pop()

    def replace_top(self, v):
        if v is not None:
            self.stack[-1] = v

    # ---- UI primitives
    def flash(self, msg):
        self.msg = msg
        if self.scr:
            self.draw()

    def prompt(self, prefix, initial="", hist=None):
        scr = self.scr
        buf, pos = list(initial), len(initial)
        hi = len(hist) if hist is not None else 0
        curses.curs_set(1)
        scr.timeout(-1)
        try:
            while True:
                h, w = scr.getmaxyx()
                line = prefix + "".join(buf)
                scr.move(h - 1, 0)
                scr.clrtoeol()
                put(scr, h - 1, 0, line[-(w - 2):], curses.A_BOLD)
                try:
                    scr.move(h - 1, min(w - 2, len(prefix) + pos))
                except curses.error:
                    pass
                try:
                    ch = scr.get_wch()
                except curses.error:
                    continue
                if isinstance(ch, str):
                    if ch in ("\n", "\r"):
                        return "".join(buf)
                    if ch == "\x1b":
                        return None
                    if ch in ("\x7f", "\b"):
                        if pos:
                            del buf[pos - 1]
                            pos -= 1
                    elif ch == "\x15":
                        buf, pos = [], 0
                    elif ch.isprintable():
                        buf.insert(pos, ch)
                        pos += 1
                else:
                    if ch == curses.KEY_BACKSPACE:
                        if pos:
                            del buf[pos - 1]
                            pos -= 1
                    elif ch == curses.KEY_DC and pos < len(buf):
                        del buf[pos]
                    elif ch == curses.KEY_LEFT:
                        pos = max(0, pos - 1)
                    elif ch == curses.KEY_RIGHT:
                        pos = min(len(buf), pos + 1)
                    elif ch == curses.KEY_HOME:
                        pos = 0
                    elif ch == curses.KEY_END:
                        pos = len(buf)
                    elif ch in (curses.KEY_UP, curses.KEY_DOWN) and hist:
                        hi = max(0, hi - 1) if ch == curses.KEY_UP else min(len(hist), hi + 1)
                        buf = list(hist[hi]) if hi < len(hist) else []
                        pos = len(buf)
        finally:
            curses.curs_set(0)
            scr.timeout(400)

    def draw(self):
        scr = self.scr
        scr.erase()
        h, w = scr.getmaxyx()
        if h < 8 or w < 40:
            put(scr, 0, 0, "terminal too small")
            scr.refresh()
            return
        v = self.stack[-1]
        left = " rlv %s | %s | ns: %s | files: %d" % (VERSION, os.path.basename(self.b.root.rstrip("/")),
                                                       self.ns or "all", len(self.b.files))
        right = self.scanner.progress() + " "
        put(scr, 0, 0, (left + " " * w)[: w - 1 - len(right)] + right, cp(C_HDR) | curses.A_BOLD)
        crumbs = " > ".join(x.title for x in self.stack[-4:])
        put(scr, 1, 0, " <%s>" % crumbs, cp(C_DIM) | curses.A_BOLD)
        self.page = h - 4
        v.draw(2, h - 4, w)
        put(scr, h - 2, 0, self.msg or v.status(), cp(C_YEL) if self.msg else cp(C_DIM))
        put(scr, h - 1, 0, v.hints(), curses.A_DIM)
        scr.refresh()

    def loop(self):
        self.scr.timeout(400)
        while True:
            self.draw()
            ch = self.scr.getch()
            if ch in (-1, curses.KEY_RESIZE):
                continue
            self.msg = ""
            k = chr(ch) if 32 <= ch < 127 else ch
            try:
                if not self.stack[-1].key(k):
                    self.global_key(k)
            except Quit:
                return
            except Exception as e:  # never crash the UI
                self.msg = "error: %s" % e

    def global_key(self, k):
        if k == ":":
            s = self.prompt(":", hist=self.history)
            if s and s.strip():
                self.history.append(s)
                self.exec_line(s)
        elif k == "?":
            self.push(Pager(self, "help", HELP.splitlines()))
        elif k == "q":
            if len(self.stack) > 1:
                self.pop()
            else:
                raise Quit()

    # ---- commands
    def exec_line(self, line):
        try:
            self.push(self.run_command(line))
        except Quit:
            raise
        except Exception as e:
            self.msg = "error: %s" % e

    def run_command(self, line):
        line = line.strip()
        if not line:
            return None
        if line.startswith("!"):
            return self.cmd_shell(line[1:])
        try:
            lx = shlex.shlex(line, posix=True, punctuation_chars="|")
            lx.whitespace_split = True
            toks = list(lx)
        except ValueError as e:
            self.msg = "parse error: %s" % e
            return None
        stages = [[]]
        for t in toks:
            if t == "|":
                stages.append([])
            else:
                stages[-1].append(t)
        if not stages[0]:
            self.msg = "empty command"
            return None
        view = self.dispatch(stages[0][0], stages[0][1:], len(stages) > 1)
        if view is None or len(stages) == 1:
            return view
        lines = view.as_lines()
        for st in stages[1:]:
            if st:
                lines = self.pipe_stage(lines, st)
        return Pager(self, line, lines)

    def dispatch(self, c, args, piped):
        c = c.lower()
        if c in ("q", "quit", "exit"):
            raise Quit()
        if c in ("?", "help", "h"):
            return Pager(self, "help", HELP.splitlines())
        if c in ("summary", "sum", "home", "overview"):
            return Pager(self, "summary", self.summary_lines())
        if c in ("issues", "issue", "analyze", "analyse", "problems"):
            return self.issues_view()
        if c in ("logs", "log"):
            return self.cmd_logs(args, piped) if args else self.logs_view()
        if c in ("sys", "syslog", "systemlogs"):
            return self.files_view(kinds=("syslog",), title="system logs")
        if c in ("secrets", "creds", "credentials"):
            return self.secrets_view(args)
        if c in ("diff", "changes", "compare"):
            return self.diff_view()
        if c in ("net", "listeners", "ports"):
            return self.resource_view("listeners")
        if c in ("timeline", "tl"):
            return self.cmd_timeline(args)
        if c in ("sysinfo", "host", "system"):
            return self.files_view(filt=r"systeminfo/|networking/|(^|/)versions$", title="system info")
        if c in ("files", "ls", "find", "tree"):
            return self.files_view(filt=" ".join(args))
        if c in ("cat", "open", "view", "less"):
            return self.cmd_cat(args)
        if c == "grep":
            return self.cmd_grep(args)
        if c in ("describe", "desc"):
            return self.cmd_describe(args)
        if c in ("ns", "namespace") and args:
            self.ns = None if args[0] in ("all", "-", "*") else args[0]
            self.msg = "namespace filter: %s" % (self.ns or "all")
            for v in self.stack:
                if isinstance(v, TableView):
                    v.refresh()
            return None
        if c == "get":
            return self.cmd_get(args)
        return self.cmd_get([c] + args)

    def parse_k(self, args):
        pos, ns = [], None
        i = 0
        while i < len(args):
            a = args[i]
            if a in ("-n", "--namespace") and i + 1 < len(args):
                ns = args[i + 1]
                i += 1
            elif a.startswith("--namespace="):
                ns = a.split("=", 1)[1]
            elif a in ("-A", "--all-namespaces"):
                ns = ""
            elif a in ("-o", "--output") and i + 1 < len(args):
                i += 1
            elif a.startswith("-"):
                pass
            else:
                pos.append(a)
            i += 1
        return pos, ns

    def timeline_scan(self, lo, hi, minlevel, pat):
        lo = -1e18 if lo is None else lo
        hi = 1e18 if hi is None else hi
        self.flash("scanning logs for timeline ...")
        ents, rank = [], {"ERROR": 2, "WARN": 1, "INFO": 0}
        for f in self.b.files:
            if f.kind in ("kubectl", "crictl") or len(ents) >= 50000:
                continue
            if not f.path.endswith(".gz") and is_binary(f.path):
                continue
            try:
                with open_text(f.path) as fh:
                    for ln, line in enumerate(fh, 1):
                        if pat is not None and not pat.search(line):
                            continue
                        lv = line_level(line)
                        if pat is None and lv < minlevel:
                            m = COMBINED.search(line)      # curated rules count even without "error" wording
                            if not m:
                                continue
                            lv = {"ERROR": 2, "WARN": 1, "INFO": 0}[RULES[int(m.lastgroup[1:])][0]]
                            if lv < minlevel:
                                continue
                        ts = parse_ts(line)
                        if ts is None or ts < lo or ts > hi:
                            continue
                        ents.append((ts, ("INFO", "WARN", "ERROR")[lv], "", f.rel, ln, line.rstrip()[:400]))
            except (OSError, EOFError, gzip.BadGzipFile):
                continue
        for e in json_entries(self.b):
            if lo <= e[0] <= hi and (rank[e[1]] >= minlevel if pat is None else pat.search(e[5])):
                ents.append(e)
        return ents

    def timeline_view(self, title, ents, cap=6000):
        ents = sorted(ents, key=lambda e: (e[0], e[3], e[4]))[:cap]
        rows = [[fmt_ts(e[0]), e[1], (e[2] + ": " if e[2] else "") + "/".join(e[3].split("/")[-2:]), e[5]] for e in ents]

        def enter(v, e):
            if e[4]:
                self.go(self.open_file(e[3], e[4]))
            else:
                self.go(Pager(self, "event", [e[5]]))
        return TableView(self, title, ["TIME", "SEV", "SOURCE", "TEXT"], rows, payloads=ents, enter=enter,
                         colorfn=color_sev, hint="%d entries, oldest first; Enter opens the source line" % len(rows))

    def timeline_around(self, ts, window=120, lvl=2):
        return self.timeline_view("timeline %s +-%ds" % (fmt_ts(ts), window), self.timeline_scan(ts - window, ts + window, lvl, None))

    def cmd_timeline(self, args):
        around = lo = hi = None
        window, lvl, pos, i = 120, 2, [], 0
        while i < len(args):
            a = args[i]
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if a in ("-w", "--window"):
                window, i = parse_dur(nxt), i + 1
            elif a in ("-l", "--level"):
                lvl, i = {"all": 0, "warn": 1, "error": 2}.get(nxt.lower(), 2), i + 1
            elif a == "--from":
                lo, i = parse_user_time(nxt), i + 1
            elif a == "--to":
                hi, i = parse_user_time(nxt), i + 1
            elif a.startswith("-"):
                pass
            elif around is None and parse_user_time(a) is not None:
                around = parse_user_time(a)
            else:
                pos.append(a)
            i += 1
        pat = smart_re(" ".join(pos)) if pos else None
        if around is not None:
            lo, hi = around - window, around + window
        if lo is None and hi is None and pat is None:
            sc, ents = self.scanner, list(json_entries(self.b))
            with sc.lock:
                snap = {k: list(v) for k, v in sc.hits.items()}
            for idx, hs in snap.items():
                sev, cat = RULES[idx][0], RULES[idx][1]
                ents += [(h[3], sev, cat, h[0], h[1], h[2]) for h in hs if len(h) > 3 and h[3]]
            if not sc.done:
                self.msg = "scan still running (%s): timeline is partial, reopen when done" % sc.progress()
            if not ents:
                self.msg = self.msg or "no timestamped findings yet"
                return None
            return self.timeline_view("timeline (key events)", ents)
        return self.timeline_view("timeline", self.timeline_scan(lo, hi, lvl, pat))

    def secrets_view(self, args=()):
        include_low, reveal = "all" in args, "reveal" in args
        self.flash("scanning all files for credential-like strings ...")
        hits = scan_secrets(self.b)
        cnt = Counter(h[4] for h in hits)
        shown = [h for h in hits if include_low or h[4] != "LOW"]
        if not shown:
            self.msg = "no HIGH/MEDIUM credential-like strings (LOW hidden: %d; use 'secrets all') - heuristic" % cnt["LOW"]
            return None
        rows = [[h[0], str(h[1]), h[4], h[2], h[5], (h[3] if not reveal else h[3].replace("<redacted>", h[6]))] for h in shown]
        self.msg = "HIGH %d  MEDIUM %d  LOW %d%s  - masked unless 'secrets reveal'" % (
            cnt["HIGH"], cnt["MEDIUM"], cnt["LOW"], "" if include_low else " (LOW hidden: 'secrets all')")
        return TableView(self, "secrets", ["FILE", "LINE", "CONF", "TYPE", "SHAPE", "CONTEXT"], rows, payloads=shown,
                         enter=lambda v, h: self.go(self.open_file(h[0], h[1])),
                         colorfn=lambda hd, r: {"HIGH": cp(C_RED), "MEDIUM": cp(C_YEL), "LOW": cp(C_DIM)}.get(r[2], 0),
                         hint="Enter opens the raw line locally")

    def diff_view(self):
        if not self.base:
            self.msg = "no baseline loaded: start with  rlv.py <current> --baseline <older>"
            return None
        if not (self.scanner.done and self.base.sc.done):
            self.msg = "scans still running (current %s, baseline %s): log-error deltas are partial" % (
                self.scanner.progress(), self.base.sc.progress())
        rows = [list(r) for r in compute_diff(self.b, self.scanner, self.base.b, self.base.sc)]

        def color(h, r):
            if r[1] == "finding":
                return {"+": cp(C_RED), "-": cp(C_GRN), "~": cp(C_YEL)}[r[0]]
            return cp(C_YEL) if r[0] == "~" else cp(C_DIM)
        return TableView(self, "diff", ["CHG", "CATEGORY", "ITEM", "DETAIL"], rows, colorfn=color,
                         hint="+ new/added   - gone/removed   ~ changed   (vs baseline %s)" % os.path.basename(self.base.b.root))

    def cmd_get(self, args):
        pos, ns = self.parse_k(args)
        if not pos:
            self.msg = "usage: get <resource> [name] [-n ns|-A]"
            return None
        return self.resource_view(pos[0], ns=ns, filt=re.escape(pos[1]) if len(pos) > 1 else "")

    def cmd_describe(self, args):
        pos, ns = self.parse_k(args)
        if len(pos) < 2:
            self.msg = "usage: describe <node|pod|resource> <name>"
            return None
        return self.describe_view(pos[0], pos[1])

    def cmd_logs(self, args, piped):
        prev, tail, pos, ns, i = False, None, [], None, 0
        while i < len(args):
            a = args[i]
            if a in ("-p", "--previous"):
                prev = True
            elif a == "--tail" and i + 1 < len(args):
                tail = int(args[i + 1])
                i += 1
            elif a.startswith("--tail="):
                tail = int(a.split("=", 1)[1])
            elif a in ("-n", "--namespace") and i + 1 < len(args):
                ns = args[i + 1]
                i += 1
            elif a.startswith("-"):
                pass
            else:
                pos.append(a)
            i += 1
        if not pos:
            return self.logs_view()
        pod = pos[0]
        if "/" in pod:
            ns, pod = pod.split("/", 1)
        files = self.b.pod_logs(ns, pod, prev)
        if not files:
            self.msg = "no %slog file matches %s" % ("previous " if prev else "", pod)
            return None
        if len(files) > 1 and not piped:
            return self.files_view(files=files, title="logs %s" % pod)
        lines = []
        for f in files:
            lines += read_lines(f.path)
        if tail:
            lines = lines[-tail:]
        return Pager(self, "logs %s" % pod, lines, path=files[0].rel if len(files) == 1 else None)

    def cmd_cat(self, args):
        if not args:
            self.msg = "usage: cat <path-substring>"
            return None
        sub = args[0]
        m = [f for f in self.b.files if f.rel == sub] or \
            [f for f in self.b.files if sub in f.rel or fnmatch.fnmatch(f.rel, sub)]
        if not m:
            self.msg = "no file matches %s" % sub
            return None
        if len(m) > 1:
            return self.files_view(files=m, title="cat %s" % sub)
        return self.open_file(m[0].rel)

    def cmd_grep(self, args):
        cs, lit, pos = None, False, []
        for a in args:
            if a == "-s":
                cs = True
            elif a == "-F":
                lit = True
            elif a == "-i":
                cs = False
            else:
                pos.append(a)
        if not pos:
            self.msg = "usage: grep [-s] [-F] <regex> [path-substring|glob]"
            return None
        pat = smart_re(pos[0], cs, lit)
        scope = pos[1] if len(pos) > 1 else None
        self.flash("searching bundle for %s ..." % pat.pattern)
        hits = []
        for f in self.b.files:
            if scope and not (scope in f.rel or fnmatch.fnmatch(f.rel, scope)):
                continue
            if not f.path.endswith(".gz") and is_binary(f.path):
                continue
            try:
                with open_text(f.path) as fh:
                    for ln, line in enumerate(fh, 1):
                        if pat.search(line):
                            hits.append((f.rel, ln, line.rstrip()[:500]))
                            if len(hits) >= MAX_GREP_HITS:
                                break
            except (OSError, EOFError, gzip.BadGzipFile):
                continue
            if len(hits) >= MAX_GREP_HITS:
                break
        self.msg = "%d hits%s" % (len(hits), " (capped)" if len(hits) >= MAX_GREP_HITS else "")
        return self.hits_view("grep %s" % pos[0], hits, pat)

    def cmd_shell(self, cmd):
        try:
            r = subprocess.run(cmd, shell=True, cwd=self.b.root, capture_output=True, text=True,
                               errors="replace", timeout=180)
            out = (r.stdout + r.stderr).splitlines() or ["(no output, exit %d)" % r.returncode]
        except subprocess.TimeoutExpired:
            out = ["command timed out"]
        return Pager(self, "!" + cmd, out)

    def pipe_stage(self, lines, st):
        c, a = st[0], st[1:]
        nums = [int(x.lstrip("-")) for x in a if re.fullmatch(r"-?\d+", x)]
        if c == "grep":
            inv = cnt = False
            pat = None
            for x in a:
                if x == "-v":
                    inv = True
                elif x == "-c":
                    cnt = True
                elif x.startswith("-") and pat is None:
                    pass
                elif pat is None:
                    pat = smart_re(x, True if "-s" in a else None, "-F" in a)
            if pat is None:
                return lines
            out = [l for l in lines if bool(pat.search(l)) != inv]
            return [str(len(out))] if cnt else out
        if c == "head":
            return lines[: nums[0] if nums else 10]
        if c == "tail":
            return lines[-(nums[0] if nums else 10):]
        if c == "wc":
            return [str(len(lines))]
        if c == "sort" and all(re.fullmatch(r"-[rn]+", x) for x in a):
            flags = "".join(a)
            if "n" in flags:
                def nk(l):
                    m = re.match(r"\s*(-?\d+(?:\.\d+)?)", l)
                    return float(m.group(1)) if m else float("-inf")
                return sorted(lines, key=nk, reverse="r" in flags)
            return sorted(lines, reverse="r" in flags)
        if c == "uniq" and all(x in ("-c",) for x in a):
            out, prev, n = [], None, 0
            for l in lines + [None]:
                if l == prev:
                    n += 1
                    continue
                if prev is not None:
                    out.append(("%7d %s" % (n, prev)) if a else prev)
                prev, n = l, 1
            return out
        try:
            r = subprocess.run(st, input="\n".join(lines) + "\n", capture_output=True, text=True,
                               errors="replace", timeout=60)
        except FileNotFoundError:
            raise RuntimeError("unknown command in pipe: %s" % c)
        return (r.stdout + r.stderr).splitlines()

    # ---- view factories (return a view, never push)
    def go(self, v):
        self.push(v)

    def open_file(self, rel, line=None, pat=None):
        f = next((x for x in self.b.files if x.rel == rel), None)
        if not f:
            self.msg = "file not found: %s" % rel
            return None
        return Pager(self, os.path.basename(rel), read_lines(f.path), line=line, pat=pat, path=rel)

    def hits_view(self, title, hits, pat=None):
        rows = [[h[0], str(h[1]), h[2]] for h in hits]
        return TableView(self, title, ["FILE", "LINE", "TEXT"], rows, payloads=hits,
                         enter=lambda v, p: self.go(self.open_file(p[0], p[1], pat)),
                         hint="Enter opens file at line")

    def files_view(self, filt="", kinds=None, files=None, title="files"):
        fl = files if files is not None else [f for f in self.b.files if not kinds or f.kind in kinds]
        rows = [[f.kind, human(f.size), f.rel] for f in fl]
        return TableView(self, title, ["KIND", "SIZE", "PATH"], rows, payloads=[f.rel for f in fl],
                         enter=lambda v, rel: self.go(self.open_file(rel)), filt=filt)

    def logs_view(self):
        fl = [f for f in self.b.files if f.kind in ("podlog", "syslog")]
        st = self.scanner.file_stats
        rows = [[f.kind, str(st[f.rel][0]) if f.rel in st else "-", str(st[f.rel][1]) if f.rel in st else "-",
                 human(f.size), f.rel] for f in fl]
        return TableView(self, "logs", ["KIND", "ERR", "WARN", "SIZE", "PATH"], rows,
                         payloads=[f.rel for f in fl], enter=lambda v, rel: self.go(self.open_file(rel)),
                         sortcol=1, rev=True, hint="ERR/WARN counts fill in as the background scan finishes")

    def issues_view(self):
        fs = build_findings(self.b, self.scanner)
        rows = [[f.sev, f.cat, f.title, str(f.count), f.where] for f in fs]

        def enter(v, f):
            if f.hits:
                self.go(self.hits_view(f.title, f.hits, f.pat))
            elif f.ref and f.ref[0] == "pod":
                self.go(self.pod_logs_view(f.ref[1], f.ref[2], False))
            elif f.ref and f.ref[0] == "node":
                self.go(self.describe_view("nodes", f.ref[1]))
            elif f.ref and f.ref[0] == "events":
                self.go(self.resource_view("events", ns="", filt=re.escape(f.ref[1])))

        def refresh(v, _):
            self.replace_top(self.issues_view())
        return TableView(self, "issues", ["SEV", "CATEGORY", "ISSUE", "COUNT", "WHERE"], rows, payloads=fs,
                         enter=enter, colorfn=color_sev, keys={"R": (refresh, "rescan view")},
                         hint="Enter drills down")

    def pod_logs_view(self, ns, pod, prev):
        files = self.b.pod_logs(ns, pod, prev)
        if not files:
            self.msg = "no %slog file for %s/%s in bundle" % ("previous " if prev else "", ns, pod)
            return None
        if len(files) > 1:
            return self.files_view(files=files, title="logs %s" % pod)
        f = files[0]
        return Pager(self, "logs %s/%s" % (ns, pod) if ns else "logs " + pod, read_lines(f.path), path=f.rel)

    def describe_view(self, res, name):
        blocks = self.b.describe_blocks(res)
        if not blocks:
            self.msg = "no describe output for '%s' in this bundle" % res
            return None
        k = name if name in blocks else next((x for x in blocks if name in x), None)
        if not k:
            self.msg = "%s '%s' not found in describe output" % (res, name)
            return None
        return Pager(self, "describe %s" % k, blocks[k].splitlines())

    def row_detail(self, view, row):
        raw = view.current_raw()
        lines = json.dumps(raw, indent=2, default=str).splitlines() if raw else \
            ["%-22s %s" % (h, c) for h, c in zip(view.headers, row)]
        self.go(Pager(self, "detail", lines))

    def resource_view(self, name, ns=None, filt="", src=0):
        key = self.b.find_key(name)
        if not key:
            known = ", ".join(sorted(self.b.resources)[:12])
            self.msg = "unknown command/resource '%s'. known resources: %s  (? for help)" % (name, known)
            return None
        tabs = self.b.resources[key]
        src %= len(tabs)
        t = tabs[src]
        kind = canon(key)
        keys, enter, color = {}, self.row_detail, None

        def logs(prev):
            def f(v, r):
                self.go(self.pod_logs_view(v.cell(r, "NAMESPACE"), v.cell(r, "NAME"), prev))
            return f

        def events(v, r):
            self.go(self.resource_view("events", ns="", filt=re.escape(v.cell(r, "NAME"))))

        def desc(v, r):
            nm, ns_ = v.cell(r, "NAME"), v.cell(r, "NAMESPACE")
            v_ = (self.describe_view(kind, ns_ + "/" + nm) if ns_ else None) or self.describe_view(kind, nm)
            if v_:
                self.msg = ""
                self.go(v_)
            else:
                self.row_detail(v, r)
        if kind == "pods":
            enter, color = logs(False), color_pod
            keys = {"l": (logs(False), "logs"), "p": (logs(True), "previous logs"),
                    "d": (desc, "describe"), "e": (events, "events")}
        elif kind == "nodes":
            enter, color = desc, color_node
            keys = {"d": (desc, "describe"), "e": (events, "events")}
        elif kind == "events":
            color = color_event
        elif kind in ("crictl-psa", "crictl-pods"):
            def clog(v, r):
                self.go(self.pod_logs_view(v.cell(r, "NAMESPACE"), v.cell(r, "POD") or v.cell(r, "NAME"), False))
            enter, color = clog, color_state
        elif kind == "namespaces":
            def pick(v, r):
                self.ns = v.cell(r, "NAME")
                self.pop()
                self.msg = "namespace filter: %s" % self.ns
                for x in self.stack:
                    if isinstance(x, TableView):
                        x.refresh()
            enter = pick
        elif key in self.b.describes or kind in [canon(k) for k in self.b.describes]:
            keys = {"d": (desc, "describe")}
        if len(tabs) > 1:
            keys["]"] = (lambda v, r: self.replace_top(self.resource_view(name, ns, filt, src + 1)), "next source")
            keys["["] = (lambda v, r: self.replace_top(self.resource_view(name, ns, filt, src - 1)), "prev source")
        return TableView(self, key, t.headers, t.rows, enter=enter, colorfn=color, keys=keys, filt=filt, ns=ns,
                         hint="source: %s" % t.src, raw=t.raw)

    def summary_lines(self):
        b, L = self.b, []
        kinds = Counter(f.kind for f in b.files)
        size = sum(f.size for f in b.files)
        L += ["Bundle      : %s" % b.root,
              "Files       : %d (%s)   %s" % (len(b.files), human(size),
                                               ", ".join("%s=%d" % kv for kv in sorted(kinds.items()))), ""]
        L.append("Parsed kubectl tables:")
        for k, tabs in sorted(b.resources.items()):
            L.append("  %-30s %5d rows   %s" % (k, len(tabs[0].rows), tabs[0].src))
        if b.describes:
            L.append("  describe files: %s" % ", ".join(sorted(b.describes)))
        t = (b.resources.get("pods") or [None])[0]
        if t and t.idx("STATUS") >= 0:
            c = Counter(r[t.idx("STATUS")] for r in t.rows)
            L += ["", "Pods by status: " + ", ".join("%s=%d" % kv for kv in c.most_common())]
        t = (b.resources.get("nodes") or [None])[0]
        if t:
            L += ["", "Nodes:"]
            for r in t.rows:
                L.append("  " + "  ".join(r[:5]))
        vf = next((f for f in b.files if os.path.basename(f.rel) == "versions" and f.rel.count("/") <= 2), None)
        if vf:
            L += ["", "versions (%s):" % vf.rel] + ["  " + l for l in read_lines(vf.path, 12)]
        L += ["", "Background %s" % self.scanner.progress()] + ["Note: " + n for n in b.notes]
        L += ["", "Top findings:"]
        for f in build_findings(b, self.scanner)[:15]:
            L.append("  [%-5s] %-14s %s (%d)" % (f.sev, f.cat, f.title[:90], f.count))
        L += ["", "Press : and type 'issues' to drill down, '?' for help."]
        return L


# --------------------------------------------------------------------------- #
# entry points
# --------------------------------------------------------------------------- #
def tui(scr, app):
    os.environ.setdefault("ESCDELAY", "25")
    curses.curs_set(0)
    init_colors()
    app.scr = scr
    app.scanner.start()
    if app.base:
        app.base.sc.start()
    start = app.resource_view("pods") if "pods" in app.b.resources else None
    app.stack = [start or Pager(app, "summary", app.summary_lines())]
    app.loop()


def main():
    ap = argparse.ArgumentParser(description="k9s-style offline browser for Rancher logs-collector bundles")
    ap.add_argument("path", help="extracted bundle dir, .tar.gz, or a dir containing several tarballs")
    ap.add_argument("-c", "--command", action="append", help="run a command non-interactively (repeatable)")
    ap.add_argument("--summary", action="store_true", help="print summary and exit")
    ap.add_argument("--issues", action="store_true", help="print detected issues and exit")
    ap.add_argument("--baseline", metavar="OLD", help="older bundle to compare against (enables the diff command)")
    ap.add_argument("--diff", action="store_true", help="with --baseline: print the diff and exit")
    ap.add_argument("--secrets", action="store_true", help="scan the bundle for credentials and exit (values masked)")
    ap.add_argument("--reveal", action="store_true", help="with --secrets: print the matched values (local terminal only!)")
    ap.add_argument("--include-low", action="store_true", help="with --secrets: also list LOW-confidence matches")
    ap.add_argument("--sanitize", metavar="OUTDIR", help="write a redacted copy of the bundle to OUTDIR and exit")
    ap.add_argument("--verify-offline", action="store_true",
                    help="run a representative analysis with an audit hook and report any network/subprocess activity")
    ap.add_argument("--redact", action="store_true",
                    help="mask tokens/passwords/JWTs/private keys in everything displayed, saved or printed")
    a = ap.parse_args()
    os.environ.setdefault("ESCDELAY", "25")
    REDACT[0] = a.redact
    events = []
    if a.verify_offline:   # hook is installed BEFORE the bundle is opened/extracted so nothing is missed
        watch = ("socket.", "subprocess.", "urllib.", "http.", "ssl.", "ftplib.", "smtplib.",
                 "os.system", "os.exec", "os.posix_spawn", "os.fork")
        sys.addaudithook(lambda ev, args: events.append(ev) if ev.startswith(watch) else None)
    app = App(Bundle(a.path))
    if a.baseline:
        app.base = Snapshot(Bundle(a.baseline))
    if a.sanitize:
        n, nf, ns = sanitize_bundle(app.b, a.sanitize)
        print("sanitized copy written to %s: %d lines masked in %d files; %d binary/unreadable files copied as-is "
              "(see SANITIZE-REPORT.txt)" % (a.sanitize, n, nf, ns))
        return
    if a.secrets:
        hits = scan_secrets(app.b)
        if not hits:
            print("no credential-like strings found (heuristic scan - not a guarantee)")
            return
        cnt = Counter(h[4] for h in hits)
        print("SECRET SCAN: %d keyword/pattern matches in %d files" % (len(hits), len({h[0] for h in hits})))
        print("  HIGH   %5d  random-looking secret material (tokens, keys, JWTs, hex/base64 strings)" % cnt["HIGH"])
        print("  MEDIUM %5d  password/token-like values - VERIFY these" % cnt["MEDIUM"])
        print("  LOW    %5d  names, paths, URLs, placeholders - usually NOT secrets (e.g. secret=ns/name)" % cnt["LOW"])
        low = Counter((h[7] or h[2], h[5]) for h in hits if h[4] == "LOW")
        if low:
            print("\nWhat the LOW matches are (keyword -> value shape : count):")
            for (kw, shp), n in low.most_common(8):
                print("  %-28s -> %-26s %d" % (kw, shp, n))
        per = defaultdict(Counter)
        for h in hits:
            if h[4] != "LOW":
                per[h[0]][h[4]] += 1
        if per:
            print("\nHIGH/MEDIUM by file:")
            for rel, c in sorted(per.items(), key=lambda kv: -(kv[1]["HIGH"] * 1000 + kv[1]["MEDIUM"]))[:30]:
                print("  HIGH %-4d MEDIUM %-4d %s" % (c["HIGH"], c["MEDIUM"], rel))
            print("\nSamples (%s):" % ("VALUES SHOWN - keep this output private" if a.reveal else "values masked"))
            shown = [h for h in hits if h[4] != "LOW" or a.include_low]
            for h in shown[:30]:
                ctx = h[3] if not a.reveal else h[3].replace("<redacted>", h[6])
                print("  [%-6s] %s:%d  %s=%s\n           %s" % (h[4], h[0], h[1], h[7] or h[2], h[5], ctx[:150]))
            print("\nTo cross-check a line:  open the bundle in the TUI, run  :secrets  and press Enter on the row.")
            print("To share safely:        rlv.py <bundle> --sanitize <outdir>")
            sys.exit(2)
        print("\nNo HIGH/MEDIUM matches: everything flagged looks like names/paths/placeholders.")
        return
    if a.verify_offline:
        import io
        import contextlib
        a.summary = a.issues = False
        a.command = ["summary", "issues", "timeline", "grep -i error", "net", "sysinfo", "get pods | grep -v Running"]
        a.diff = bool(app.base)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _headless(app, a)
        n = len(out.getvalue().splitlines())
        print("Analysed the bundle (summary, issues, timeline, grep, net, sysinfo, pipes%s): %d output lines."
              % (", diff" if app.base else "", n))
        print("Network / subprocess events recorded: %s" % (", ".join(sorted(set(events))) if events else "NONE"))
        print("RESULT: %s" % ("FAIL - activity above" if events else "PASS - no network or subprocess activity"))
        sys.exit(1 if events else 0)
    if a.summary or a.issues or a.command or a.diff:
        try:
            _headless(app, a)
        except BrokenPipeError:
            pass
        return
    try:
        curses.wrapper(tui, app)
    except KeyboardInterrupt:
        pass


def _headless(app, a):
    if True:
        app.scanner.run()
        if app.base:
            app.base.sc.run()
        cmds = (["diff"] if a.diff else []) + (["summary"] if a.summary else []) + (["issues"] if a.issues else []) + (a.command or [])
        for c in cmds:
            v = app.run_command(c)
            print("\n".join(v.as_lines()) if v else (app.msg or ""))


if __name__ == "__main__":
    main()