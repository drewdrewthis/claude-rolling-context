"""On-disk persistence for completed folds (issue #65).

https://github.com/drewdrewthis/langwatch-claude-agents/issues/65

The in-memory CompressionStore dies with the proxy, so every restart threw
away every summary and the next request went upstream raw. One small JSON file
per owner survives that. Files hold conversation summaries: dir 0700, file 0600.
"""
import copy
import hashlib
import json
import logging
import os
import re
import stat
import tempfile
import time

log = logging.getLogger("rolling-context")

# Bump when _hash_message changes: old hashes would never match, and a loaded
# fold with stale hashes is dead weight rather than a bug.
HASH_SCHEME = 1
_VERSION = 1
# Read at call time so tests can monkeypatch.
MAX_FILE_BYTES = 8 * 1024 * 1024
TMP_MAX_AGE = 3600
# Called at read time so tests can monkeypatch; absent on Windows (no uid check).
_euid = getattr(os, "geteuid", lambda: None)
_FOLD_RE = re.compile(r"^fold-[0-9a-f]{32}\.json$")


def _strip_cache_control(prefix: list) -> list:
    """Deep copy without cache_control; the breakpoint belongs to one request."""
    out = copy.deepcopy(prefix)
    for msg in out:
        content = msg.get("content") if isinstance(msg, dict) else None
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    block.pop("cache_control", None)
    return out


def _valid_message(m) -> bool:
    if not (isinstance(m, dict) and m.get("role") in ("user", "assistant")):
        return False
    c = m.get("content")
    return isinstance(c, str) or (
        isinstance(c, list) and all(isinstance(b, dict) for b in c))


def _valid(rec) -> bool:
    if not isinstance(rec, dict):
        return False
    if rec.get("version") != _VERSION or rec.get("hash_scheme") != HASH_SCHEME:
        return False
    hashes = rec.get("original_hashes")
    if not (isinstance(hashes, list) and hashes
            and all(isinstance(h, str) for h in hashes)):
        return False
    prefix = rec.get("prefix")
    return (isinstance(prefix, list) and isinstance(rec.get("owner"), str)
            and all(_valid_message(m) for m in prefix))


def _fold_name(owner: str) -> str:
    return "fold-" + hashlib.sha256(owner.encode("utf-8")).hexdigest()[:32] + ".json"


class FoldStore:
    def __init__(self, directory: str, max_entries: int = 128):
        self.directory = directory
        self.max_entries = max_entries

    def _files_newest_first(self) -> list:
        try:
            names = [n for n in os.listdir(self.directory) if _FOLD_RE.match(n)]
        except OSError:
            return []
        paths = [os.path.join(self.directory, n) for n in names]

        def mtime(p):
            try:
                return os.stat(p).st_mtime
            except OSError:
                return 0.0
        return sorted(paths, key=mtime, reverse=True)

    def _ensure_dir(self) -> None:
        if os.path.isdir(self.directory):
            return
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        # makedirs mode is masked by umask; fix only a dir we just created.
        os.chmod(self.directory, 0o700)

    def _remove_stale_tmp(self) -> None:
        cutoff = time.time() - TMP_MAX_AGE
        try:
            names = os.listdir(self.directory)
        except OSError:
            return
        for n in names:
            if not (n.startswith("fold-") and n.endswith(".tmp")):
                continue
            p = os.path.join(self.directory, n)
            try:
                if os.lstat(p).st_mtime < cutoff:
                    os.unlink(p)
            except OSError:
                pass

    def save(self, owner: str, original_hashes: list, prefix: list):
        if not owner:
            return None
        self._ensure_dir()
        path = os.path.join(self.directory, _fold_name(owner))
        body = {"version": _VERSION, "hash_scheme": HASH_SCHEME, "owner": owner,
                "original_hashes": list(original_hashes),
                "prefix": _strip_cache_control(prefix), "saved_at": time.time()}
        # Same-dir temp + replace: a crash mid-write never leaves a torn fold.
        fd, tmp = tempfile.mkstemp(dir=self.directory, prefix="fold-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(body, f)
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        self._remove_stale_tmp()
        for old in self._files_newest_first()[self.max_entries:]:
            try:
                os.unlink(old)
            except OSError:
                pass
        return path

    def delete(self, owner, original_hashes: list) -> bool:
        """Remove the owner's fold only if it still holds exactly these hashes."""
        if not owner:
            return False
        path = os.path.join(self.directory, _fold_name(owner))
        try:
            rec = self._read(path)
            if not (isinstance(rec, dict)
                    and rec.get("original_hashes") == list(original_hashes)):
                return False
            os.unlink(path)
            return True
        except Exception:
            return False

    def _read(self, path: str):
        """Parsed JSON, or None if the file is not ours, regular and small.

        Checks run on the opened fd, so nothing can be swapped in between
        check and read. O_NONBLOCK keeps a FIFO from hanging the open.
        """
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
        fd = os.open(path, flags)
        try:
            st = os.fstat(fd)
            uid = _euid()
            if (not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES
                    or (uid is not None and st.st_uid != uid)):
                os.close(fd)
                return None
            f = os.fdopen(fd, encoding="utf-8")
        except BaseException:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        with f:
            return json.load(f)

    def load(self) -> list:
        out = []
        for path in self._files_newest_first()[:self.max_entries]:
            name = os.path.basename(path)
            try:
                rec = self._read(path)
                if rec is None:
                    continue
                if not _valid(rec):
                    log.warning(f"[STATE] Skipping invalid fold {name}")
                    continue
                out.append({"owner": rec["owner"],
                            "original_hashes": rec["original_hashes"],
                            "prefix": rec["prefix"]})
            except Exception as e:  # incl. RecursionError on hostile JSON
                log.warning(f"[STATE] Skipping unreadable fold {name}: {e!r}")
        return out
