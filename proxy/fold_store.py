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
import tempfile
import time

log = logging.getLogger("rolling-context")

# Bump when _hash_message changes: old hashes would never match, and a loaded
# fold with stale hashes is dead weight rather than a bug.
HASH_SCHEME = 1
_VERSION = 1


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
            and all(isinstance(m, dict) and "role" in m and "content" in m
                    for m in prefix))


class FoldStore:
    def __init__(self, directory: str, max_entries: int = 128):
        self.directory = directory
        self.max_entries = max_entries

    def _files_newest_first(self) -> list:
        try:
            names = [n for n in os.listdir(self.directory) if n.endswith(".json")]
        except OSError:
            return []
        paths = [os.path.join(self.directory, n) for n in names]

        def mtime(p):
            try:
                return os.stat(p).st_mtime
            except OSError:
                return 0.0
        return sorted(paths, key=mtime, reverse=True)

    def save(self, owner: str, original_hashes: list, prefix: list) -> str:
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        # makedirs mode is masked by umask and ignored for an existing dir.
        os.chmod(self.directory, 0o700)
        path = os.path.join(
            self.directory,
            hashlib.sha256(owner.encode("utf-8")).hexdigest()[:32] + ".json")
        body = {"version": _VERSION, "hash_scheme": HASH_SCHEME, "owner": owner,
                "original_hashes": list(original_hashes),
                "prefix": _strip_cache_control(prefix), "saved_at": time.time()}
        # Same-dir temp + replace: a crash mid-write never leaves a torn fold.
        fd, tmp = tempfile.mkstemp(dir=self.directory, suffix=".tmp")
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
        for old in self._files_newest_first()[self.max_entries:]:
            try:
                os.unlink(old)
            except OSError:
                pass
        return path

    def load(self) -> list:
        out = []
        for path in self._files_newest_first()[:self.max_entries]:
            try:
                with open(path, encoding="utf-8") as f:
                    rec = json.load(f)
            except (OSError, ValueError) as e:
                log.warning(f"[STATE] Skipping unreadable fold {os.path.basename(path)}: {e}")
                continue
            if not _valid(rec):
                log.warning(f"[STATE] Skipping invalid fold {os.path.basename(path)}")
                continue
            out.append({"owner": rec["owner"],
                        "original_hashes": rec["original_hashes"],
                        "prefix": rec["prefix"]})
        return out
