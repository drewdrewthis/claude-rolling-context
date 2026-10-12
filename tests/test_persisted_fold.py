#!/usr/bin/env python3
"""Issue #65 — a fold must survive a proxy restart.

Before: the content-addressed fold store lived only in memory, so every proxy
restart threw away every summary and the next request went upstream raw (full
price, possibly over the context window).

Now: each completed fold is saved to ROLLING_CONTEXT_STATE_DIR (default
$HOME/.claude/rolling-context) and loaded again on startup.

  A. FoldStore unit tests (proxy/fold_store.py)
  B. restart integration against tests/mock_endpoint.py, plus a control run
     whose second proxy has an empty state dir (must NOT be shrunk — proves the
     test tells fixed from unfixed).

    python tests/test_persisted_fold.py
"""
import copy
import hashlib
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PROXY = os.path.join(HERE, "..", "proxy")
MOCK = os.path.join(HERE, "mock_endpoint.py")
sys.path.insert(0, PROXY)

_fails = 0


def check(label, cond, extra=""):
    global _fails
    if cond:
        print(f"  ok  {label}")
    else:
        _fails += 1
        print(f"  FAIL {label} {extra}")


# ---------------------------------------------------------------- part A ----

def _fname(owner):
    return "fold-" + hashlib.sha256(owner.encode("utf-8")).hexdigest()[:32] + ".json"


FOLD_RE = re.compile(r"^fold-[0-9a-f]{32}\.json$")


def unit_tests():
    print("A. FoldStore")
    try:
        import fold_store
        from fold_store import FoldStore
    except ImportError as e:
        check("proxy/fold_store.py exports FoldStore", False, f"({e})")
        return

    scheme = getattr(fold_store, "HASH_SCHEME", None)
    check("HASH_SCHEME is an int constant", isinstance(scheme, int), repr(scheme))

    def raw_record(d, name, **over):
        rec = {"version": 1, "hash_scheme": scheme, "owner": "o",
               "original_hashes": ["h"], "prefix": [{"role": "user", "content": "c"}],
               "saved_at": 1}
        rec.update(over)
        for k in [k for k, v in over.items() if v is _DROP]:
            rec.pop(k)
        os.makedirs(d, exist_ok=True)
        if not name.startswith("fold-"):
            name = _fname(name)
        with open(os.path.join(d, name), "w") as f:
            json.dump(rec, f)

    root = tempfile.mkdtemp(prefix="fold-store-test-")
    hashes = ["h1", "h2", "h3"]
    prefix = [{"role": "user", "content": "summary of our earlier conversation: x"},
              {"role": "assistant", "content": "ok"}]

    print(" round trip")
    d = os.path.join(root, "rt", "state")
    store = FoldStore(d)
    path = store.save("sid:abc:123", hashes, prefix)
    check("save returns the path written", os.path.isfile(path), path)
    check("file name is fold-sha256(owner)[:32].json",
          os.path.basename(path) == _fname("sid:abc:123"), os.path.basename(path))
    body = json.load(open(path, encoding="utf-8"))
    check("body version is 1", body.get("version") == 1)
    check("body hash_scheme is HASH_SCHEME", body.get("hash_scheme") == scheme)
    check("body has owner", body.get("owner") == "sid:abc:123")
    check("body has original_hashes", body.get("original_hashes") == hashes)
    check("body has prefix", body.get("prefix") == prefix)
    check("body has saved_at", "saved_at" in body)
    loaded = FoldStore(d).load()
    check("load returns the saved fold from a fresh instance",
          loaded == [{"owner": "sid:abc:123", "original_hashes": hashes, "prefix": prefix}],
          repr(loaded)[:200])

    print(" permissions")
    check("directory is 0700", stat.S_IMODE(os.stat(d).st_mode) == 0o700,
          oct(stat.S_IMODE(os.stat(d).st_mode)))
    check("file is 0600", stat.S_IMODE(os.stat(path).st_mode) == 0o600,
          oct(stat.S_IMODE(os.stat(path).st_mode)))

    print(" hostile and colliding owners")
    d = os.path.join(root, "own")
    store = FoldStore(d)
    evil = store.save("sid:../../x:abc", ["a"], prefix)
    check("path-like owner is written inside the dir",
          os.path.dirname(os.path.realpath(evil)) == os.path.realpath(d), evil)
    pa = store.save("a:b", ["a"], prefix)
    pb = store.save("a-b", ["b"], prefix)
    check("owners 'a:b' and 'a-b' get distinct files", pa != pb)
    check("both folds load", sorted(g["owner"] for g in store.load())
          == sorted(["sid:../../x:abc", "a:b", "a-b"]))

    print(" overwrite")
    d = os.path.join(root, "ow")
    store = FoldStore(d)
    p1 = store.save("same", ["a"], prefix)
    p2 = store.save("same", ["a", "b"], prefix)
    check("same owner writes the same path", p1 == p2)
    check("only one file on disk", len(os.listdir(d)) == 1, str(os.listdir(d)))
    got = store.load()
    check("latest save wins", len(got) == 1 and got[0]["original_hashes"] == ["a", "b"])

    print(" cache_control stripped")
    d = os.path.join(root, "cc")
    store = FoldStore(d)
    cc_prefix = [{"role": "user", "content": [
        {"type": "text", "text": "s", "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": "t"}]}]
    snapshot = copy.deepcopy(cc_prefix)
    p = store.save("cc", ["a"], cc_prefix)
    check("cache_control absent from the file", "cache_control" not in open(p).read())
    check("text content survives the strip",
          json.load(open(p))["prefix"][0]["content"][0]["text"] == "s")
    check("caller's prefix is not modified", cc_prefix == snapshot)

    print(" bad records are skipped")
    d = os.path.join(root, "bad")
    FoldStore(d).save("good", ["g"], prefix)
    with open(os.path.join(d, _fname("garbage")), "w") as f:
        f.write("{ not json")
    raw_record(d, "oldver.json", version=2)
    raw_record(d, "missing.json", prefix=_DROP)
    raw_record(d, "otherscheme.json", hash_scheme=(scheme or 0) + 1)
    raw_record(d, "noscheme.json", hash_scheme=_DROP)
    raw_record(d, "emptyhashes.json", original_hashes=[])
    raw_record(d, "nonstrhashes.json", original_hashes=[1, 2])
    raw_record(d, "hashesnotlist.json", original_hashes="abc")
    raw_record(d, "prefixnotlist.json", prefix="text")
    raw_record(d, "prefixnotdicts.json", prefix=["x"])
    raw_record(d, "prefixnorole.json", prefix=[{"content": "c"}])
    raw_record(d, "prefixnocontent.json", prefix=[{"role": "user"}])
    raw_record(d, "sysrole.json", prefix=[{"role": "system", "content": "c"}])
    raw_record(d, "toolrole.json", prefix=[{"role": "tool", "content": "c"}])
    raw_record(d, "intcontent.json", prefix=[{"role": "user", "content": 5}])
    raw_record(d, "nonecontent.json", prefix=[{"role": "user", "content": None}])
    raw_record(d, "strlistcontent.json", prefix=[{"role": "user", "content": ["a"]}])
    raw_record(d, "listcontent.json", owner="listok",
               prefix=[{"role": "assistant", "content": [{"type": "text", "text": "t"}]}])
    try:
        got = FoldStore(d).load()
        err = ""
    except Exception as e:  # noqa: BLE001
        got, err = None, repr(e)
    check("load does not raise", got is not None, err)
    check("only the valid folds are returned",
          got is not None and sorted(g["owner"] for g in got) == ["good", "listok"],
          repr(got)[:300])

    print(" max_entries")
    d = os.path.join(root, "cap")
    FoldStore(d)  # no-op construct
    for i, name in enumerate(["old", "mid", "new"]):
        raw_record(d, _fname(name), owner=name, original_hashes=[name])
        os.utime(os.path.join(d, _fname(name)), (1_000_000 + i * 100,) * 2)
    got = FoldStore(d, max_entries=2).load()
    check("load keeps only max_entries newest by mtime",
          sorted(g["owner"] for g in got) == ["mid", "new"],
          str(sorted(g["owner"] for g in got)))

    print(" save prunes the directory")
    d = os.path.join(root, "prune")
    for i, name in enumerate(["old", "mid", "new"]):
        raw_record(d, _fname(name), owner=name, original_hashes=[name])
        os.utime(os.path.join(d, _fname(name)), (1_000_000 + i * 100,) * 2)
    FoldStore(d, max_entries=2).save("fresh", ["f"], prefix)
    left = sorted(n for n in os.listdir(d) if n.endswith(".json"))
    check("only max_entries files remain", len(left) == 2, str(left))
    check("the oldest files were deleted",
          _fname("old") not in left and _fname("mid") not in left, str(left))
    check("the new save is kept", _fname("fresh") in left, str(left))

    print(" only fold-named files are managed")
    d = os.path.join(root, "unrelated")
    os.makedirs(d)
    others = ["settings.json", "other.json"] + [f"u{i}.json" for i in range(200)]
    for n in others:
        with open(os.path.join(d, n), "w") as f:
            json.dump({"version": 1, "hash_scheme": scheme, "owner": "u",
                       "original_hashes": ["h"], "prefix": [{"role": "user", "content": "c"}]}, f)
    st = FoldStore(d, max_entries=2)
    for o in ("a", "b", "c"):
        st.save(o, ["h"], prefix)
    check("save deletes no unrelated file",
          all(os.path.exists(os.path.join(d, n)) for n in others),
          str(sum(not os.path.exists(os.path.join(d, n)) for n in others)) + " missing")
    check("load returns only fold-named records",
          sorted(g["owner"] for g in st.load()) != [] and
          all(g["owner"] in ("a", "b", "c") for g in st.load()), repr(st.load())[:200])
    check("prune still caps fold files at max_entries",
          len([n for n in os.listdir(d) if FOLD_RE.match(n)]) == 2)

    print(" existing directory mode is left alone")
    d = os.path.join(root, "preexisting")
    os.makedirs(d)
    os.chmod(d, 0o755)
    FoldStore(d).save("o", ["h"], prefix)
    check("0755 dir stays 0755", stat.S_IMODE(os.stat(d).st_mode) == 0o755,
          oct(stat.S_IMODE(os.stat(d).st_mode)))

    print(" load never raises")
    d = os.path.join(root, "hostile")
    FoldStore(d).save("good", ["g"], prefix)
    target = os.path.join(root, "elsewhere.json")
    raw_record(root, "elsewhere", owner="viasymlink")
    os.replace(os.path.join(root, _fname("elsewhere")), target)
    os.symlink(target, os.path.join(d, _fname("symlinked")))
    os.mkdir(os.path.join(d, _fname("adir")))
    with open(os.path.join(d, _fname("deep")), "w") as f:
        f.write("[" * 100000)
    max_bytes = getattr(fold_store, "MAX_FILE_BYTES", None)
    check("MAX_FILE_BYTES is an int constant", isinstance(max_bytes, int), repr(max_bytes))
    raw_record(d, "big", owner="big", prefix=[{"role": "user", "content": "x" * 5000}])
    fold_store.MAX_FILE_BYTES = 2000
    try:
        got = FoldStore(d).load()
        err = ""
    except BaseException as e:  # noqa: BLE001
        got, err = None, repr(e)
    finally:
        if max_bytes is not None:
            fold_store.MAX_FILE_BYTES = max_bytes
        else:
            del fold_store.MAX_FILE_BYTES
    check("load does not raise on hostile entries", got is not None, err)
    check("only the regular, small, parseable fold loads",
          got is not None and [g["owner"] for g in got] == ["good"], repr(got)[:300])

    print(" empty owner")
    for bad_owner in ("", None):
        d = os.path.join(root, "noowner-" + repr(bad_owner))
        try:
            r = FoldStore(d).save(bad_owner, ["h"], prefix)
        except Exception as e:  # noqa: BLE001
            r = repr(e)
        check(f"save({bad_owner!r}) returns None", r is None, repr(r))
        check(f"save({bad_owner!r}) writes nothing",
              not os.path.exists(d) or os.listdir(d) == [])

    print(" delete")
    d = os.path.join(root, "del")
    st = FoldStore(d)
    path = st.save("o", ["a", "b"], prefix)
    check("FoldStore.delete exists", hasattr(st, "delete"))
    r = st.delete("o", ["a"]) if hasattr(st, "delete") else None
    check("delete with different hashes returns False", r is False, repr(r))
    check("delete with different hashes keeps the file", os.path.exists(path))
    r = st.delete("o", ["a", "b"]) if hasattr(st, "delete") else None
    check("delete with matching hashes returns True", r is True, repr(r))
    check("delete with matching hashes removes the file", not os.path.exists(path))
    r = st.delete("o", ["a", "b"]) if hasattr(st, "delete") else None
    check("delete of a missing file returns False", r is False, repr(r))

    print(" delete refuses special files")
    import signal

    def _alarm(signum, frame):
        raise TimeoutError("blocked")

    old_handler = signal.signal(signal.SIGALRM, _alarm)
    try:
        fd_dir = os.path.join(root, "del-fifo")
        os.makedirs(fd_dir)
        fifo = os.path.join(fd_dir, _fname("o"))
        os.mkfifo(fifo)
        t0 = time.time()
        signal.alarm(3)
        try:
            r = FoldStore(fd_dir).delete("o", ["a"])
        except TimeoutError:
            r = "blocked"
        finally:
            signal.alarm(0)
        elapsed = time.time() - t0
        check("delete on a FIFO returns False", r is False, repr(r))
        check("delete on a FIFO returns within 2 s", elapsed < 2, f"{elapsed:.1f}s")

        real_dir = os.path.join(root, "del-real")
        target = FoldStore(real_dir).save("o", ["a", "b"], prefix)
        link_dir = os.path.join(root, "del-link")
        os.makedirs(link_dir)
        os.symlink(target, os.path.join(link_dir, _fname("o")))
        signal.alarm(3)
        try:
            r = FoldStore(link_dir).delete("o", ["a", "b"])
        except TimeoutError:
            r = "blocked"
        finally:
            signal.alarm(0)
        check("delete through a symlink returns False", r is False, repr(r))
        check("delete through a symlink leaves the target", os.path.exists(target))
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

    print(" load skips folds owned by another uid")
    uid_dir = os.path.join(root, "uid")
    FoldStore(uid_dir).save("o", ["a"], prefix)
    check("fold loads as the owning uid", len(FoldStore(uid_dir).load()) == 1)
    had = hasattr(fold_store, "_euid")
    saved_euid = getattr(fold_store, "_euid", None)
    fold_store._euid = lambda: os.geteuid() + 1
    try:
        got = FoldStore(uid_dir).load()
    finally:
        if had:
            fold_store._euid = saved_euid
        else:
            del fold_store._euid
    check("fold owned by another uid is skipped", got == [], repr(got))
    check("fold_store exposes _euid", had and saved_euid is not None)

    print(" stale tmp files")
    d = os.path.join(root, "tmp")
    os.makedirs(d)
    max_age = getattr(fold_store, "TMP_MAX_AGE", None)
    check("TMP_MAX_AGE is an int constant", isinstance(max_age, int), repr(max_age))
    age = max_age if isinstance(max_age, int) else 3600
    old_tmp, new_tmp, other_tmp = (os.path.join(d, n) for n in
                                   ("fold-old.tmp", "fold-new.tmp", "other.tmp"))
    for p_ in (old_tmp, new_tmp, other_tmp):
        open(p_, "w").close()
    past = time.time() - age - 100
    os.utime(old_tmp, (past, past))
    os.utime(other_tmp, (past, past))
    FoldStore(d).save("o", ["h"], prefix)
    check("save removes an old fold-*.tmp", not os.path.exists(old_tmp))
    check("save keeps a fresh fold-*.tmp", os.path.exists(new_tmp))
    check("save keeps an old non-fold .tmp", os.path.exists(other_tmp))

    print(" missing directory")
    try:
        got = FoldStore(os.path.join(root, "never-created")).load()
    except Exception as e:  # noqa: BLE001
        got = repr(e)
    check("load returns []", got == [], repr(got))

    print(" CompressionStore.find_match with a non-zero offset")
    home = os.path.join(root, "home")
    os.makedirs(os.path.join(home, ".claude"))
    os.environ["HOME"] = os.environ["USERPROFILE"] = home
    try:
        import server
        cs = server.CompressionStore()
        entry = cs.add()
        entry["original_hashes"] = ["b", "c", "d"]
        entry["prefix"] = prefix
        match, end = cs.find_match(["x", "y", "b", "c", "d", "z"])
        check("chain starting at offset 2 matches", match is entry, repr(match))
        check("match end is after the chain", end == 5, str(end))
    except Exception as e:  # noqa: BLE001
        check("CompressionStore importable and matching", False, repr(e))


_DROP = object()


# ---------------------------------------------------------------- part B ----

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.3).close()
            return True
        except OSError:
            time.sleep(0.15)
    return False


def conversation(pairs, tail):
    msgs = []
    for i in range(pairs):
        msgs.append({"role": "user", "content": f"question {i} " + "x" * 400})
        msgs.append({"role": "assistant", "content": f"answer {i} " + "y" * 400})
    msgs.append({"role": "user", "content": tail})
    return msgs


SID = "persisted-fold-session"


def post(port, msgs):
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/v1/messages",
        data=json.dumps({"model": "glm-4.6", "max_tokens": 64,
                         "stream": True, "messages": msgs}).encode(),
        headers={"content-type": "application/json", "x-api-key": "k",
                 "anthropic-version": "2023-06-01",
                 "X-Claude-Code-Session-Id": SID})
    with urllib.request.urlopen(req, timeout=60) as r:
        r.read()


def start_proxy(home, mock_port, state_dir=None):
    port, mitm = free_port(), free_port()
    env = {k: v for k, v in os.environ.items() if not k.startswith("ROLLING_CONTEXT_")}
    env.update(HOME=home, USERPROFILE=home,
               ROLLING_CONTEXT_PORT=str(port), ROLLING_CONTEXT_MITM_PORT=str(mitm),
               ROLLING_CONTEXT_UPSTREAM=f"http://127.0.0.1:{mock_port}",
               ROLLING_CONTEXT_TRIGGER="1000", ROLLING_CONTEXT_TARGET="400")
    if state_dir:
        env["ROLLING_CONTEXT_STATE_DIR"] = state_dir
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=PROXY, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert wait_port(port), "proxy did not start"
    return proc, port


def stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


def read_chats(log):
    out = []
    with open(log, encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            if rec["kind"] == "request" and not rec["detail"]["compaction"]:
                out.append(rec["detail"])
    return out


def state_files(d):
    try:
        return [n for n in os.listdir(d) if FOLD_RE.match(n)]
    except OSError:
        return []


def restart_case(control):
    label = ("control: second proxy has an EMPTY state dir" if control
             else "restart reuses the saved fold")
    print(f"B. {label}")
    root = tempfile.mkdtemp(prefix="persisted-fold-")
    home = os.path.join(root, "home")
    os.makedirs(os.path.join(home, ".claude"))
    log = os.path.join(root, "mock.jsonl")
    state = os.path.join(home, ".claude", "rolling-context")
    mock_port = free_port()
    mock = subprocess.Popen([sys.executable, MOCK, str(mock_port), log],
                            env=dict(os.environ, MOCK_TOKENS_FROM_SIZE="1"))
    procs = []
    try:
        assert wait_port(mock_port), "mock endpoint did not start"

        base = conversation(24, "turn one: do the thing")
        p1, port1 = start_proxy(home, mock_port)
        procs.append(p1)
        post(port1, base)
        end = time.time() + 30
        while time.time() < end and not state_files(state):
            time.sleep(0.3)
        check("fold saved to HOME/.claude/rolling-context", bool(state_files(state)),
              f"no fold-*.json in {state} after 30s")
        stop(p1)

        n_before = len(read_chats(log))
        log_path = os.path.join(home, ".claude", "rolling-context-debug.log")
        offset = os.path.getsize(log_path) if os.path.exists(log_path) else 0

        other = None
        if control:
            other = os.path.join(root, "empty-state")
            os.makedirs(other)
        p2, port2 = start_proxy(home, mock_port, state_dir=other)
        procs.append(p2)
        turn2 = base + [{"role": "assistant", "content": "did the thing"},
                        {"role": "user", "content": "turn two: keep going"}]
        post(port2, turn2)
        time.sleep(1)

        chats = read_chats(log)[n_before:]
        first = chats[0] if chats else None
        raw_chars = len(json.dumps(turn2))
        sent = first["convo_chars"] if first else None
        with open(log_path, encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            tail = f.read()
        print(f"    ({sent} chars sent upstream vs {raw_chars} raw)")

        if control:
            check("first request after restart is raw-sized",
                  sent is not None and sent >= raw_chars * 0.9,
                  f"sent={sent} raw={raw_chars}")
            check("no summary injected", bool(first) and not first["carries_summary"])
            check("no '[STATE] Loaded 1' logged", "[STATE] Loaded 1" not in tail)
        else:
            check("first request after restart is < 50% of raw",
                  sent is not None and sent < raw_chars * 0.5,
                  f"sent={sent} raw={raw_chars}")
            check("first request after restart carries the summary",
                  bool(first) and first["carries_summary"])
            check("second proxy logs '[STATE] Loaded 1'", "[STATE] Loaded 1" in tail)
            check("second proxy logs '[MSG] Injecting:'", "[MSG] Injecting:" in tail)
    finally:
        for p in procs:
            if p.poll() is None:
                stop(p)
        stop(mock)


def main():
    unit_tests()
    restart_case(control=False)
    restart_case(control=True)
    if _fails:
        print(f"\n{_fails} FAILED")
        sys.exit(1)
    print("\nall passed")


if __name__ == "__main__":
    main()
