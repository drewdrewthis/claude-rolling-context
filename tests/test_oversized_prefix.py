#!/usr/bin/env python3
"""Regression suite for issue #14 — an oversized prefix must fold, not loop.

compress() picks ONE cut that bounds only the recent tail, then summarized the
ENTIRE prefix in a single request. Once the prefix outgrew the summarizer's
input window every attempt 400'd ("prompt is too long: N tokens > 1000000
maximum"), the conversation cooled down 300s, and the next attempt re-sent the
same oversized prompt forever — context never shrank.

Now: when the prefix exceeds ROLLING_CONTEXT_SUMMARIZE_MAX_CHARS the compressor
folds it in bounded windows, each window integrating the running partial
summary, so no single request ever exceeds the budget. The common
(fits-one-window) native path is untouched.

Runnable directly, no framework:

    python tests/test_oversized_prefix.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "proxy"))
import compressor  # noqa: E402

_fails = 0


def check(label, cond, extra=""):
    global _fails
    if cond:
        print(f"  ok  {label}")
    else:
        _fails += 1
        print(f"  FAIL {label} {extra}")


# --- wire helpers (mirror tests/test_empty_summary.py) ----------------------

def sse(events):
    return "".join("event: {}\ndata: {}\n\n".format(e["type"], json.dumps(e))
                   for e in events).encode()


def start(model):
    return {"type": "message_start", "message": {
        "id": "msg", "type": "message", "role": "assistant", "model": model,
        "content": [], "stop_reason": None,
        "usage": {"input_tokens": 708, "output_tokens": 1,
                  "cache_creation_input_tokens": 105340, "cache_read_input_tokens": 0}}}


def text_stream(model, text):
    return sse([
        start(model),
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": text}},
        {"type": "content_block_stop", "index": 0},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn", "stop_sequence": None},
         "usage": {"output_tokens": 12}},
        {"type": "message_stop"},
    ])


def anthropic_json(text):
    return json.dumps({
        "id": "m", "type": "message", "role": "assistant", "model": "x",
        "content": [{"type": "text", "text": text}],
        "stop_reason": "end_turn", "usage": {"output_tokens": 12}}).encode()


class FakeResponse:
    def __init__(self, body, status=200):
        self.status = status
        self._body = body

    def read(self):
        return self._body


class FakeConn:
    """Answers native vs flattened requests by shape, and — like the real API —
    rejects any request whose measured size exceeds the budget with a 400. That
    400 is exactly what sank the unfixed compressor: one oversized prefix, one
    doomed request."""
    sent = []
    fold_calls = 0

    def __init__(self, *a, **k):
        pass

    def request(self, method, path, body=None, headers=None):
        FakeConn.sent.append(json.loads(body))

    def getresponse(self):
        body = FakeConn.sent[-1]
        size = compressor.RollingCompressor()._count_chars(body.get("messages", []))
        if size > compressor.SUMMARIZE_MAX_CHARS:
            return FakeResponse(
                json.dumps({"type": "error", "error": {"type": "invalid_request_error",
                            "message": f"prompt is too long: {size} tokens > "
                                       f"{compressor.SUMMARIZE_MAX_CHARS} maximum"}}).encode(),
                status=400)
        content = body["messages"][-1]["content"] if body.get("messages") else ""
        if isinstance(content, str) and compressor.COMPACTION_MARKER in content:
            return FakeResponse(text_stream(body.get("model", "m"), "NATIVE SUMMARY"))
        FakeConn.fold_calls += 1
        return FakeResponse(anthropic_json(f"PARTIAL-SUMMARY-{FakeConn.fold_calls}"))

    def close(self):
        pass


def reset():
    FakeConn.sent = []
    FakeConn.fold_calls = 0
    compressor._summarizer_conn = lambda timeout=600: FakeConn()
    compressor.SUMMARIZER_BASE_URL = "https://api.anthropic.com"


def conversation(pairs, chunk):
    msgs = []
    for i in range(pairs):
        msgs.append({"role": "user", "content": f"q{i} " + "x" * chunk})
        msgs.append({"role": "assistant", "content": f"a{i} " + "y" * chunk})
    msgs.append({"role": "user", "content": "do the thing"})
    return msgs


def sent_size(body):
    return compressor.RollingCompressor()._count_chars(body.get("messages", []))


def main():
    print("issue #14: oversized prefix folds instead of 400-cooldown-looping")

    messages = conversation(30, 3000)      # ~183k chars of prefix
    payload = {"model": "claude-opus-4", "max_tokens": 32000,
               "stream": True, "messages": messages}
    rtc = 500_000                          # keep_ratio ~8% -> tiny tail, huge prefix

    # -- oversized prefix: bounded fold ------------------------------------
    print(" prefix exceeds the budget -> bounded fold")
    reset()
    compressor.SUMMARIZE_MAX_CHARS = 20_000
    rc = compressor.RollingCompressor()
    compressed = None
    err = None
    try:
        compressed = rc.compress(messages, {}, real_token_count=rtc, payload=payload)
    except Exception as e:                  # noqa: BLE001 — unfixed compressor 400s here
        err = e
    check("compress() does not raise (no 400-cooldown loop)", err is None, repr(err))
    check("compress() returns a compressed list", bool(compressed), "returned None")

    flattened = [b for b in FakeConn.sent
                 if isinstance(b["messages"][-1]["content"], str)
                 and "CONVERSATION TO COMPRESS" in b["messages"][-1]["content"]]
    check("more than one summarize request was sent (fold happened)",
          len(flattened) > 1, f"only {len(flattened)} request(s)")
    over = [sent_size(b) for b in FakeConn.sent if sent_size(b) > compressor.SUMMARIZE_MAX_CHARS]
    check("every request is within the char budget", not over, f"oversized: {over}")

    if len(flattened) > 1:
        second = flattened[1]["messages"][-1]["content"]
        check("2nd fold request carries the prior partial summary",
              "PARTIAL-SUMMARY-1" in second and
              "EXISTING ROLLING SUMMARY FROM PREVIOUS COMPRESSIONS" in second,
              "fold-forward marker missing")

    if compressed:
        check("compressed[0] is the rolling summary message",
              compressor.SUMMARY_MARKER in compressed[0].get("content", ""))
        recent = compressed[2:]
        check("recent tail preserved (no kept history dropped)",
              recent == messages[len(messages) - len(recent):] and
              compressed[-1] is messages[-1],
              "tail mismatch")

    # -- control: small prefix keeps the single native path ----------------
    print(" prefix fits one window -> exactly one native request (no regression)")
    reset()
    compressor.SUMMARIZE_MAX_CHARS = 2_000_000
    rc = compressor.RollingCompressor()
    compressed = rc.compress(messages, {}, real_token_count=rtc, payload=payload)
    check("compress() returns a compressed list", bool(compressed))
    check("exactly one summarize request", len(FakeConn.sent) == 1,
          f"sent {len(FakeConn.sent)}")
    check("it is the native cloned request (prompt-cache path intact)",
          bool(FakeConn.sent) and
          compressor.COMPACTION_MARKER in json.dumps(FakeConn.sent[0]))

    if _fails:
        print(f"\n{_fails} FAILED")
        sys.exit(1)
    print("\nall passed")


if __name__ == "__main__":
    main()
