from flask import Flask, request
import datetime, os

app = Flask(__name__)

@app.route("/xss-catch")
def catch():
    with open("xss_log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} - {request.url}\n")
    return "ok"

@app.route("/")
def home():
    return "Listener is running!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
