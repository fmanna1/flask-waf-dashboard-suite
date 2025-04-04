from flask import Flask, request, jsonify, render_template
import logging
import re
import os
from datetime import datetime
import pandas as pd
import plotly.express as px
from dash import Dash, dcc, html, dash_table
from dash.dependencies import Input, Output

# --- Flask App Setup ---
flask_app = Flask(__name__)
log_path = "waf_logs.log"

# --- Logging Setup ---
logging.basicConfig(
    filename=log_path,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - Blocked %(message)s"
)

# --- OWASP Categories ---
OWASP = {
    "SQL Injection": "A03:2021-Injection",
    "XSS": "A03:2021-Injection",
    "CSRF": "A01:2021-Broken Access Control"
}

# --- Enhanced SQLi & XSS Patterns ---
SQLI = [
    r"(?i)(union\s+select)",
    r"(?i)'?\s*or\s+1\s*=\s*1",
    r"(?i)select\s+.*\s+from",
    r"(?i)insert\s+into",
    r"(?i)drop\s+table",
    r"(?i)--",
    r"(?i)\bOR\b.+\b=\b"
]

XSS = [r"(?i)<script.*?>", r"(?i)onerror\s*=", r"(?i)<.*?alert\(.*?\)>"]
CSRF_REQUIRED = True

# --- Helper Functions ---
def log_attack(ip, type_, payload):
    time_tag = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    logging.warning(f"{type_} attack from {ip} at {time_tag}. Payload: {payload}")

def detect(payload, patterns):
    for pattern in patterns:
        if re.search(pattern, payload):
            return True
    return False

def parse_logs():
    if not os.path.exists(log_path):
        return pd.DataFrame(columns=["Timestamp", "Level", "Attack Type", "IP Address", "Payload"])
    
    logs = []
    with open(log_path, 'r') as f:
        for line in f:
            match = re.search(r'^(.*?) - (\w+) - Blocked (.*?) attack from (.*?) at (.*?)\. Payload: (.*)$', line)
            if match:
                ts, level, atype, ip, time_tag, payload = match.groups()
                logs.append({
                    "Timestamp": time_tag,
                    "Level": level,
                    "Attack Type": atype,
                    "IP Address": ip,
                    "Payload": payload
                })
    return pd.DataFrame(logs)

# --- WAF Middleware ---
@flask_app.before_request
def waf():
    # ✅ Allow Dash internal requests
    if request.path.startswith("/dashboard/_dash") or request.path.startswith("/dashboard/assets"):
        return

    ip = request.remote_addr
    payload = str(request.args.to_dict()) + str(request.form.to_dict())

    if detect(payload, SQLI):
        log_attack(ip, "SQL Injection", payload)
        return jsonify({"error": "Blocked: SQL Injection", "owasp": OWASP["SQL Injection"]}), 403

    if detect(payload, XSS):
        log_attack(ip, "XSS", payload)
        return jsonify({"error": "Blocked: XSS", "owasp": OWASP["XSS"]}), 403

    if CSRF_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            log_attack(ip, "CSRF", payload)
            return jsonify({"error": "Blocked: CSRF token missing", "owasp": OWASP["CSRF"]}), 403

# --- Flask Routes ---
@flask_app.route('/')
def home():
    return render_template('index.html')

@flask_app.route('/waf/search')
def search():
    return jsonify({"message": "Search executed (if not blocked)."})

@flask_app.route('/waf/login', methods=['POST'])
def login():
    return jsonify({"message": "Login successful (if not blocked)."})

# --- Dash App (Dashboard) ---
dash_app = Dash(__name__, server=flask_app, routes_pathname_prefix='/dashboard/')

dash_app.layout = html.Div([
    html.H2("📊 WAF Dashboard (Live Auto-Refresh)"),
    dcc.Interval(id='interval-update', interval=5 * 1000, n_intervals=0),
    dcc.Graph(id="attack-graph"),
    dash_table.DataTable(
        id='log-table',
        columns=[],
        page_size=10,
        style_table={"overflowX": "auto"},
        style_cell={"textAlign": "left"},
    )
])

@dash_app.callback(
    [Output("attack-graph", "figure"),
     Output("log-table", "columns"),
     Output("log-table", "data")],
    [Input("interval-update", "n_intervals")]
)
def update_dashboard(n):
    df = parse_logs()
    if df.empty:
        df = pd.DataFrame(columns=["Timestamp", "Level", "Attack Type", "IP Address", "Payload"])
    fig = px.histogram(df, x="Attack Type", color="Attack Type", title="Attack Frequency")
    columns = [{"name": i, "id": i} for i in df.columns]
    return fig, columns, df.to_dict("records")

# --- Run App ---
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    flask_app.run(host="0.0.0.0", port=port, debug=True)
