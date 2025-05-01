from flask import Flask, request, jsonify, render_template
import re
from datetime import datetime
import pandas as pd
import plotly.express as px
from dash import Dash, dcc, html, dash_table
from dash.dependencies import Input, Output
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple
import os

# -------------------- Flask App (WAF) --------------------
flask_app = Flask(__name__)
attack_log = []  # In-memory log

# --- Patterns ---
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
def detect(payload, patterns):
    for pattern in patterns:
        if re.search(pattern, payload):
            return True
    return False

def log_attack(ip, attack_type, payload):
    attack_log.append({
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Attack Type": attack_type,
        "IP Address": ip,
        "Payload": payload
    })

# --- WAF Middleware ---
@flask_app.before_request
def waf():
    path = request.path
    if path.startswith("/dashboard") or path.startswith("/_dash") or path.startswith("/assets"):
        return

    ip = request.remote_addr or "unknown"
    payload = str(request.args.to_dict()) + str(request.form.to_dict())

    if detect(payload, SQLI):
        log_attack(ip, "SQL Injection", payload)
        return jsonify({"error": "Blocked: SQL Injection"}), 403
    if detect(payload, XSS):
        log_attack(ip, "XSS", payload)
        return jsonify({"error": "Blocked: XSS"}), 403
    if CSRF_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            log_attack(ip, "CSRF", payload)
            return jsonify({"error": "Blocked: CSRF token missing or invalid"}), 403

# --- Routes ---
@flask_app.route('/')
def home():
    return "Welcome to the unified WAF app with dashboard + tester."

@flask_app.route('/waf/search')
def search():
    return jsonify({"message": "Search executed successfully (if not blocked)."})

@flask_app.route('/waf/login', methods=['POST'])
def login():
    return jsonify({"message": "Login successful (if not blocked)."})

@flask_app.route('/tester', methods=["GET", "POST"])
def tester():
    return '''
        <h2>🚨 WAF Attack Simulator</h2>
        <form method="get" action="/waf/search">
            SQLi / XSS Input: <input name="q"><input type="submit" value="Search">
        </form><br>
        <form method="post" action="/waf/login">
            Username: <input name="username">
            Password: <input name="password">
            <br>CSRF Token (use: securetoken123): <input name="csrf" value="securetoken123">
            <input type="submit" value="Login">
        </form>
    '''

# -------------------- Dash App --------------------
dash_app = Dash(__name__, server=flask_app, routes_pathname_prefix='/dashboard/')

dash_app.layout = html.Div([
    html.H2("📊 WAF Dashboard (Live Auto-Refresh)"),
    dcc.Interval(id='interval-update', interval=5*1000, n_intervals=0),
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
    df = pd.DataFrame(attack_log)
    if df.empty:
        df = pd.DataFrame(columns=["Timestamp", "Attack Type", "IP Address", "Payload"])
    fig = px.histogram(df, x="Attack Type", color="Attack Type", title="Attack Frequency")
    columns = [{"name": i, "id": i} for i in df.columns]
    return fig, columns, df.to_dict("records")

# -------------------- Mount Flask + Dash --------------------
application = DispatcherMiddleware(flask_app, {
    "/dashboard": dash_app.server
})

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    run_simple("0.0.0.0", port, application, use_debugger=True, use_reloader=True)
