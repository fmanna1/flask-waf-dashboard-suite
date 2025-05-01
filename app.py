
from flask import Flask, request, jsonify, render_template_string
import re
import logging
from datetime import datetime
import pandas as pd
from dash import Dash, dcc, html, dash_table
from dash.dependencies import Input, Output
from werkzeug.middleware.dispatcher import DispatcherMiddleware
from werkzeug.serving import run_simple

flask_app = Flask(__name__)
attack_logs = []  # In-memory log store

# --- Attack Patterns ---
SQLI_PATTERNS = [
    r"(?i)(\bor\b|\band\b).*(=|\bLIKE\b|\bIN\b|\bIS\b|\bNULL\b)",
    r"(?i)(union(\s+all)?(\s+select))",
    r"(?i)select.+from",
    r"(?i)insert\s+into",
    r"(?i)drop\s+table",
    r"(?i)'\s*or\s*'1'='1"
]

XSS_PATTERNS = [
    r"(?i)<script.*?>.*?</script.*?>",
    r"(?i)javascript:",
    r"(?i)onerror\s*=",
    r"(?i)<img\s+.*?on\w+=.*?>"
]

CSRF_TOKENS_REQUIRED = True

# --- WAF Middleware ---
@flask_app.before_request
def waf_filter():
    if request.path.startswith("/dashboard") or request.path == "/tester":
        return  # skip WAF for internal interfaces

    ip = request.remote_addr or "unknown"
    full_data = str(request.args.to_dict()) + str(request.form.to_dict())

    for pattern in SQLI_PATTERNS:
        if re.search(pattern, full_data):
            attack_logs.append(log_row("SQL Injection", ip, full_data))
            return jsonify({"error": "Blocked: SQL Injection"}), 403

    for pattern in XSS_PATTERNS:
        if re.search(pattern, full_data):
            attack_logs.append(log_row("XSS", ip, full_data))
            return jsonify({"error": "Blocked: XSS"}), 403

    if CSRF_TOKENS_REQUIRED and request.method == "POST":
        token = request.headers.get("X-CSRF-Token")
        if not token or token != "securetoken123":
            attack_logs.append(log_row("CSRF", ip, full_data))
            return jsonify({"error": "Blocked: Missing CSRF token"}), 403

def log_row(atype, ip, payload):
    return {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Attack Type": atype,
        "IP Address": ip,
        "Payload": payload
    }

# --- Routes ---
@flask_app.route('/')
def home():
    return "Welcome to the unified WAF app with dashboard + tester."

@flask_app.route('/waf/search')
def search():
    return jsonify({"message": "Search executed (if not blocked)."})

@flask_app.route('/waf/login', methods=["POST"])
def login():
    return jsonify({"message": "Login successful (if not blocked)."})

@flask_app.route('/tester', methods=["GET", "POST"])
def tester():
    result = ""
    if request.method == "GET" and "q" in request.args:
        import requests
        try:
            q = request.args.get("q", "")
            r = requests.get("http://127.0.0.1:5000/waf/search", params={"q": q})
            result = f"GET /waf/search → {r.status_code} | {r.text}"
        except Exception as e:
            result = str(e)
    elif request.method == "POST":
        import requests
        try:
            uname = request.form.get("username", "")
            pwd = request.form.get("password", "")
            headers = {"X-CSRF-Token": request.form.get("csrf_token", "")}
            data = {"username": uname, "password": pwd}
            r = requests.post("http://127.0.0.1:5000/waf/login", data=data, headers=headers)
            result = f"POST /waf/login → {r.status_code} | {r.text}"
        except Exception as e:
            result = str(e)

    return render_template_string("""
        <h2>🧪 WAF Attack Tester</h2>
        <form method="get">
            <b>SQLi/XSS via GET</b><br>
            <input type="text" name="q" placeholder="Payload here" size="60"/>
            <input type="submit" value="Test GET" />
        </form>
        <br><hr><br>
        <form method="post">
            <b>CSRF via POST</b><br>
            Username: <input type="text" name="username" />
            Password: <input type="password" name="password" />
            CSRF Token: <input type="text" name="csrf_token" value="securetoken123" />
            <input type="submit" value="Test POST" />
        </form>
        <br><br>
        <textarea rows="10" cols="100">{{result}}</textarea>
    """, result=result)

# --- Dash App for Dashboard ---
dash_app = Dash(__name__, server=flask_app, routes_pathname_prefix='/dashboard/')

dash_app.layout = html.Div([
    html.H2("📊 WAF Dashboard (Live)"),
    dcc.Interval(id='interval-update', interval=5*1000, n_intervals=0),
    dcc.Graph(id="attack-graph"),
    dash_table.DataTable(
        id="log-table",
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
    df = pd.DataFrame(attack_logs)
    if df.empty:
        df = pd.DataFrame(columns=["Timestamp", "Attack Type", "IP Address", "Payload"])
    fig = px.histogram(df, x="Attack Type", color="Attack Type", title="Attack Frequency")
    columns = [{"name": i, "id": i} for i in df.columns]
    return fig, columns, df.to_dict("records")

# --- Launch App ---
if __name__ == '__main__':
    app = DispatcherMiddleware(flask_app, {
        '/dashboard': dash_app.server
    })
    run_simple("0.0.0.0", 5000, app, use_reloader=True, use_debugger=True)
