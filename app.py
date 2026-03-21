from flask import Flask, request, jsonify, render_template_string
from firewall import LLMFirewall

app = Flask(__name__)
fw = LLMFirewall()

HTML = """
<!DOCTYPE html>
<html>
<head>
<title>LLM Firewall</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0f1a; color: #c8e6f0; font-family: monospace; padding: 30px; }
  h1 { color: #00e5ff; letter-spacing: 3px; margin-bottom: 6px; }
  p { color: #4a7a99; font-size: 13px; margin-bottom: 30px; }
  .row { display: flex; gap: 20px; margin-bottom: 20px; }
  .box { flex: 1; }
  label { font-size: 12px; color: #4a7a99; letter-spacing: 2px; display: block; margin-bottom: 8px; }
  textarea { width: 100%; height: 120px; background: #0d1f2d; border: 1px solid #0d2d45; color: #c8e6f0; padding: 12px; font-family: monospace; font-size: 13px; border-radius: 6px; resize: none; }
  .btns { display: flex; gap: 12px; margin-bottom: 20px; }
  button { padding: 10px 24px; border: 1px solid #00e5ff; background: transparent; color: #00e5ff; font-family: monospace; font-size: 13px; letter-spacing: 2px; cursor: pointer; border-radius: 4px; }
  button:hover { background: rgba(0,229,255,0.1); }
  .result { background: #0d1f2d; border: 1px solid #0d2d45; border-radius: 6px; padding: 16px; min-height: 80px; font-size: 13px; }
  .blocked { border-color: #ff2d55; color: #ff2d55; }
  .allowed { border-color: #00ff88; color: #00ff88; }
  .logs { margin-top: 24px; }
  .log-item { padding: 10px 14px; border-bottom: 1px solid #0d2d45; font-size: 12px; }
  .log-item:last-child { border-bottom: none; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-right: 8px; }
  .tag-block { background: rgba(255,45,85,0.15); color: #ff2d55; border: 1px solid #ff2d55; }
  .tag-allow { background: rgba(0,255,136,0.1); color: #00ff88; border: 1px solid #00ff88; }
</style>
</head>
<body>
<h1>⚡ LLM FIREWALL</h1>
<p>PROMPT INJECTION + PII LEAK DETECTION</p>

<div class="row">
  <div class="box">
    <label>USER INPUT (scan before sending to LLM)</label>
    <textarea id="inputText" placeholder="Type a message to scan..."></textarea>
  </div>
  <div class="box">
    <label>LLM OUTPUT (scan before showing to user)</label>
    <textarea id="outputText" placeholder="Paste LLM response to scan..."></textarea>
  </div>
</div>

<div class="btns">
  <button onclick="scanInput()">SCAN INPUT</button>
  <button onclick="scanOutput()">SCAN OUTPUT</button>
  <button onclick="clearLogs()">CLEAR LOGS</button>
</div>

<label>RESULT</label>
<div class="result" id="result">Waiting for scan...</div>

<div class="logs">
  <label style="margin-top:20px">AUDIT LOG</label>
  <div class="result" id="logs" style="margin-top:8px;max-height:300px;overflow-y:auto"></div>
</div>

<script>
async function scanInput() {
  const text = document.getElementById('inputText').value;
  const res = await fetch('/scan/input', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: text})
  });
  const data = await res.json();
  showResult(data);
  addLog(data, 'INPUT');
}

async function scanOutput() {
  const text = document.getElementById('outputText').value;
  const res = await fetch('/scan/output', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message: text})
  });
  const data = await res.json();
  showResult(data);
  addLog(data, 'OUTPUT');
}

function showResult(data) {
  const el = document.getElementById('result');
  if (!data.allowed) {
    el.className = 'result blocked';
    el.innerHTML = `🚫 BLOCKED — ${data.threat}<br><small style="opacity:0.7">${data.detail}</small>${data.confidence ? `<br><small>Confidence: ${data.confidence}%</small>` : ''}`;
  } else {
    el.className = 'result allowed';
    el.innerHTML = '✓ CLEAN — No threats detected';
  }
}

function addLog(data, type) {
  const logs = document.getElementById('logs');
  const tag = data.allowed
    ? `<span class="tag tag-allow">ALLOWED</span>`
    : `<span class="tag tag-block">BLOCKED</span>`;
  const div = document.createElement('div');
  div.className = 'log-item';
  div.innerHTML = `${tag} [${type}] ${data.original?.substring(0,60) || ''}... ${data.threat ? '— ' + data.threat : ''}`;
  logs.prepend(div);
}

function clearLogs() {
  document.getElementById('logs').innerHTML = '';
  document.getElementById('result').className = 'result';
  document.getElementById('result').innerHTML = 'Waiting for scan...';
}
</script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/scan/input', methods=['POST'])
def scan_input():
    data = request.get_json()
    ip = request.remote_addr
    result = fw.scan_input(data.get('message', ''), ip=ip)
    return jsonify(result)

@app.route('/scan/output', methods=['POST'])
def scan_output():
    data = request.get_json()
    result = fw.scan_output(data.get('message', ''))
    return jsonify(result)

@app.route('/logs', methods=['GET'])
def get_logs():
    return fw.get_logs()

if __name__ == '__main__':
    app.run(debug=True, port=5000)


