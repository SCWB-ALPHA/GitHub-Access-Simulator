import csv
import os
from datetime import datetime
from flask import Flask, render_template_string, request, redirect, url_for, send_file, flash

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev")

# ---------- App meta ----------
APP_NAME = "GitHub Access Simulator"
VERSION = "1.2 (Simple Layout)"
CREATION_DATE = "2025-09-08"
DISCLAIMER = (
    "This simulator is a training tool that mirrors typical GitHub-like policies. "
    "It does not connect to real repositories or secrets, and no real data is modified."
)

# ---------- Policy model ----------
ACTION_CLASS = {
    "read": "read",
    "write": "write",
    "delete": "delete",
    "open_pr": "write",
    "merge_pr": "write",
    "approve_review": "write",
    "create_branch": "write",
    "push_commit": "write",
    "push_protected": "write",
    "read_secret": "read",
    "add_secret": "write",
    "delete_repo": "delete",
}

ALLOWED_ACTIONS = [
    "read", "write", "delete",
    "open_pr", "approve_review", "merge_pr",
    "create_branch", "push_commit", "push_protected",
    "read_secret", "add_secret",
    "delete_repo",
]

RESOURCE_TYPES = [
    "Report",
    "Compliance_File",
    "PII_Report",
    "Pull_Request",
    "Issue",
    "Workflow",
    "Environment",
    "Secret",
    "Artifact",
    "Package",
    "Repo_Settings",
    "Protected_Branch",
]

ACCESS_RULES = {
    "Administrator": {"read": ["all"], "write": ["all"], "delete": ["all"]},
    "Maintainer": {
        "read": ["all"],
        "write": ["Repo_Settings", "Workflow", "Environment", "Report", "Pull_Request", "Issue", "Protected_Branch"],
        "delete": ["Artifact", "Package"],
    },
    "Developer": {"read": ["all"], "write": ["Report", "Pull_Request", "Issue", "Artifact", "Package"], "delete": []},
    "Reviewer": {"read": ["Compliance_File", "Report", "Pull_Request", "Issue"], "write": [], "delete": []},
    "Security Analyst": {"read": ["Secret", "Report", "Workflow"], "write": ["Secret"], "delete": []},
    "Auditor": {"read": ["all"], "write": [], "delete": []},
    "Intern": {"read": ["Report", "Issue"], "write": ["Issue"], "delete": []},
    "Contractor": {"read": ["Report"], "write": [], "delete": []},
    "Bot/CI": {"read": ["all"], "write": ["Workflow", "Artifact", "Package"], "delete": []},
}

SENSITIVE_TYPES = {"PII_Report", "Secret"}
COMPLIANCE_TYPES = {"Compliance_File"}

TRAINING_SCENARIOS = {
    "General_Access": {"role": "Contractor", "resource": "Report", "action": "read"},
    "PII_Protocol_Violation": {"role": "Contractor", "resource": "PII_Report", "action": "read"},
    "Compliance_Deletion_Attempt": {"role": "Reviewer", "resource": "Compliance_File", "action": "delete"},
    "Administrator_Action": {"role": "Administrator", "resource": "Compliance_File", "action": "delete"},
    "Protected_Branch_Push": {"role": "Developer", "resource": "Protected_Branch", "action": "push_protected"},
    "Read_Secret": {"role": "Security Analyst", "resource": "Secret", "action": "read_secret"},
}

QUIZ_BANK = {
    "Onboarding": [
        {"id": "onb_q1", "type": "mcq1", "prompt": "Who can delete a Compliance_File?",
         "choices": ["Administrator", "Maintainer", "Reviewer", "Developer"],
         "answer": ["Administrator"],
         "explain": "Only Administrators may delete compliance files."},
        {"id": "onb_q2", "type": "tf", "prompt": "Interns can write to Pull Requests.",
         "answer": ["False"],
         "explain": "Interns may open Issues only."},
    ],
    "PII_Basics": [
        {"id": "pii_q1", "type": "mcq1", "prompt": "Who may read a PII_Report?",
         "choices": ["Administrator", "Reviewer", "Contractor", "Auditor"],
         "answer": ["Administrator"],
         "explain": "PII access is restricted to Administrators."},
        {"id": "pii_q2", "type": "tf", "prompt": "Security Analysts may read and add Secrets.",
         "answer": ["True"],
         "explain": "They can read/add secrets; others cannot."},
    ],
}

# ---------- Persistence ----------
AUDIT_LOG = []
AUDIT_CSV = "audit_log.csv"
QUIZ_CSV = "quiz_results.csv"
MAX_LOG = 600

def _load_audit():
    if not os.path.exists(AUDIT_CSV):
        return
    try:
        with open(AUDIT_CSV, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))[-MAX_LOG:]
            for ts, role, action, res, result, code in rows:
                AUDIT_LOG.append(f"[{ts}] Role='{role}', Action='{action}', Resource='{res}' -> {result} ({code})")
    except Exception:
        pass

def _append_audit(ts, role, action, res, result, code):
    try:
        with open(AUDIT_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, role, action, res, result, code])
    except Exception:
        pass

def _append_quiz(ts, track, score, total):
    try:
        with open(QUIZ_CSV, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([ts, track, score, total])
    except Exception:
        pass

_load_audit()

# ---------- Policy engine ----------
def evaluate_access(role: str, action: str, resource: str):
    if role not in ACCESS_RULES:
        return False, "UNKNOWN_ROLE", f"Unknown role '{role}'."
    if action not in ACTION_CLASS:
        return False, "UNKNOWN_ACTION", f"Unknown action '{action}'."

    if action == "delete_repo" and role != "Administrator":
        return False, "REPO_DELETE_PROTOCOL", "Only Administrators can delete repositories."

    if resource in SENSITIVE_TYPES:
        if resource == "PII_Report" and role != "Administrator":
            return False, "PII_PROTOCOL", "Only Administrators may access PII Reports."
        if resource == "Secret":
            if action == "read_secret" and role not in {"Administrator", "Security Analyst"}:
                return False, "SECRET_READ_DENY", "Only Administrators/Security Analysts may read secrets."
            if action == "add_secret" and role not in {"Administrator", "Security Analyst"}:
                return False, "SECRET_WRITE_DENY", "Only Administrators/Security Analysts may add secrets."

    if resource in COMPLIANCE_TYPES and action == "delete" and role != "Administrator":
        return False, "COMPLIANCE_DELETION", "Only Administrators may delete compliance files."

    if resource == "Protected_Branch" and action == "push_protected":
        if role not in {"Maintainer", "Administrator"}:
            return False, "BRANCH_PROTECTION", "Only Maintainers/Administrators may push to protected branches."
        return True, "APPROVED", "Protected branch push allowed."

    allowed_targets = ACCESS_RULES[role].get(ACTION_CLASS[action], [])
    if "all" in allowed_targets or resource in allowed_targets:
        return True, "APPROVED", "Approved by rule."
    return False, "DENIED", f"'{role}' is not allowed to '{action}' the '{resource}'."

# ---------- Styles (neutral + HC mode) ----------
STYLES = """
<style>
  :root{--bg:#f6f7fb;--card:#ffffff;--line:#e5e7eb;--text:#111827;--muted:#6b7280;--blue:#2563eb;--green:#16a34a;--red:#dc2626}
  body{margin:0;font-family:Inter,system-ui,Segoe UI,Roboto,Arial,sans-serif;background:var(--bg);color:var(--text)}
  .wrap{max-width:1080px;margin:20px auto;padding:0 16px}
  .header{padding:18px 20px;background:var(--card);border:1px solid var(--line);border-radius:14px}
  .title{font-size:22px;font-weight:900;margin:0}
  .sub{margin:6px 0 0 0;color:var(--muted)}
  .grid{display:grid;grid-template-columns:1.1fr .9fr;gap:16px;margin-top:16px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}
  .section-title{font-weight:800;margin:0 0 8px 0}
  .small{font-size:13px;color:var(--muted)}
  label{font-weight:600;font-size:14px}
  select,button{font-size:16px}
  select{width:100%;padding:10px;border:1px solid var(--line);border-radius:10px;background:#fff}
  .btn{display:inline-flex;gap:.5rem;align-items:center;padding:10px 14px;border-radius:10px;border:1px solid var(--line);background:#fff;font-weight:800}
  .btn-primary{background:var(--blue);border-color:#1d4ed8;color:#fff}
  .btn-danger{background:var(--red);border-color:#b91c1c;color:#fff}
  .btn-ghost{background:#fff}
  .banner{padding:12px;border-radius:12px;border:1px solid;display:flex;gap:.65rem;align-items:flex-start}
  .ok{background:#ecfdf5;border-color:#a7f3d0;color:#065f46}
  .den{background:#fef2f2;border-color:#fecaca;color:#7f1d1d}
  .log{display:flex;flex-direction:column;gap:8px}
  .log-item{padding:10px;border:1px solid var(--line);border-radius:10px;background:#fff;font-size:14px;color:#374151}
  .footer{margin-top:16px;padding:12px 16px;border:1px solid var(--line);background:var(--card);border-radius:14px;display:flex;justify-content:space-between;flex-wrap:wrap;gap:8px}
  /* Preferences */
  .pref-note{border-left:4px solid var(--line);padding-left:10px;margin-top:6px}
  /* A11y toggles */
  .txt-s{font-size:14px}.txt-m{font-size:16px}.txt-l{font-size:18px}
  .hc{--bg:#fff;--card:#fff;--line:#000;--text:#000;--muted:#000}
  @media(max-width:860px){.grid{grid-template-columns:1fr}}
</style>
"""

# ---------- Templates ----------
MAIN = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{{ app_name }}</title>
  {{ styles|safe }}
</head>
<body id="root" class="txt-m">
  <div class="wrap">
    <div class="header">
      <h1 class="title">{{ app_name }}</h1>
      <p class="sub">Instant, safe feedback — practice without touching real repos.</p>
    </div>

    <div class="grid">
      <!-- Left: training controls -->
      <div class="card">
        <h3 class="section-title">Training</h3>

        <form method="post" action="{{ url_for('check') }}" id="trainForm">
          <div style="display:grid;gap:12px">
            <div>
              <label>Scenario</label>
              <select name="scenario" id="scenario">
                <option value="">— Manual Selection —</option>
                {% for key in scenarios.keys() %}
                  <option value="{{ key }}">{{ key.replace('_',' ') }}</option>
                {% endfor %}
              </select>
              <div class="small">Auto-fills fields for a real-world case.</div>
            </div>

            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
              <div>
                <label>Role</label>
                <select name="role" id="role" required>
                  {% for r in roles %}<option value="{{ r }}">{{ r }}</option>{% endfor %}
                </select>
              </div>
              <div>
                <label>Resource</label>
                <select name="resource" id="resource" required>
                  {% for t in resources %}<option value="{{ t }}">{{ t }}</option>{% endfor %}
                </select>
              </div>
            </div>

            <div>
              <label>Action</label>
              <select name="action" id="action" required>
                {% for a in actions %}<option value="{{ a }}">{{ a }}</option>{% endfor %}
              </select>
            </div>

            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <button class="btn btn-primary" type="submit">Test Permissions</button>
              <a class="btn btn-ghost" href="{{ url_for('quiz') }}">Knowledge Test</a>
            </div>
          </div>
        </form>
      </div>

      <!-- Right: result + actions + preferences -->
      <div class="card">
        <h3 class="section-title">Result & Actions</h3>

        {% if message %}
          <div class="banner {% if ok %}ok{% else %}den{% endif %}" role="status" aria-live="polite">
            <div style="font-size:20px">{{ '✓' if ok else '✗' }}</div>
            <div>
              <div><strong>{{ message }}</strong></div>
              <div class="small">Reason: <strong>{{ code }}</strong> — {{ reason }}</div>
            </div>
          </div>
        {% else %}
          <p class="small">Run a test to see the outcome here.</p>
        {% endif %}

        <div style="margin-top:14px;display:flex;gap:8px;flex-wrap:wrap">
          <a class="btn btn-ghost" href="{{ url_for('export_log') }}">Export Log</a>
          <a class="btn btn-danger" href="{{ url_for('clear_log') }}">Clear Log</a>
        </div>

        <hr style="margin:18px 0;border:none;border-top:1px solid var(--line)"/>

        <h4 class="section-title" style="font-size:16px;margin-bottom:6px">Interface Preferences</h4>
        <div class="pref-note small"><strong>Note:</strong> These settings change the interface only. They are <em>not part of training</em> and do not affect permissions.</div>

        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:10px">
          <div>
            <label>Text Size</label>
            <select id="prefText">
              <option value="m">M (default)</option>
              <option value="s">S</option>
              <option value="l">L</option>
            </select>
          </div>
          <div>
            <label>High Contrast</label>
            <select id="prefContrast">
              <option value="off">Off (default)</option>
              <option value="on">On</option>
            </select>
          </div>
        </div>
      </div>
    </div>

    <div class="card" style="margin-top:16px">
      <h3 class="section-title">Simulated Audit Log</h3>
      {% if audit %}
        <div class="log" style="margin-top:8px">
          {% for line in audit %}
            <div class="log-item">{{ line }}</div>
          {% endfor %}
        </div>
      {% else %}
        <p class="small">No activity yet.</p>
      {% endif %}
    </div>

    <div class="footer" role="contentinfo">
      <div class="small">Created: {{ created }} • Version: {{ version }}</div>
      <div class="small"><strong>Disclaimer:</strong> {{ disclaimer }}</div>
    </div>
  </div>

<script>
  // Scenario autofill
  const scenario = document.getElementById('scenario');
  const role = document.getElementById('role');
  const resource = document.getElementById('resource');
  const action = document.getElementById('action');

  scenario.addEventListener('change', (e)=>{
    const key = e.target.value;
    if(!key) return;
    const S = {{ scenarios|tojson }};
    const s = S[key];
    if(s){ role.value = s.role; resource.value = s.resource; action.value = s.action; }
  });

  // Interface preferences (saved locally)
  const root = document.getElementById('root');
  const textSel = document.getElementById('prefText');
  const conSel = document.getElementById('prefContrast');

  function applyPrefs(){
    const t = localStorage.getItem('sim.text') || 'm';
    const c = localStorage.getItem('sim.contrast') || 'off';
    textSel.value = t; conSel.value = c;
    root.classList.remove('txt-s','txt-m','txt-l','hc');
    root.classList.add(t==='s'?'txt-s':(t==='l'?'txt-l':'txt-m'));
    if(c==='on'){ root.classList.add('hc'); }
  }
  textSel.addEventListener('change', e=>{ localStorage.setItem('sim.text', e.target.value); applyPrefs();});
  conSel.addEventListener('change', e=>{ localStorage.setItem('sim.contrast', e.target.value); applyPrefs();});
  applyPrefs();
</script>
</body>
</html>
"""

QUIZ = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Knowledge Test</title>
  {{ styles|safe }}
</head>
<body id="root" class="txt-m">
  <div class="wrap">
    <div class="header">
      <h1 class="title">Knowledge Test</h1>
      <p class="sub">Short checks to reinforce learning.</p>
    </div>

    <div class="card">
      <form method="get" action="{{ url_for('quiz') }}" style="display:flex;gap:8px;flex-wrap:wrap">
        <div style="flex:1;min-width:220px">
          <label>Track</label>
          <select name="track">
            {% for t in tracks %}
              <option value="{{ t }}" {% if current==t %}selected{% endif %}>{{ t }}</option>
            {% endfor %}
          </select>
        </div>
        <button class="btn btn-primary" style="align-self:end">Load</button>
        <a class="btn btn-ghost" style="align-self:end" href="{{ url_for('index') }}">Back</a>
      </form>
    </div>

    {% if items %}
    <form method="post" action="{{ url_for('quiz_submit') }}" class="card" style="margin-top:12px">
      <input type="hidden" name="track" value="{{ current }}"/>
      <div style="display:grid;gap:12px">
        {% for q in items %}
          <fieldset class="card" style="padding:12px">
            <legend style="font-weight:800">{{ loop.index }}. {{ q.prompt }}</legend>
            {% if q.type == "mcq1" %}
              {% for c in q.choices %}
              <label style="display:block;margin-top:6px">
                <input type="radio" name="{{ q.id }}" value="{{ c }}" required> {{ c }}
              </label>
              {% endfor %}
            {% else %}
              <label style="display:block;margin-top:6px"><input type="radio" name="{{ q.id }}" value="True" required> True</label>
              <label style="display:block;margin-top:6px"><input type="radio" name="{{ q.id }}" value="False" required> False</label>
            {% endif %}
          </fieldset>
        {% endfor %}
      </div>
      <div style="display:flex;gap:8px;margin-top:12px">
        <button class="btn btn-primary" type="submit">Submit</button>
        <a class="btn btn-ghost" href="{{ url_for('export_quiz') }}">Export Results</a>
      </div>
    </form>
    {% endif %}

    {% if result %}
      <div class="card" style="margin-top:12px">
        <div class="banner {% if result.passed %}ok{% else %}den{% endif %}">
          <div style="font-size:20px">{{ '✓' if result.passed else '✗' }}</div>
          <div><strong>Score:</strong> {{ result.score }}/{{ result.total }} — {% if result.passed %}Passed{% else %}Try again{% endif %}</div>
        </div>
      </div>
    {% endif %}

    <div class="footer" role="contentinfo">
      <div class="small">Created: {{ created }} • Version: {{ version }}</div>
      <div class="small"><strong>Disclaimer:</strong> {{ disclaimer }}</div>
    </div>
  </div>

<script>
  const root = document.getElementById('root');
  const t = localStorage.getItem('sim.text') || 'm';
  const c = localStorage.getItem('sim.contrast') || 'off';
  root.classList.remove('txt-s','txt-m','txt-l','hc');
  root.classList.add(t==='s'?'txt-s':(t==='l'?'txt-l':'txt-m'));
  if(c==='on') root.classList.add('hc');
</script>
</body>
</html>
"""

# ---------- Routes ----------
@app.route("/", methods=["GET"])
def index():
    return render_template_string(
        MAIN,
        styles=STYLES,
        app_name=APP_NAME,
        roles=list(ACCESS_RULES.keys()),
        resources=RESOURCE_TYPES,
        actions=ALLOWED_ACTIONS,
        scenarios=TRAINING_SCENARIOS,
        message=None,
        ok=False,
        code="",
        reason="",
        audit=AUDIT_LOG,
        created=CREATION_DATE,
        version=VERSION,
        disclaimer=DISCLAIMER,
    )

@app.route("/check", methods=["POST"])
def check():
    key = request.form.get("scenario") or ""
    if key and key in TRAINING_SCENARIOS:
        role = TRAINING_SCENARIOS[key]["role"]
        resource = TRAINING_SCENARIOS[key]["resource"]
        action = TRAINING_SCENARIOS[key]["action"]
    else:
        role = request.form.get("role", "")
        resource = request.form.get("resource", "")
        action = request.form.get("action", "")

    allowed, code, reason = evaluate_access(role, action, resource)
    msg = ("Permission Approved! "
           f"'{role}' can '{action}' the '{resource}'.") if allowed else \
          ("Permission Denied. " + reason)

    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    result = "APPROVED" if allowed else "DENIED"
    line = f"[{ts}] Role='{role}', Action='{action}', Resource='{resource}' -> {result} ({code})"
    AUDIT_LOG.insert(0, line)
    del AUDIT_LOG[MAX_LOG:]
    _append_audit(ts, role, action, resource, result, code)

    return render_template_string(
        MAIN,
        styles=STYLES,
        app_name=APP_NAME,
        roles=list(ACCESS_RULES.keys()),
        resources=RESOURCE_TYPES,
        actions=ALLOWED_ACTIONS,
        scenarios=TRAINING_SCENARIOS,
        message=msg,
        ok=allowed,
        code=code,
        reason=reason,
        audit=AUDIT_LOG,
        created=CREATION_DATE,
        version=VERSION,
        disclaimer=DISCLAIMER,
    )

@app.route("/export")
def export_log():
    if not os.path.exists(AUDIT_CSV):
        flash("No log yet. Run a test first.")
        return redirect(url_for("index"))
    return send_file(AUDIT_CSV, as_attachment=True, download_name="audit_log.csv")

@app.route("/clear")
def clear_log():
    AUDIT_LOG.clear()
    try:
        if os.path.exists(AUDIT_CSV):
            os.remove(AUDIT_CSV)
    except Exception:
        pass
    flash("Audit log cleared.")
    return redirect(url_for("index"))

@app.route("/quiz", methods=["GET"])
def quiz():
    track = request.args.get("track")
    items = QUIZ_BANK.get(track, []) if track else []
    return render_template_string(
        QUIZ,
        styles=STYLES,
        tracks=list(QUIZ_BANK.keys()),
        current=track,
        items=items,
        result=None,
        created=CREATION_DATE,
        version=VERSION,
        disclaimer=DISCLAIMER,
    )

@app.route("/quiz/submit", methods=["POST"])
def quiz_submit():
    track = request.form.get("track")
    qs = QUIZ_BANK.get(track, [])
    if not qs:
        flash("Pick a valid track.")
        return redirect(url_for("quiz"))

    score = 0
    for q in qs:
        given = request.form.get(q["id"])
        if given is None:
            continue
        if q["type"] == "mcq1":
            if given in q["answer"]:
                score += 1
        else:
            if given == q["answer"][0]:
                score += 1
    total = len(qs)
    passed = score >= max(1, int(0.8 * total))
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _append_quiz(ts, track, score, total)

    return render_template_string(
        QUIZ,
        styles=STYLES,
        tracks=list(QUIZ_BANK.keys()),
        current=track,
        items=qs,
        result={"score": score, "total": total, "passed": passed},
        created=CREATION_DATE,
        version=VERSION,
        disclaimer=DISCLAIMER,
    )

@app.route("/quiz/export")
def export_quiz():
    if not os.path.exists(QUIZ_CSV):
        flash("No quiz results yet.")
        return redirect(url_for("quiz"))
    return send_file(QUIZ_CSV, as_attachment=True, download_name="quiz_results.csv")

if __name__ == "__main__":
    app.run(debug=True)
