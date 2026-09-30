import sqlite3, csv, io, secrets, os, json, hmac, hashlib, base64, urllib.request, urllib.parse
from datetime import date
from functools import wraps
from flask import Flask, request, jsonify, session, g, Response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static", static_url_path="")
app.secret_key = "change-this-secret-key"
DB = "events.db"
DEFAULT_UPI = "yourname@upi"   # <-- put YOUR UPI ID here (used when an event has no UPI ID)
RZP_KEY = os.environ.get("RAZORPAY_KEY_ID", "")        # optional: Razorpay test key id
RZP_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")  # optional: Razorpay test key secret

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'student');
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT,
  category TEXT, venue TEXT, date TEXT, time TEXT, capacity INTEGER DEFAULT 100,
  fee INTEGER DEFAULT 0, organizer_id INTEGER, status TEXT DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS registrations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, user_id INTEGER,
  created TEXT DEFAULT CURRENT_TIMESTAMP, UNIQUE(event_id, user_id));
CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, user_id INTEGER,
  rating INTEGER, comment TEXT, UNIQUE(event_id, user_id));
CREATE TABLE IF NOT EXISTS announcements(
  id INTEGER PRIMARY KEY AUTOINCREMENT, event_id INTEGER, message TEXT,
  created TEXT DEFAULT CURRENT_TIMESTAMP);
"""


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def q(sql, args=()):
    return [dict(r) for r in db().execute(sql, args).fetchall()]


def run(sql, args=()):
    cur = db().execute(sql, args)
    db().commit()
    return cur


def auth(*roles):
    def deco(f):
        @wraps(f)
        def wrap(*a, **k):
            if "uid" not in session:
                return jsonify(error="Please login"), 401
            if roles and session["role"] not in roles:
                return jsonify(error="Not allowed"), 403
            return f(*a, **k)
        return wrap
    return deco


def new_ticket(eid, uid):
    return f"CF{eid:03d}-{uid:03d}-{secrets.token_hex(3).upper()}"


@app.get("/")
def home():
    return app.send_static_file("index.html")


# ---------- auth ----------
@app.post("/api/register")
def register():
    d = request.json
    role = d.get("role") if d.get("role") in ("student", "organizer") else "student"
    try:
        run("INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)",
            (d["name"], d["email"].lower(), generate_password_hash(d["password"]), role))
    except sqlite3.IntegrityError:
        return jsonify(error="Email already registered"), 400
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    d = request.json
    u = q("SELECT * FROM users WHERE email=?", (d["email"].lower(),))
    if not u or not check_password_hash(u[0]["password"], d["password"]):
        return jsonify(error="Invalid email or password"), 401
    session.update(uid=u[0]["id"], role=u[0]["role"], name=u[0]["name"])
    return jsonify(id=u[0]["id"], name=u[0]["name"], role=u[0]["role"])


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    if "uid" not in session:
        return jsonify(user=None)
    return jsonify(user=dict(id=session["uid"], name=session["name"], role=session["role"]))


# ---------- events ----------
@app.get("/api/events")
def events():
    uid, role = session.get("uid"), session.get("role")
    sql = """SELECT e.*, u.name organizer,
      (SELECT COUNT(*) FROM registrations r WHERE r.event_id=e.id AND r.waitlisted=0) registered,
      (SELECT CASE WHEN r.waitlisted=1 THEN 2 ELSE 1 END FROM registrations r
        WHERE r.event_id=e.id AND r.user_id=?) joined,
      (SELECT ROUND(AVG(rating),1) FROM feedback f WHERE f.event_id=e.id) rating
      FROM events e JOIN users u ON u.id=e.organizer_id WHERE 1=1"""
    args = [uid or 0]
    scope = request.args.get("scope", "public")
    if scope == "mine" and role in ("organizer", "admin"):
        sql += " AND e.organizer_id=?"; args.append(uid)
    elif scope == "pending" and role == "admin":
        sql += " AND e.status='pending'"
    else:
        sql += " AND e.status='approved'"
    if request.args.get("search"):
        sql += " AND (e.title LIKE ? OR e.description LIKE ?)"
        s = "%" + request.args["search"] + "%"; args += [s, s]
    if request.args.get("category"):
        sql += " AND e.category=?"; args.append(request.args["category"])
    return jsonify(q(sql + " ORDER BY e.date, e.time", args))


@app.post("/api/events")
@auth("organizer", "admin")
def create_event():
    d = request.json
    clash = q("""SELECT id FROM events WHERE venue=? AND date=? AND time=?
                 AND status IN ('approved','pending')""", (d["venue"], d["date"], d["time"]))
    if clash:
        return jsonify(error="Venue already booked at that date and time"), 400
    status = "approved" if session["role"] == "admin" else "pending"
    run("""INSERT INTO events(title,description,category,venue,date,time,capacity,fee,organizer_id,status,team_size,upi,poster)
           VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (d["title"], d.get("description", ""), d["category"], d["venue"], d["date"], d["time"],
         int(d.get("capacity") or 100), int(d.get("fee") or 0), session["uid"], status,
         max(1, int(d.get("team_size") or 1)), (d.get("upi") or "").strip(), d.get("poster")))
    return jsonify(ok=True, status=status)


def owns(eid):
    e = q("SELECT organizer_id FROM events WHERE id=?", (eid,))
    return bool(e) and (session["role"] == "admin" or e[0]["organizer_id"] == session["uid"])


@app.put("/api/events/<int:eid>")
@auth("organizer", "admin")
def update_event(eid):
    if not owns(eid):
        return jsonify(error="Not allowed"), 403
    d = request.json
    clash = q("""SELECT id FROM events WHERE venue=? AND date=? AND time=? AND id!=?
                 AND status IN ('approved','pending')""", (d["venue"], d["date"], d["time"], eid))
    if clash:
        return jsonify(error="Venue already booked at that date and time"), 400
    joined = q("SELECT COUNT(*) n FROM registrations WHERE event_id=?", (eid,))[0]["n"]
    cap = int(d.get("capacity") or 100)
    if cap < joined:
        return jsonify(error=f"Capacity cannot be less than {joined} (already registered)"), 400
    run("""UPDATE events SET title=?,description=?,category=?,venue=?,date=?,time=?,capacity=?,fee=?,team_size=?,upi=?,poster=COALESCE(?,poster)
           WHERE id=?""",
        (d["title"], d.get("description", ""), d["category"], d["venue"], d["date"], d["time"],
         cap, int(d.get("fee") or 0), max(1, int(d.get("team_size") or 1)), (d.get("upi") or "").strip(), d.get("poster"), eid))
    return jsonify(ok=True)


@app.delete("/api/events/<int:eid>")
@auth("organizer", "admin")
def delete_event(eid):
    if not owns(eid):
        return jsonify(error="Not allowed"), 403
    run("DELETE FROM registrations WHERE event_id=?", (eid,))
    run("DELETE FROM events WHERE id=?", (eid,))
    return jsonify(ok=True)


@app.post("/api/events/<int:eid>/<action>")
@auth("admin")
def review(eid, action):
    if action not in ("approve", "reject"):
        return jsonify(error="Bad action"), 400
    run("UPDATE events SET status=? WHERE id=?",
        ("approved" if action == "approve" else "rejected", eid))
    return jsonify(ok=True)


# ---------- registrations ----------
@app.post("/api/events/<int:eid>/join")
@auth("student")
def join(eid):
    e = q("""SELECT capacity, fee, team_size,(SELECT COUNT(*) FROM registrations WHERE event_id=events.id AND waitlisted=0) n
             FROM events WHERE id=? AND status='approved'""", (eid,))
    if not e:
        return jsonify(error="Event not found"), 404
    d = request.get_json(silent=True) or {}
    if (e[0]["team_size"] or 1) > 1 and not (d.get("team_name") or "").strip():
        return jsonify(error="Please enter your team name"), 400
    full = e[0]["n"] >= e[0]["capacity"]
    code = None if full else new_ticket(eid, session["uid"])
    pay = "unpaid" if (e[0]["fee"] or 0) > 0 else "free"
    try:
        run("""INSERT INTO registrations(event_id,user_id,ticket,waitlisted,payment,team_name,team_members)
               VALUES(?,?,?,?,?,?,?)""",
            (eid, session["uid"], code, int(full), pay, d.get("team_name", ""), d.get("team_members", "")))
    except sqlite3.IntegrityError:
        return jsonify(error="Already registered"), 400
    return jsonify(ok=True, ticket=code, waitlisted=full, needs_payment=(pay == "unpaid" and not full))


@app.post("/api/events/<int:eid>/leave")
@auth("student")
def leave(eid):
    run("DELETE FROM registrations WHERE event_id=? AND user_id=?", (eid, session["uid"]))
    nxt = q("SELECT id, user_id FROM registrations WHERE event_id=? AND waitlisted=1 ORDER BY id LIMIT 1", (eid,))
    cap = q("""SELECT capacity, (SELECT COUNT(*) FROM registrations WHERE event_id=? AND waitlisted=0) n
               FROM events WHERE id=?""", (eid, eid))
    if nxt and cap and cap[0]["n"] < cap[0]["capacity"]:
        run("UPDATE registrations SET waitlisted=0, ticket=? WHERE id=?",
            (new_ticket(eid, nxt[0]["user_id"]), nxt[0]["id"]))
    return jsonify(ok=True)


@app.get("/api/my-registrations")
@auth("student")
def my_regs():
    return jsonify(q("""SELECT e.*, r.waitlisted, r.attended, r.payment FROM events e JOIN registrations r ON r.event_id=e.id
                        WHERE r.user_id=? ORDER BY e.date""", (session["uid"],)))


def participants(eid):
    return q("""SELECT r.id rid, u.name, u.email, r.created, r.attended, r.payment, r.utr, r.team_name, r.team_members FROM registrations r
                JOIN users u ON u.id=r.user_id WHERE r.event_id=? AND r.waitlisted=0""", (eid,))


@app.get("/api/events/<int:eid>/participants")
@auth("organizer", "admin")
def parts(eid):
    if not owns(eid):
        return jsonify(error="Not allowed"), 403
    return jsonify(participants(eid))


@app.get("/api/events/<int:eid>/csv")
@auth("organizer", "admin")
def parts_csv(eid):
    if not owns(eid):
        return jsonify(error="Not allowed"), 403
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["Name", "Email", "Team", "Members", "Registered at", "Payment", "UTR", "Attended"])
    for p in participants(eid):
        w.writerow([p["name"], p["email"], p["team_name"], (p["team_members"] or "").replace("\n", ", "), p["created"], p["payment"], p["utr"], "Yes" if p["attended"] else "No"])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=event_{eid}.csv"})


# ---------- payments ----------
def my_reg(eid):
    r = q("""SELECT r.id, r.payment, r.waitlisted, e.title, e.fee, e.upi FROM registrations r
             JOIN events e ON e.id=r.event_id WHERE r.event_id=? AND r.user_id=?""", (eid, session["uid"]))
    return r[0] if r and not r[0]["waitlisted"] else None


@app.get("/api/events/<int:eid>/payment-info")
@auth("student")
def payment_info(eid):
    r = my_reg(eid)
    if not r:
        return jsonify(error="No active registration found"), 404
    uri = "upi://pay?" + urllib.parse.urlencode(
        {"pa": r["upi"] or DEFAULT_UPI, "pn": "CampusFest", "am": r["fee"], "cu": "INR", "tn": r["title"][:40]},
        quote_via=urllib.parse.quote)
    return jsonify(title=r["title"], fee=r["fee"], payment=r["payment"], upi=uri, razorpay=RZP_KEY or None)


@app.post("/api/events/<int:eid>/pay")
@auth("student")
def submit_utr(eid):
    r, utr = my_reg(eid), (request.json.get("utr") or "").strip()
    if not r:
        return jsonify(error="No active registration found"), 404
    if len(utr) < 8:
        return jsonify(error="Enter the UPI transaction ID (at least 8 characters)"), 400
    if r["payment"] != "paid":
        run("UPDATE registrations SET utr=?, payment='pending' WHERE id=?", (utr, r["id"]))
    return jsonify(ok=True)


@app.post("/api/events/<int:eid>/razorpay-order")
@auth("student")
def rzp_order(eid):
    r = my_reg(eid)
    if not RZP_KEY:
        return jsonify(error="Razorpay is not configured"), 400
    if not r:
        return jsonify(error="No active registration found"), 404
    body = json.dumps({"amount": r["fee"] * 100, "currency": "INR", "receipt": f"reg{r['id']}"}).encode()
    hdr = base64.b64encode(f"{RZP_KEY}:{RZP_SECRET}".encode()).decode()
    req = urllib.request.Request("https://api.razorpay.com/v1/orders", body,
                                 {"Content-Type": "application/json", "Authorization": "Basic " + hdr})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            o = json.load(resp)
    except Exception as ex:
        return jsonify(error=f"Razorpay error: {ex}"), 502
    return jsonify(order_id=o["id"], amount=o["amount"], key=RZP_KEY)


@app.post("/api/events/<int:eid>/razorpay-verify")
@auth("student")
def rzp_verify(eid):
    d, r = request.json, my_reg(eid)
    if not r:
        return jsonify(error="No active registration found"), 404
    sig = hmac.new(RZP_SECRET.encode(), f"{d['order_id']}|{d['payment_id']}".encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, d["signature"]):
        return jsonify(error="Payment verification failed"), 400
    run("UPDATE registrations SET payment='paid', utr=? WHERE id=?", (d["payment_id"], r["id"]))
    return jsonify(ok=True)


@app.post("/api/registrations/<int:rid>/verify")
@auth("organizer", "admin")
def verify_payment(rid):
    r = q("SELECT event_id FROM registrations WHERE id=?", (rid,))
    if not r or not owns(r[0]["event_id"]):
        return jsonify(error="Not allowed"), 403
    run("UPDATE registrations SET payment='paid' WHERE id=?", (rid,))
    return jsonify(ok=True)


# ---------- feedback & announcements ----------
@app.post("/api/events/<int:eid>/feedback")
@auth("student")
def feedback(eid):
    r = q("""SELECT r.attended, e.date FROM registrations r JOIN events e ON e.id=r.event_id
             WHERE r.event_id=? AND r.user_id=? AND r.waitlisted=0""", (eid, session["uid"]))
    if not r:
        return jsonify(error="You are not registered for this event"), 400
    if not r[0]["attended"] and r[0]["date"] >= date.today().isoformat():
        return jsonify(error="You can rate an event after attending it"), 400
    d = request.json
    run("INSERT OR REPLACE INTO feedback(event_id,user_id,rating,comment) VALUES(?,?,?,?)",
        (eid, session["uid"], max(1, min(5, int(d["rating"]))), d.get("comment", "")))
    return jsonify(ok=True)


@app.post("/api/events/<int:eid>/announce")
@auth("organizer", "admin")
def announce(eid):
    msg = (request.json.get("message") or "").strip()
    if not owns(eid):
        return jsonify(error="Not allowed"), 403
    if not msg:
        return jsonify(error="Please write a message"), 400
    run("INSERT INTO announcements(event_id,message) VALUES(?,?)", (eid, msg))
    return jsonify(ok=True)


@app.get("/api/announcements")
def announcements():
    return jsonify(q("""SELECT a.message, a.created, e.title, u.name organizer FROM announcements a
                        JOIN events e ON e.id=a.event_id JOIN users u ON u.id=e.organizer_id
                        ORDER BY a.id DESC LIMIT 30"""))


# ---------- ticket & check-in ----------
@app.get("/api/events/<int:eid>/ticket")
@auth("student")
def ticket(eid):
    r = q("""SELECT r.id, r.ticket, r.attended, r.waitlisted, r.payment, e.title, e.date, e.time, e.venue, e.category
             FROM registrations r JOIN events e ON e.id=r.event_id
             WHERE r.event_id=? AND r.user_id=?""", (eid, session["uid"]))
    if not r:
        return jsonify(error="You are not registered for this event"), 404
    t = r[0]
    if t["waitlisted"]:
        return jsonify(error="You are on the waitlist. A ticket is issued when a seat opens."), 400
    if not t["ticket"]:  # registrations made before tickets existed
        t["ticket"] = new_ticket(eid, session["uid"])
        run("UPDATE registrations SET ticket=? WHERE id=?", (t["ticket"], t["id"]))
    t["student"] = session["name"]
    return jsonify(t)


@app.post("/api/checkin")
@auth("organizer", "admin")
def checkin():
    code = (request.json.get("code") or "").strip().upper()
    r = q("""SELECT r.id, r.attended, r.payment, r.event_id, u.name, e.title FROM registrations r
             JOIN users u ON u.id=r.user_id JOIN events e ON e.id=r.event_id
             WHERE r.ticket=?""", (code,))
    if not r:
        return jsonify(error="Invalid ticket code"), 404
    r = r[0]
    if not owns(r["event_id"]):
        return jsonify(error="This ticket is for another organizer's event"), 403
    if r["payment"] in ("unpaid", "pending"):
        return jsonify(error=f"Payment not verified yet for {r['name']}"), 400
    if r["attended"]:
        return jsonify(error=f"{r['name']} is already checked in"), 400
    run("UPDATE registrations SET attended=1 WHERE id=?", (r["id"],))
    return jsonify(ok=True, name=r["name"], title=r["title"])


# ---------- dashboard ----------
@app.get("/api/stats")
@auth("admin")
def stats():
    return jsonify(
        users=q("SELECT COUNT(*) n FROM users")[0]["n"],
        events=q("SELECT COUNT(*) n FROM events WHERE status='approved'")[0]["n"],
        registrations=q("SELECT COUNT(*) n FROM registrations WHERE waitlisted=0")[0]["n"],
        attended=q("SELECT COUNT(*) n FROM registrations WHERE attended=1")[0]["n"],
        categories=q("""SELECT e.category, COUNT(r.id) n FROM events e
                        LEFT JOIN registrations r ON r.event_id=e.id AND r.waitlisted=0
                        WHERE e.status='approved' GROUP BY e.category ORDER BY n DESC"""),
        per_event=q("""SELECT e.title, COUNT(r.id) n FROM events e
                       LEFT JOIN registrations r ON r.event_id=e.id AND r.waitlisted=0
                       WHERE e.status='approved' GROUP BY e.id ORDER BY n DESC LIMIT 8"""))


def add_cols(c, table, cols):
    have = [r[1] for r in c.execute(f"PRAGMA table_info({table})")]
    for name, ddl in cols.items():
        if name not in have:
            c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init():
    with sqlite3.connect(DB) as c:
        c.executescript(SCHEMA)
        cols = [r[1] for r in c.execute("PRAGMA table_info(registrations)")]
        if "ticket" not in cols:
            c.execute("ALTER TABLE registrations ADD COLUMN ticket TEXT")
        add_cols(c, "events", {"upi": "TEXT", "team_size": "INTEGER DEFAULT 1", "poster": "TEXT"})
        add_cols(c, "registrations", {"payment": "TEXT DEFAULT 'free'", "utr": "TEXT",
                                      "team_name": "TEXT", "team_members": "TEXT"})
        if "waitlisted" not in cols:
            c.execute("ALTER TABLE registrations ADD COLUMN waitlisted INTEGER DEFAULT 0")
        if "attended" not in cols:
            c.execute("ALTER TABLE registrations ADD COLUMN attended INTEGER DEFAULT 0")
        if not c.execute("SELECT 1 FROM users WHERE role='admin'").fetchone():
            c.execute("INSERT INTO users(name,email,password,role) VALUES(?,?,?,'admin')",
                      ("Admin", "admin@college.edu", generate_password_hash("admin123")))


if __name__ == "__main__":
    init()
    app.run(debug=True)
