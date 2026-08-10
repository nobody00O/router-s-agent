# Home Network Guardian 🛡️

Basically — a website where you can sign up, tell it about your WiFi router, and it'll warn you if something weird is happening on your network. Like an unknown device connecting, or one of your smart gadgets quietly sending data somewhere it shouldn't.

No AI/ML magic here, and that's on purpose. Every alert this thing gives you comes from a simple, readable "if this happens, flag it" rule — good for a 1st-year project because you can literally point at the line of code and say "this is why it flagged that."

---

## The backstory (why this project even exists)

This didn't start as "let's build a network scanner." It started with me digging into some open-source WiFi research repos (`ESP32-CSI-Tool` and `AntiEave-WiFi-Sensing`) and realizing WiFi signals can be used to sense what's happening inside a house — like, literally detect movement through walls just from how WiFi signal bounces around. That's a genuinely cool but also kind of unsettling thing to learn.

That got me thinking the other way: if WiFi tech can be used to snoop on people, shouldn't there be an easy way for regular homeowners to check if THEIR OWN network is the one being messed with? That's where this came from — instead of building something that watches people, build something that protects them.

## What it actually does

1. You sign up on the website.
2. You tell it your router's specs (subnet, interface, known devices).
3. You download a small script (the "agent") and run it — this is the part that actually looks at your network, since the website itself literally cannot see inside your home network from wherever it's hosted.
4. The agent reports back what it found.
5. Your dashboard shows you: what devices are on your network, and any alerts (new device joined, something contacted a known tracker domain, etc).

## Important honest thing to know upfront

**A website can't scan your home network by itself.** No website can — not this one, not any "network security" product you'll ever see advertised. Your router's connected-devices list is only visible to something running INSIDE your home network. That's why this is split into two pieces: the website (accounts + dashboard) and a little agent script (the actual scanner) that YOU run on YOUR OWN network.

## The folder layout — what's what

```
home-network-guardian/
│
├── README.md              ← you're reading it
├── SETUP_GUIDE.md          ← literal step-by-step, GitHub + Render, start here
├── requirements.txt         ← what the WEBSITE needs (just flask + gunicorn)
├── Procfile                  ← tells Render how to start the app
│
├── netguard/                 ← the "brain" — all the detection logic lives here
│   ├── config.py               → stores/validates router settings
│   ├── discover.py             → finds devices on a network (ARP scan)
│   ├── fingerprint.py          → figures out what brand a device is from its MAC address
│   ├── dns_watch.py            → watches for sketchy outbound traffic
│   └── anomaly_rules.py        → the actual "if X then alert" rules
│
├── webapp/                    ← the actual website (Flask)
│   ├── app.py                    → all the page routes (signup, login, dashboard, etc)
│   ├── db.py                     → talks to the database
│   ├── auth.py                   → signup/login/password stuff
│   ├── router_config.py          → saves your router info
│   ├── scan_ingest.py            → where your agent's scan results land
│   └── templates/                → the actual HTML pages
│
├── agent/
│   ├── local_agent.py            ← THIS is the file YOU download and run on your own network
│   └── requirements-agent.txt     ← what the AGENT needs (requests + scapy) — separate from the website's deps on purpose, so Render's build stays light
│
└── scripts/
    └── run_platform_checks.py    → runs every test to prove it all works
```

## Does this actually work? (yes, and here's proof, not just me saying so)

I built this piece by piece and ran/tested every single module before moving to the next one — not just wrote code and hoped:

- Database: created, all 4 tables show up correctly ✅
- Signup/login: tested signup, duplicate-email rejection, correct login, wrong-password rejection, all pass ✅
- Router config saving: tested bad input gets rejected, good input saves and reloads correctly ✅
- The alert engine: fed it fake "new device + sketchy domain" data, it correctly flagged both ✅
- The whole website: ran the REAL Flask server, hit it with REAL HTTP requests (signup → save router → agent reports in → dashboard shows it), checked the server's own access log to prove it actually happened ✅
- Ran it under `gunicorn` (a real production server, not just Flask's built-in dev one) — works ✅
- Ran it again in a completely isolated, freshly-created environment with ONLY `flask` + `gunicorn` installed (nothing else) — still works, confirming the website truly doesn't secretly need `scapy`/`requests`, which are only for the separate agent script ✅

The one thing that genuinely could NOT be tested by me: a real scan of a real WiFi network, because I don't have a physical network card in my environment at all — no `ip`, no `arp`, nothing. That part only becomes real once someone runs the agent on their actual home network.

## What this thing WON'T do (being honest, not just hyping it)

- It alerts you, it doesn't block anything automatically.
- It only catches stuff that matches one of its rules — it's not "smart," it won't catch something totally new it's never seen before.
- Phones/laptops randomize their MAC address these days for privacy, so you WILL see some "unknown device" false alarms in normal daily life — that's expected, not a bug.
- It can only see plain old DNS traffic — a lot of modern apps use encrypted DNS which this can't peek into.

## Go set it up

Seriously, don't try to read all the code files top to bottom first — just go to **SETUP_GUIDE.md** and follow the steps. It's written for exactly this situation (old/limited computer, browser-only setup, no installs needed on your end).
