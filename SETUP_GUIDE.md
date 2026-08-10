# SETUP_GUIDE.md — GitHub + Render, start to finish

One path, no detours. Everything below happens in your browser. Nothing installs on your computer.

---

## Step 1 — Get the code onto GitHub

1. Go to **github.com**, sign up free if you don't have an account.
2. Click the **+** icon (top right) → **New repository**.
3. Name it `home-network-guardian`. Leave it **Public**. Click **Create repository**.
4. On the new empty repo page, click **"uploading an existing file"** (it's a link in the middle of the page).
5. Unzip the project on your computer first (just double-click the zip, most computers handle this natively). Then drag the **contents** of the `home-network-guardian` folder into GitHub's upload box — all of it: `netguard/`, `webapp/`, `agent/`, `scripts/`, `README.md`, `SETUP_GUIDE.md`, `requirements.txt`, `Procfile`.
6. Scroll down, click **Commit changes**.

Done — your code now lives on GitHub. That's the only "upload" step in this whole process.

---

## Step 2 — Deploy it on Render

1. Go to **render.com**, sign up free — easiest is "Sign up with GitHub" so the two are already connected.
2. Click **New +** (top right) → **Web Service**.
3. Pick your `home-network-guardian` repo from the list, click **Connect**.
4. Render will show you settings. Set these exactly:
   - **Name:** whatever you want, e.g. `home-network-guardian`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --chdir . -w 2 -b 0.0.0.0:$PORT webapp.app:app`
5. Scroll to **Environment Variables**, click **Add Environment Variable**:
   - Key: `NETGUARD_SECRET_KEY`
   - Value: type anything random, like `xk29-pineapple-secret-482`
6. Pick the **Free** instance type.
7. Click **Create Web Service**.

Render now builds and starts your site — takes 2-5 minutes. You'll see live logs scroll by. Once it says **"Live"** at the top, you'll see your real URL, something like:

```
https://home-network-guardian-xxxx.onrender.com
```

That's it. That link works right now, permanently, whether or not your browser is even open.

---

## Step 3 — Try it

1. Open your new `.onrender.com` link.
2. Sign up.
3. Go to **Router Setup**, fill in anything (even test values work to try it out).
4. Go to **Get Agent** — copy the API key shown there. Keep this page open or copy the key somewhere.
5. Check the **Dashboard** — it'll be empty until an agent reports in, which is expected.

---

## Step 4 — Get some real data into the dashboard (optional, once you have a real computer to test from)

The website itself can never scan a network — only `agent/local_agent.py`, running on an actual computer with an actual network card, can do that. When you (or anyone) has access to a real machine:

1. Download just `agent/local_agent.py` and the whole `netguard/` folder onto that machine.
2. Install its dependencies (separate from the website's): `pip install -r agent/requirements-agent.txt`
3. Edit the top of `local_agent.py`:
   ```python
   API_KEY = "paste the key from Get Agent page"
   SERVER_URL = "https://your-actual-onrender-link"
   USE_REAL_SCAN = False   # leave False first — proves the connection works with safe fake data
   ```
4. Run it: `python3 local_agent.py`
5. Check your Dashboard — you should see device/alert data appear within a few seconds.
6. Once that works, flip `USE_REAL_SCAN = True`, fill in that machine's real subnet/interface (find with `ifconfig` or `ip addr`), and run again with `sudo python3 local_agent.py` for an actual scan of that network.

---

## The one thing worth knowing about the free tier

Render's free plan spins your service down after periods of no traffic, and its disk storage isn't guaranteed to persist across redeploys — meaning signed-up accounts could occasionally reset. Completely fine for a class project. If this ever needs to hold real, permanent user data, that's a "swap SQLite for Render's managed Postgres" upgrade later — not something to worry about now.

---

## If something breaks

- **Render build fails:** click into the build logs it shows you — almost always a typo in the Start Command, double-check it matches Step 2.5 exactly.
- **Site loads but errors out:** check your `NETGUARD_SECRET_KEY` environment variable is actually set.
- **Still stuck:** paste me the exact error text from Render's logs, not just "it doesn't work" — the logs almost always say exactly what's wrong.
