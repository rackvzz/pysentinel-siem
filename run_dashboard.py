#!/usr/bin/env python
"""Entrypoint for the read-only web dashboard.

    python run_dashboard.py

Serves on http://127.0.0.1:5000 and opens your browser with a one-time
access link. Does not need admin rights -- only run_collector.py touches the
Windows Event Log.
"""

import threading
import webbrowser

from dashboard.app import app

HOST, PORT = "127.0.0.1", 5000

if __name__ == "__main__":
    url = f"http://{HOST}:{PORT}/?token={app.config['ACCESS_TOKEN']}"
    print("pysentinel-siem dashboard is running.")
    print(f"Open: {url}")
    print("(This link is your access key -- don't share it. It changes every time the dashboard starts.)")
    threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    app.run(host=HOST, port=PORT, debug=False)
