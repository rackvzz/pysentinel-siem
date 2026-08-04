#!/usr/bin/env python
"""Entrypoint for the read-only web dashboard.

    python run_dashboard.py

Serves on http://127.0.0.1:5000 by default. Does not need admin rights --
only run_collector.py touches the Windows Event Log.
"""

from dashboard.app import app

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
