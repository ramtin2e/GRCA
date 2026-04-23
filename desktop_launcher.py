"""
GRCA Desktop Launcher
Launch the GRC Threat Modeler as a native desktop application.
"""

import threading
import time
import webview
import sys
from web.app import app

def start_flask():
    """Start the Flask server in a background thread."""
    # We use a specific port for the desktop app
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)

def main():
    # 1. Start Flask in a daemon thread
    flask_thread = threading.Thread(target=start_flask)
    flask_thread.daemon = True
    flask_thread.start()

    # 2. Wait a moment for the server to start
    time.sleep(1.5)

    # 3. Create the webview window
    window = webview.create_window(
        'GRC Threat Modeler v0.2.0',
        'http://127.0.0.1:5000',
        width=1400,
        height=900,
        min_size=(1000, 700),
        text_select=True,
        confirm_close=True
    )

    # 4. Start the webview loop
    webview.start()

if __name__ == '__main__':
    main()
