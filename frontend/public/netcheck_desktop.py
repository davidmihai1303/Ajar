"""
NetCheck Desktop Companion
- System Tray with dynamic security states (Green / Amber / Red / Blue)
- Floating Desktop Widget (Tkinter, draggable, always-on-top)
- Windows Desktop Notifications on scan completion and threat alerts
- Quick actions: Open Dashboard, Scan Now, Toggle Widget
"""

import os
import sys
import time
import json
import webbrowser
import threading
import urllib.request
import urllib.error
from typing import Optional, Dict, Any

from PIL import Image, ImageDraw, ImageFont
import pystray
from pystray import MenuItem as item
import tkinter as tk

# Configuration
FRONTEND_URL = os.environ.get("NETCHECK_UI_URL", "http://127.0.0.1:5173")
BACKEND_URL = os.environ.get("NETCHECK_API_URL", "http://127.0.0.1:8001")

# State colors
COLOR_SAFE = "#1e6b3a"      # Green
COLOR_ATTENTION = "#8a5a00" # Amber
COLOR_RISKY = "#b42318"     # Red
COLOR_SCANNING = "#1f5c99"  # Blue
COLOR_NEUTRAL = "#4f5862"   # Grey
COLOR_BG_DARK = "#2a2420"   # Walnut dark

current_state = {
    "score": 95,
    "level": "safe", # safe, attention, risky, scanning, offline
    "ssid": "Wi-Fi Acasă",
    "devices_count": 5,
    "high": 0,
    "medium": 0,
    "low": 0,
    "scanning": False,
    "last_notified_id": None
}

tray_icon: Optional[pystray.Icon] = None
widget_window: Optional[tk.Tk] = None
widget_visible = True


def create_tray_image(color_hex: str, text: str = "✓") -> Image.Image:
    """Generates a high-contrast 64x64 tray icon."""
    size = (64, 64)
    image = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    # Outer circle
    draw.ellipse([(4, 4), (60, 60)], fill=color_hex, outline="#ffffff", width=3)

    # Inner symbol or score
    # Simple fallback shapes for high visibility
    if text == "✓":
        draw.line([(18, 34), (28, 44), (46, 20)], fill="#ffffff", width=5)
    elif text == "!":
        draw.line([(32, 18), (32, 36)], fill="#ffffff", width=6)
        draw.ellipse([(29, 42), (35, 48)], fill="#ffffff")
    elif text == "●":
        draw.ellipse([(24, 24), (40, 40)], fill="#ffffff")
    elif text == "↻":
        draw.arc([(18, 18), (46, 46)], start=30, end=330, fill="#ffffff", width=5)
    else:
        # Draw small text if possible
        draw.ellipse([(20, 20), (44, 44)], fill="#ffffff")

    return image


def get_state_color(level: str) -> str:
    if level == "safe":
        return COLOR_SAFE
    if level == "attention":
        return COLOR_ATTENTION
    if level == "risky":
        return COLOR_RISKY
    if level == "scanning":
        return COLOR_SCANNING
    return COLOR_NEUTRAL


def update_tray():
    global tray_icon
    if not tray_icon:
        return
    level = current_state["level"]
    score = current_state["score"]
    symbol = "✓" if level == "safe" else ("!" if level == "risky" else ("●" if level == "attention" else "↻"))
    color = get_state_color(level)
    
    tray_icon.icon = create_tray_image(color, symbol)
    tray_icon.title = f"NetCheck: Scor {score}/100 | {current_state['ssid']} | {level.upper()}"


def send_desktop_notification(title: str, message: str):
    """Sends a native desktop notification via tray icon."""
    global tray_icon
    if tray_icon:
        try:
            tray_icon.notify(title=title, message=message)
        except Exception as e:
            print(f"[Notificare] Eroare la trimitere: {e}")


def open_browser():
    webbrowser.open(FRONTEND_URL)


def trigger_scan():
    """Triggers scan flow by opening the scan page or calling backend."""
    current_state["scanning"] = True
    current_state["level"] = "scanning"
    update_tray()
    if widget_window:
        widget_window.after(0, update_widget_ui)
    
    send_desktop_notification(
        "NetCheck: Scanare pornită",
        "Ajar verifică vulnerabilitățile rețelei locale..."
    )
    # Open frontend to consent / monitor scan
    webbrowser.open(f"{FRONTEND_URL}/#/scan")


def toggle_widget():
    global widget_visible, widget_window
    if not widget_window:
        return
    if widget_visible:
        widget_window.withdraw()
        widget_visible = False
    else:
        widget_window.deiconify()
        widget_visible = True


def quit_app():
    global tray_icon, widget_window
    if tray_icon:
        tray_icon.stop()
    if widget_window:
        widget_window.destroy()
    os._exit(0)


# ==========================================
# Background Sync Loop
# ==========================================
def sync_worker():
    """Polls backend or mock API to sync live state with tray and widget."""
    while True:
        try:
            # Check backend history
            req = urllib.request.Request(f"{BACKEND_URL}/api/history", headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
                if isinstance(data, list) and len(data) > 0:
                    latest = data[0]
                    score = latest.get("score")
                    scan_id = latest.get("id")
                    if score is not None:
                        current_state["score"] = score
                        if score >= 80:
                            current_state["level"] = "safe"
                        elif score >= 50:
                            current_state["level"] = "attention"
                        else:
                            current_state["level"] = "risky"

                        # Notify on new scan completed
                        if current_state["last_notified_id"] != scan_id:
                            current_state["last_notified_id"] = scan_id
                            send_desktop_notification(
                                f"NetCheck: Scanare completă ({score}/100)",
                                f"Scor rețea: {score}/100. Stare: {current_state['level'].upper()}."
                            )

                    current_state["scanning"] = False
                    update_tray()
                    if widget_window:
                        widget_window.after(0, update_widget_ui)
        except Exception:
            # Running standalone or in frontend demo mode
            pass

        time.sleep(5)


# ==========================================
# Tkinter Desktop Floating Widget
# ==========================================
lbl_score = None
lbl_ssid = None
lbl_details = None
lbl_badge = None

def start_widget():
    global widget_window, lbl_score, lbl_ssid, lbl_details, lbl_badge

    root = tk.Tk()
    widget_window = root
    root.title("NetCheck Widget")
    root.geometry("300x170+100+100")
    root.overrideredirect(True) # Frameless
    root.attributes("-topmost", True) # Always on top
    root.configure(bg=COLOR_BG_DARK)

    # Enable window dragging
    def start_move(event):
        root.x = event.x
        root.y = event.y

    def do_move(event):
        deltax = event.x - root.x
        deltay = event.y - root.y
        x = root.winfo_x() + deltax
        y = root.winfo_y() + deltay
        root.geometry(f"+{x}+{y}")

    root.bind("<ButtonPress-1>", start_move)
    root.bind("<B1-Motion>", do_move)

    # Container frame
    container = tk.Frame(root, bg=COLOR_BG_DARK, padx=14, pady=12)
    container.pack(fill="both", expand=True)

    # Header row
    hdr_frame = tk.Frame(container, bg=COLOR_BG_DARK)
    hdr_frame.pack(fill="x", pady=(0, 6))

    lbl_title = tk.Label(hdr_frame, text="🛡️ NetCheck Widget", fg="#faf8f5", bg=COLOR_BG_DARK, font=("Segoe UI", 10, "bold"))
    lbl_title.pack(side="left")

    btn_close = tk.Button(hdr_frame, text="✕", fg="#cfc6bb", bg=COLOR_BG_DARK, bd=0, font=("Segoe UI", 10), command=toggle_widget, cursor="hand2")
    btn_close.pack(side="right")

    # Body row (Score + SSID)
    body_frame = tk.Frame(container, bg=COLOR_BG_DARK)
    body_frame.pack(fill="x", pady=4)

    lbl_score = tk.Label(body_frame, text="95", fg="#1e6b3a", bg="#e3f3e8", font=("Segoe UI", 26, "bold"), width=3, relief="flat", padx=6, pady=2)
    lbl_score.pack(side="left", padx=(0, 12))

    info_frame = tk.Frame(body_frame, bg=COLOR_BG_DARK)
    info_frame.pack(side="left", fill="both")

    lbl_ssid = tk.Label(info_frame, text="Wi-Fi Rețea", fg="#ffffff", bg=COLOR_BG_DARK, font=("Segoe UI", 11, "bold"), anchor="w")
    lbl_ssid.pack(fill="x")

    lbl_badge = tk.Label(info_frame, text="✓ Rețea Sigură", fg="#b4dcc1", bg=COLOR_BG_DARK, font=("Segoe UI", 9), anchor="w")
    lbl_badge.pack(fill="x")

    lbl_details = tk.Label(info_frame, text="0 riscuri critice găsite", fg="#cfc6bb", bg=COLOR_BG_DARK, font=("Segoe UI", 8), anchor="w")
    lbl_details.pack(fill="x")

    # Actions row
    act_frame = tk.Frame(container, bg=COLOR_BG_DARK)
    act_frame.pack(fill="x", pady=(10, 0))

    btn_scan = tk.Button(act_frame, text="⚡ Scanează", bg="#5a3a22", fg="#ffffff", bd=0, font=("Segoe UI", 9, "bold"), padx=10, pady=4, cursor="hand2", command=trigger_scan)
    btn_scan.pack(side="left", fill="x", expand=True, padx=(0, 6))

    btn_open = tk.Button(act_frame, text="↗️ Deschide", bg="#4a2f1b", fg="#ffffff", bd=0, font=("Segoe UI", 9), padx=10, pady=4, cursor="hand2", command=open_browser)
    btn_open.pack(side="right", fill="x", expand=True)

    update_widget_ui()
    root.mainloop()


def update_widget_ui():
    global lbl_score, lbl_ssid, lbl_details, lbl_badge
    if not lbl_score:
        return
    score = current_state["score"]
    level = current_state["level"]

    lbl_score.config(text=str(score))
    if level == "safe":
        lbl_score.config(fg="#1e6b3a", bg="#e3f3e8")
        lbl_badge.config(text="✓ Rețea Sigură", fg="#b4dcc1")
        lbl_details.config(text="Nicio vulnerabilitate critică")
    elif level == "attention":
        lbl_score.config(fg="#8a5a00", bg="#fff3c4")
        lbl_badge.config(text="● Atenție Recomandată", fg="#f1d67a")
        lbl_details.config(text="Vulnerabilități medii detectate")
    elif level == "risky":
        lbl_score.config(fg="#b42318", bg="#fdecea")
        lbl_badge.config(text="▲ Risc Ridicat", fg="#f3b8b1")
        lbl_details.config(text="Probleme critice detectate!")
    elif level == "scanning":
        lbl_score.config(fg="#1f5c99", bg="#e7f0fa", text="...")
        lbl_badge.config(text="↻ Scanare în curs...", fg="#b7d0ea")
        lbl_details.config(text="Se analizează porturile...")

    lbl_ssid.config(text=current_state["ssid"])


# ==========================================
# Main Entry Point
# ==========================================
def main():
    global tray_icon

    # Start background sync thread
    sync_thread = threading.Thread(target=sync_worker, daemon=True)
    sync_thread.start()

    # Setup System Tray
    initial_img = create_tray_image(COLOR_SAFE, "✓")
    menu = pystray.Menu(
        item("📌 Deschide Dashboard", open_browser, default=True),
        item("⚡ Scanează rețeaua acum", trigger_scan),
        item("🗂️ Comută Widget Desktop", toggle_widget),
        item("🔔 Testează Notificare", lambda: send_desktop_notification("NetCheck Desktop", "Notificările pe desktop funcționează perfect!")),
        pystray.Menu.SEPARATOR,
        item("❌ Ieșire", quit_app),
    )

    tray_icon = pystray.Icon("netcheck_tray", initial_img, "NetCheck - Securitate Rețea", menu)

    # Run tray in separate thread so Tkinter mainloop can run on main thread
    tray_thread = threading.Thread(target=tray_icon.run, daemon=True)
    tray_thread.start()

    # Notify initial startup
    send_desktop_notification(
        "NetCheck Desktop Pornit",
        "Aplicația rulează în System Tray și monitorizează securitatea rețelei."
    )

    # Start Tkinter widget on main thread
    start_widget()


if __name__ == "__main__":
    main()
