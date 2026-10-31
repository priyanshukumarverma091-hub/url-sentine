import re
import socket
import ipaddress
import threading
import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse


# SECURITY RULES

suspicious_keywords = [
    "login", "verify", "password",
    "bank", "account", "secure",
    "gift", "free"
]

shorteners = [
    "bit.ly", "tinyurl.com",
    "t.co", "cutt.ly", "is.gd"
]


# URL ANALYZER

def analyze_url(url):

    score = 0
    reasons = []

    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    domain = parsed.hostname

    if not domain or any(char.isspace() for char in url):
        return None

    try:
        parsed.port
    except ValueError:
        return None

    # HTTPS CHECK

    if parsed.scheme != "https":
        score += 15
        reasons.append("HTTPS is not enabled")

    # IP DETECTION

    try:
        ipaddress.ip_address(domain)
        score += 25
        reasons.append("IP address used instead of domain")

    except ValueError:
        pass

    # KEYWORD DETECTION

    for word in suspicious_keywords:

        if word in url.lower():
            score += 10
            reasons.append("Suspicious keyword: " + word)

    # URL LENGTH

    if len(url) > 75:
        score += 10
        reasons.append("Unusually long URL")

    # SPECIAL CHARACTER

    if "@" in parsed.netloc:
        score += 20
        reasons.append("@ symbol detected")

    # SHORTENER CHECK

    if domain.lower() in shorteners:
        score += 20
        reasons.append("URL shortener detected")

    # DNS CHECK

    try:
        socket.gethostbyname(domain)

    except socket.gaierror:
        score += 20
        reasons.append("DNS resolution failed")

    score = min(score, 100)

    if score < 30:
        status = "LOW RISK"

    elif score < 60:
        status = "MEDIUM RISK"

    else:
        status = "HIGH RISK"

    return {
        "url": url,
        "domain": domain,
        "score": score,
        "status": status,
        "reasons": reasons,
        "https": parsed.scheme == "https"
    }


# GUI FUNCTIONS

def start_analysis():

    url = url_entry.get().strip()

    if not url:
        result_label.config(
            text="Please enter a URL",
            fg="#ff5555"
        )
        return

    analyze_button.config(
        state="disabled",
        text="ANALYZING..."
    )

    result_box.delete("1.0", tk.END)
    result_box.insert(tk.END, "Analyzing URL...\n")

    threading.Thread(
        target=run_analysis,
        args=(url,),
        daemon=True
    ).start()


def run_analysis(url):

    result = analyze_url(url)

    root.after(0, lambda: show_result(result))


def show_result(result):

    analyze_button.config(
        state="normal",
        text="ANALYZE URL"
    )

    result_box.delete("1.0", tk.END)

    if result is None:
        result_label.config(
            text="INVALID URL",
            fg="#ff5555"
        )
        result_box.insert(
            tk.END,
            "URL format could not be parsed."
        )
        return

    score = result["score"]
    status = result["status"]

    if score < 30:
        color = "#00e676"

    elif score < 60:
        color = "#ffb300"

    else:
        color = "#ff5252"

    result_label.config(
        text=status,
        fg=color
    )

    score_label.config(
        text=f"{score}/100",
        fg=color
    )

    result_box.insert(
        tk.END,
        f"URL: {result['url']}\n\n"
    )

    result_box.insert(
        tk.END,
        f"DOMAIN: {result['domain']}\n"
    )

    result_box.insert(
        tk.END,
        f"HTTPS: {'Enabled' if result['https'] else 'Disabled'}\n\n"
    )

    result_box.insert(
        tk.END,
        "SECURITY ANALYSIS\n"
    )

    result_box.insert(
        tk.END,
        "-" * 35 + "\n"
    )

    if result["reasons"]:

        for reason in result["reasons"]:
            result_box.insert(
                tk.END,
                "[!] " + reason + "\n"
            )

    else:

        result_box.insert(
            tk.END,
            "[+] No suspicious indicators detected\n"
        )

    result_box.insert(
        tk.END,
        "\nNote: This is a rule-based analysis, "
        "not a guarantee of website safety."
    )


def clear_all():

    url_entry.delete(0, tk.END)
    result_box.delete("1.0", tk.END)

    result_label.config(
        text="WAITING FOR ANALYSIS",
        fg="#aaaaaa"
    )

    score_label.config(
        text="--/100",
        fg="#ffffff"
    )


# MAIN WINDOW

root = tk.Tk()

root.title("URL SENTINEL | Security Analyzer")
root.geometry("850x650")
root.minsize(700, 550)
root.configure(bg="#101722")


# HEADER

header = tk.Frame(
    root,
    bg="#101722"
)

header.pack(fill="x", pady=25)

tk.Label(
    header,
    text="URL SENTINEL",
    font=("Segoe UI", 27, "bold"),
    fg="#00e5ff",
    bg="#101722"
).pack()

tk.Label(
    header,
    text="CYBERSECURITY • URL THREAT ANALYSIS",
    font=("Segoe UI", 10),
    fg="#8293a8",
    bg="#101722"
).pack(pady=5)


# MAIN CONTAINER

main = tk.Frame(
    root,
    bg="#1b2736",
    padx=25,
    pady=25
)

main.pack(
    fill="both",
    expand=True,
    padx=35,
    pady=10
)


# INPUT SECTION

tk.Label(
    main,
    text="ENTER WEBSITE URL",
    font=("Segoe UI", 11, "bold"),
    fg="#ffffff",
    bg="#1b2736"
).pack(anchor="w")


url_entry = tk.Entry(
    main,
    font=("Segoe UI", 13),
    bg="#101722",
    fg="#ffffff",
    insertbackground="white",
    relief="flat"
)

url_entry.pack(
    fill="x",
    pady=12,
    ipady=12
)

url_entry.bind(
    "<Return>",
    lambda event: start_analysis()
)


# BUTTONS

button_frame = tk.Frame(
    main,
    bg="#1b2736"
)

button_frame.pack(
    fill="x",
    pady=10
)


analyze_button = tk.Button(
    button_frame,
    text="ANALYZE URL",
    command=start_analysis,
    bg="#00bcd4",
    fg="#101722",
    font=("Segoe UI", 11, "bold"),
    relief="flat",
    cursor="hand2",
    padx=20,
    pady=10
)

analyze_button.pack(
    side="left",
    fill="x",
    expand=True,
    padx=(0, 8)
)


tk.Button(
    button_frame,
    text="CLEAR",
    command=clear_all,
    bg="#344458",
    fg="white",
    font=("Segoe UI", 11, "bold"),
    relief="flat",
    cursor="hand2",
    padx=20,
    pady=10
).pack(
    side="right",
    fill="x",
    expand=True,
    padx=(8, 0)
)


# RESULT STATUS

status_frame = tk.Frame(
    main,
    bg="#1b2736"
)

status_frame.pack(
    fill="x",
    pady=20
)


result_label = tk.Label(
    status_frame,
    text="WAITING FOR ANALYSIS",
    font=("Segoe UI", 15, "bold"),
    fg="#aaaaaa",
    bg="#1b2736"
)

result_label.pack(side="left")


score_label = tk.Label(
    status_frame,
    text="--/100",
    font=("Segoe UI", 22, "bold"),
    fg="white",
    bg="#1b2736"
)

score_label.pack(side="right")


# RESULT BOX

tk.Label(
    main,
    text="SECURITY REPORT",
    font=("Segoe UI", 11, "bold"),
    fg="#00e5ff",
    bg="#1b2736"
).pack(anchor="w", pady=(5, 10))


result_box = tk.Text(
    main,
    height=12,
    bg="#101722",
    fg="#d6e4f0",
    font=("Consolas", 10),
    relief="flat",
    padx=15,
    pady=15,
    wrap="word"
)

result_box.pack(
    fill="both",
    expand=True
)


# FOOTER

tk.Label(
    root,
    text="URL SENTINEL | RULE-BASED SECURITY ENGINE",
    font=("Segoe UI", 9),
    fg="#65778d",
    bg="#101722"
).pack(pady=12)


root.mainloop()