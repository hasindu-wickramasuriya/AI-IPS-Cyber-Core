"""Safe smoke check for the local AI-IPS dashboard.

Checks the already-running web app over HTTP. It does not sniff packets,
change firewall rules, or generate attack traffic.
"""
from urllib.error import URLError, HTTPError
from urllib.request import build_opener, HTTPCookieProcessor
from http.cookiejar import CookieJar
from urllib.parse import urlparse

BASE_URL = "http://127.0.0.1:5000"
opener = build_opener(HTTPCookieProcessor(CookieJar()))


def check(path):
    try:
        with opener.open(f"{BASE_URL}{path}", timeout=5) as response:
            return response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        raise RuntimeError(f"{path}: got HTTP {exc.code}") from exc
    except URLError as exc:
        raise RuntimeError(f"Cannot reach dashboard at {BASE_URL}: {exc.reason}") from exc


try:
    login_page = check("/login")
    if "username" not in login_page.lower() or "password" not in login_page.lower():
        raise RuntimeError("Login page loaded, but username/password fields were not found")

    # The home page should redirect unauthenticated users to the login page.
    check("/")
    with opener.open(BASE_URL, timeout=5) as response:
        final_path = urlparse(response.geturl()).path
        if final_path != "/login":
            raise RuntimeError(f"Expected unauthenticated home page to redirect to /login; got {response.geturl()}")

    print("PASS: dashboard is reachable at", BASE_URL)
    print("PASS: login page responds and contains username/password fields")
    print("PASS: protected home page redirects to login when signed out")
    print("This check uses HTTP only; no packet capture or firewall changes were made.")
except Exception as exc:
    print("FAIL:", exc)
    raise SystemExit(1)
