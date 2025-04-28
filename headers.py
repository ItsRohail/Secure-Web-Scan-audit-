#!/usr/bin/env python3
# SecureWeb Scan is a Web Applications Security Scanner

import urllib.request
import re
import time

# Terminal colors
class colors:
    def __init__(self):
        self.green = "\033[92m"
        self.blue = "\033[94m"
        self.bold = "\033[1m"
        self.yellow = "\033[93m"
        self.red = "\033[91m"
        self.end = "\033[0m"

ga = colors()

# HTTP Header Keys
class HTTP_HEADER:
    HOST = "Host"
    SERVER = "Server"

# Global opener with User-Agent
class UserAgent(urllib.request.FancyURLopener):
    version = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:22.0) Gecko/20100101 Firefox/22.0'

# Deprecated in Python 3, use build_opener instead:
useragent = urllib.request.build_opener()
useragent.addheaders = [('User-agent', UserAgent.version)]

def headers_reader(url):
    print(ga.bold + "\n [!] Fingerprinting the backend Technologies." + ga.end)

    try:
        response = useragent.open(url)
        code = response.getcode()

        if code == 200:
            print(ga.green + " [!] Status code: 200 OK" + ga.end)
        elif code == 404:
            print(ga.red + " [!] Page was not found! Please check the URL \n" + ga.end)
            exit()
        
        headers = response.headers
        host = url.split("/")[2]
        server = headers.get(HTTP_HEADER.SERVER, "Unknown")

        print(ga.green + " [!] Host: " + str(host) + ga.end)
        print(ga.green + " [!] WebServer: " + str(server) + ga.end)

        # Detect powered-by headers
        for key, value in headers.items():
            if "x-powered-by" in key.lower():
                print(ga.green + " [!] " + key + ": " + value + ga.end)

    except Exception as e:
        print(ga.red + f" [!] Error reading headers: {e}" + ga.end)
