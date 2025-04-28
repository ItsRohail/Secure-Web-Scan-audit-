#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SecureWeb Scan
# A Simple Web Application Security Scanner

import re
import urllib
from headers import *
from vulnz import *

# Define ANSI color codes
class ga:
    green = '\033[92m'
    red = '\033[91m'
    bold = '\033[1m'
    end = '\033[0m'

print(ga.green + r'''                                                       
   _____                                           
  / ____|                                    
 | (___   ___  ___ _   _ _ __ ___   
  \___ \ / _ \/ __| | | | '__/ _ \   
  ____) |  __/ (__| |_| | | |  __/    
 |_____/ \___|\___|\__,_|_|  \___|                 
                                                                  
              Web Application Security Scanner
****************************************************************************
*  "Secure Web Scan"                                                       *
*  Supports: Remote Code Execution (RCE), Cross-Site Scripting (XSS),      *
*            SQL Injection (SQLi)                                          *
*  Author: Your Name                                                       *
*  For Educational and Ethical Testing Purposes                            *
****************************************************************************
''' + ga.end)


def urls_or_list():
    url_or_list = input(" [!] Scan URL or List of URLs? [1/2]: ")
    if url_or_list == "1":
        url = input(" [!] Enter the URL: ")
        if "?" in url:
            rce_func(url)
            xss_func(url)
            error_based_sqli_func(url)
        else:
            print(ga.red + "\n [Warning] " + ga.end + ga.bold + f"{url}" + ga.end + ga.red + " is not a valid URL." + ga.end)
            print(ga.red + " [Warning] Please enter a full URL, e.g., http://site.com/page.php?id=value \n" + ga.end)
    elif url_or_list == "2":
        urls_list = input(ga.green + " [!] Enter the list file name (e.g., list.txt): " + ga.end)
        try:
            with open(urls_list) as f:
                open_list = f.readlines()
            for line in open_list:
                url = line.strip()
                if "?" in url:
                    print(ga.green + f"\n [!] Now Scanning {url}" + ga.end)
                    rce_func(url)
                    xss_func(url)
                    error_based_sqli_func(url)
                else:
                    print(ga.red + "\n [Warning] " + ga.end + ga.bold + f"{url}" + ga.end + ga.red + " is not a valid URL." + ga.end)
                    print(ga.red + " [Warning] Please enter a full URL, e.g., http://site.com/page.php?id=value \n" + ga.end)
        except FileNotFoundError:
            print(ga.red + " [!] File not found. Please check the filename and try again." + ga.end)

urls_or_list()
