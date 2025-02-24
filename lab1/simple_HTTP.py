#!/usr/bin/env python3
import requests

url = "http://ipinfo.io/ip"
headers = {
    "User-Agent": "curl/7.88.1",
    "Accept": "*/*"
}

response = requests.get(url, headers=headers)
print(response.text.strip())