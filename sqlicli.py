import requests
import urllib3
from bs4 import BeautifulSoup
import re
import argparse
import sys
from diff import difference

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def has_parameters(url):
    if '?' in url:
        base_url, params_str = url.split('?', 1)
        if '=' in params_str:
            return True
    return False

def perform_request(url, sql_payload, method, post_data=None):
    if method == 'GET':
        r = requests.get(url + sql_payload, verify=False, proxies=proxies)
    elif method == 'POST':
        r = requests.post(url, data=post_data, verify=False, proxies=proxies)
    else:
        raise ValueError("Invalid method specified.")
    return r



def main():
    parser = argparse.ArgumentParser(description="SQL Injection Exploiter")
    parser.add_argument('-u', help='Enter URL', dest='url')
    parser.add_argument('-m', help='Enter method', dest='method')
    parser.add_argument('-d', help='Enter post data', dest='post_data')
    parser.add_argument('-o', help='save file', dest='file', action="store_true")
    args = parser.parse_args()
    arged = False
    def help():
        print("\033[92mSQL INJECTION\033[0m")
        print ('''usage: sqlicli.py [-h] [-u URL] [-m METHOD] [-d POST_DATA]

        optional arguments:
        -h, --help    show this help message and exit
        -u URL        Enter url
        -m METHOD     Enter request method
        -d DATA       Enter your post data''')

    
if __name__ == '__main__':
    main()