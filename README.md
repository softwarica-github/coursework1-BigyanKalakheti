# SQL Injection Exploiter

## Introduction
This repository contains Python scripts that can be used for SQL injection exploitation on web applications. The scripts utilize the requests library for making HTTP requests, urllib3 to disable SSL warnings, and BeautifulSoup for HTML parsing.

## Prerequisites
Before using these scripts, make sure you have the following installed:

Python 3.x
Required Python libraries (requests, urllib3, bs4)

## Instructions
### SQL Injection Exploiter (GUI Version)
Usage
Run the script sql_injection_gui.py.
Enter the target URL in the provided entry field.
Select the method (GET or POST) using the checkbox.
If using POST, provide the POST data in the respective entry field.
Optionally, check the "Try Login" checkbox to attempt a login using a predefined SQL payload.
Click the "Execute SQL Injection" button to initiate the exploitation.
View the results in the displayed text area.
Notes
The script includes an option to save the results to a file through the menu.

## SQL Injection Exploiter (CLI Version)
Usage
Run the script sql_injection_cli.py using the command line.
```bash
python sql_injection_cli.py -u <URL> -m <METHOD> -d <POST_DATA> -o 
```
Replace <URL> with the target URL, <METHOD> with the request method (GET or POST), and <POST_DATA> with the POST data if using the POST method.
Optionally, include the -o flag to save the results to a file.
Notes
If POST data is required, the script will prompt you to enter it.
The script supports basic command-line arguments for ease of use.

## Disclaimer
These scripts are provided for educational and informational purposes only. The use of these scripts for unauthorized access or any malicious activities is strictly prohibited. Use them responsibly and only on systems for which you have explicit permission. The authors and contributors are not responsible for any misuse or damage caused by these scripts.

## Contributors
[Bigyan Kalakheti]
Youtube Link : https://youtu.be/QT5hn9-TM44?si=cKvhmSR_Amyx4vkS
Feel free to contribute to this project by opening issues or submitting pull requests.