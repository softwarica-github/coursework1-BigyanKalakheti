import requests
import urllib3
from bs4 import BeautifulSoup
import re
import argparse
import sys
from diff import difference

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



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