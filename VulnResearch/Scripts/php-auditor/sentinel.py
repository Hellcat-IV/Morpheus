# File: auditor.py
# Author: github.com/bxsic-fr
# Updated: 07th May 2025
# Sentinel is a python tool to check for common vulnerabilities
# Version 1.0.0

from colorama import Fore, Style, init
import re, os, contextlib, mmap, sys
from utils.head import main
from utils.vuln import *  # importing regex template for common vulnerabilities (vuln_patterns)

def search_reg(_path, reg_val, vuln_tested): # searching for vulnerability payload
    regex = re.compile(reg_val, re.IGNORECASE)
    with open(_path, 'r') as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_COPY)) as txt:
            for i, line in enumerate(bytes(txt).decode('utf-8').splitlines()):

                for match in re.finditer(regex, line):
                  _line = line.strip()

                  if _line[0] == '/': # if the line is commentary
                    highlighted_line = _line.replace(match.group(), f"{Fore.BLUE}{match.group()}{Style.RESET_ALL}")
                    print(f"{Fore.BLUE}[0]{Style.RESET_ALL} [{_path.split('/')[-1]}] Found {Fore.BLUE}Commentary{Style.RESET_ALL} on line {i+1}: {highlighted_line}")

                  elif (vuln_tested == 'Command Execution') or (vuln_tested == 'Code Execution'):

                    if not "$_" in _line: # if variables are local and not dynamic as user requets
                      highlighted_line = _line.replace(match.group(), f"{Fore.YELLOW}{match.group()}{Style.RESET_ALL}")
                      print(f"{Fore.YELLOW}[1]{Style.RESET_ALL} [{_path.split('/')[-1]}] Found {Fore.YELLOW}{vuln_tested}{Style.RESET_ALL} possible on line {i+1}: {highlighted_line}")

                  else:
                    highlighted_line = _line.replace(match.group(), f"{Fore.RED}{match.group()}{Style.RESET_ALL}")
                    print(f"{Fore.RED}[2]{Style.RESET_ALL} [{_path.split('/')[-1]}] Found {Fore.RED}{vuln_tested}{Style.RESET_ALL} on line {i+1}: {highlighted_line}")

def search_for(filename): # rotating lines for differents attacks method
    for vuln_type, patterns in vuln_patterns.items():
        #print(f"Searching for {vuln_type}")
        for pattern in patterns:
            file_path = os.path.join(os.getcwd(), filename)
            search_reg(file_path, pattern, vuln_type)

@main
def _r():
  
  init()
  
  global fnme

  dirlistfiles = []
  
  try:
    fnme = sys.argv[1]
    #print("Filename : ", str(fnme))
  except Exception as e:
      print(str(e.args))
    #print("Usage: " + str(__file__).split("/")[-1] + " filename.php - for single script scan")
    #print("Usage: " + str(__file__).split("/")[-1] + " foldername   - for project folder scan")
    #exit(1)

  print("Filename : ", str(fnme))
  if not '.php' in fnme:
      print("Usage of project folder")
      for file in os.listdir(os.getcwd() + '/' + fnme):
          #print('FFF : ' + file)
          if file.endswith('.php'):
              print('FFF PHP OUI : ' + file)
              dirlistfiles.append(fnme + '/' + file)
              #print("NEW DIRLISTFILES : " + str(dirlistfiles))

  try:
    #print("DIRLISTFILES : " + str(dirlistfiles))
    if len(dirlistfiles) > 1:
        for fil_e in dirlistfiles:
            search_for(fil_e)
    else:
        search_for(fnme)
  except Exception as e:
    print(f'{Fore.YELLOW}Error: {str(e)}{Style.RESET_ALL}')

if __name__ == '__main__':
  _r()
