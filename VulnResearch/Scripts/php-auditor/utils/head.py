# File: head.py
# Author: github.com/bxsic-fr
# Updated: 07th May 2025
# Sentinel is a python tool to check for common vulnerabilities
# Version 1.0.0

from colorama import Fore, Style, init

ascii_header = """      ::::::::  :::::::::: ::::    ::: ::::::::::: ::::::::::: ::::    ::: :::::::::: :::  
    :+:    :+: :+:        :+:+:   :+:     :+:         :+:     :+:+:   :+: :+:        :+:   
   +:+        +:+        :+:+:+  +:+     +:+         +:+     :+:+:+  +:+ +:+        +:+    
  +#++:++#++ +#++:++#   +#+ +:+ +#+     +#+         +#+     +#+ +:+ +#+ +#++:++#   +#+     
        +#+ +#+        +#+  +#+#+#     +#+         +#+     +#+  +#+#+# +#+        +#+      
#+#    #+# #+#        #+#   #+#+#     #+#         #+#     #+#   #+#+# #+#        #+#       
########  ########## ###    ####     ###     ########### ###    #### ########## ########## 

                          Author: github.com/bxsic-fr"""

banner = """
          #-----------------------------#           
          #   Sentinel - PHP Auditor    #
          # Author: github.com/bxsic-fr #
          #-----------------------------#"""

infos = f"""
    {Fore.BLUE}[0]{Style.RESET_ALL} : Commentary including code which has potential vulnerability
    {Fore.YELLOW}[1]{Style.RESET_ALL} : Warning : Verify source of the variable in in the parameters of the function. If a user can modify any values...
    {Fore.RED}[2]{Style.RESET_ALL} : Vulnerability detected
"""

def main(func):
  def wrp():
    init()
    print(ascii_header + infos)
    func()
  return wrp
