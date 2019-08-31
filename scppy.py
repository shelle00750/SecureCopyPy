#!/usr/bin/python
# -*- coding: utf-8 -*-

import os,os.path,sys,traceback,socket,subprocess,shutil,getpass,pexpect
from pexpect import *
from time import sleep

from colorama import init
from termcolor import cprint 
from pyfiglet import figlet_format

init(strip=not sys.stdout.isatty())
    
exit_msg = "\033[3;91m\n[++] Shutting down..\n\033[3;m"

cprint(figlet_format('SecureCopyPy', font='doom'),
       'green', attrs=['bold'])
       
print("""\033[1;36m By shell.e00750..\033[1;m
""")
print(""" \033[1;36m
Options file transfer protocol¯\_(ツ)_/¯\033[1;m
""")

def getpath_desktop():

    if os.name == "posix":
	# This is the Linux Path
        path = os.getenv('HOME') + '/Desktop'
    else:
	#This is the OS X Path
	path = os.path.join(os.path.expanduser("~"), "Desktop")
         
    if not os.path.isdir(path):
        sys.exit(0)
    return path

def send_command(child,cmd):
    child.sendline(cmd)
    print child.before
    child.interact()
  
def main():
    
    host = ''
    user = ''
    port = ''
    password = ''
    path_srv = '/tmp'
    
    try:
	def scp(user, host, port, password,path_srv):
	    
	    try:
		path = getpath_desktop()
		pathfi = '%s' % path
	    except Exception, e:
		    print '[!] %s' % (e)
	    
	    print ("\n\033[1;36m[1] - \033[1;mfolders and directories.\033[37m")
	    print ("\033[1;36m[2] - \033[1;mFile.deb\033[37m")
	    print ("\033[1;36m[3] - \033[1;mFile tar.gz\033[37m")
	    print ("\033[1;36m[4] - \033[1;mFile tar.bz2\033[37m")
	    print ("\033[1;36m[5] - \033[1;mPython\033[37m")
	    print ("\033[1;36m[6] - \033[1;mBash\033[37m")
	    print ("\033[1;36m[7] - \033[1;mHtml\033[37m")
	    print ("\033[1;36m[8] - \033[1;mPHP\033[37m")
	    print ("\033[1;36m[9] - \033[1;mCSS\033[37m")
	    print ("\033[1;36m[10] - \033[1;mJS\033[37m")
	    print ("\033[1;36m[11] - \033[1;mClose\n\033[37m")
            
	    try:
	       option =(int(raw_input("\033[1;36m[?] - \033[1;moption:\033[37m")))
	    except ValueError:
		print("\033[1;91m\n[!] Error : Invalid option entered.\n\033[37m")
		scp(user, host, port, password,path_srv)
		
	    if option == 1:

		action_scp = raw_input("\n\033[3;34mscp -rp -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view folders python on desktop.\033[3;34m)" % (port)).strip()

		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(""):
			source = file
			print "[+]%s" % source

		directories = raw_input("\n\033[3;34mscp -rp -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		if os.path.isdir(pathfi +'/'+ directories) and os.access(pathfi +'/'+ directories, os.R_OK):
		    action_scp = raw_input("\n\033[3;34mscp -rp -P \033[3;34m%s\033[3;34m \033[3;34m%s\033[3;34m/%s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,pathfi,directories)).strip()
		
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -rp -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,directories,user,host,path_srv)).strip()
		    
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":

			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + directories + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
					'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
				    '[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child 
			

		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
	    
	    if option == 2:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file .deb on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".deb"):
			source = file
			print "[+]%s" % source
		
		action_deb = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_deb) and os.access(pathfi + '/' + action_deb, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_deb)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_deb,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":

			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_deb + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    
			    
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
			
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\033[34m\n")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
		    
	    
	    if option == 3:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file tar.gz on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".tar.gz"):
			source = file
			print "[+]%s" % source
		
		action_tar_gz = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_tar_gz) and os.access(pathfi + '/' + action_tar_gz, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_tar_gz)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_tar_gz,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":

			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_tar_gz + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\033[34m\n")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)

	    
	    if option == 4:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file tar.bz2 on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".tar.bz2"):
			source = file
			print "[+]%s" % source
		
		action_tar_bz2 = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_tar_bz2) and os.access(pathfi + '/' + action_tar_bz2, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_tar_bz2)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_tar_bz2,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":

			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_tar_bz2 + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m\n")
		    scp(user, host, port, password,path_srv)
		    
		    
	    if option == 5:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file python on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".py"):
			source = file
			print "[+]%s" % source
		
		action_py = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_py) and os.access(pathfi + '/' + action_py, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_py)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_py,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":

			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_py + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
		    
	    if option == 6:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file bash on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".sh"):
			source = file
			print "[+]%s" % source
		
		action_sh = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_sh) and os.access(pathfi + '/' + action_sh, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_sh)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_sh,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":
			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_sh + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
		    
	    if option == 7:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file HTML on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".html"):
			source = file
			print "[+]%s" % source
		
		action_html = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_html) and os.access(pathfi + '/' + action_html, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_html)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_html,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":
			
			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_html + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
		    
	    if option == 8:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file PHP on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".php"):
			source = file
			print "[+]%s" % source
		
		action_php = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_php) and os.access(pathfi + '/' + action_php, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_php)).strip()

		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_php,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":
			
			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_php + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
		    
	    if option == 9:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file CSS on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".css"):
			source = file
			print "[+]%s" % source
		
		action_css = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_css) and os.access(pathfi + '/' + action_css, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_css)).strip()
		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_css,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":
    
			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_css + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)
		    

	    if option == 10:

		action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33mEnter to view file JavaScript on desktop.\033[3;34m)" % (port)).strip()
	    
		files_store = os.listdir(path)
		for file in files_store:
		    if file.endswith(".js"):
			source = file
			print "[+]%s" % source

		action_js = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s \033[3;34m(\033[3;33m...\033[3;34m):" % (port)).strip()
		
		if os.path.isfile(pathfi + '/' + action_js) and os.access(pathfi + '/' + action_js, os.R_OK):

		    action_scp = raw_input("\n\033[3;34mscp -r -P \033[3;34m%s\033[3;34m %s\033[3;34m \033[3;34m(\033[3;33mEnter to next.\033[3;34m)" % (port,action_js)).strip()

		    print("\033[3;34m\n[+]Enter (\033[3;33mrun\033[3;34m) to execute the (\033[3;33mscp\033[3;34m) command.\n\033[3;m")
		    action_run = raw_input("\033[3;34mscp -r -P \033[3;34m%s\033[3;34m\033[3;34m %s/\033[3;34m%s\033[3;34m\033[3;34m %s@%s\033[3;34m\033[3;34m:%s:\033[3;34m" % (port,pathfi,action_js,user,host,path_srv)).strip()
	        
		    if action_run == "back":
			scp(user, host, port, password,path_srv)
		    elif action_run == "exit":
			sys.exit(exit_msg)	
		    elif action_run == "run":
			
			ssh_newkey = 'Are you sure you want to continue connecting'
	    
			connStr = 'scp -r -P '+ port + ' ' + '%s/' % pathfi + action_js + ' ' + user + '@' + host+ ':' + path_srv

			child = pexpect.spawn(connStr)
			ret = child.expect([pexpect.TIMEOUT, ssh_newkey,\
				'[P|p]assword:'])
			if ret == 0:
			    print '[-] Error Connecting'
			    return
    
			if ret == 1:
			    child.sendline('yes')
			    ret = child.expect([pexpect.TIMEOUT, \
					'[P|p]assword:'])
			    if ret == 0:
				print '[-] Error Connecting'
				return
    
			child.sendline(password)
			return child
		
		    else:
			print("\033[0;91m\n[!] Error : Command not found.\n\033[34m")
			scp(user, host, port, password,path_srv)#'''
			
		else:
		    print("\033[0;91m\n[!] Error : Either the file is missing or not readable.\n\033[34m")
		    scp(user, host, port, password,path_srv)

	    elif option == 11:
		print("..")
		sleep(1)
		print("....")
		sleep(1)
		sys.exit(exit_msg)
		quit()
		
	    else:
		print("\033[0;91m\n[!] Error : Invalid option entered.\033[37m\n")
		scp(user, host, port, password,path_srv)
    
	child = scp(user, host, port, password,path_srv)
	send_command(child, 'Done..!')
	scp(user, host, port, password,path_srv)

    except KeyboardInterrupt:
	print ("\n" + exit_msg)
	
	
	sleep(1)
    except Exception:
	traceback.print_exc(file=sys.stdout)
	sys.exit(0)#'''

if __name__ == '__main__':
    main()
