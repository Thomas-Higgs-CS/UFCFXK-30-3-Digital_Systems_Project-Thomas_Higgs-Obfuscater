#########################################
#	Title: Obfuscater					#
#	Author: Thomas Higgs				#
#	Purpose: Data obfuscation			#
#	Last update: 21/04/2020				#
#	Version: 7.0						#
#	To do Next: - Clear password var 	#
#########################################

# Import Libaries #
import os
import re
import hashlib
import datetime
import webbrowser
import tkinter as tk
import base64
import tkinter.font as tkFont
from tkinter import *
from tkinter import ttk
from pathlib import Path
from tkinter import messagebox
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import Blowfish
from datetime import datetime

# Function to read file contents (used by both classes) #
def fileread(file):
	global content 
	with open(file, 'rb') as f:	# Function to read file contents as bytes #
		content = f.read()
		f.close()

# Function to get current time (used by both classes) #
def gettime():
	global current_time
	current_time = datetime.now()
	current_time = str(current_time)

# Function to check if a file exists & is accessible #
def pathcheck(file):
	global value
	value = 0
	file = Path(file)
	if file.exists():
		try:
			os.rename(file, file)
			return
		except OSError as c:
			messagebox.showinfo("Warning", "The specified file is being used by another process!\nPlease close any processes using the file and try again.")
			value = 1
			return
	else:
		messagebox.showinfo("Warning", "The specified file path could not be found!")
		value = 2
		return

# Function to clear passwords from memory (used by both classes) #
def clear(passwd, password, key):
	char = "*"
	for elem in passwd:
		char = char + "*"
	passwd = char * 2
	for elem in password:
		char = char + "*"
	password = char * 2
	for elem in key:
		char = char + "*"
	key = char * 2

# Application class #
class Application(Frame):										# Func to build notebook #					
	def __init__(self, parent=None):							
		Frame.__init__(self, parent) 
		self.notebook = ttk.Notebook(width=500, height=650)
		self.add_tab()
		self.notebook.grid(row=0)

	def add_tab(self):											# Func to add GUI frames #
		tb1 = EmTb(self.notebook)								
		self.notebook.add(tb1, text="Embed")
		tb3 = ExTb(self.notebook)
		self.notebook.add(tb3, text="Extract")
		Tb3 = HelpTb(self.notebook)
		self.notebook.add(Tb3, text="Help")
		self.notebook.pack(expand=0, fill="both")

# EmTb class #
class EmTb(Frame):
	def __init__(self, name, *args, **kwargs):					# Func to add GUI inputs etc #
		Frame.__init__(self, *args, **kwargs)
		self.style = ttk.Style()
		self.style.theme_create("AppStyle", parent="alt", settings={"TNotebook.Tab": {"configure":{"padding": [10,10], "background": "#F0F0F0"},}})
		self.style.theme_use("AppStyle") 
		self.titlefont = tkFont.Font(self, family="Helvetica", size=20)
		self.emtitl = tk.Label(self, text="Embed", font=self.titlefont, bg="#F0F0F0")	
		self.emtitl.grid(row=0, column=0, padx=202, pady=10)

		self.cfil_lb = tk.Label(self, text="Cover File: ", bg="#F0F0F0")	# Cover file input #
		self.cfil_lb.place(x=15, y=55)
		self.cfilen = tk.Entry(self)
		self.cfilen.place(x=15, y=85, width=465)

		self.hfil_lb = tk.Label(self, text="Hidden File: ", bg="#F0F0F0")	# Hidden file input #
		self.hfil_lb.place(x=15, y=125)
		self.hfilen = tk.Entry(self)
		self.hfilen.place(x=15, y=155, width=465)

		en_choice = [ 'AES', 'DES', 'Blowfish' ]		# encryption drop down #
		self.emdefault = StringVar(self)	
		self.emdefault.set('AES')
		self.en_lb = tk.Label(self, text="Encryption Algorithm: ", bg="#F0F0F0")
		self.en_lb.place(x=15, y=195)
		self.en_drop = OptionMenu(self, self.emdefault, *en_choice)
		self.en_drop.place(x=15, y=225, width=465)

		self.passwd_lb = tk.Label(self, text="Password: ", bg="#F0F0F0")	 # password input #
		self.passwd_lb.place(x=15, y=285, width=465)
		self.passwdem = tk.Entry(self, show="*")
		self.passwdem.place(x=15, y=315, width=465)

		self.butn = tk.Button(self, text="Embed", command=self.embed)	# Button #
		self.butn.place(x=135, y=365, width=232)

		self.emtext = tk.Text(self, height=8)		# Text box for log messages #
		self.emtext.place(x= 15, y= 415, width=465)
		self.emtext.tag_config('Error', foreground="red")
		self.emtext.tag_config('Complete', foreground="green")

	def embed(self):
		cfile = self.cfilen.get()	# Get inputs from widgets #
		hfile = self.hfilen.get()
		encryp = self.emdefault.get()
		passwd = self.passwdem.get()

		flag = 'ENCRYPTE'	# flag used for decryption check #

		if cfile == "":
			messagebox.showinfo("Warning", "No cover file given!")
			gettime()																		
			self.emtext.insert(tk.END, current_time + ": No cover file given!" + '\n', 'Error')
			return

		if hfile == '':
			messagebox.showinfo("Warning", "No file to hide given!")
			gettime()																		
			self.emtext.insert(tk.END, current_time + ": No hidden file given!" + '\n', 'Error')
			return

		if passwd == "":
			messagebox.showinfo("Warning", "No password given!")
			gettime()																		
			self.emtext.insert(tk.END, current_time + ": No pasword given!" + '\n', 'Error')
			return

		gettime()																
		self.emtext.insert(tk.END, current_time + ": Reading cover file." + '\n')		# Get contents of both files #
		file = cfile 
		pathcheck(file)
		if value == 1:
			self.emtext.insert(tk.END, current_time + ": File in use!" + '\n', 'Error')
			return
		elif value == 2:
			self.emtext.insert(tk.END, current_time + ": File could not be found!" + '\n', 'Error')
			return
		fileread(file)
		ccontent = content
		gettime()																		
		self.emtext.insert(tk.END, current_time + ": Reading hidden file." + '\n')
		file = hfile
		pathcheck(file)
		if value == 1:
			self.emtext.insert(tk.END, current_time + ": File in use!" + '\n', 'Error')
			return
		elif value == 2:
			self.emtext.insert(tk.END, current_time + ": File could not be found!" + '\n', 'Error')
			return
		fileread(file)
		hcontent = content 

		gettime()																	# Perform password check #														
		self.emtext.insert(tk.END, current_time + ": Checking password." + '\n')
		password = passwd.encode()			
		self.check_password(password)

		if self.value == 1:				# If password fails #
			gettime()																		
			self.emtext.insert(tk.END, current_time + ": password did not meet requirements!" + '\n', 'Error')
			self.passwdem.delete(0, 'end')
			return

		gettime()																		
		self.emtext.insert(tk.END, current_time + ": encrypting data." + '\n')

		if encryp == 'AES':			# encryption #
			salt = 'salt'.encode()		
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 16 * '\x00'
			mode = AES.MODE_CFB
			encryptor = AES.new(key, mode, IV=IV)
			flag = encryptor.encrypt(flag)
			hcontent = encryptor.encrypt(hcontent)
		elif encryp == 'DES':
			hcontent = self.pad(hcontent)
			salt = 'salt'.encode()		
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)	
			key = key[:8]													# Generate sha256 hash and then take first 8 bytes and use as key #
			IV =  "........"
			mode = DES.MODE_CFB
			encryptor = DES.new(key, mode, IV=IV)
			flag = encryptor.encrypt(flag)
			hcontent = encryptor.encrypt(hcontent)
		elif encryp == 'Blowfish':
			hcontent = self.pad(hcontent)
			salt = 'salt'.encode()	
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 8 * '\x00'
			mode = Blowfish.MODE_CFB
			encryptor = Blowfish.new(key, mode, IV=IV)
			flag = encryptor.encrypt(flag)
			hcontent = encryptor.encrypt(hcontent)

		gettime()																	# Calculate file length #																	
		self.emtext.insert(tk.END, current_time + ": Checking file length." + '\n')
		length = len(ccontent) + len(hcontent) + len(flag) + 4

		if length % 512 == 0:					# Checking if file can be divided by 512 #
			gettime()																											
			self.emtext.insert(tk.END, current_time + ": Adding padding." + '\n')
			hcontent = hcontent + b'\x00'

		percent = (length - len(ccontent))/len(ccontent)*100		# Calculate difference in file size #
		if percent > 100:
			message = messagebox.askquestion("Warning", "The hidden file's size will be considerably larger than the cover file after this operation. This may make your hidden file stand out.\n\nConsider using a larger cover file or compress your hidden file.\n\nDo you want to continue anyway?")
			if message == 'no':
				gettime()																	# Abort #																	
				self.emtext.insert(tk.END, current_time + ": Operation aborted." + '\n', 'Error')
				return

		gettime()																	# Overwriting file #																	
		self.emtext.insert(tk.END, current_time + ": Overwriting file." + '\n')
		self.em_write(hfile, ccontent, hcontent, flag)	

		gettime()																	# Chaning extension #																	
		self.emtext.insert(tk.END, current_time + ": Chaning extension." + '\n')
		null, extension = cfile.split('.', 1) 			
		if re.match('^[^.]*$', hfile):
			name = hfile
		else:
			name, null = hfile.split('.', 1)
		new_name = name + "." + extension
		
		try:
			os.rename(hfile, name + '.' + extension)
		except WindowsError:
			messagebox.showinfo("Warning", "The file: " + new_name +" already exists!\nPlease rename your hidden file.")
			gettime()
			self.emtext.insert(tk.END, current_time + ": File already exists!" + '\n', 'Error')
			return

		gettime()																																		
		self.emtext.insert(tk.END, current_time + ": Operation complete!" + '\n', 'Complete')

		self.cfilen.delete(0, 'end')	# Reset widgets #
		self.hfilen.delete(0, 'end')
		self.passwdem.delete(0, 'end')
		clear(passwd, password, key)

	def check_password(self, password):	# Checking the length of passwords #
		if len(password) < 8:
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using a longer password.")
			self.value = 1
		elif password.islower():
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using a mix of upper and lower case characters.")
			self.value = 1
		elif password.isalnum():
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using non alphanumeric characters.")
			self.value = 1
		elif re.match(b'[a-zA-Z]', password) is None:
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using a mix of alphabetic characters and numbers.")
			self.value = 1
		else:
			self.value = 0

	def em_write(self, hfile, ccontent, hcontent, flag): 	# Func to overwrite file #
		with open (hfile, 'wb') as f:	
			f.write(ccontent)
			f.close()
		with open (hfile, 'ab') as f:
			f.write(b"\x23\x23\x23\x23")
			f.close()
		with open (hfile, 'ab') as f:
			f.write(flag)
			f.close()
		with open (hfile, 'ab') as f:
			f.write(hcontent)
			f.close()

	def pad(self, hcontent):
		while len(hcontent) % 8 != 0:				# Paading for 8 bit encryption #
			gettime()																											
			self.emtext.insert(tk.END, current_time + ": Adding padding." + '\n')
			hcontent += b' '
		return hcontent

# EmTb class #
class ExTb(Frame):
	def __init__(self, name, *args, **kwargs):			# Func to add GUI inputs etc #
		Frame.__init__(self, *args, **kwargs)
		self.style = ttk.Style()
		self.style.theme_use("AppStyle") 
		self.titlefont = tkFont.Font(self, family="Helvetica", size=20)
		self.extitl = tk.Label(self, text="Extract", font=self.titlefont, bg="#F0F0F0")	
		self.extitl.grid(row=0, column=0, padx=202, pady=10)

		self.efil_lb = tk.Label(self, text="File: ", bg="#F0F0F0")	# File input #
		self.efil_lb.place(x=15, y=55)
		self.efilen = tk.Entry(self)
		self.efilen.place(x=15, y=85, width=465)

		self.exten_lb = tk.Label(self, text="Extension: ", bg="#F0F0F0")	# extension file input #
		self.exten_lb.place(x=15, y=125)
		self.extenen = tk.Entry(self)
		self.extenen.place(x=15, y=155, width=465)

		en_choice = [ 'AES', 'DES', 'Blowfish' ]		# Decryption drop down #
		self.exdefault = StringVar(self)	
		self.exdefault.set('AES')
		self.en_lb = tk.Label(self, text="Encryption Algorithm: ", bg="#F0F0F0")	
		self.en_lb.place(x=15, y=195)
		self.en_drop = OptionMenu(self, self.exdefault, *en_choice)
		self.en_drop.place(x=15, y=225, width=465)

		self.passwdLb = tk.Label(self, text="Password: ", bg="#F0F0F0") 	# password input #
		self.passwdLb.place(x=15, y=285, width=465)
		self.passwdex = tk.Entry(self, show="*")
		self.passwdex.place(x=15, y=315, width=465)

		self.butn = tk.Button(self, text="Extract", command=self.extract)	# Button #
		self.butn.place(x=135, y=365, width=232)

		self.extext = tk.Text(self, height=8)		# Text box for logs #
		self.extext.place(x= 15, y= 415, width=465)
		self.extext.tag_config('Error', foreground="red")
		self.extext.tag_config('Complete', foreground="green")

	def extract(self):
		efile = self.efilen.get()		# Get all inputs from widgets #
		extension = self.extenen.get()
		decryp = self.exdefault.get()
		passwd = self.passwdex.get()

		if efile == '':
			messagebox.showinfo("Warning", "No file given!")
			gettime()																		
			self.extext.insert(tk.END, current_time + ": No file given!" + '\n', 'Error')
			return

		if extension == '':
			messagebox.showinfo("Warning", "No extension given!")
			gettime()																		
			self.extext.insert(tk.END, current_time + ": No extension given!" + '\n', 'Error')
			return

		if passwd == '':
			messagebox.showinfo("Warning", "No password given!")
			gettime()																		
			self.extext.insert(tk.END, current_time + ": No pasword given!" + '\n', 'Error')
			return

		gettime()																 # Get contents of file #
		self.extext.insert(tk.END, current_time + ": Reading File." + '\n')
		file = efile 	
		pathcheck(file)
		if value == 1:
			self.emtext.insert(tk.END, current_time + ": File in use!" + '\n', 'Error')
			return
		elif value == 2:
			self.emtext.insert(tk.END, current_time + ": File could not be found!" + '\n', 'Error')
			return
		fileread(file)
		econtent = content

		pos = econtent.find(b'\x23\x23\x23\x23')	# Find marker and remove prior data #
		length = 400000000
		data = econtent[pos:pos+length]
		data = re.sub(b"(\x23\x23\x23\x23)", b'', data)

		cipher_text = data 		# Asigning data to new variable #
		password = passwd.encode()

		gettime()																											
		self.extext.insert(tk.END, current_time + ": Decrypting file." + '\n')

		if decryp == 'AES':				# Decryption #
			salt = 'salt'.encode()
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 16 * '\x00'
			mode = AES.MODE_CFB
			decryptor = AES.new(key, mode, IV=IV)
			new_data = decryptor.decrypt(cipher_text)
		elif decryp == 'DES':
			salt = 'salt'.encode()		
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			key = key[:8]													# Generate sha256 hash and then take first 8 bytes and use as key #
			mode = DES.MODE_CFB
			decryptor = DES.new(key, DES.MODE_ECB)
			new_data = decryptor.decrypt(cipher_text)
		elif decryp == "Blowfish":
			salt = 'salt'.encode()
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 8 * '\x00'
			mode = Blowfish.MODE_CFB
			decryptor = Blowfish.new(key, mode, IV=IV)
			new_data = decryptor.decrypt(cipher_text)

		gettime()																										
		self.extext.insert(tk.END, current_time + ": Verifying decryption." + '\n')

		if re.match(b'^ENCRYPTE', new_data):				# Check decryption #
			new_data = re.sub(b"ENCRYPTE", b'', new_data)
		else:
			messagebox.showinfo("Warning", "Incorrect password!")
			gettime()																										
			self.extext.insert(tk.END, current_time + ": Incorrect password!" + '\n', 'Error')
			self.passwdEx.delete(0, 'end')
			return		

		gettime()																	# Overwrite file # 																				
		self.extext.insert(tk.END, current_time + ": Overwriting file." + '\n')
		self.exwrite(efile, new_data) 		

		gettime()																	# Change extension # 																				
		self.extext.insert(tk.END, current_time + ": Changing extension." + '\n')
		name, null = efile.split('.', 1)			
		os.rename(efile, name + '.' + extension)

		gettime()																																		
		self.extext.insert(tk.END, current_time + ": Operation complete!" + '\n', 'Complete')

		self.efilen.delete(0, 'end')	# Reset all inputs #
		self.extenEn.delete(0, 'end')
		self.passwdEx.delete(0, 'end')
		clear(passwd, password, key)

	def exwrite(self, efile, new_data):
		with open(efile, 'wb') as f:	# Function to overwrite file with extracted data #
			f.write(new_data)
			f.close()

class HelpTb(Frame):
	def __init__(self, name, *args, **kwargs):			# Initilise and add contents #
		Frame.__init__(self, *args, **kwargs)
		self.style = ttk.Style()
		self.style.theme_use("AppStyle") 
		self.titlefont = tkFont.Font(self, family="Helvetica", size=20)
		self.subtitlefont = tkFont.Font(self, family="Helvetica", size=14)
		self.hltitl = tk.Label(self, text="Help", font=self.titlefont, bg="#F0F0F0")	
		self.hltitl.grid(row=0, column=0, padx=220, pady=10)

		self.hlemtitl = tk.Label(self, text="Embedding data", font=self.subtitlefont, bg="#F0F0F0")	
		self.hlemtitl.place(x=15, y=55)		
		self.hlem = tk.Label(self, text='''This system allows you to protect files by making them appear and function like other \nfiles.
											\nFor example you may have an important text document you wish to protect. Using this \nsystem you are can make that text document look and run like an .mp4 file.
											\nTo do this navigate to the "Embed" tab using the buttons along the top. Then enter a \nfile you want your hidden file to look like. This is called a cover file. Next enter the \nfile path of the file you wish to hide. Then choose an encryption algorigthm.\nAES is the most commonly used algorithm supported by this system and is the \nstrongest. Finally choose a strong password and click the "Embed" button.
											\nThe system will then encrypt your hidden file and add the cover file to the begining.
											\nPlease note this system does not store passwords. Data will be unrecoverable if \npasswords are forgotten!''', bg="#F0F0F0", anchor='w', justify='left')
		self.hlem.place(x=15, y=85, width=465)

		self.hlextitl = tk.Label(self, text="Extracting data", font=self.subtitlefont, bg="#F0F0F0")	
		self.hlextitl.place(x=15, y=350)	
		self.hlEx = tk.Label(self, text='''To recover data first, navigate to the "Extract" tab using the buttons along the top.\nThen enter the file you wish to extract data from. Next enter the original file's extension.\nIf the file had no extension then leave this field blank. Then choose the encryption \nalgorighm used to encrypt the original data. Finally enter the password which was used \nto embed the orginal data and press the "Extract" button.
											\nFiles will not be returned if incorrect passwords or algorithms are used.''', bg="#F0F0F0", anchor='w', justify='left')
		self.hlEx.place(x=15, y=380, width=465)

		self.vidtx = tk.Label(self, text="If you require more help, a tutorial can be found here: ", font=self.subtitlefont, bg="#F0F0F0")	
		self.vidtx.place(x=15, y=510)

		self.vidlnk = Label(self, text="https://youtu.be/4Nkk1Gv7KD0", fg="blue", cursor="hand2")
		self.vidlnk.place(x=140, y=540)
		self.vidlnk.bind("<Button-1>", self.link)

	def link(self, event):
		webbrowser.open_new('https://youtu.be/4Nkk1Gv7KD0')

# Run application #
if __name__ == "__main__":
	root = Tk()
	root.title("Obfuscater")
	ico = '''AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAIAAAAAAAAAQAACMuAAAjLgAAAAAAAAAAAAAAAAAAAAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/
			wAAAP8AAAAAAAAAAAAAAP8Awfj/GrTg/xq04P9Q0vf/UNL3/1DS9/8Awfj/GrTg/xq04P8atOD/GrTg/xq04P8AAAD/AAAAAAAAAAAAAAD/UNL3/1DS9/8atOD/GrTg/xq04P8AAAD/AAAA/1DS9/8Awfj/UNL
			3/1DS9/8atOD/AAAA/wAAAAAAAAAAAAAA/xq04P8atOD/GrTg/1DS9/8Awfj/AAAA/wAAAP8atOD/GrTg/xq04P9Q0vf/UNL3/wAAAP8AAAAAAAAAAAAAAP9Q0vf/AMH4/wDB+P8atOD/GrTg/wAAAP8AAAD/U
			NL3/wDB+P8atOD/GrTg/1DS9/8AAAD/AAAAAAAAAAAAAAD/GrTg/xq04P9Q0vf/UNL3/wAAAP8AAAD/AAAA/wAAAP9Q0vf/UNL3/wDB+P8Awfj/AAAA/wAAAAAAAAAAAAAA/1DS9/9Q0vf/GrTg/xq04P8AAAD
			/AAAA/wAAAP8AAAD/GrTg/1DS9/9Q0vf/UNL3/wAAAP8AAAAAAAAAAAAAAP8atOD/AMH4/wDB+P9Q0vf/UNL3/wAAAP8AAAD/AMH4/1DS9/8atOD/GrTg/wDB+P8AAAD/AAAAAAAAAAAAAAAAAAAA/wAAAP8AA
			AD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAA/wAAAP8AAAD/AAAAAAAAAAAAAAAAAAAAAAAAAP9LS0v/AAAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP+UlJT/AAAA/wAAAAAAAAAAAAAAAAAAAAAA
			AAD/S0tL/5SUlP8AAAD/AAAAAAAAAAAAAAAAAAAAAAAAAP/IyMj/S0tL/wAAAP8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP+UlJT/AAAA/wAAAAAAAAAAAAAAAAAAAAAAAAD/yMjI/wAAAP8AAAAAAAAAAAAAAAA
			AAAAAAAAAAAAAAAAAAAD/yMjI/8jIyP8AAAD/AAAA/wAAAP8AAAD/yMjI/8jIyP8AAAD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP9LS0v/S0tL/8jIyP+UlJT/lJSU/0tLS/8AAAD/AAAAAAAAAA
			AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/wAAAP/IyMj/lJSU/wAAAP8AAAD/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/wAAAP8AAAAAAAAAAAAAA
			AAAAAAAAAAAAAAAAAAAAAAAgAEAAIABAACAAQAAgAEAAIABAACAAQAAgAEAAIABAADAAwAAx+MAAMPDAADjxwAA4AcAAPAPAAD4HwAA/n8AAA=='''													# Base 64 encoded favicon #
	icon = base64.b64decode(ico)
	temp = "favicon.ico"
	with open("favicon.ico", "wb") as f:
		f.write(icon)
		f.close()
	root.iconbitmap(default="favicon.ico")
	os.remove(temp)
	root.minsize(500, 650)
	root.maxsize(500, 650)	
	app = Application(root)
	app.mainloop()