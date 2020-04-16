#########################################
#	Title: Obfuscater					#
#	Author: Thomas Higgs				#
#	Purpose: Data obfuscation			#
#	Last update: 25/02/2020				#
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
	global Content 
	with open(file, 'rb') as f:	# Function to read file contents as bytes #
		Content = f.read()
		f.close()

# Function to get current time (used by both classes) #
def gettime():
	global CurrentTime
	CurrentTime = datetime.now()
	CurrentTime = str(CurrentTime)

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
def clear(Pass, password, key):
	char = "*"
	for elem in Pass:
		char = char + "*"
	Pass = char * 2
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
		Tb1 = EmTb(self.notebook)								
		self.notebook.add(Tb1, text="Embed")
		Tb2 = ExTb(self.notebook)
		self.notebook.add(Tb2, text="Extract")
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
		self.Titlefont = tkFont.Font(self, family="Helvetica", size=20)
		self.EmTitl = tk.Label(self, text="Embed", font=self.Titlefont, bg="#F0F0F0")	
		self.EmTitl.grid(row=0, column=0, padx=202, pady=10)

		self.CfilLb = tk.Label(self, text="Cover File: ", bg="#F0F0F0")	# Cover file input #
		self.CfilLb.place(x=15, y=55)
		self.CfilEn = tk.Entry(self)
		self.CfilEn.place(x=15, y=85, width=465)

		self.HfilLb = tk.Label(self, text="Hidden File: ", bg="#F0F0F0")	# Hidden file input #
		self.HfilLb.place(x=15, y=125)
		self.HfilEn = tk.Entry(self)
		self.HfilEn.place(x=15, y=155, width=465)

		EnChoice = [ 'AES', 'DES', 'Blowfish' ]		# Encryption drop down #
		self.EmDefault = StringVar(self)	
		self.EmDefault.set('AES')
		self.EnLb = tk.Label(self, text="Encryption Algorithm: ", bg="#F0F0F0")
		self.EnLb.place(x=15, y=195)
		self.EnDrop = OptionMenu(self, self.EmDefault, *EnChoice)
		self.EnDrop.place(x=15, y=225, width=465)

		self.PassLb = tk.Label(self, text="Password: ", bg="#F0F0F0")	 # Password input #
		self.PassLb.place(x=15, y=285, width=465)
		self.PassEm = tk.Entry(self, show="*")
		self.PassEm.place(x=15, y=315, width=465)

		self.Butn = tk.Button(self, text="Embed", command=self.embed)	# Button #
		self.Butn.place(x=135, y=365, width=232)

		self.EmText = tk.Text(self, height=8)		# Text box for log messages #
		self.EmText.place(x= 15, y= 415, width=465)
		self.EmText.tag_config('Error', foreground="red")
		self.EmText.tag_config('Complete', foreground="green")

	def embed(self):
		Cfile = self.CfilEn.get()	# Get inputs from widgets #
		Hfile = self.HfilEn.get()
		Encryp = self.EmDefault.get()
		Pass = self.PassEm.get()

		Flag = 'ENCRYPTE'	# Flag used for decryption check #

		if Cfile == "":
			messagebox.showinfo("Warning", "No cover file given!")
			gettime()																		
			self.EmText.insert(tk.END, CurrentTime + ": No cover file given!" + '\n', 'Error')

			return

		if Hfile == '':
			messagebox.showinfo("Warning", "No file to hide given!")
			gettime()																		
			self.EmText.insert(tk.END, CurrentTime + ": No hidden file given!" + '\n', 'Error')
			return

		if Pass == "":
			messagebox.showinfo("Warning", "No password given!")
			gettime()																		
			self.EmText.insert(tk.END, CurrentTime + ": No pasword given!" + '\n', 'Error')
			return

		gettime()																
		self.EmText.insert(tk.END, CurrentTime + ": Reading cover file." + '\n')		# Get contents of both files #
		file = Cfile 
		pathcheck(file)
		if value == 1:
			self.EmText.insert(tk.END, CurrentTime + ": File in use!" + '\n', 'Error')
			return
		elif value == 2:
			self.EmText.insert(tk.END, CurrentTime + ": File could not be found!" + '\n', 'Error')
			return
		fileread(file)
		CContent = Content
		gettime()																		
		self.EmText.insert(tk.END, CurrentTime + ": Reading hidden file." + '\n')
		file = Hfile
		pathcheck(file)
		if value == 1:
			self.EmText.insert(tk.END, CurrentTime + ": File in use!" + '\n', 'Error')
			return
		elif value == 2:
			self.EmText.insert(tk.END, CurrentTime + ": File could not be found!" + '\n', 'Error')
			return
		fileread(file)
		HContent = Content 

		gettime()																	# Perform password check #														
		self.EmText.insert(tk.END, CurrentTime + ": Checking password." + '\n')
		password = Pass.encode()			
		self.CheckPassword(password)

		if self.Value == 1:				# If password fails #
			gettime()																		
			self.EmText.insert(tk.END, CurrentTime + ": Password did not meet requirements!" + '\n', 'Error')
			self.PassEm.delete(0, 'end')
			return

		gettime()																		
		self.EmText.insert(tk.END, CurrentTime + ": Encrypting data." + '\n')

		if Encryp == 'AES':			# Encryption #
			salt = 'salt'.encode()		
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 16 * '\x00'
			mode = AES.MODE_CFB
			encryptor = AES.new(key, mode, IV=IV)
			Flag = encryptor.encrypt(Flag)
			HContent = encryptor.encrypt(HContent)
		elif Encryp == 'DES':
			HContent = self.pad(HContent)
			salt = 'salt'.encode()		
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)	
			key = key[:8]													# Generate sha256 hash and then take first 8 bytes and use as key #
			IV =  "........"
			mode = DES.MODE_CFB
			encryptor = DES.new(key, mode, IV=IV)
			Flag = encryptor.encrypt(Flag)
			HContent = encryptor.encrypt(HContent)
		elif Encryp == 'Blowfish':
			HContent = self.pad(HContent)
			salt = 'salt'.encode()	
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 8 * '\x00'
			mode = Blowfish.MODE_CFB
			encryptor = Blowfish.new(key, mode, IV=IV)
			Flag = encryptor.encrypt(Flag)
			HContent = encryptor.encrypt(HContent)

		gettime()																	# Calculate file length #																	
		self.EmText.insert(tk.END, CurrentTime + ": Checking file length." + '\n')
		length = len(CContent) + len(HContent) + len(Flag) + 4

		if length % 512 == 0:					# Checking if file can be divided by 512 #
			gettime()																											
			self.EmText.insert(tk.END, CurrentTime + ": Adding padding." + '\n')
			HContent = HContent + b'\x00'

		percent = (length - len(CContent))/len(CContent)*100		# Calculate difference in file size #
		if percent > 100:
			message = messagebox.askquestion("Warning", "The hidden file's size will be considerably larger than the cover file after this operation. This may make your hidden file stand out.\n\nConsider using a larger cover file or compress your hidden file.\n\nDo you want to continue anyway?")
			if message == 'no':
				gettime()																	# Abort #																	
				self.EmText.insert(tk.END, CurrentTime + ": Operation aborted." + '\n', 'Error')
				return

		gettime()																	# Overwriting file #																	
		self.EmText.insert(tk.END, CurrentTime + ": Overwriting file." + '\n')
		self.EmWrite(Hfile, CContent, HContent, Flag)	

		gettime()																	# Chaning extenstion #																	
		self.EmText.insert(tk.END, CurrentTime + ": Chaning extenstion." + '\n')
		null, extenstion = Cfile.split('.', 1) 			
		if re.match('^[^.]*$', Hfile):
			name = Hfile
		else:
			name, null = Hfile.split('.', 1)
		os.rename(Hfile, name + '.' + extenstion)

		gettime()																																		
		self.EmText.insert(tk.END, CurrentTime + ": Operation complete!" + '\n', 'Complete')

		self.CfilEn.delete(0, 'end')	# Reset widgets #
		self.HfilEn.delete(0, 'end')
		self.PassEm.delete(0, 'end')
		clear(Pass, password, key)

	def CheckPassword(self, password):	# Checking the length of passwords #
		if len(password) < 8:
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using a longer password.")
			self.Value = 1
		elif password.islower():
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using a mix of upper and lower case characters.")
			self.Value = 1
		elif password.isalnum():
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using non alphanumeric characters.")
			self.Value = 1
		elif re.match(b'[a-zA-Z]', password) is None:
			messagebox.showinfo("Warning", "The supplied password is very weak!\nConsider using a mix of alphabetic characters and numbers.")
			self.Value = 1
		else:
			self.Value = 0

	def EmWrite(self, Hfile, CContent, HContent, Flag): 	# Func to overwrite file #
		with open (Hfile, 'wb') as f:	
			f.write(CContent)
			f.close()
		with open (Hfile, 'ab') as f:
			f.write(b"\x23\x23\x23\x23")
			f.close()
		with open (Hfile, 'ab') as f:
			f.write(Flag)
			f.close()
		with open (Hfile, 'ab') as f:
			f.write(HContent)
			f.close()

	def pad(self, HContent):
		while len(HContent) % 8 != 0:				# Paading for 8 bit encryption #
			gettime()																											
			self.EmText.insert(tk.END, CurrentTime + ": Adding padding." + '\n')
			HContent += b' '
		return HContent

# EmTb class #
class ExTb(Frame):
	def __init__(self, name, *args, **kwargs):			# Func to add GUI inputs etc #
		Frame.__init__(self, *args, **kwargs)
		self.style = ttk.Style()
		self.style.theme_use("AppStyle") 
		self.Titlefont = tkFont.Font(self, family="Helvetica", size=20)
		self.ExTitl = tk.Label(self, text="Extract", font=self.Titlefont, bg="#F0F0F0")	
		self.ExTitl.grid(row=0, column=0, padx=202, pady=10)

		self.EfilLb = tk.Label(self, text="File: ", bg="#F0F0F0")	# File input #
		self.EfilLb.place(x=15, y=55)
		self.EfilEn = tk.Entry(self)
		self.EfilEn.place(x=15, y=85, width=465)

		self.ExtenLb = tk.Label(self, text="Extenstion: ", bg="#F0F0F0")	# Extenstion file input #
		self.ExtenLb.place(x=15, y=125)
		self.ExtenEn = tk.Entry(self)
		self.ExtenEn.place(x=15, y=155, width=465)

		EnChoice = [ 'AES', 'DES', 'Blowfish' ]		# Decryption drop down #
		self.ExDefault = StringVar(self)	
		self.ExDefault.set('AES')
		self.EnLb = tk.Label(self, text="Encryption Algorithm: ", bg="#F0F0F0")	
		self.EnLb.place(x=15, y=195)
		self.EnDrop = OptionMenu(self, self.ExDefault, *EnChoice)
		self.EnDrop.place(x=15, y=225, width=465)

		self.PassLb = tk.Label(self, text="Password: ", bg="#F0F0F0") 	# Password input #
		self.PassLb.place(x=15, y=285, width=465)
		self.PassEx = tk.Entry(self, show="*")
		self.PassEx.place(x=15, y=315, width=465)

		self.Butn = tk.Button(self, text="Extract", command=self.Extract)	# Button #
		self.Butn.place(x=135, y=365, width=232)

		self.ExText = tk.Text(self, height=8)		# Text box for logs #
		self.ExText.place(x= 15, y= 415, width=465)
		self.ExText.tag_config('Error', foreground="red")
		self.ExText.tag_config('Complete', foreground="green")

	def Extract(self):
		Efile = self.EfilEn.get()		# Get all inputs from widgets #
		Extenstion = self.ExtenEn.get()
		Encryp = self.ExDefault.get()
		Pass = self.PassEx.get()

		if Efile == '':
			messagebox.showinfo("Warning", "No file given!")
			gettime()																		
			self.ExText.insert(tk.END, CurrentTime + ": No file given!" + '\n', 'Error')
			return

		if Extenstion == '':
			messagebox.showinfo("Warning", "No extension given!")
			gettime()																		
			self.ExText.insert(tk.END, CurrentTime + ": No extension given!" + '\n', 'Error')
			return

		if Pass == '':
			messagebox.showinfo("Warning", "No password given!")
			gettime()																		
			self.ExText.insert(tk.END, CurrentTime + ": No pasword given!" + '\n', 'Error')
			return

		gettime()																 # Get contents of file #
		self.ExText.insert(tk.END, CurrentTime + ": Reading File." + '\n')
		file = Efile 	
		pathcheck(file)
		if value == 1:
			self.EmText.insert(tk.END, CurrentTime + ": File in use!" + '\n', 'Error')
			return
		elif value == 2:
			self.EmText.insert(tk.END, CurrentTime + ": File could not be found!" + '\n', 'Error')
			return
		fileread(file)
		EContent = Content

		pos = EContent.find(b'\x23\x23\x23\x23')	# Find marker and remove prior data #
		length = 400000000
		data = EContent[pos:pos+length]
		data = re.sub(b"(\x23\x23\x23\x23)", b'', data)

		Ciphertext = data 		# Asigning data to new variable #
		password = Pass.encode()

		gettime()																											
		self.ExText.insert(tk.END, CurrentTime + ": Decrypting file." + '\n')

		if Encryp == 'AES':				# Decryption #
			salt = 'salt'.encode()
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 16 * '\x00'
			mode = AES.MODE_CFB
			decryptor = AES.new(key, mode, IV=IV)
			Newdata = decryptor.decrypt(Ciphertext)
		elif Encryp == 'DES':
			salt = 'salt'.encode()		
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			key = key[:8]													# Generate sha256 hash and then take first 8 bytes and use as key #
			mode = DES.MODE_CFB
			decryptor = DES.new(key, DES.MODE_ECB)
			Newdata = decryptor.decrypt(Ciphertext)
		elif Encryp == "Blowfish":
			salt = 'salt'.encode()
			key = hashlib.pbkdf2_hmac('sha256', password, salt, 100000)
			IV = 8 * '\x00'
			mode = Blowfish.MODE_CFB
			decryptor = Blowfish.new(key, mode, IV=IV)
			Newdata = decryptor.decrypt(Ciphertext)

		gettime()																										
		self.ExText.insert(tk.END, CurrentTime + ": Verifying decryption." + '\n')

		if re.match(b'^ENCRYPTE', Newdata):				# Check decryption #
			Newdata = re.sub(b"ENCRYPTE", b'', Newdata)
		else:
			messagebox.showinfo("Warning", "Incorrect password!")
			gettime()																										
			self.ExText.insert(tk.END, CurrentTime + ": Incorrect password!" + '\n', 'Error')
			self.PassEx.delete(0, 'end')
			return		

		gettime()																	# Overwrite file # 																				
		self.ExText.insert(tk.END, CurrentTime + ": Overwriting file." + '\n')
		self.ExWrite(Efile, Newdata) 		

		gettime()																	# Change extension # 																				
		self.ExText.insert(tk.END, CurrentTime + ": Changing extension." + '\n')
		name, null = Efile.split('.', 1)			
		os.rename(Efile, name + '.' + Extenstion)

		gettime()																																		
		self.ExText.insert(tk.END, CurrentTime + ": Operation complete!" + '\n', 'Complete')

		self.EfilEn.delete(0, 'end')	# Reset all inputs #
		self.ExtenEn.delete(0, 'end')
		self.PassEx.delete(0, 'end')
		clear(Pass, password, key)

	def ExWrite(self, Efile, Newdata):
		with open(Efile, 'wb') as f:	# Function to overwrite file with extracted data #
			f.write(Newdata)
			f.close()

class HelpTb(Frame):
	def __init__(self, name, *args, **kwargs):			# Initilise and add contents #
		Frame.__init__(self, *args, **kwargs)
		self.style = ttk.Style()
		self.style.theme_use("AppStyle") 
		self.Titlefont = tkFont.Font(self, family="Helvetica", size=20)
		self.Subtitlefont = tkFont.Font(self, family="Helvetica", size=14)
		self.HlTitl = tk.Label(self, text="Help", font=self.Titlefont, bg="#F0F0F0")	
		self.HlTitl.grid(row=0, column=0, padx=220, pady=10)

		self.HlEmTitl = tk.Label(self, text="Embedding data", font=self.Subtitlefont, bg="#F0F0F0")	
		self.HlEmTitl.place(x=15, y=55)		
		self.HlEm = tk.Label(self, text='''This system allows you to protect files by making them appear and function like other \nfiles.
											\nFor example you may have an important text document you wish to protect. Using this \nsystem you are can make that text document look and run like an .mp4 file.
											\nTo do this navigate to the "Embed" tab using the buttons along the top. Then enter a \nfile you want your hidden file to look like. This is called a cover file. Next enter the \nfile path of the file you wish to hide. Then choose an encryption algorigthm.\nAES is the most commonly used algorithm supported by this system and is the \nstrongest. Finally choose a strong password and click the "Embed" button.
											\nThe system will then encrypt your hidden file and add the cover file to the begining.
											\nPlease note this system does not store passwords. Data will be unrecoverable if \npasswords are forgotten!''', bg="#F0F0F0", anchor='w', justify='left')
		self.HlEm.place(x=15, y=85, width=465)

		self.HlExTitl = tk.Label(self, text="Extracting data", font=self.Subtitlefont, bg="#F0F0F0")	
		self.HlExTitl.place(x=15, y=350)	
		self.HlEx = tk.Label(self, text='''To recover data first, navigate to the "Extract" tab using the buttons along the top.\nThen enter the file you wish to extract data from. Next enter the original file's extension.\nIf the file had no extension then leave this field blank. Then choose the encryption \nalgorighm used to encrypt the original data. Finally enter the password which was used \nto embed the orginal data and press the "Extract" button.
											\nFiles will not be returned if incorrect passwords or algorithms are used.''', bg="#F0F0F0", anchor='w', justify='left')
		self.HlEx.place(x=15, y=380, width=465)

		self.Vidtx = tk.Label(self, text="If you require more help, a tutorial can be found here: ", font=self.Subtitlefont, bg="#F0F0F0")	
		self.Vidtx.place(x=15, y=510)

		self.Vidlnk = Label(self, text="https://youtu.be/4Nkk1Gv7KD0", fg="blue", cursor="hand2")
		self.Vidlnk.place(x=140, y=540)
		self.Vidlnk.bind("<Button-1>", self.link)

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