import json, hashlib, getpass, os, pyperclip, sys 
from cryptography.fernet import Fernet 

#Hash master password
def hash_password(password):
    hash= hashlib.sha256()
    hash.update(password.encode())
    return hash.hexdigest()

#Get encryption key password
def get_encryption_key():
    return Fernet.generate_key()

#Init Fernet cipher with the key
def init_cipher(key):
    return Fernet(key)

#Encrypt PWD
def encrypt(cipher,pwd):
    return cipher.encrypt(pwd.encode()).decode()

#Decrypt PWD
def decrypt(cipher,pwd):
    return cipher.decrypt(pwd.encode()).decode()


#Function to register master user
def register(username,master_pwd):
    hashed_master_pwd= hash_password(master_pwd)
    user_data={'username':username, 'master_pwd':hashed_master_pwd}
    file_name= 'master_user_data.json'
    #if path exists and file is empty
    if os.path.exists(file_name) and  os.path.getsize(file_name)==0 : 
        with open(file_name, 'w') as file:
            json.dump(user_data,file)
            
    else:
        with open(file_name , 'x') as file:
            json.dump(user_data,file)
    
    print ('USER REGISTERED')

def login(username,pwd): 
    try:
        with open('master_user_data.json', 'r') as file:
            master_user_data=json.load(file)  
        stored_pwd= master_user_data.get('master_pwd')  
        hash_pwd= hash_password(pwd)
        if hash_pwd == stored_pwd and username == master_user_data.get('username'):
            print('login successful ..')
        else:
            print('unvalid Login creds')
            sys.exit()
    except Exception:
        print('You have not registerd , register first')
        sys.exit()


# Load or generate the encryption key.
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
   with open(key_filename, 'rb') as key_file:
       key = key_file.read()
else:
   key = get_encryption_key()
   with open(key_filename, 'wb') as key_file:
       key_file.write(key)

cipher = init_cipher(key)

# Function to add wesite
def add_acc_pwd(acc,pwd):
    if not os.path.exists('passwords.json'):
        data = []
    else:
        try:
            with open('passwords.json', 'r') as file:
                data=json.load(file)
        except json.JSONDecodeError:
            data=[]
    encrypted_pwd= encrypt(cipher,pwd)
    pwd_entry= {'acc':acc,'password':encrypted_pwd}
    data.append(pwd_entry)
    with open('passwords.json','w') as file:
        json.dump(data, file, indent=4)

        
# Function to retrieve a saved password.
def get_password(acc):
   # Check if passwords.json exists
   if not os.path.exists('passwords.json'):
       return None
   # Load existing data from passwords.json
   try:
       with open('passwords.json', 'r') as file:
           data = json.load(file)
   except json.JSONDecodeError:
       data = []
   # Loop through all the websites and check if the requested website exists.
   for entry in data:
       if entry['acc'] == acc:
           # Decrypt and return the password
           decrypted_password = decrypt(cipher, entry['password'])
           return decrypted_password
   return None



def view_websites():
   try:
       with open('passwords.json', 'r') as data:
           view = json.load(data)
           print("\nWebsites you saved...\n")
           for x in view:
               print(x['website'])
           print('\n')
   except FileNotFoundError:
       print("\n[-] You have not saved any passwords!\n")
       
while True:
   print("1. Register")
   print("2. Login")
   print("3. Quit")
   choice = input("Enter your choice: ")
   if choice == '1':  
       file = 'master_user_data.json'
       if os.path.exists(file) and os.path.getsize(file) != 0:
           print("\n[-] Master user already exists!!")
           sys.exit()
       else:
           username = input("Enter your username: ")
           master_password = getpass.getpass("Enter your master password: ")
           register(username, master_password)
   elif choice == '2':  
       file = 'master_user_data.json'
       if os.path.exists(file):
           username = input("Enter your username: ")
           master_password = getpass.getpass("Enter your master password: ")
           login(username, master_password)
       else:
           print("\n[-] You have not registered. Please do that.\n")
           sys.exit()
       while True:
           print("1. Add Password")
           print("2. Get Password")
           print("3. View Saved websites")
           print("4. Quit")
           password_choice = input("Enter your choice: ")
           if password_choice == '1':
               website = input("Enter website: ")
               password = getpass.getpass("Enter password: ")
               add_acc_pwd(website, password)
               print("\n[+] Password added!\n")
           elif password_choice == '2':  
               website = input("Enter website: ")
               decrypted_password = get_password(website)
               if website and decrypted_password:
                   pyperclip.copy(decrypted_password)
                   print(f"\n[+] Password for {website}: {decrypted_password}\n[+] Password copied to clipboard.\n")
               else:
                   print("\n[-] Password not found! Did you save the password?"
                         "\n[-] Use option 3 to see the websites you saved.\n")
           elif password_choice == '3': 
               view_websites()
           elif password_choice == '4':  
               break
   elif choice == '3': 
       break