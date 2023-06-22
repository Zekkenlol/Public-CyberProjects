##
# scanme.nmap.org only
# 45.33.32.156


'''
Example usage and output.
'''

## py NetworkScanner.py scanme.nmap.org,127.0.0.1 79-81 --save --timeout T3
## 0.2
## Saving to file
## Starting tcp scan on scanme.nmap.org
## 79 is closed
## 80 is open. Server: Server: Apache/2.4.7 (Ubuntu)
##  Status: HTTP/1.1 200 OK
##  Site Title: Go ahead and ScanMe!
## 81 is closed
## Scan finished
## Starting tcp scan on 127.0.0.1
## 79 is closed
## 80 is closed
## 81 is closed
## Scan finished
## All scans finished for 2 hosts


import socket, sys, re, random, os, time, logging, argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def scanMe(target_host, target_port, save_to_file, protocol="tcp", timeout="T2"):

    ports = []
    hosts= []
    banner = ''
    webServerPattern = "Server: [^\n]+\n?"
    webStatusPattern = "HTTP/[\d\.]+ [\d]+ [^\n]+\n?"
    webTitlePattern = "<title>.*</title>"

    # This normalizes protocol input
    protocol = protocol.lower()

    # Timeout settings
    T0 = 2
    T1 = 1
    T2 = .5 # default
    T3 = .2

    if timeout == "T0":
        timeout = T0
        print(T0)
    elif timeout == "T1":
        print(T1)
        timeout = T1
    elif timeout == "T2":
        print(T2)
        timeout = T2
    elif timeout == "T3":
        print(T3)
        timeout = T3
    else:
        timeout = T2
        print(T2)

# Allows user to put in specific IP's (Many IP's)
    hosts = [i.strip() for i in target_host.split(",")]
        
# This Checks for single or multple ports

    if "-" in target_port:
        start, end = target_port.split("-")
        start = int(start)
        end = int(end) + 1
        ports = list(range(start, end))

    else:
        ports = [int(target_port)]
        print("made it to else,", type(ports), ports)
    
# Notifies user if a file is being saved or not

    if save_to_file:
        print("Saving to file")
    else:
        print("not saving")

    for host in hosts:
        if save_to_file:
            with open("results.txt", "a") as file:
                print(f"Starting {protocol} scan on {host}")
                file.write(f"Starting {protocol} scan on {target_host}\n")
        else:
            print(f"Starting {protocol} scan on {target_host}\n")
    
        for port in ports:
            
    ## This is the TCP SCAN
            
            if protocol == "tcp":                   
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                        socket.setdefaulttimeout(timeout)
                        client.connect((host, port))

                        try:
                            if port:
                                client.send(b'GET / HTTP/1.0\r\n\r\n')
                            else:
                                client.send(b'')
                        except:
                            pass
                        banner = client.recv(1024)
                        try:
                            banner = banner.decode()
                        except:
                            banner = ""

                        if save_to_file:
                            with open("results.txt", "a") as file:
                                if "HTTP" in banner[:4]:
                    
                                    webServer = re.findall(webServerPattern,banner)
                                    if webServer:
                                        webServer = webServer[0]
                                    else:
                                        webServer = None               
                                                                    
                                    webTitle = re.findall(webTitlePattern,banner)
                                    if webTitle:
                                        webTitle = webTitle[0].replace("<title>","").replace("</title>","")
                                    else:
                                        webTitle = None
                              
                                    webStatus = re.findall(webStatusPattern,banner)
                                    if webStatus:
                                        webStatus = webStatus[0]
                                    else:
                                        webStatus = None
                                                                                      
                                    print(f'{port} is open. Server: {webServer} Status: {webStatus} Site Title: {webTitle}')
                                    file.write(f"{port} is open. Server: {webServer} Status: {webStatus} Site Title: {webTitle}")
                                                            
                                else:
                                    print(f"{port} is open. Banner: {banner}")
                                    file.write(f"{port} is open. Banner: {banner}")
                        else:
                            if "HTTP" in banner[:4]:
                    
                                webServer = re.findall(webServerPattern,banner)
                                if webServer:
                                    webServer = webServer[0]
                                else:
                                    webServer = None               
                                                                
                                webTitle = re.findall(webTitlePattern,banner)
                                if webTitle:
                                    webTitle = webTitle[0].replace("<title>","").replace("</title>","")
                                else:
                                    webTitle = None
                          
                                webStatus = re.findall(webStatusPattern,banner)
                                if webStatus:
                                    webStatus = webStatus[0]
                                else:
                                    webStatus = None
                                                                                  
                                print(f'{port} is open. Server: {webServer} Status: {webStatus} Site Title: {webTitle}')
                                                        
                            else:
                                print(f"{port} is open. Banner: {banner}")
        
                except socket.timeout:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        socket.setdefaulttimeout(timeout)

                        result = s.connect_ex((host, port))

                        if save_to_file:
                            with open("results.txt", "a") as file:
                                if result == 0:
                                    print(f"{port} is open")
                                    file.write(f"{port} is open\n")
                                else:
                                    print(f"{port} is closed")
                                    file.write(f"{port} is closed\n")
                        else:
                            if result == 0:
                                print(f"{port} is open")
                            else:
                                print(f"{port} is closed")
                                
                        s.close()
                    except KeyboardInterrupt:
                        print("\n Exiting Program !!!!")
                        sys.exit()
                                            
                except ConnectionRefusedError:
                    if save_to_file:
                        with open("results.txt", "a") as file:
                            print(f"{port} is closed")
                            file.write(f"{port} is closed\n")
                            continue
                    else:
                        print(f"{port} is closed")
                        continue
                
                except ConnectionResetError as e:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        socket.setdefaulttimeout(timeout)

                        result = s.connect_ex((host, port))

                        if save_to_file:
                            with open("results.txt", "a") as file:
                                if result == 0:
                                    print(f"{port} is open")
                                    file.write(f"{port} is open\n")
                                else:
                                    print(f"{port} is closed")
                                    file.write(f"{port} is closed\n")
                        else:
                            if result == 0:
                                print(f"{port} is open")
                            else:
                                print(f"{port} is closed")
                        s.close()
                    except KeyboardInterrupt:
                        print("\n Exiting Program !!!!")
                        sys.exit()

                except Exception as e:
                    import traceback
                    print(f"something went wrong: {e}")
                    
                except KeyboardInterrupt:
                        print("\n Exiting Program !!!!")
                        sys.exit()

# UDP scan was suppose to be here.

            elif protocol == "udp":
                print("UDP is not setup")

# Defaults to TCP
                    
            else:
                print("Protocol not set or invalid, defaulting to TCP")
                protocol = "tcp"
                print(f"Starting {protocol} scan on {host}")

        if save_to_file:
            with open("results.txt", "a") as file:
                print('Scan finished')
                file.write(f"Scan finished\n")
        else:
            print(f"Scan finished for host: {host}")
    print("All scans finished for",len(hosts),"hosts")
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scan specified IP address and port.")
    parser.add_argument("target_host", help="IP address to scan")
    parser.add_argument("target_port", help="Port to scan. You can set the range by using a '-'. Ex. py NetworkScanner.py scanme.nmap.org 22-80 ")
    parser.add_argument("--save", help="Save output to results.txt", action="store_true")
    parser.add_argument("--protocol", help="You can put the protocol by using 'tcp' or 'udp'. Ex. py NetworkScanner.py scanme.nmap.org --protocol tcp ", default="tcp")
    parser.add_argument("--timeout", help="You can set the timeout option with 'T0', 'T1', 'T2', 'T3'. Ex. py NetworkScanner.py scanme.nmap.org --timeout T3 ", default="T2")
    
    args = parser.parse_args()

    scanMe(args.target_host, args.target_port, args.save, args.protocol, args.timeout)


