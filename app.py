import os
import signal
import sys
import distro
import subprocess
import json
import requests
import validators
import platform
import ipaddress
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage
import shutil
from urllib.parse import urlparse
import pyminizip
import secrets
import string

system=platform.system().lower()
arch=platform.machine().upper()
dist=distro.id().lower()
REPORT_DIR_HOST="report-host"
REPORT_DIR_WEB="report-website"
all_reports = [
    REPORT_DIR_WEB,
    f"{REPORT_DIR_WEB}.zip",
    REPORT_DIR_HOST,
    f"{REPORT_DIR_HOST}.zip"
]

def cipher(length=12):
    characters=string.ascii_letters+string.digits+string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def delete_reports():
    for path in all_reports:
        try:
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)
            print(f"Deleted:{path}")
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"Path:{path}, Error:{e}")

def zipping(dir, output):
    password=cipher()
    srcfiles=[]
    prefixs=[]
    for root, dirs, files in os.walk(dir):
        for file in files:
            absolute_path=os.path.join(root, file)
            srcfiles.append(absolute_path)
            prefixs.append(dir)
    pyminizip.compress_multiple(srcfiles, prefixs, output, password, 5)
    return password

def mail(subject, body, receiver, report):
    while not receiver:
        receiver=input("Please enter mail address: ").strip()
    try:
        msg=EmailMessage()
        msg["Subject"]=subject
        msg["From"]=EMAIL_ADDR
        msg["To"]=receiver
        msg.set_content(body)
        with open(report, "rb") as f:
            data=f.read()
            filename=os.path.basename(report)
        msg.add_attachment(data, maintype="application", subtype="zip", filename=filename)

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(EMAIL_ADDR, EMAIL_PASS)
            smtp.send_message(msg)
    except Exception as e:
        print(e)

def check_system():
    if "linux" in system:
        pass
    else:
        print(f"Supported OS is Linux, and you use {system.title()}")
        sys.exit(1)

def url_check():
    while True:
        global TARGET_URL
        TARGET_URL=input("Enter Target: ").strip()
        if validators.url(TARGET_URL):
            return TARGET_URL
        elif TARGET_URL.startswith("http://localhost") or TARGET_URL.startswith("https://localhost"):
            return TARGET_URL
        else:
            print("Invalid URL type try again")

def ip_check():
    while True:
        try:
            global TARGET_IP
            TARGET_IP=input("Enter IP: ").strip()
            result=ipaddress.ip_address(TARGET_IP)
            if result:
                break
            else:
                pass
        except ValueError:
            print("Invalid IP type try again")

def handle_ctrlc(signum, frame):
    sys.exit(0)
signal.signal(signal.SIGINT, handle_ctrlc)

def load_env():
    try:
        load_dotenv()
    except FileNotFoundError:
        sys.exit(1)
    except Exception as e:
        print(e)  

load_env()
EMAIL_ADDR = os.getenv("EMAIL_ADDR")
EMAIL_PASS = os.getenv("EMAIL_PASS")

def website_pentest(target):
    REPORT_DIR_WEB="report-web"
    os.makedirs(REPORT_DIR_WEB, exist_ok=True)
    try:
        print("Running Nikto")
        if os.path.exists(f"{REPORT_DIR_WEB}/nikto.txt"):
            os.remove(f"{REPORT_DIR_WEB}/nikto.txt")
        with open(f"{REPORT_DIR_WEB}/nikto.txt", "w") as f:
            subprocess.run(["nikto", "-C", "all", "-host", target, "-output", f"{REPORT_DIR_WEB}/nikto.txt"],stdout=f, stderr=subprocess.DEVNULL)
        print("Running Wapiti")
        if os.path.exists(f"{REPORT_DIR_WEB}/wapiti.txt"):
            os.remove(f"{REPORT_DIR_WEB}/wapiti.txt")
        with open(f"{REPORT_DIR_WEB}/wapiti.txt", "w") as f:
            subprocess.run(["wapiti", "-u", target, "-o", f"{REPORT_DIR_WEB}/wapiti.txt", "-f", "txt"], stdout=f, stderr=subprocess.DEVNULL)
        wordlist=input("Enter ffuf wordlist path(default SecLists/Discovery/Web-Content/common.txt): ").strip()
        if not wordlist:
            wordlist="SecLists/Discovery/Web-Content/common.txt"
        fr=input("Response codes for filter(default 403, type as 403 or 403,401,500 and etc): ").strip()
        if not fr:
            fr = "403"
        extension=input("Extension to search (leave for nothing): ").strip()
        print("Running ffuf directory bruteforce")
        if os.path.exists(f"{REPORT_DIR_WEB}/ffuf.json"):
            os.remove(f"{REPORT_DIR_WEB}/ffuf.json")
        ffuf_cmd=["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist, "-fc", fr, "-json", "-o", f"{REPORT_DIR_WEB}/ffuf.json"]
        if extension:
            ffuf_cmd+=["-e", extension]
        subprocess.run(ffuf_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        param_urls=[]
        print("Running paremeter url discovery")
        common_params = ["id", "page", "q", "query", "search", "file", "lang", "user", "ref"]
        if os.path.exists(f"{REPORT_DIR_WEB}/ffuf.json"):
            with open(f"{REPORT_DIR_WEB}/ffuf.json") as f:
                data=json.load(f)
                paramlist=[result.get("url", "") for result in data.get("results", [])]
            for param_url in paramlist:
                if not param_url or "?" in param_url:
                    param_urls.append(param_url)
                    continue
                for param in common_params:
                    request = f"{param_url}?{param}=1"
                    try:
                        response = requests.get(request, timeout=5)
                        if response.status_code < 500 and "1" in response.text:
                            print(f"Potential parameter found: {request}")
                            param_urls.append(request)
                            break
                    except Exception:
                        continue
        if not param_urls:
            pass
        else:
            for id_url, url in enumerate(param_urls):
                paramtest=input(f"Do you want to test {id_url+1}. {url} (y/n): ").strip().lower()
                if paramtest=="y":
                    print(f"Parameterized URL test {url}")
                    dalfox_cmd=["file", "url", url]
                    if "AMD64" in arch:
                        dalfox_cmd[0]="./dalfox-linux-amd64"
                    elif "ARM64" in arch:
                        dalfox_cmd[0]="./dalfox-linux-arm64"
                    dalfox_blind=input("Test Blind XSS (y/n): ").strip().lower()
                    if dalfox_blind=="y":
                        dalfox_cmd.append("--blind")
                    cookie=input("Enter cookies (leave empty for nonset): ").strip()
                    if cookie:
                        dalfox_cmd+=["--cookie", cookie]
                    method = input("HTTP method (GET/POST/PUT/DELETE/PATCH, default GET): ").strip()
                    if method:
                        dalfox_cmd+=["--method", method]
                    with open(os.path.join(REPORT_DIR_WEB, f"dalfox_{id_url}.txt"), "w") as f:
                        subprocess.run(dalfox_cmd, stdout=f, stderr=subprocess.DEVNULL)
                    sqlmap_cmd=["python3", "sqlmap/sqlmap.py", "-u", url, "--batch"]
                    dbms=input("DBMS type (leave empty for automatic detection): ").strip()
                    if dbms:
                        sqlmap_cmd+=["--dbms", dbms]
                    else:
                        sqlmap_cmd+=["--dbs"]
                    risk=input("Risk level (1-3, default 1): ").strip()
                    if not risk:
                        risk="1"
                    level=input("Attack level (1-5, default 1): ").strip()
                    if not level:
                        level="1"
                    random_agent=input("Do you want to test with random agents (y/n): ").strip()
                    if random_agent:
                        sqlmap_cmd+=["--random-agent"]
                    else:
                        pass
                    sqlmap_cmd +=["--risk", risk, "--level", level]
                    tamper=input("SQLMap tamper script, write as (space2comment,space2hash): ").strip()
                    if tamper:
                        sqlmap_cmd+=["--tamper", tamper]
                    with open(os.path.join(REPORT_DIR_WEB, f"sqlmap_{id_url}_.txt"), "w") as f:
                        subprocess.run(sqlmap_cmd, stdout=f, stderr=subprocess.DEVNULL)
                else:
                    pass
        if os.path.exists(f"{REPORT_DIR_WEB}/gobuster-dns.txt"):
            os.remove(f"{REPORT_DIR_WEB}/gobuster-dns.txt")
        with open(f"{REPORT_DIR_WEB}/gobuster-dns.txt", "w") as f:
            parse = urlparse(target)
            target = parse.netloc or parse.path
            target = target.split(':')[0]
            subdomains=input("Enter subdomain wordlist path (default SecLists/Discovery/DNS/subdomains-top1million-5000.txt): ").strip()
            if not subdomains:
                subdomains="SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
            print("Running Gobuster subdomain enum")
            subprocess.run(["gobuster", "dns", "-d", target, "-w", subdomains, "-o", f"{REPORT_DIR_WEB}/gobuster.txt"], stdout=f, stderr=subprocess.DEVNULL)

        zip=f"{REPORT_DIR_WEB}.zip"
        password=zipping(f"{REPORT_DIR_WEB}", f"{REPORT_DIR_WEB}.zip")
        print("Zip password: ",password)
        mail(
            subject="Web Pentest Report",
            body=f"Pentest report for {target}",
            receiver=input("Enter mail address: ").strip(),
            report=zip
        )
    except Exception as e:
        print(e)

def host_pentest(target):
    try:
        os.makedirs(REPORT_DIR_HOST, exist_ok=True)
        print("Running Nmap top ports scan with version and default scripts")
        subprocess.run(["sudo", "nmap", "-sV", "-sC", "-oN", os.path.join(REPORT_DIR_HOST, "nmap.txt"), target],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("Searching exploits")
        with open(f"{REPORT_DIR_HOST}/nmap.txt", "r") as f:
            lines=f.readlines()
        services=[]
        for line in lines:
            if "/" in line and "open" in line:
                parts = line.strip().split()
                if len(parts)>=3:
                    version=" ".join(parts[3:]) if len(parts) > 3 else ""
                    services.append(f"{version}".strip())
        with open(os.path.join(REPORT_DIR_HOST, "searchsploit.txt"), "w") as output:
            for exploit in services:
                print(f"Searchsploit: {exploit}")
                result=subprocess.run(["searchsploit", exploit], capture_output=True, text=True)
                output.write(f"\n{exploit}\n")
                output.write(result.stdout)
        zip=f"{REPORT_DIR_HOST}.zip"
        password=zipping(f"{REPORT_DIR_HOST}", f"{REPORT_DIR_HOST}.zip")
        print("Zip password: ",password)
        mail(
            subject="Host Pentest Report",
            body=f"Pentest report for {target}",
            receiver=input("Enter mail address: ").strip(),
            report=zip
        )
    except PermissionError:
        print("Run script with sudo")
    except Exception as e:
        print(e)

def install_dependencies():
    debian_packages=("nikto wapiti nmap git gobuster python3.13 ffuf")
    arch_packages=("nikto wapiti nmap git gobuster python3.13 ffuf")
    redhat_epel=("epel-release")
    redhat_packages=("nikto wapiti nmap git gobuster python3.13 ffuf")
    if "kali" in dist or "parrot" in dist or "ubuntu" in dist:
        os.system("sudo apt update")
        os.system(f"sudo apt install -y {debian_packages}")
        os.system("sudo rm -rf /opt/exploitdb /usr/local/bin/searchsploit sqlmap SecLists")
        os.system("sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb")
        os.system("sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit")
        os.system("git clone https://github.com/sqlmapproject/sqlmap")
        os.system("git clone https://github.com/danielmiessler/SecLists")
        os.system("pip3.13 -r req.txt")        
        if "AMD64" in arch:
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz")
            os.system("tar -xzvf dalfox-linux-amd64.tar.gz")
            os.system("rm -rf dalfox-linux-amd64.tar.gz")
        elif "ARM64" in arch:
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-arm64.tar.gz")
            os.system("tar -xzvf dalfox-linux-arm64.tar.gz")
            os.system("rm -rf dalfox-linux-arm64.tar.gz")
    elif "blackarch" in dist or "arch" in dist:
        os.system("sudo pacman -Syu --noconfirm")
        os.system(f"sudo pacman -S --noconfirm {arch_packages}")
        os.system("sudo rm -rf /opt/exploitdb /usr/local/bin/searchsploit sqlmap SecLists")
        os.system("sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb")
        os.system("sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit")
        os.system("git clone https://github.com/sqlmapproject/sqlmap")
        os.system("git clone https://github.com/danielmiessler/SecLists")
        os.system("pip3.13 -r req.txt")    
        if "AMD64" in arch:
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz")
            os.system("tar -xzvf dalfox-linux-amd64.tar.gz")
            os.system("rm -rf dalfox-linux-amd64.tar.gz")
        elif "ARM64" in arch:
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-arm64.tar.gz")
            os.system("tar -xzvf dalfox-linux-arm64.tar.gz")
            os.system("rm -rf dalfox-linux-arm64.tar.gz")
    elif "fedora" in dist or "rocky" in dist or "alma" in dist:
        os.system(f"sudo dnf update -y")
        os.system(f"sudo dnf install -y {redhat_epel}")
        os.system(f"sudo dnf install -y {redhat_packages}")
        os.system("sudo rm -rf /opt/exploitdb /usr/local/bin/searchsploit sqlmap SecLists")
        os.system("sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb")
        os.system("sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit")
        os.system("git clone https://github.com/sqlmapproject/sqlmap")
        os.system("git clone https://github.com/danielmiessler/SecLists")
        os.system("pip3.13 -r req.txt")    
        if "AMD64" in arch:
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz")
            os.system("tar -xzvf dalfox-linux-amd64.tar.gz")
            os.system("rm -rf dalfox-linux-amd64.tar.gz")
        elif "ARM64" in arch:
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-arm64.tar.gz")
            os.system("tar -xzvf dalfox-linux-arm64.tar.gz")
            os.system("rm -rf dalfox-linux-arm64.tar.gz")
    else:
        print(f"Unsupported distribution: {dist}\n")
        print("Application will not run on this system correctly please manually install packages")


def update_packages():
    if "kali" in dist or "parrot" in dist or "ubuntu" in dist:
        os.system("sudo apt update")
        os.system("sudo apt upgrade -y")
        os.system("sudo rm -rf /opt/exploitdb /usr/local/bin/searchsploit sqlmap SecLists")
        os.system("sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb")
        os.system("sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit")
        os.system("git clone https://github.com/sqlmapproject/sqlmap")
        os.system("git clone https://github.com/danielmiessler/SecLists")
        if "AMD64" in arch:
            os.system("sudo rm dalfox-linux-amd64")
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz")
            os.system("tar -xzvf dalfox-linux-amd64.tar.gz")
            os.system("rm -rf dalfox-linux-amd64.tar.gz")
        elif "ARM64" in arch:
            os.system("sudo rm dalfox-linux-arm64")
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-arm64.tar.gz")
            os.system("tar -xzvf dalfox-linux-arm64.tar.gz")
            os.system("rm -rf dalfox-linux-arm64.tar.gz")
    elif "blackarch" in dist or "arch" in dist:
        os.system("sudo pacman -Syu --noconfirm")
        os.system("sudo rm -rf /opt/exploitdb /usr/local/bin/searchsploit sqlmap SecLists")
        os.system("sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb")
        os.system("sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit")
        os.system("git clone https://github.com/sqlmapproject/sqlmap")
        os.system("git clone https://github.com/danielmiessler/SecLists")
        if "AMD64" in arch:
            os.system("sudo rm dalfox-linux-amd64")
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz")
            os.system("tar -xzvf dalfox-linux-amd64.tar.gz")
            os.system("rm -rf dalfox-linux-amd64.tar.gz")
        elif "ARM64" in arch:
            os.system("sudo rm dalfox-linux-arm64")
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-arm64.tar.gz")
            os.system("tar -xzvf dalfox-linux-arm64.tar.gz")
            os.system("rm -rf dalfox-linux-arm64.tar.gz")
    elif "fedora" in dist or "rocky" in dist or "alma" in dist:
        os.system("sudo dnf update -y")
        os.system("sudo rm -rf /opt/exploitdb /usr/local/bin/searchsploit sqlmap SecLists")
        os.system("sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb")
        os.system("sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit")
        os.system("git clone https://github.com/sqlmapproject/sqlmap")
        os.system("git clone https://github.com/danielmiessler/SecLists")
        if "AMD64" in arch:
            os.system("sudo rm dalfox-linux-amd64")
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz")
            os.system("tar -xzvf dalfox-linux-amd64.tar.gz")
            os.system("rm -rf dalfox-linux-amd64.tar.gz")
        elif "ARM64" in arch:
            os.system("sudo rm dalfox-linux-arm64")
            os.system("wget https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-arm64.tar.gz")
            os.system("tar -xzvf dalfox-linux-arm64.tar.gz")
            os.system("rm -rf dalfox-linux-arm64.tar.gz")
    else:
        print(f"Unsupported distribution: {dist}\n")
        print("Application will not run on this system correctly please manually install packages") 

def menu():
    while True:
        print(f"\n=== Attack Toolkit V1===")
        print("1. Website Pentest")
        print("2. Host Pentest")
        print("3. Install Dependencies")
        print("4. Update Packages")
        print("5. Delete Reports")
        print("0. Exit\n")
        choice = input("Select an option: ").strip()
        if choice=="1":
            url_check()
            website_pentest(TARGET_URL)
        elif choice=="2":
            ip_check()
            host_pentest(TARGET_IP)
        elif choice=="3":
            install_dependencies()
        elif choice=="4":
            update_packages()
        elif choice=="5":
            delete_reports()
        elif choice=="0":
            print("Exiting. Goodbye!")
            break
        else:
            print("Invalid input try again")

if __name__=="__main__":
    check_system()
    menu()