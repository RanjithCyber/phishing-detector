import re
import time
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime
from bs4 import BeautifulSoup
from colorama import Fore, init

init()

# =====================
# Banner
# =====================

banner = """
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║
██████╔╝███████║██║███████╗███████║
██╔═══╝ ██╔══██║██║╚════██║██╔══██║
██║     ██║  ██║██║███████║██║  ██║
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝

ADVANCED PHISHING DETECTOR
"""

print(Fore.GREEN + banner)

# =====================
# Known brands
# =====================

brands = [
"paypal","google","amazon","facebook",
"microsoft","apple","instagram","netflix"
]

# =====================
# URL validation
# =====================

def valid_url(url):

    pattern = re.compile(
        r'^(https?:\/\/)'
        r'([a-zA-Z0-9\-\.]+|\d+\.\d+\.\d+(\.\d+)?)'
        r'(:\d+)?'
        r'(\/.*)?$'
    )

    return re.match(pattern,url)

# =====================
# Loading animation
# =====================

def loading():

    print(Fore.YELLOW+"[+] Initializing security engine...")
    time.sleep(1)

    print("[+] Loading threat modules...")
    time.sleep(1)

    print("[+] Performing analysis...\n")
    time.sleep(1)

    for i in range(0,101,20):

        bar="#"*(i//10)+"-"*(10-(i//10))
        print(Fore.YELLOW+f"[{bar}] {i}%")
        time.sleep(0.3)

# =====================
# Domain age
# =====================

def domain_age(domain):

    try:

        w = whois.whois(domain)

        creation = w.creation_date

        if isinstance(creation,list):
            creation = creation[0]

        age = (datetime.now()-creation).days

        return age

    except:
        return None

# =====================
# Redirect chain
# =====================

def redirect_chain(url):

    chain=[]

    try:

        r=requests.get(url,timeout=5,allow_redirects=True)

        for resp in r.history:
            chain.append(resp.url)

        chain.append(r.url)

    except:
        pass

    return chain

# =====================
# Brand impersonation
# =====================

def brand_impersonation(domain):

    for b in brands:

        if b in domain and domain != f"{b}.com":
            return True

    return False

# =====================
# Homograph detection
# =====================

def homograph(domain):

    replacements={
        "0":"o",
        "1":"l",
        "@":"a",
        "3":"e"
    }

    normalized=domain

    for k,v in replacements.items():
        normalized=normalized.replace(k,v)

    for b in brands:

        if b in normalized and b not in domain:
            return True

    return False

# =====================
# Webpage analysis
# =====================

def analyze_webpage(url):

    score=0
    reasons=[]

    try:

        r=requests.get(url,timeout=5)

        soup=BeautifulSoup(r.text,"html.parser")

        parsed=urlparse(url)

        # detect login forms
        forms=soup.find_all("form")

        for form in forms:

            password=form.find("input",{"type":"password"})

            if password:

                score+=30
                reasons.append("Password input field detected")

                action=form.get("action")

                if action and parsed.netloc not in action:

                    score+=25
                    reasons.append("External credential submission detected")

        # iframe detection
        if soup.find("iframe"):

            score+=5
            reasons.append("Embedded iframe detected")

        # javascript redirect detection
        scripts=soup.find_all("script")

        for s in scripts:

            code=str(s)

            if "window.location" in code:

                if parsed.netloc not in code:

                    score+=10
                    reasons.append("External JavaScript redirect detected")
                    break

    except:
        pass

    return score,reasons

# =====================
# Scanner
# =====================

def scan(url):

    score=0
    reasons=[]

    parsed=urlparse(url)

    domain=parsed.netloc
    path=parsed.path

    # HTTP detection
    if url.startswith("http://"):

        score+=10
        reasons.append("Insecure HTTP protocol")

    # phishing keywords
    keywords=["login","verify","secure","account","update","password"]

    for k in keywords:

        if k in url.lower():

            score+=15
            reasons.append(f"Phishing keyword detected: {k}")
            break

    # credential harvesting
    if "login" in path or "account" in path or "verify" in path:

        score+=25
        reasons.append("Credential harvesting page detected")

    # IP detection
    if re.search(r"\d+\.\d+\.\d+",domain):

        score+=30
        reasons.append("IP address used instead of domain")

        attacker_ips=["10.","192.168.","172.16."]

        for ip in attacker_ips:

            if domain.startswith(ip):

                score+=60
                reasons.append("Private attacker infrastructure")

    # suspicious characters
    if "@" in url or "=" in url:

        score+=10
        reasons.append("Suspicious redirect characters")

    # brand impersonation
    if brand_impersonation(domain):

        score+=40
        reasons.append("Brand impersonation detected")

    # homograph phishing
    if homograph(domain):

        score+=40
        reasons.append("Homograph phishing detected")

    # domain age
    age=domain_age(domain)

    if age and age<180:

        score+=15
        reasons.append("Newly registered domain")

    # redirects
    redirects=redirect_chain(url)

    if len(redirects)>2:

        score+=10
        reasons.append("Multiple redirects detected")

    # webpage analysis
    html_score,html_reasons=analyze_webpage(url)

    score+=html_score
    reasons.extend(html_reasons)

    if score>100:
        score=100

    return score,reasons,redirects,age

# =====================
# Main menu
# =====================

while True:

    print(Fore.CYAN+"\n========== MAIN MENU ==========")
    print("1. Scan URL")
    print("2. Exit")
    print("===============================\n")

    choice=input("Select option: ")

    if choice=="1":

        url=input("\nEnter URL to analyze: ").strip()

        if not valid_url(url):

            print(Fore.RED+"\nInvalid URL format")
            print("Example: https://example.com\n")
            continue

        loading()

        score,reasons,redirects,age=scan(url)

        print(Fore.WHITE+"\n========== SECURITY REPORT ==========\n")

        print("Target URL:",url)

        if age:
            print("Domain Age:",age,"days")

        if redirects:

            print("\nRedirect Chain:")

            for r in redirects:
                print(" ->",r)

        print("\nAI Risk Score:",score,"%")

        if score>=60:
            threat=Fore.RED+"HIGH RISK"
        elif score>=30:
            threat=Fore.YELLOW+"MEDIUM RISK"
        else:
            threat=Fore.GREEN+"LOW RISK"

        print("\nThreat Level:",threat)

        if reasons:

            print("\nDetected Indicators:")

            for r in reasons:
                print(" •",r)

        else:
            print("\nNo suspicious indicators detected")

        print("\nRecommendation:")

        if score>=60:
            print(Fore.RED+"DO NOT VISIT THIS WEBSITE")
        else:
            print(Fore.GREEN+"Website appears safe")

        print(Fore.WHITE+"\n=====================================")

    elif choice=="2":

        print(Fore.GREEN+"\nExiting tool...")
        break

    else:

        print(Fore.RED+"Invalid option")
