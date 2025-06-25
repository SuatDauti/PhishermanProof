import pandas as pd
from tqdm import tqdm
import ipaddress
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import whois
from urllib.parse import urlparse, quote
import urllib.request

# ---------------------- Feature Extraction Functions ----------------------

def havingIP(url):
    try:
        ipaddress.ip_address(url)
        return 1
    except:
        return 0

def haveAtSign(url):
    return 1 if "@" in url else 0

def getLength(url):
    return 1 if len(url) >= 54 else 0

def getDepth(url):
    return len([i for i in urlparse(url).path.split('/') if i])

def redirection(url):
    pos = url.rfind('//')
    return 1 if pos > 7 else 0

def httpDomain(url):
    domain = urlparse(url).netloc
    return 1 if 'https' in domain else 0

shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"

def tinyURL(url):
    return 1 if re.search(shortening_services, url) else 0

def prefixSuffix(url):
    return 1 if '-' in urlparse(url).netloc else 0

def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + quote(url)).read(), "xml").find("REACH")['RANK']
        return 1 if int(rank) < 100000 else 0
    except:
        return 1

def domainAge(domain_name):
    try:
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if isinstance(creation_date, list): creation_date = creation_date[0]
        if isinstance(expiration_date, list): expiration_date = expiration_date[0]
        if not creation_date or not expiration_date:
            return 1
        age = abs((expiration_date - creation_date).days)
        return 1 if (age / 30) < 6 else 0
    except:
        return 1

def domainEnd(domain_name):
    try:
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if not expiration_date:
            return 1
        today = datetime.now()
        end = abs((expiration_date - today).days)
        return 0 if (end / 30) < 6 else 1
    except:
        return 1

def iframe(response):
    try:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1
    except:
        return 1

def mouseOver(response): 
    try:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0
    except:
        return 1

def rightClick(response):
    try:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1
    except:
        return 1

def forwarding(response):
    try:
        return 0 if len(response.history) <= 2 else 1
    except:
        return 1

# ---------------------- Main Extraction Wrapper ----------------------

def featureExtraction(url):
    features = []
    
    # Address-bar based features
    features.append(havingIP(url))
    features.append(haveAtSign(url))
    features.append(getLength(url))
    features.append(getDepth(url))
    features.append(redirection(url))
    features.append(httpDomain(url))
    features.append(tinyURL(url))
    features.append(prefixSuffix(url))

    # Domain-based features
    try:
        domain_name = whois.whois(urlparse(url).netloc)
        dns = 0
    except:
        domain_name = None
        dns = 1

    features.append(dns)
    features.append(web_traffic(url))
    features.append(1 if dns == 1 else domainAge(domain_name))
    features.append(1 if dns == 1 else domainEnd(domain_name))

    # HTML/JS features
    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features

# ---------------------- Dataset Processing ----------------------

# Step 1: Load dataset
df = pd.read_csv("Data/new_data_urls.csv")

# Step 2: Sample 5000 phishing and 5000 legit URLs
phishing_df = df[df['status'] == 0].sample(n=5000, random_state=42)
legit_df = df[df['status'] == 1].sample(n=5000, random_state=42)
balanced_df = pd.concat([phishing_df, legit_df]).reset_index(drop=True)

# Step 3: Extract features
features_data = []
error_urls = []

print("🔍 Extracting features from 10,000 URLs...")
for i, row in tqdm(balanced_df.iterrows(), total=10000):
    url = row['url']
    label = row['status']
    try:
        features = featureExtraction(url)
        features.append(label)
        features_data.append(features)
    except Exception as e:
        print(f"[!] Error: {url} -> {e}")
        error_urls.append(url)

# Step 4: Save to CSV
feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth', 'Redirection', 
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 
                 'Web_Traffic', 'Domain_Age', 'Domain_End', 'iFrame', 
                 'Mouse_Over', 'Right_Click', 'Web_Forwards', 'Label']

features_df = pd.DataFrame(features_data, columns=feature_names)
features_df.to_csv("features_10000.csv", index=False)
print("✅ Feature extraction complete. File saved as 'features_10000.csv'.")
