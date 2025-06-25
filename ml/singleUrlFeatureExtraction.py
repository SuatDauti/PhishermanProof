import ipaddress
import re
import requests
from bs4 import BeautifulSoup
from datetime import datetime
import whois
from urllib.parse import urlparse, quote
import urllib.request

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
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + quote(url)).read(), "xml").find("REACH")["RANK"]
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

def extract_features(url):
    features = {}
    features['Have_IP'] = havingIP(url)
    features['Have_At'] = haveAtSign(url)
    features['URL_Length'] = getLength(url)
    features['URL_Depth'] = getDepth(url)
    features['Redirection'] = redirection(url)
    features['https_Domain'] = httpDomain(url)
    features['TinyURL'] = tinyURL(url)
    features['Prefix/Suffix'] = prefixSuffix(url)

    try:
        domain_name = whois.whois(urlparse(url).netloc)
        features['DNS_Record'] = 0
    except:
        domain_name = None
        features['DNS_Record'] = 1

    features['Web_Traffic'] = web_traffic(url)
    features['Domain_Age'] = 1 if features['DNS_Record'] else domainAge(domain_name)
    features['Domain_End'] = 1 if features['DNS_Record'] else domainEnd(domain_name)

    try:
        response = requests.get(url, timeout=5)
    except:
        response = ""

    features['iFrame'] = iframe(response)
    features['Mouse_Over'] = mouseOver(response)
    features['Right_Click'] = rightClick(response)
    features['Web_Forwards'] = forwarding(response)

    return features