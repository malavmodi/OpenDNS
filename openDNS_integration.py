import ssl
import OpenSSL
import urllib3
import requests
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) #Suppresses warnings for insecure SSL validation
url = input("Please enter a HTTPS url to test: ") #url to grab SSL cert from
parsed_url = urlparse(url) #check / validate url
session = requests.Session() #Request the session
response = session.get(url, proxies = proxies, verify = False) #Actual HTTPS request, with SSL verification off

def isGETsuccesful(response_code = response.status_code): #simply checks if the request returned 200
    if(response_code == 200):
        print("HTTPS GET request to", url, "was successful!")
        return
    else:
        print("HTTPS GET request error", str(response_code) + ":", url,":", "Please Try Again!") #prints out other return code
        return

def openDNS_lookup(hostname = url.replace("https://www.",""), port = 443): #grabs SSL cert and checks for OpenDNS subject
    cert = ssl.get_server_certificate((hostname,port))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    subjects = x509.get_subject().get_components() #gets the subject headers from the SSL cert
    value = dict(subjects) #takes list of tuples, and creates a dictionary for faster lookup
    for key in value:
        key_char = (str(key, encoding = "utf-8")) #converts the original class of bytes to proper utf-8 string format
        location = (str(value[key], encoding = "utf-8"))
        if(key_char == 'O' and location == 'OpenDNS, Inc.'): #check for O = Open DNS subject header by iterating through dict
            print("Found! This domain should not be trusted!")
            break
            return
        else:
            print("Not found! Please look more into this domain for further analysis!")
            continue

def main():
    isGETsuccesful()
    openDNS_lookup() #closes the session

if __name__ == "__main__":
    main()
session.close()    
