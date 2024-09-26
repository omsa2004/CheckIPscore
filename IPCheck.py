from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from IPy import IP
import time
import re
from getpass import getpass

# Initialize Selenium WebDriver with headless mode
chrome_options = Options()
# chrome_options.add_argument("--use_subprocess")
#chrome_options.add_argument('user-data-dir=C:\\Users\\OMA1700\\AppData\\Local\\Google\\Chrome\\User Data')
# chrome_options.add_argument('profile-directory=Profile 1')
chrome_options.add_argument('--ignore-certificate-errors')
chrome_options.add_argument('--ignore-ssl-errors')
# chrome_options.add_argument("--headless")  # Run Chrome in headless mode
service = Service(".\\chromedriver.exe")  # Replace "path/to/chromedriver" with your chromedriver path




def get_ip_reputation(driver, IP):
    try:
        driver.switch_to.window(driver.window_handles[0])
        time.sleep(1)
        input_element= WebDriverWait(driver,10).until(EC.presence_of_element_located((By.XPATH,"//input[@class='form-control ip_value field-filled']")))
        time.sleep(1)
        input_element.clear()
        input_element.send_keys(IP + Keys.ENTER)
        # Wait for the page to fully load
        WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.XPATH, "//table[@class='results']")))
        time.sleep(1)
        # Get the page source
        page_source = driver.page_source

        # Parse HTML content using BeautifulSoup
        soup = BeautifulSoup(page_source, "html.parser")

        # Find and extract the required information
        result = soup.find("table", {"class":"results"})
        if result:
            # Example: Get the IP reputation
            ip_reputation = result.find("b",{"class":"country_code"}).text
            country = result.find("b",{"class":"fraud_score"}).text
            return ip_reputation, country
    except: 
         print(f"Couldn't get IP reputation for{IP}")
         ip_reputation = ""
         country = ""
         return ip_reputation, country



def get_whois(driver,IP):
    OrgName =""
    driver.switch_to.window(driver.window_handles[1])
    time.sleep(1)
    input_element= WebDriverWait(driver,10).until(EC.presence_of_element_located((By.XPATH,"/html/body/header/nav/div[1]/form/div/input")))
    time.sleep(1)
    input_element.clear()
    input_element.send_keys(IP + Keys.ENTER)    
    WebDriverWait(driver,60).until(EC.presence_of_element_located((By.ID,"registryData")))
    time.sleep(1)
    page_source = driver.page_source
    soup = BeautifulSoup(page_source, "html.parser")
    result = soup.find("pre", {"id":"registryData"})
    if result:
        # Example: Get the IP reputation
        try:
            OrgName = re.search("OrgName:[^\r\n,']+",result.text).group().split(":")[1].strip()
        except:
            try:
                OrgName = re.search("org-name:[^\r\n,']+",result.text).group().split(":")[1].strip()
            except:
                OrgName=""
                print(f"couldn't get Whoise information")
                return OrgName
    return OrgName




username = input("Enter Username for IPQos site:")

if not username:
    print("you didn't enter a valid hostname")
if username:
    password = getpass(f"Enter Password of the user {username}: ")
    driver = webdriver.Chrome(service=service, options=chrome_options)
    url = f"https://www.ipqualityscore.com/user/proxy-detection-api/lookup"
    driver.get(url)
    Email= WebDriverWait(driver,10).until(EC.presence_of_element_located((By.ID,"email")))
    passd = WebDriverWait(driver,10).until(EC.presence_of_element_located((By.ID,"password")))

    Email.send_keys(username)
    passd.send_keys(password)
    passd.send_keys(Keys.ENTER)

    WebDriverWait(driver,20).until(EC.presence_of_element_located((By.XPATH,"//input[@class='form-control ip_value field-filled']")))


    # opening second tab
    driver.execute_script("window.open('about:blank','secondtab');")
    driver.switch_to.window("secondtab")
    driver.get('https://www.whois.com/whois/')
    WebDriverWait(driver,20).until(EC.presence_of_element_located((By.CLASS_NAME,"form-control")))


    global_block = ["AE","AF","AL","AM","AR","AZ","BA","BB","BG","BO","BS","BY","BZ","CD","CE","CF","CI","CL","CN","CO","CR","CU","CZ","DO","DZ","EC","EG","EH","GH","GW","HN","HR","HT","HU","IQ","IR","JO","KG","KH","KP","KZ","LA","LB","LR","LY","MA","MD","ME","MK","ML","MM","MN","NG","NI","PA","PE","PK","PS","PT","PY","RO","RS","RU","SD","SI","SO","SS","SV","SY","TN","TT","TZ","UA","VE","YE","ZW"]

    with open("checkedIP.CSV","w+") as nf:
        with open("Tobechecked.txt","r+") as f:
                lines = f.readlines()
                if lines:
                    for  line in lines:
                            if IP(line.strip()):
                                country, iprep = get_ip_reputation(driver,line.strip())
                                whois = get_whois(driver,line.strip())
                                if country.strip() in global_block:
                                    nf.write(f'{line.strip()},{country},{iprep},{whois}, Blocked by GEOLocation\n')
                                else:
                                    nf.write(f'{line.strip()},{country},{iprep},{whois},\n')
                            else:
                                print(f"Line {line}, is not a valid IP")
                    f.truncate(0) 

    driver.quit()