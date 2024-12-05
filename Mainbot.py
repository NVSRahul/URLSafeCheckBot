from typing import Final
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import time
import requests
import subprocess
import re
from datetime import datetime, timedelta
from urllib.parse import urlparse
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
import asyncio
import firebase_admin
from firebase_admin import credentials, firestore

# Setting up firestore
cred = credentials.Certificate('url-scan-request-firebase-adminsdk-YOUR-FILE-FROM-FIRE-BASE.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

# Telegram bot Api Key
TOKEN: Final = 'YOUR TOKEN'
# Telegram Bot userid
BOT_USERNAME: Final = 'YOUR-USER-BOT-ID'

URL_LIMIT = 10
RESET_TIME = timedelta(days=1)


async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"""<b>Hello! Welcome to URLSafe Check Bot</b> \n\n<code><b>To run the bot directly give the website URL starting with 'https://' or 'http://' only\n\nYou can only scan {URL_LIMIT} URLs per day</b></code>""", parse_mode="HTML")


async def run_bot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("<b>Please Enter the url to Scan</b>", parse_mode='HTML')


async def handle_url_input(update: Update, context: ContextTypes.DEFAULT_TYPE):
    # Take user Input
    user_input = update.message.text
    user_input = user_input.strip().lower()

    parsed_url = urlparse(user_input)

    # Validation of the url
    if not (parsed_url.scheme in ['https', 'http'] and parsed_url.netloc):
        await update.message.reply_text("<code><b>🚫 Invalid URL. Please enter a valid URL.</b></code>", parse_mode="HTML")
        return

    if '.' not in parsed_url.netloc or len(parsed_url.netloc.split('.')[-1]) < 2:
        await update.message.reply_text("<code><b>🚫 Invalid URL. Please enter a valid URL.</b></code>", parse_mode="HTML")
        return
    
    username = update.message.from_user.username or ""
    first_name = update.message.from_user.first_name or ""
    last_name = update.message.from_user.last_name or ""
    user_id = update.message.from_user.id
    current_time = datetime.now()
    timestamp = current_time.timestamp()

    # Reference to the Firestore document where user data will be stored
    user_ref = db.collection('users').document(str(user_id))

    # Get the user data from Firestore, or initialize if new user
    user_data = user_ref.get()

    if user_data.exists:
        user_data = user_data.to_dict()
        user_data["msg_time"] = float(user_data["msg_time"])
    else:
        # Initialize new user data in Firestore
        user_data = {"count": 0, "msg_time": timestamp}
        user_ref.set(user_data)

    # Check if it's a new day since last reset
    if int(timestamp) - int(user_data["msg_time"]) >= 86400:
        # Reset the count if a new day
        user_data["count"] = 0
        user_data["msg_time"] = timestamp
        user_ref.update(user_data)

    # Check if the user has reached the daily limit
    if user_data["count"] >= URL_LIMIT:
        await update.message.reply_text(
            f"<code><b>🚫 You've reached your daily limit of {URL_LIMIT} URL Scan Requests.</b></code>",
            parse_mode="HTML")
        return

    # Update the count and Send message
    if user_id == 1027396173:
        user_data["count"] += 0
    else:
        user_data["count"] += 1

    # Update Firestore with the new count
    user_ref.update(user_data)

    url_req = f"✅ URL Accepted \n"
    url_req += f"Available URL Scan Requests: <code>{URL_LIMIT - user_data['count']}</code>"
    await update.message.reply_text(f"<b>{url_req}</b>", parse_mode="HTML")

    # Converting the url to domain
    if not user_input.startswith(("https://" or "http://")):
        user_input = "https://" + user_input

    parsed_url = urlparse(str(user_input))
    domain1 = parsed_url.netloc

    start_wait = f"please wait for 10 Sec...\n"
    start_wait += "Getting Data"
    response = f"💯 URL SCAN DONE\n\n"
    response += f"👦🏻 Requested User Name: <code>{first_name}</code>" + " " + f"<code>{last_name}</code>\n\n"
    response += f"🧑🏻‍💻 Requested username: <code>@{username}</code>\n\n"
    response += f"👤 Requested User ID: <code>{user_id}</code>\n\n"
    response += f"🔗 URL: <code>{user_input}</code>\n\n"

    # starting the selenium
    service = Service(ChromeDriverManager().install())
    options = Options()
    options = webdriver.ChromeOptions()
    options.add_argument("--headless")
    options.add_argument("--disable-gpu")  # Optional: Disable GPU hardware acceleration
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.binary_location = "/usr/bin/google-chrome"
    driver = webdriver.Chrome(service=service, options=options)

    # URL of the page to scrape
    url = f"https://safeweb.norton.com/report?url={user_input}"


    # Open the URL
    driver.get(url)


    # Wait for 5 seconds to allow the page to fully load (including JavaScript content)
    waiting_msg = await update.message.reply_text(f"<b>{start_wait}</b>", parse_mode="HTML")
    await asyncio.sleep(5.5)

    # Get the HTML content of the page
    html_content = driver.page_source

    # Parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(html_content, 'html.parser')

    # Define the classes you want to extract
    classes_to_extract1 = ['rating-label']

    classes_to_extract2 = ['current-category-header']

    p_tags1 = soup.find_all('p', class_='small-body-text')

    # Extract and print the text for each class
    for class_name in classes_to_extract1:
        # Find all <p> tags with the specified class
        p_tags = soup.find_all('p', class_=class_name)

        # Print the text content of each <p> tag with the current class
        for p in p_tags:
            if p.get_text() == "Safe":
                response += f"🌐 Website Rating : <code>{p.get_text()} ✅</code>\n\n"
                response += f"<code>🌐 Website is safe to use ✅</code>\n\n"
            elif p.get_text() == "Warning":
                response += f"🌐 Website Rating: <code>{p.get_text()} ❌</code>\n\n"
                response += f"<code>Possible Threat - Not safe ❌</code>\n\n"
            elif p.get_text() == "Untested":
                response += f"🌐 Website Rating: <code>{p.get_text()} ❓</code>\n\n"
                response += f"<code>🌐 Website Untested</code> ❓\n\n"
            elif p.get_text() == "Caution":
                response += f"🌐 Website Rating: <code>{p.get_text()} ⚠️</code>\n\n"
                response += f"<code>Possible Threat - Not safe</code> ⚠️\n\n"
            else:
                response += f"🌐 Website Rating : <code>{p.get_text()} </code>\n\n"

    for class_name in classes_to_extract2:
        # Find all <p> tags with the specified class
        p_tags = soup.find_all('p', class_=class_name)

        # Print the text content of each <p> tag with the current class
        for p in p_tags:
            response += f"📚 {p.get_text()}: "

    for p in p_tags1:
        if p.find('span'):  # Check if <span> element is present inside the <p> tag
            response += " "+f"<code>{p.get_text()}</code>"+" "

    await waiting_msg.delete()
    await update.message.reply_text(f"<b>{response}</b>", parse_mode="HTML")

    result = subprocess.run(["dig", f"{domain1}", "A"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    ip_response = f"📍 IP ADDRESS LIST\n\n"
    ip_response += f"Domain: <code>{domain1}</code>\n\n"
    # Check if the command was successful
    if result.returncode == 0:
        # Use a regular expression to capture each IP address in the ANSWER SECTION
        answer_section = re.search(r";; ANSWER SECTION:[\s\S]*?;;", result.stdout)
        if answer_section:
            # Find all IP addresses in the ANSWER SECTION
            ip_addresses = re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', answer_section.group(0))
            ip_list = ip_addresses
            for index, ip in enumerate(ip_list, start=1):
                ip_response += f"{index}. <code>{ip}</code>\n\n"  # Output list of IP addresses(List)
        else:
            await update.message.reply_text("<code><b>❗ No IP found.</b></code>", parse_mode="HTML")
            return
    else:
        await update.message.reply_text(f"Error: {result.stderr}")
        return
    await update.message.reply_text(f"<b>{ip_response}</b>", parse_mode="HTML")

    for i in range(len(ip_list)):
        wanted_ip = ip_list[i]
        ip_address = f"{wanted_ip}"

        # Base URL to get the website cookies
        base_url = 'https://nordvpn.com'

        # Send a GET request to the base website to fetch cookies
        response_base = requests.get(base_url)

        # Get all cookies from the base URL and convert them into a 'Cookie' header format
        cookie_header = '; '.join([f'{cookie.name}={cookie.value}' for cookie in response_base.cookies])

        # Now, set the URL for the specific query
        query_url = f'https://nordvpn.com/wp-admin/admin-ajax.php?action=get_user_info_data&ip={ip_address}'

        # Headers with the cookies from the base URL
        headers = {
            'Accept': '*/*',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-GB,en;q=0.8',
            'Cache-Control': 'no-cache',
            'Cookie': cookie_header,
            'Dnt': '1',
            'Pragma': 'no-cache',
            'Referer': 'https://nordvpn.com/ip-lookup/',
            'Sec-Ch-Ua': '"Chromium";v="130", "Brave";v="130", "Not?A_Brand";v="99"',
            'Sec-Ch-Ua-Mobile': '?0',
            'Sec-Ch-Ua-Platform': '"macOS"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'Sec-Gpc': '1',
            'User-Agent': 'Mozilla/6.0 (Macintosh; Intel Mac OS X 12_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36',
        }

        # Send a GET request to fetch info of ip with the provided query and headers
        response_query = requests.get(query_url, headers=headers)
        if response_query.status_code == 200:
            response_data = response_query.json()

            time.sleep(1)

            # Converting Json to plane text to modify
            def convert_json_to_plain_text(json_data):

                plain_text = []
                ip_regex_strict = r'\b((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b'
                domain = list(json_data.values())[3]

                # Extract and format each value as a string
                plain_text.append(f"IP Address: <code>{json_data['ip']}</code>")
                plain_text.append(f"Internet Service Provider: <code>{json_data['isp']}</code>")
                if re.search(ip_regex_strict, list(domain.values())[0]):
                    plain_text.append(f"Hostname: <code>Null</code>")
                else:
                    plain_text.append(f"Hostname: <code>{list(domain.values())[0]} ({list(domain.values())[1]})</code>")
                plain_text.append(f"Location: <code>{json_data['location']}</code>")
                plain_text.append(
                    f"Coordinates: <code>Latitude {json_data['coordinates']['latitude']}, Longitude {json_data['coordinates']['longitude']}</code>")
                plain_text.append(f"Country: <code>{json_data['country']}</code>")
                plain_text.append(f"Region: <code>{json_data['region']}</code>")
                plain_text.append(f"City: <code>{json_data['city']}</code>")
                plain_text.append(f"Area Code: <code>{json_data['area_code']}</code>")
                plain_text.append(f"Country Code: <code>{json_data['country_code']}</code>")

                return '\n'.join(plain_text)

            # Convert JSON to plain text and print it
            plain_text_output = convert_json_to_plain_text(response_data)
            ip_text = f"🔍 IP DETAILS - {i+1}\n\n"
            ip_text += plain_text_output
            await update.message.reply_text(f"<b>{ip_text}</b>", parse_mode="HTML")

# Run the bot
if __name__ == '__main__':

    print("starting bot...")
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler('start', start_command))
    app.add_handler(CommandHandler('run', run_bot))

    # Will continuously check the userinput to execute the code
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_url_input))

    print("polling started...")
    app.run_polling(poll_interval=1)
