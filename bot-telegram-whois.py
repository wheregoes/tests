import telebot
import whois
import json
import socket
import shodan
import logging
from datetime import datetime

TOKEN = 'YOUR_TELEGRAM_BOT_TOKEN'
SHODAN_API_KEY = 'YOUR_SHODAN_API_KEY'
YOUR_TELEGRAM_USER_ID = 'YOUR_TELEGRAM_USER_ID'

bot = telebot.TeleBot(TOKEN)

logging.basicConfig(filename='bot-test-whois_log.txt', level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        return super().default(obj)

@bot.message_handler(commands=['start'])
def start(message):
    logger.info(f"User {message.from_user.id} sent /start")
    bot.reply_to(message, "Use /domain <domain_name> to get WHOIS information, IP address, and open ports of a domain.")

@bot.message_handler(commands=['domain'])
def get_domain_info(message):
    if str(message.from_user.id) != YOUR_TELEGRAM_USER_ID:
        logger.warning(f"Unauthorized user {message.from_user.id} attempted to use /domain command")
        bot.reply_to(message, "Sorry, you are not authorized to use this bot.")
        return

    logger.info(f"User {message.from_user.id} sent /domain command with domain name: {message.text}")
    args = message.text.split()
    if len(args) == 1:
        bot.reply_to(message, "Please provide a domain name after /domain.")
        return

    domain = args[1]
    try:
        domain_info = whois.whois(domain)
        ip_address = socket.gethostbyname(domain)
        shodan_results = get_shodan_results(domain)
        formatted_info = format_domain_info(domain_info, ip_address, shodan_results)
        bot.reply_to(message, f"<b>WHOIS information for {domain}:</b>\n\n{formatted_info}", parse_mode="HTML")
    except Exception as e:
        logger.error(f"Error fetching information for {domain}: {e}")
        bot.reply_to(message, f"Failed to fetch information for {domain}. Error: {e}")

def get_shodan_results(domain):
    shodan_api = shodan.Shodan(SHODAN_API_KEY)
    results = shodan_api.search(domain)
    return results['matches'] if 'matches' in results else []

def format_domain_info(domain_info, ip_address, shodan_results):
    formatted = ""
    for key, value in domain_info.items():
        if isinstance(value, list):
            if all(isinstance(item, datetime) for item in value):
                value = "\n".join([item.strftime("%Y-%m-%d %H:%M:%S") for item in value])
            else:
                value = "\n".join([str(item) for item in value])
        elif isinstance(value, datetime):
            value = value.strftime("%Y-%m-%d %H:%M:%S")
        formatted += f"<b>{key}:</b> {value}\n"
    formatted += f"<b>IP Address:</b> {ip_address}\n"
    if shodan_results:
        formatted += f"\n<b>Open Ports (from Shodan):</b>\n"
        for result in shodan_results:
            formatted += f"{result['port']} - {result['transport']} - {result['ip_str']}\n"
    else:
        formatted += "\n<b>Open Ports (from Shodan):</b> None"
    return formatted

if __name__ == "__main__":
    bot.polling()