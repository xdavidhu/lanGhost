#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# lanGhost.py
# author: xdavidhu

from telegram.error import NetworkError, Unauthorized
from telegram.ext import Updater, CommandHandler
from netaddr import IPAddress
from time import sleep
import netifaces
import telegram
import requests
import logging
import nmap
import json
import os

if os.geteuid() != 0:
    print("[!] Please run lanGhost as root!")
    exit()

def scan():
    global ip_range
    nm = nmap.PortScanner()
    scan = nm.scan(hosts=ip_range, arguments='-sP')
    hosts = []
    for host in scan["scan"]:
        if "mac" in scan["scan"][host]["addresses"]:
            hosts.append([host, scan["scan"][host]["addresses"]["mac"]])
    return hosts

def resolveMac(mac):
    r = requests.get('https://api.macvendors.com/' + mac)
    return r.text

def msg_start(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Welcome to lanGhost! 👻")

def msg_ping(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Pong! ⚡️")

def msg_scan(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Scanning network... 🔎")
    hosts = scan()
    textline = "📱 Devices online:\n\n"
    for host in hosts:
        textline += host[0] + " ➖ " + resolveMac(host[1])[:15] + "\n"
    textline = textline[:-2]
    bot.send_message(chat_id=update.message.chat_id, text=textline)

def main():
    updater = Updater(token=telegram_api)
    dispatcher = updater.dispatcher
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)

    start_handler = CommandHandler('start', msg_start)
    dispatcher.add_handler(start_handler)
    ping_handler = CommandHandler('ping', msg_ping)
    dispatcher.add_handler(ping_handler)
    scan_handler = CommandHandler('scan', msg_scan)
    dispatcher.add_handler(scan_handler)

    print("[+] Telegram bot started...")
    updater.start_polling()

if __name__ == '__main__':
    script_path = os.path.dirname(os.path.realpath(__file__)) + "/"

    try:
        with open(script_path + "config.cfg") as f:
            config = f.read()
            f.close()
    except Exception:
        print("[!] Config file not found... Please run the 'setup.py' script first.")
        exit()

    try:
        config = json.loads(config)
    except:
        print("[!] Config file damaged... Please run the 'setup.py' script to regenerate the file.")
        exit()

    interface = config.get("interface", False)
    telegram_api = config.get("telegram_api", False)

    if interface == False or telegram_api == False:
        print("[!] Config file damaged... Please run the 'setup.py' script to regenerate the file.")
        exit()

    iface_info = netifaces.ifaddresses(interface)[netifaces.AF_INET][0]
    netmask = iface_info["netmask"]
    ip = iface_info["addr"]
    ip_range = ip + "/" + str(IPAddress(netmask).netmask_bits())
    gw_ip = False
    for i in netifaces.gateways()[2]:
        if i[1] == interface:
            gw_ip = i[0]
    if not gw_ip:
        print("[!] Cant get gateway...")
    print("[+] IP address: " + ip)
    print("[+] Netmask: " + netmask)
    print("[+] IP range: " + ip_range)
    print("[+] Gateway IP: " + gw_ip)
    main()
