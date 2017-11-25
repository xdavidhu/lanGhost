#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# lanGhost.py
# author: xdavidhu

from telegram.ext import Updater, CommandHandler
from netaddr import IPAddress
from time import sleep
import netifaces
import threading
import telegram
import requests
import logging
import time
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
    return r.text[:15]

def subscriptionHandler(bot):
    global admin_chatid

    hosts = False
    while True:
        print("[+] Scanning for new hosts...")
        new_hosts = scan()
        connected_hosts = []
        disconnected_hosts = []
        if not hosts == False:
            for new_host in new_hosts:
                if not new_host in hosts:
                    connected_hosts.append(new_host)
            for host in hosts:
                if not host in new_hosts:
                    disconnected_hosts.append(host)

        hosts = new_hosts

        for host in connected_hosts:
            print("[+] New device connected: " + resolveMac(host[1]) + " - " + host[0])
            bot.send_message(chat_id=admin_chatid, text="➕📱 New device connected: " + resolveMac(host[1]) + " ➖ " + host[0])
        for host in disconnected_hosts:
            print("[+] Device disconnected: " + resolveMac(host[1]) + " - " + host[0])
            bot.send_message(chat_id=admin_chatid, text="➖📱 Device disconnected: " + resolveMac(host[1]) + " ➖ " + host[0])

        time.sleep(5)

def msg_start(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Welcome to lanGhost! 👻")

def msg_ping(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Pong! ⚡️")

def msg_scan(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="Scanning network... 🔎")
    hosts = scan()
    textline = "📱 Devices online:\n\n"
    for host in hosts:
        textline += host[0] + " ➖ " + resolveMac(host[1]) + "\n"
    textline = textline[:-2]
    bot.send_message(chat_id=update.message.chat_id, text=textline)

def main():
    updater = Updater(token=telegram_api)
    dispatcher = updater.dispatcher
    bot = updater.bot

    t = threading.Thread(target=subscriptionHandler, args=[bot])
    t.daemon = True
    t.start()

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
    admin_chatid = config.get("admin_chatid", False)

    if interface == False or telegram_api == False or admin_chatid == False:
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
