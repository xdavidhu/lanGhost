#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# setup.py
# author: xdavidhu

from telegram.ext import Updater, MessageHandler, Filters
from random import randint
import telegram
import json
import os

if __name__ == '__main__':
    GREEN = '\033[1m' + '\033[32m'
    WHITE = '\033[1m' + '\33[97m'
    END = '\033[0m'
    header = """
                    """ + GREEN + """ _            """ + WHITE + """  _____ _               _     .-.
                    """ + GREEN + """| |           """ + WHITE + """ / ____| |             | |   | OO|
                    """ + GREEN + """| | __ _ _ __ """ + WHITE + """| |  __| |__   ___  ___| |_  |   |
                    """ + GREEN + """| |/ _` | '_ \\""" + WHITE + """| | |_ | '_ \ / _ \/ __| __| '^^^'
                    """ + GREEN + """| | (_| | | | """ + WHITE + """| |__| | | | | (_) \__ | |_
                    """ + GREEN + """|_|\__,_|_| |_""" + WHITE + """|\_____|_| |_|\___/|___/\__|
                    """
    try:
        print(header + """          v1.0 """ + WHITE + """by David Schütz (@xdavidhu)    """ + "\n" + END)
    except:
        print(header + """                         v1.0 """ + WHITE + """by @xdavidhu    """ + "\n" + END)

    print("[+] Starting setup...")
    interface = input("[?] Please enter the name of the network interface " +\
                        "connected/will be connected to the target LAN: ")
    print("[+] Interface '" + interface + "' set.")
    print("\n[+] Please create a Telegram API key by messaging @BotFather on " +\
            "Telegram with the command '/newbot'. Follow the instructions and " +\
            "make note of your bot's @username.")
    telegram_api = input("[?] Telegram API key: ")
    print("\n[+] For lanGhost to send you updates / info about new devices "+\
            "on the target LAN, and to only allow access to you, please " +\
            "send the number below to the bot you just created. Just search " +\
            "for your bot's @username to find it.")
    verification_code = ''.join(str(randint(0,9)) for _ in range(6))
    print("\n[+] Verification code to send: " + verification_code)
    admin_chatid = False
    def check_code(bot, update):
        global admin_chatid
        if update.message.text == verification_code:
            bot.send_message(chat_id=update.message.chat_id, text="✅ Verification successful.")
            admin_chatid = str(update.message.chat_id)
        else:
            bot.send_message(chat_id=update.message.chat_id, text="❌ Incorrect code.")

    try:
        updater = Updater(token=telegram_api)
    except:
        print("[!] Telegram API token is invalid... Please try again.")
    dispatcher = updater.dispatcher

    verify_handler = MessageHandler(Filters.text, check_code)
    dispatcher.add_handler(verify_handler)

    print("\n[+] Waiting for your message...")
    updater.start_polling()

    while True:
        try:
            if not admin_chatid == False:
                print("\n[+] Device linked successfully! Shutting down Telegram " +\
                        "bot, please wait a second...")
                updater.stop()
                break
        except:
            print("\n[!] Failed to get your chat ID, please try again. Exiting...")
            updater.stop()
            exit()

    print("[+] Generating config file...")
    config_object = {"interface": interface, "telegram_api": telegram_api, "admin_chatid": admin_chatid}
    config_json = json.dumps(config_object)
    script_path = os.path.dirname(os.path.realpath(__file__)) + "/"
    with open(script_path + "config.cfg", "w") as f:
        f.write(config_json)
        f.close()
    print("[+] Setup done.")
