from mitmproxy import http
import sqlite3, time, os

script_path = os.path.dirname(os.path.realpath(__file__)) + "/"
DBconn = sqlite3.connect(script_path + "lanGhost.db")
DBcursor = DBconn.cursor()
DBcursor.execute("CREATE TABLE IF NOT EXISTS lanGhost_mitm (id integer primary key autoincrement, source VARCHAR(50),host TEXT, url TEXT, method VARCHAR(50), data TEXT, time TEXT)")
DBconn.commit()
DBconn.close()

# source, host, url, method, data, time

def request(flow):
    DBconn = sqlite3.connect(script_path + "lanGhost.db")
    DBcursor = DBconn.cursor()
    if flow.request.method == "POST":
        DBcursor.execute("INSERT INTO lanGhost_mitm(source, host, url, method, data, time) VALUES (?, ?, ?, ?, ?, ?)", (str(flow.client_conn.address()[0]), str(flow.request.host), str(flow.request.pretty_url), str(flow.request.method), str(flow.request.text), str(int(time.time()))))
        DBconn.commit()
        print(str(flow.client_conn.address()[0]) + " - " + flow.request.host + " - " + flow.request.pretty_url + " - " + flow.request.method + " - " + str(flow.request.text) + " - " + str(int(time.time())))
    else:
        DBcursor.execute("INSERT INTO lanGhost_mitm(source, host, url, method, data, time) VALUES (?, ?, ?, ?, ?, ?)", (str(flow.client_conn.address()[0]), str(flow.request.host), str(flow.request.pretty_url), str(flow.request.method), "false", str(int(time.time()))))
        DBconn.commit()
        print(str(flow.client_conn.address()[0]) + " - " + flow.request.host + " - " + flow.request.pretty_url + " - " + flow.request.method + " - " + "false" + " - " + str(int(time.time())))
    DBconn.close()
