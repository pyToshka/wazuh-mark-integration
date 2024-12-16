#!/var/ossec/framework/python/bin/python3
import json
import sys
import time
import os
from socket import socket, AF_UNIX, SOCK_DGRAM

try:
    import requests
except Exception as e:
    print(
        "No module 'requests' found. "
        "Install: pip install requests. Error {}".format(e)
    )
    sys.exit(1)

# Global vars
debug_enabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
# alert dictionary
alert = {}
# time now
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")
# log file for integrations logging
log_file = "{0}/logs/integrations.log".format(pwd)
# Wazuh socket address
socket_addr = "{0}/queue/sockets/queue".format(pwd)


def debug(msg):
    if debug_enabled:
        msg = "{0}: {1}\n".format(now, msg)
    integration_logs = open(log_file, "a")
    integration_logs.write(str(msg))
    integration_logs.close()


def in_database(data, srcip):
    result = data["src_ip"]
    if result == 0:
        return False
    return True


def send_event(msg, agent=None):
    if not agent or agent["id"] == "000":
        string = "1:mark:{0}".format(json.dumps(msg))
    else:
        string = "1:[{0}] ({1}) {2}->chatgpt:{3}".format(
            agent["id"],
            agent["name"],
            agent["ip"] if "ip" in agent else "any",
            json.dumps(msg),
        )
    debug(string)
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()


def get_mark_info(alert, mark_base_domain):
    alert_output = {}
    # Exit if the alert does not contain a source IP address.
    if "srcip" not in alert["data"]:
        return 0
    # Request info using MARK API
    data = query_api(alert["data"]["srcip"], mark_base_domain)
    # Create alert
    alert_output["mark"] = {}
    alert_output["integration"] = "custom-mark"
    alert_output["mark"]["found"] = 0
    alert_output["mark"]["source"] = {}
    alert_output["mark"]["source"]["alert_id"] = alert["id"]
    alert_output["mark"]["source"]["rule"] = alert["rule"]["id"]
    alert_output["mark"]["source"]["description"] = alert["rule"]["description"]
    alert_output["mark"]["source"]["full_log"] = alert["full_log"]
    alert_output["mark"]["source"]["srcip"] = alert["data"]["srcip"]
    src_ip = alert["data"]["srcip"]

    # Check if MARK has any info about the srcip
    if in_database(data, src_ip):
        alert_output["mark"]["found"] = 1
    # Info about the IP found in chatgpt
    if alert_output["mark"]["found"] == 1:
        # Populate JSON Output object with chatgpt request
        alert_output["mark"]["srcip"] = src_ip
        alert_output["mark"]["info"] = data
        debug(alert_output)

    return alert_output


def query_api(src_ip, mark_base_domain):
    headers = {
        "Content-Type": "application/json",
    }
    response = requests.get(
        mark_base_domain + "/ip-reputation?ip={}".format(src_ip), headers=headers
    )
    if response.status_code == 200:
        # Create new JSON
        data = response.json()
        return data
    else:
        alert_output = {"mark": {}, "integration": "custom-mark"}
        json_response = response.json()
        debug("# Error: The mark encountered an error")
        alert_output["mark"]["error"] = response.status_code
        alert_output["mark"]["description"] = json_response
        send_event(alert_output)
        exit(0)


if __name__ == "__main__":
    debug("# Starting")
    alert_file_location = sys.argv[1]
    # MARK API base domain
    mark_base_domain = sys.argv[3]
    debug("# File location")
    debug(alert_file_location)
    # Load alerts for parsing JSON objects.
    with open(alert_file_location) as alert_file:
        alert = json.load(alert_file)
    debug("# Processing alert")
    debug(alert)
    msg = get_mark_info(alert, mark_base_domain)
    # If a positive match is detected, send the event to the Wazuh Manager.
    if msg:
        send_event(msg, alert["agent"])
