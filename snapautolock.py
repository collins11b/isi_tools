"""Module providing functions to get and lock snapshots 
meeting certain criteria for a user specified # of days"""

from getpass import getpass
import argparse
import logging
import sys
import base64
import os
import datetime
import ipaddress
import json
import requests
import urllib3


def validateinput(ip):
    """This function checks for valid input"""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print("\nPlease enter a valid IP address!\n")
        sys.exit()


def datetoepoch(days):
    """This function converts a datetime, checks validity, then returns epoch time"""
    currentdate = datetime.datetime.now()
    expirydate = int((currentdate + datetime.timedelta(days=int(days))).timestamp())
    return expirydate


def getsession(uri):
    """This function gets a session and sets headers, returns session"""
    creds = "creds.json"
    if os.path.isfile(creds):
        with open(creds, "r", encoding="utf-8") as f:
            data = json.load(f)
            user = data["username"]
            p = base64.b64decode(data["password"]).decode("utf-8")
    elif os.path.isfile(creds) is False:
        user = input("Please provide your user name? \n")
        print("\nPlease provide the password for your user account...\n")
        p = getpass()

    print("\n\nAttempting session to " + uri + " ...\n")
    headers = {"Content-Type": "application/json"}
    data = json.dumps({"username": user, "password": p, "services": ["platform"]})
    api_session = requests.Session()
    response = api_session.post(
        uri + "/session/1/session", data=data, headers=headers, verify=False
    )
    if response.status_code == 200 or response.status_code == 201:
        print("Session to " + uri + " established.\n")
        logging.info("API session created successfully by " + user + " at " + uri)
    elif response.status_code != 200 or response.status_code != 201:
        print(
            "\nSession to "
            + uri
            + " not established. Please check your password, user name, or IP and try again.\n"
        )
        logging.info(
            "Creation of API session by " + user + " at " + uri + " unsuccessful"
        )
        sys.exit()
    api_session.headers["referer"] = uri
    api_session.headers["X-CSRF-Token"] = api_session.cookies.get("isicsrf")
    return api_session, user


def getsnapshots(api_session, uri):
    """This function gets a list of snapshots and locks unlocked 
    snapshots for a certain time with exclusions"""
    resourceurl = "/platform/1/snapshot/snapshots"
    snapresult = api_session[0].get(uri + resourceurl, verify=False)
    if snapresult.status_code == 200 or snapresult.status_code == 201:
        logging.info(
            "GET request at by "
            + api_session[1]
            + " at "
            + uri
            + resourceurl
            + " successful"
        )
        snapresult = json.loads(snapresult.content.decode(encoding="UTF-8"))
    elif snapresult.status_code != 200 or snapresult.status_code != 201:
        logging.info(
            "GET request at by "
            + api_session[1]
            + " at "
            + uri
            + resourceurl
            + " unsuccessful"
        )
        print(
            "\nIssue encountered with retrieving snapshots at "
            + uri
            + " Please try again.\n"
        )
        return 0
    snapids = []
    if len(snapresult["snapshots"]) == 0:
        print("\nThere are no snapshots!")
        return 0
    else:
        lis = ["SIQ", "FSAnalyze", "Index"]
        for snapshot in snapresult["snapshots"]:
            if (
                snapshot["has_locks"] is False
                and any(substring in snapshot["name"] for substring in lis) is False
            ):
                snapids.append(snapshot["id"])
    return snapids


def locksnapshots(api_session, uri, days, snapids):
    """This function will lock a snapshot or list of snapshots"""
    expirydate = datetoepoch(int(days))
    for snap in snapids:
        resourceurl = "/platform/12/snapshot/snapshots/" + str(snap) + "/locks"
        print("\nProceeding with creation of snapshot lock...\n")
        data = json.dumps(
            {
                "comment": "This lock was created by snapautolock.",
                "expires": expirydate,
            }
        )
        response = api_session[0].post(uri + resourceurl, data=data, verify=False)
        if response.status_code == 200 or response.status_code == 201:
            logging.info(
                "POST request by "
                + api_session[1]
                + " at "
                + uri
                + resourceurl
                + " successful"
            )
            response = json.loads(response.content.decode(encoding="UTF-8"))
            lockid = response["id"]
            print(
                "\nLock ID "
                + str(lockid)
                + " created "
                + "on snap ID "
                + str(snap)
                + "!\n"
            )
        elif response.status_code != 200 or response.status_code != 201:
            logging.info(
                "POST request by "
                + api_session[1]
                + " at "
                + uri
                + resourceurl
                + " unsuccessful"
            )
            print("\nLock creation encountered an issue. Try again!")

    return 0


def main():
    """This function is the main function that runs the snaplock"""
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    parser = argparse.ArgumentParser(
        description="Lock all snapshots for provided timeframe"
    )
    parser.add_argument("ip", help="Enter a valid IP address")
    parser.add_argument(
        "days",
        help="Type a number of days for the snapshots to be locked.",
    )
    args = parser.parse_args()

    ip = args.ip
    validateinput(ip)
    days = args.days

    logging.basicConfig(
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        filename="isi_tools.log",
        level=logging.INFO,
    )

    port = 8080
    uri = "https://" + str(ip) + ":" + str(port)

    api_session = getsession(uri)
    snapids = getsnapshots(api_session, uri)
    if not snapids:
        print(
            "No non-system derived snapshots were found that did not have a lock!\n\n"
        )
    else:
        locksnapshots(api_session, uri, days, snapids)


if __name__ == "__main__":
    main()
