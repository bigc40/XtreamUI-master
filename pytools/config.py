import sys
import json
import base64
import os
from itertools import cycle

rConfigPath = "/home/xtreamcodes/iptv_xtream_codes/config"


def doDecrypt():
    rDecrypt = decrypt()
    if rDecrypt:
        print("Server ID: %s%d" % (" "*10, int(rDecrypt["server_id"])))
        print("Host: %s%s" % (" "*15, rDecrypt["host"]))
        print("Port: %s%d" % (" "*15, int(rDecrypt["db_port"])))
        print("Username: %s%s" % (" "*11, rDecrypt["db_user"]))
        print("Password: %s%s" % (" "*11, rDecrypt["db_pass"]))
        print("Database: %s%s" % (" "*11, rDecrypt["db_name"]))
    else:
        print("Config file could not be read!")


def decrypt():
    try:
        with open(rConfigPath, 'rb') as f:
            decoded = base64.b64decode(f.read()).decode()
            return json.loads(''.join(chr(ord(c) ^ ord(k)) for c, k in zip(decoded, cycle('5709650b0d7806074842c6de575025b1'))))
    except:
        return None


def encrypt(rInfo):
    try:
        os.remove(rConfigPath)
    except:
        pass

    with open(rConfigPath, 'wb') as f:
        encoded = json.dumps(rInfo).encode()
        encrypted = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(encoded, cycle('5709650b0d7806074842c6de575025b1')))
        f.write(base64.b64encode(encrypted.encode()))


if __name__ == "__main__":
    try:
        rCommand = sys.argv[1]
    except:
        rCommand = None

    if rCommand and rCommand.lower() == "decrypt":
        doDecrypt()
    elif rCommand and rCommand.lower() == "encrypt":
        print("Current configuration")
        print(" ")
        doDecrypt()
        print(" ")
        rEnc = {"pconnect": 0}
        try:
            rEnc["server_id"] = int(input("Server ID: %s" % (" "*10)))
            rEnc["host"] = input("Host: %s" % (" "*15))
            rEnc["db_port"] = input("Port: %s" % (" "*15))
            rEnc["db_user"] = input("Username: %s" % (" "*11))
            rEnc["db_pass"] = input("Password: %s" % (" "*11))
            rEnc["db_name"] = input("Database: %s" % (" "*11))
            print(" ")
        except:
            print("Invalid entries!")
            sys.exit(1)
        try:
            encrypt(rEnc)
            print("Written to config file!")
        except:
            print("Couldn't write to file!")
    else:
        print("Usage: config.py [ENCRYPT | DECRYPT]")
