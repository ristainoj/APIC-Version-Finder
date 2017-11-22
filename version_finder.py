#MO's that need to be queried:
# firmwareCtrlrRunning - APIC Firmware
# firmwareRunning - Switch Firmware

import sys, os, subprocess, re, getpass, argparse, logging, logging.handlers
#from app.tasks.ept import utils as ept_utils
from acisession import Session

# setup ept_utils logger
logger = logging.getLogger(__name__)
root_logger = logging.getLogger()
root_logger.setLevel(logging.DEBUG)

logger_handler = logging.StreamHandler(sys.stdout)
fmt ="%(process)d||%(asctime)s.%(msecs).03d||%(levelname)s||%(filename)s"
fmt+=":(%(lineno)d)||%(message)s"
logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%d %H:%M:%S")
    )
logger.addHandler(logger_handler)
root_logger.addHandler(logger_handler)
#ept_utils.setup_logger(logger, quiet=True)

def env_setup(args):

# Load IP from ARGS or Prompt
    ip = args.ip
    while ip is None:
        ip = raw_input("Enter IP of APIC   :")
        if len(ip) == 0:
            print "URL is required"
            ip = None

# Set URL to HTTPS if set in ARGS
    https = args.https
    if https:
        url = str("https://" + ip)
    else:
        url = str("http://" + ip)

# Load username from ARGS or Prompt
    usr = args.username
    while usr is None:
        usr = getpass.getpass( "Enter username   : ")
        if len(usr)==0:
            print "Username is required"
            usr = None

# Load PW from ARGS or Prompt
    pwd = args.password
    while pwd is None:
        pwd = getpass.getpass( "Enter admin password   : ")
        pwd2 = getpass.getpass("Re-enter password   : ")
        if len(pwd)==0:
            pwd = None
        elif pwd!=pwd2:
            print "Passwords do not match"
            pwd = None
        elif " " in pwd:
            print "No spaces allowed in password"
            pwd = None

    return url, usr, pwd

def get_fabric_version(url, usr, pwd):
    """ use provided cert credentials and read firmwareCtrlrRunning
    """
    logger.debug("attempting to get fabric version from %s@%s" % (
        usr, url))

    # Create a Session to login to APIC
    session = Session(url, usr, pwd, verify_ssl=False)
    resp = session.login(timeout=60)
    if resp is None or not resp.ok:
            logger.error("failed to login with cert credentials")
            return None

    # GET firmwareCtrlrRunning APIC
    moUrl = "/api/node/class/firmwareCtrlrRunning.json"
    resp = session.get(moUrl)

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--no_verify", action="store_true", dest="no_verify",
        help="do not verify that user wants to proceed")
    parser.add_argument("--ip", action="store", dest="ip",
        help="APIC URL", default=None)
    parser.add_argument("--username", action="store", dest="username",
        help="admin username", default="admin")
    parser.add_argument("--password", action="store", dest="password",
        help="admin password", default=None)
    parser.add_argument("--https", action="store_true", dest="https",
        help="Specifies whether to use HTTPS authentication", default=None)

    return parser.parse_args()


if __name__ == "__main__":

    args = get_args()

    url, usr, pwd = env_setup(args)

    get_fabric_version(url, usr, pwd)
