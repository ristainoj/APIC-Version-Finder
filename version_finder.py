#MO's that need to be queried:
# firmwareCtrlrRunning - APIC Firmware
# firmwareRunning - Switch Firmware

import sys, re, getpass, argparse, logging, logging.handlers
from acisession import Session


#####################################
### Uncomment if you want logging ###
#####################################

logger = logging.getLogger(__name__)
root_logger = logging.getLogger()
#root_logger.setLevel(logging.DEBUG)

logger_handler = logging.StreamHandler(sys.stdout)
fmt ="%(process)d||%(asctime)s.%(msecs).03d||%(levelname)s||%(filename)s"
fmt+=":(%(lineno)d)||%(message)s"
logger_handler.setFormatter(logging.Formatter(
        fmt=fmt,
        datefmt="%Z %Y-%m-%d %H:%M:%S")
    )
logger.addHandler(logger_handler)
root_logger.addHandler(logger_handler)

def env_setup(args):

# Load IP from ARGS or Prompt
    ip = args.ip
    while ip is None:
        ip = raw_input("Enter IP of APIC   :")
        if len(ip) == 0:
            print "URL is required"
            ip = None

# Set URL based on auth and port number if set in ARGS
    https = args.https
    port = args.port
    if port and https:
        url = str("https://" + ip + ":" + port)
    elif port:
        url = str("http://" + ip + ":" + port)
    elif https:
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

    # GET firmwareCtrlrRunning and firmwareRunning from APIC
    apicMoUrl = "/api/node/class/firmwareCtrlrRunning.json"
    switchMoUrl = "/api/node/class/firmwareRunning.json"
    apicResp = session.get(apicMoUrl)
    apicJS = apicResp.json()
    switchResp = session.get(switchMoUrl)
    switchJS = switchResp.json()

    # Get # of APICs in cluster
    num_of_apics = apicJS['totalCount']
    if num_of_apics == "1":
        print "\n"
        print "#########################################"
        print "     There is %s APIC in the cluster" % num_of_apics
        print "#########################################"
    else:
        print "\n"
        print "#########################################"
        print "    There are %s APICs in the cluster" % num_of_apics
        print "#########################################"

    # Iterate through number of APICs and display version of each
    for i in range(0, int(num_of_apics)):
        dn = apicJS["imdata"][i]["firmwareCtrlrRunning"]["attributes"]["dn"]
        regex = re.findall("^topology\/pod-[0-9]\/(node-[0-9])", str(dn))
        version = apicJS["imdata"][i]["firmwareCtrlrRunning"]["attributes"]["version"]
        #print "APIC" + str(i + 1)  + " ----> " + version
        if str(regex) == "['node-1']":
            apic = "APIC1"
        elif str(regex) == "['node-2']":
            apic = "APIC2"
        else:
            apic = "APIC3"
        print apic + " ----> " + version

    print "\n"
    # Get # of Switches in cluster
    num_of_switch = switchJS['totalCount']
    if num_of_switch == "1":
        print "#########################################"
        print "There is %s Switch in the cluster" % num_of_switch
        print "#########################################"
    else:
        print "#########################################"
        print "   There are %s Switches in the cluster" % num_of_switch
        print "#########################################"

    # Iterate through number of Switches and display version of each
    for i in range(0, int(num_of_switch)):
        dn = switchJS["imdata"][i]["firmwareRunning"]["attributes"]["dn"]
        #regex = re.findall("^topology\/pod-[0-9]\/(node-[0-9]+)", str(dn))
        r1 = re.search("^topology\/pod-[0-9]+\/(?P<n>node-[0-9]+)", str(dn))
        if r1 is not None:
            version = switchJS["imdata"][i]["firmwareRunning"]["attributes"]["version"]
            #print "APIC" + str(i + 1)  + " ----> " + version
            print r1.group("n") + " ----> " + version

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
    parser.add_argument("--port", action="store", dest="port",
        help="port number to use for APIC communicaton", default=None)

    return parser.parse_args()


if __name__ == "__main__":

    args = get_args()

    url, usr, pwd = env_setup(args)

    get_fabric_version(url, usr, pwd)
