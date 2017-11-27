# APIC-Version-Finder
Find the version of APICs and switches in an ACI Fabric

This script queries an APIC and outputs the versions for APICs and Switches.

For example:
```
root@03c3cd5ee8f7:/Scripts/Version_Finder# python version_finder.py --help       
usage: version_finder.py [-h] [--no_verify] [--ip IP] [--username USERNAME]
                         [--password PASSWORD] [--https] [--port PORT]

optional arguments:
  -h, --help           show this help message and exit
  --no_verify          do not verify that user wants to proceed
  --ip IP              APIC URL
  --username USERNAME  admin username
  --password PASSWORD  admin password
  --https              Specifies whether to use HTTPS authentication
  --port PORT          port number to use for APIC communicaton

root@03c3cd5ee8f7:/Scripts/Version_Finder# python version_finder.py --https --ip esc-aci-fab3 --port 8011
Enter admin password   : 
Re-enter password   : 


#########################################
    There are 3 APICs in the cluster
#########################################
APIC1 ----> 3.0(2k)
APIC2 ----> 3.0(2k)
APIC3 ----> 3.0(2k)


#########################################
   There are 6 Switches in the cluster
#########################################
node-103 ----> n9000-13.0(2k)
node-102 ----> n9000-13.0(2k)
node-201 ----> n9000-13.0(2k)
node-101 ----> n9000-13.0(2k)
node-104 ----> n9000-13.0(2k)
node-202 ----> n9000-13.0(2k)
```
