#MO's that need to be queried:
# firmwareCtrlrRunning - APIC Firmware
# firmwareRunning - Switch Firmware

import sys, os, subprocess, re, getpass, logging
from app.tasks.ept import utils as ept_utils
from app.tasks.tools.acitoolkit.acisession import Session
from app.models.users import Users
from app.models.roles import Roles
from app.models.settings import Settings
from app.models.ept import EP_Settings
from app.models.utils import force_attribute_type


def get_fabric_version(hostname, apic_username, apic_cert):
    """ use provided cert credentials and read firmwareCtrlrRunning
    """
    logger.debug("attempting to get fabric domain from %s@%s" % (
        apic_username, hostname))