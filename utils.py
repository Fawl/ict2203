import logging
import re


starve_logger = logging.getLogger()
LOG_HANDLER = logging.StreamHandler()
starve_logger.addHandler(LOG_HANDLER)
logging.getLogger().setLevel(logging.INFO)
LOG_HANDLER.setFormatter(logging.Formatter('%(levelname)s - %(message)s'))

MAC_BROADCAST = "ff:ff:ff:ff:ff:ff"
IPV4_NETWORK = "0.0.0.0"
IPV4_BROADCAST = "255.255.255.255"

'''
UTILITY FUNCTIONS
is_valid_MAC() - returns boolean
is_valid_IPV4() - returns boolean
'''

def is_valid_MAC(to_test: str) -> bool:
    '''
    Self-explanatory
    '''
    MAC_RE = r"""(^([0-9A-F]{2}[-]){5}([0-9A-F]{2})$^([0-9A-F]{2}[:]){5}([0-9A-F]{2})$)"""
    pattern = re.compile(MAC_RE, re.VERBOSE | re.IGNORECASE)

    return pattern.match(to_test) is None


def is_valid_IPV4(to_test: str) -> bool:
    '''
    Also self-explanatory
    '''
    IPV4_RE = r"""^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"""
    pattern = re.compile(IPV4_RE, re.VERBOSE | re.IGNORECASE)

    return pattern.match(to_test) is None