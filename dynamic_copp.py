#!/usr/bin/env python

import sys
import getopt
import time
import re
from subprocess import Popen, PIPE

debug = False
offline = False

# location of CoPP file
copp_file = "/etc/cumulus/acl/policy.d/00control_plane.rules"
config_file = "/etc/quagga/Quagga.conf"
copp_config = []
bgp4_peers = []

'''
TODO: Support IPv6 peers. Current initalize_copp_config will prevent v6 peers from forming
TODO: put ingress interface in CoPP rule
'''


def read_file(file):
    raw_file = open(file, 'r+')

    file_list = raw_file.readlines()

    raw_file.close()

    return file_list


def get_neighbor_ips(testing=False):
    ''' 
    Parses a Quagga.conf file for a list of BGP "neighbor" commands.

    Returns:
    Set of strings for each neighbor IP
    '''
    ip_set = set()
    quagga_lines = []

    # When Quagga config changes are made the file can't be read and causes python to raise an exception
    # It's easier to just use vtysh to pull the config, but then we can't do offline testing
    if testing:
        quagga_lines = read_file(config_file)

    else:
        p = Popen("vtysh -c 'show run'", shell=True, stdout=PIPE, stderr=PIPE)

        config_chars = p.communicate()[0]
        quagga_lines = config_chars.split("\n")

    slice_len = len(" neighbor ") - 1

    for line in quagga_lines:
        v4match = re.match('^\sneighbor\s[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\s', line)
        if v4match:
            ip_set.add(v4match.group(0)[slice_len:].strip())

    if debug:
        print "Neighbor Set: " + repr(ip_set)

    return ip_set


def parse_copp_peers(line):
    ''' 
    Parses an IPtables list of BGP peers.

    Keyword Args:
    line - CSV string of BGP peer IPs

    Returns set of peer IPs (as string)
    '''

    string_ip = line.split("=")
    # ['BGP4_PEERS ', ' ""']
    # ['BGP4_PEERS ', ' "192.168.1.1,"']
    # ['BGP4_PEERS ', ' "192.168.1.1,192.168.1.2"']

    quotes = string_ip[1].strip()
    # ""
    # "192.168.1.1,"
    # "192.168.1.1,192.168.1.2"

    if quotes == "\"\"":
        return set()

    else:
        comma = quotes.split("\"")
        # ['', '192.168.1.1,', '']
        # ['', '192.168.1.1,192.168.1.2', '']

        if len(comma) == 1:
            return set([comma[0]])

        return set(comma[1].split(","))
        # ['192.168.1.1', '']
        # ['192.168.1.1', '192.168.1.2']


def add_to_copp(new_peer_set, copp_config):
    '''
    Takes in an old copp policy and adds a peer IP to 
    the list of trusted hosts.

    Keyword Args:
    old_policy - list of strings representing old CoPP config
    peer - Peer IP to add to the old_policy

    Returns - new list of strings representing updated CoPP config
    '''

    peer_set = set()
    updated_copp_config = []

    peer_set.update(new_peer_set)

    for line in copp_config:
        if "BGP4_PEERS =" in line:
            peer_set.update(parse_copp_peers(line))
            peer_string = ",".join(peer_set)
            updated_copp_config.append("BGP4_PEERS = \"" + peer_string + "\"")
        else:
            updated_copp_config.append(line)

    return updated_copp_config


def remove_from_copp(remove_peer_set, copp_config):
    '''
    Takes in an old copp policy and removes a peer IP from
    the list of trusted hosts.

    Keyword Args:
    old_policy - list of strings representing old CoPP config
    peer - Peer IP to remove from the old_policy

    Returns - new list of strings representing updated CoPP config
    '''

    peer_set = set()
    updated_copp_config = []

    for line in copp_config:
        if "BGP4_PEERS =" in line:
            peer_set.update(parse_copp_peers(line))
            peer_set = peer_set - remove_peer_set
            peer_string = ",".join(peer_set)  
            updated_copp_config.append("BGP4_PEERS = \"" + peer_string + "\"")

        else:
            updated_copp_config.append(line)

    return updated_copp_config


def initalize_copp_config(copp_file):
    '''
    Removes any bgp related lines from a CoPP config.
    Sets variables for updated CoPP config

    Keyword Args:
    copp_file - file location of the copp_file

    Returns:
    list of lines for new CoPP config
    '''

    # Default starting BGP config:
    #
    # ...v4 rule destined to BGP port
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --dport bgp -j SETCLASS --class 7
    # -A $INGRESS_CHAIN -p tcp --dport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000
    # 
    # ...v4 rule sourced from BGP port
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --sport bgp -j SETCLASS --class 7
    # -A $INGRESS_CHAIN -p tcp --sport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000
    # 
    # ...v6 rule src/dst to BGP port
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --dport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000 --set-class 7
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --sport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000 --set-class 7
    # 
    # New Config:
    # BGP4_PEERS = ""
    # BGP6_PEERS = ""
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s BGP4_PEERS -p tcp --dport bgp -j SETCLASS --class 7 --set-burst 2000
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s BGP4_PEERS -p tcp --sport bgp -j SETCLASS --class 7 --set-burst 2000
    # -A $INGRESS_CHAIN -p tcp --sport bgp -j DROP
    # -A $INGRESS_CHAIN -p tcp --dport bgp -j DROP
    #
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s BGP6_PEERS -p tcp --dport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000 --set-class 7
    # -A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s BGP6_PEERS -p tcp --sport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000 --set-class 7
    # -A $INGRESS_CHAIN -p tcp --sport bgp -j DROP
    # -A $INGRESS_CHAIN -p tcp --dport bgp -j DROP

    config_list = []

    copp = read_file(copp_file)

    v4_Martians = "-A $INNFWD_CHAIN --in-interface $INGRESS_INTF -s $MARTIAN_SOURCES_4 -j DROP"
    v6_Martians = "-A $INNFWD_CHAIN --in-interface $INGRESS_INTF -s $MARTIAN_SOURCES_6 -j DROP"

    config_list.append("BGP4_PEERS = \"\"")
    config_list.append("BGP6_PEERS = \"\"")
    config_list.append("")

    for line in copp:
        if v4_Martians in line:
            config_list.append(v4_Martians)
            config_list.append("")
            config_list.append("-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP4_PEERS -p tcp --dport bgp -j SETCLASS --class 7 --set-burst 2000")
            config_list.append("-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP4_PEERS -p tcp --sport bgp -j SETCLASS --class 7 --set-burst 2000")
            config_list.append("-A $INGRESS_CHAIN -p tcp --sport bgp -j DROP")
            config_list.append("-A $INGRESS_CHAIN -p tcp --dport bgp -j DROP")
            config_list.append("")
            continue

        if v6_Martians in line:
            config_list.append(v6_Martians)
            config_list.append("")
            config_list.append("-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP6_PEERS -p tcp --dport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst")
            config_list.append("-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP6_PEERS -p tcp --sport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst")
            config_list.append("-A $INGRESS_CHAIN -p tcp --sport bgp -j DROP")
            config_list.append("-A $INGRESS_CHAIN -p tcp --dport bgp -j DROP")
            config_list.append("")
            continue

        if "bgp" in line:
            continue

        if "BGP" in line:
            continue

        if line == "\n":
            continue

        else:
            config_list.append(line)

    return config_list


def write_copp_config(copp_config):
    ''' 
    Takes in a list of lines for the CoPP config
    and writes to the CoPP file.

    Keyword Args:
    copp_config - list of strings to write to copp config
    '''

    file_handler = open(copp_file, 'w')

    for line in copp_config:
        file_handler.write(line + "\n")

    file_handler.close()

    p = Popen("cl-acltool -i", shell=True, stdout=PIPE, stderr=PIPE)

    return p.communicate()[0]


def main(argv):
    global debug, offline

    options, remainder = getopt.getopt(sys.argv[1:], "", ["debug", "offline"])

    for opt, arg in options:
        if opt in "--debug":
            debug = True
        if opt in "--offline":
            offline = True

    # Get a list of all Established neighbor IPs. convert to set for easer operations later
    old_neighbor_list = get_neighbor_ips(testing=offline)

    if debug:
        print "List of Neighbors: " + repr(old_neighbor_list)

    copp_config = initalize_copp_config(copp_file)
    copp_config = add_to_copp(old_neighbor_list, copp_config)

    while(True):

        new_neighbor_list = get_neighbor_ips()

        # If a neighbor was removed the new_neighbor_list is a subset of old_neighbor_list
        if new_neighbor_list < old_neighbor_list:
            print "Neighbor removed from list: " + repr(old_neighbor_list.difference(new_neighbor_list))
            copp_config = remove_from_copp(old_neighbor_list.difference(new_neighbor_list), copp_config)

        # If a neighbor was added old_neighbor_list will be a subset of new_neighbor_list
        elif new_neighbor_list > old_neighbor_list:
            print "Neighbor added to list: " + repr(new_neighbor_list.difference(old_neighbor_list))
            copp_config = add_to_copp(new_neighbor_list.difference(old_neighbor_list), copp_config)

        else:
            # Peer lists are identical, no changes.
            if debug:
                print "Neighbor list unchanged"
            continue

        write_copp_config(copp_config)
        old_neighbor_list = set()
        old_neighbor_list.update(new_neighbor_list)
        time.sleep(2)

if __name__ == "__main__":
    main(sys.argv[1:])
