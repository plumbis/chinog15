#!/usr/bin/env python

import sys
import getopt
import datetime
import pickle
from subprocess import Popen, PIPE

debug = False
acl_file = "acl-baseline.pkl"
idle_time = datetime.timedelta(minutes=1)

def get_acl():
    '''
    Issues a shell call to get the ACL output.

    Returns list of strings, each line of the output
    '''
    acl_cmd = "cl-acltool -L ip"

    p = Popen(acl_cmd, shell=True, stdout=PIPE, stderr=PIPE)

    output = p.communicate()[0]

    return output.split("\n")


def parse_acl(acl_text):
    '''
    Takes in the text output of iptables and returns a list of lines for each ACE

    Keyword Args:
    acl_text - list of string representing the iptables output

    Returns list of strings with only ACE entries and counters.
    '''

    '''
    TABLE filter :
    Chain INPUT (policy ACCEPT 3264 packets, 271K bytes)
     pkts bytes target     prot opt in     out     source               destination
        0     0 DROP       all  --  swp+   any     240.0.0.0/5          anywhere
        0     0 DROP       all  --  swp+   any     loopback/8           anywhere
        0     0 DROP       all  --  swp+   any     base-address.mcast.net/8  anywhere
        0     0 DROP       all  --  swp+   any     255.255.255.255      anywhere
        0     0 SETCLASS   ospf --  swp+   any     anywhere             anywhere             SETCLASS  class:7
       77  7854 SETCLASS   icmp --  swp+   any     anywhere             anywhere             SETCLASS  class:2
       77  8162 POLICE     icmp --  any    any     anywhere             anywhere             POLICE  mode:pkt rate:100 burst:40

    Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)
    pkts bytes target     prot opt in     out     source               destination
        0     0 DROP       all  --  swp+   any     240.0.0.0/5          anywhere
    '''

    line_list = []
    skipping_copp = False

    for line in acl_text:
        split_line = line.split()
        if len(split_line) == 0:
            continue

        if "Chain INPUT " in line:
            skipping_copp = True
            continue

        if "Chain FORWARD " in line:
            skipping_copp = False

        if skipping_copp:
            continue

        if split_line[0].isdigit():
            line_list.append(split_line)

    # [ pkts, bytes, target, proto, opt, in, out, source, destination, action]
    return line_list


def update_acl_dict(acl_text):
    '''
    Builds a dict of ACL entries. Does not apply any diff logic, only populates.

    Keyword Args:
    acl_text - list of strings of ACE entries. Output of parse_acl()

    Returns dict. {<ACE String> : [Packet Count, time.time() timestamp]}
    '''

    ace_dict = {}
    for line in acl_text:
        dict_list = []
        for x in range(2, len(line)):
            dict_list.append(line[x])

        ace_dict[" ".join(dict_list)] = [int(line[0]), datetime.datetime.now()]

    return ace_dict


def acl_report(old_acl_dict, new_acl_dict):

    report_dict = {}  # ACE : last used timestamp

    if set(old_acl_dict) > set(new_acl_dict):
        # element removed from new_acl_dict. need to skip that key in checking
        key_set = set(old_acl_dict) - set(new_acl_dict)
        for key in old_acl_dict.keys():
            if key in key_set:
                continue
            else:
                time_diff = datetime.datetime.now() - old_acl_dict[key][1]
                if time_diff >= idle_time:
                    report_dict[key] = time_diff
    else:
        # No new elements, just compare
        for key in old_acl_dict.keys():
            if old_acl_dict[key][0] == new_acl_dict[key][0]:  # If the packet counter didn't change
                time_diff = datetime.datetime.now() - old_acl_dict[key][1]
                if time_diff >= idle_time:
                    report_dict[key] = time_diff

    return report_dict


def print_report(report_dict):
    print "Unused ACLs"
    print "-----------------"
    for key in report_dict.keys():
        print key + " last used " + str(report_dict[key]) + " ago"


def main(argv):

    options, remainder = getopt.getopt(sys.argv[1:], "", ["baseline", "report"])

    for opt, arg in options:
        if opt in "--report":
            action = "report"
        if opt in "--baseline":
            action = "baseline"

    current_acl = update_acl_dict(parse_acl(get_acl()))

    if action == "baseline":
        with open(acl_file, 'wb') as f:
            pickle.dump(current_acl, f, pickle.HIGHEST_PROTOCOL)

        print "Baseline created and written to " + acl_file
        return

    if action == "report":
        with open(acl_file, 'rb') as f:
            old_acl = pickle.load(f)

        print_report(acl_report(old_acl, current_acl))

if __name__ == "__main__":
    main(sys.argv[1:])