#!/usr/bin/env python
# 
# Copyright 2015 Cumulus Networks, Inc. All rights reserved.
# Author: Pete Lumbis, plumbis@cumulusnetworks.com
# 

from subprocess import Popen, PIPE
import sys
import datetime
import time
import getopt

debug = False  # Global debug flag

'''
bgp_neighbor_capture will monitor the state of BGP neighbors
and automatically begin collecting data when a peer may eventually go down.
This is based on not hearing from a peer in 1.5 keepalive intervals.

Currently this is single threaded. It is written to work with
multiple BGP peers, but a new thread needs to be spawned per peer.
As a result, this proof-of-concept code only works for the first 
Established BGP peer in "show ip bgp summary"

TODO: Multithread
TODO: Track neighbor source interface for ping
TODO: When multithreaded, if troubleshooting more than one neighbor, don't duplicate data
TODO: issuing the ping blocks the termination of other things. Need to figure out how to do that independently
'''


class Neighbor(object):

    '''
    A Neighbor object represents the information about a BGP peer.
    '''

    def __init__(self, ip):
        '''
        ip = IP address of the peer
        keepalive = currently negotiated keepalive timer
        hold_time = currently negotiated hold timer
        last_read = the last time we heard a BGP message. Based on "Last Read" line in "show ip bgp neighbor"
        last_run = the last time this neighbor was checked for liveliness
        troubleshooting = is this Neighbor currently being troubleshot
        process = a Popen process. Used to terminated tcpdump background capture

        times are kept as datetime.timedelta() instead of datetime.time() to make the math easier.
        '''

        self.ip = ip
        self.keepalive = datetime.timedelta()
        self.hold_time = datetime.timedelta()
        self.last_read = get_last_read(ip)
        self.last_run = datetime.timedelta()
        self.troubleshooting = False
        self.process = []

    def set_timers(self, holdtime_ka_tuple):
        '''
        Sets/updates timers for a BGP neighbor.
        Timers = hold_time, keepalive, last_run (to right now)

        Keyword Arguments:
        holdtime_ka_tuple = a tuple of (<holdtime>, <keepalive>) ints. 
        '''

        self.hold_time = datetime.timedelta(seconds=holdtime_ka_tuple[0])
        self.keepalive = datetime.timedelta(seconds=holdtime_ka_tuple[1])
        now = datetime.datetime.now()
        self.last_run = datetime.timedelta(hours=now.hour, minutes=now.minute, seconds=now.second)

    def set_proc(self, proc):
        ''' 
        Sets the Popen process for this Neighbor.

        Currently assumes only a single process would exist, so static insert is used.
        '''

        self.process.insert(0, proc)

    def get_proc(self):
        '''
        Returns the Popen process of this Neighbor
        '''
        return self.process[0]


def start_troubleshooting(Neighbor):
    '''
    Triggers data collections routines and sets the 
    troubleshooting flag to True

    Keyword Args:
    Neighbor - the Neighbor object to troubleshoot
    '''

    # If we are already troubleshooting, bail.
    if Neighbor.troubleshooting:
        return

    Neighbor.troubleshooting = True

    start_debugging(Neighbor)
    start_capture(Neighbor)

    # start_logging will block all other commands. Run last.
    start_logging(Neighbor)


def stop_troubleshooting(Neighbor):
    '''
    Stops data collection

    Keyword Args:
    Neighbor - the Neighbor object to stop troubleshooting
    '''

    # Safety check. Do try to kill anything if we aren't troubleshooting
    if not Neighbor.troubleshooting:
        return

    if debug:
        print "Stopping..."

    stop_logging(Neighbor)
    stop_debugging(Neighbor)
    stop_capture(Neighbor)
    Neighbor.troubleshooting = False


def start_debugging(Neighbor):
    '''
    Enables BGP debugs for a Neighbor.

    Keyword Args:
    Neighbor - the Neighbor object to enable debugs on
    '''

    debug_list = ["debug bgp keepalives", "debug bgp updates in", "debug bgp updates out"]

    for debug in debug_list:
        send_command(debug + " " + Neighbor.ip)


def stop_debugging(Neighbor):
    '''
    Disables all BGP debugs

    Keyword Args:
    Neighbor - Neighbor object to undebug
    '''

    send_command("no debug bgp")


def start_logging(Neighbor):
    '''
    Collects system data and logs it to a file.

    Keyword Args:
    Neighbor - Neighbor object to collect data about
    '''

    info_file = "bgp_log_" + Neighbor.ip + "_" + datetime.datetime.now().strftime("%m%d%Y_%H%M%S") + ".log"

    if debug:
        print "Log File: " + info_file
    # Current data to collect:
    #   Top 10 proceses by CPU utilization (thanks nixcraft!)
    #   Memory utilization
    #   socket information
    #   data plane interface data
    #   attempt to ping neighbor  

    command_list = ["ps -eo pcpu,pid,user,args | sort -k 1 -r | head -10",
                    "vmstat",
                    "ss",
                    "cl-netstat",
                    "ping -c 5 " + Neighbor.ip,
                    ]

    raw_file = open(info_file, 'a')

    for command in command_list:

        if debug:
            print "Collecting " + command

        raw_file.write(command + "\n")
        raw_file.write("==================\n")
        p = Popen(command, shell=True, stdout=PIPE, stderr=PIPE)
        raw_file.write(p.communicate()[0])
        raw_file.write("\n\n")

    raw_file.close()


def stop_logging(Neighbor):
    '''
    Disables any logging

    '''
    # Nothing currently to disable. Stub for future use.
    pass


def start_capture(Neighbor):
    '''
    Starts a tcpdump capture on the interface the Neighbor lives on.

    Keyword Arguments:
    Neighbor - the neighbor object to capture

    Returns:
    Popen process. 
    '''

    # TCPdump is dumb and can't limit a single capture based on size.
    # 10k packets is arbritary. This is about 15megs at 1500 bytes of .64 megs at 64k. I assume we can detect the trend either way.

    capture_string = "nohup tcpdump -W 1 -c 10000 -s 0 -w 'bgp_auto_capture_" + Neighbor.ip + "_" + datetime.datetime.now().strftime("%m%d%Y_%H%M%S") + ".pcap'"

    Neighbor.set_proc(Popen(capture_string, shell=True, stdout=PIPE, stderr=PIPE))


def stop_capture(Neighbor):
    '''
    Kill the TCPdump process

    Keyword Args:
    Neighbor - Neighbor object to disable TCP dump
    '''

    Neighbor.get_proc().terminate()

    if debug:
        print "Capture terminated"


def neighbor_received_message(Neighbor):
    '''
    Takes in a Neighbor object and determines if a message has been heard.
    It waits at least 1 keepalive period since last run before checking for valid messages

    Returns:
        True - A message was received or the polling wait time has not yet expired
        False - A message was not received since at least 1.5 keepalives
    '''

    time = datetime.datetime.now()
    now = datetime.timedelta(hours=time.hour, minutes=time.minute, seconds=time.second)

    if debug:
        print "Last Run"
        print Neighbor.last_run

    # don't do anything if we haven't waited at least one keepalive since last check
    if now < Neighbor.last_run + Neighbor.keepalive:
        return True

    Neighbor.last_run = now 
    current_read = get_last_read(Neighbor.ip)

    # how much to pad the keepalive to worry
    jittered_keepalive = Neighbor.keepalive.seconds * 1.25  

    # don't do anything if we heard a message    
    if current_read.seconds < jittered_keepalive:
        return True

    return False


def get_last_read(neighbor_ip):
    '''
    Returns datetime.timedelta object of last read value
    based on the line "Last read" in the output of "show ip bgp neighbor"

    Keyword Args:
    neighbor_ip - string IP address of the neighbor to find

    Returns:
    datetime.timedelta() object of the Last Read value
    '''

    '''
    Output Sample:
        BGP neighbor is 192.168.1.1, remote AS 65111, local AS 65222, external link
        BGP version 4, remote router ID 10.1.1.1
        BGP state = Established, up for 01w4d15h
        Last read 01:13:55, Last write 01w4d15h
        Hold time is 180, keepalive interval is 60 seconds
        Neighbor capabilities:
    '''

    # if parsing fails, this should make it look like the neighbor isn't up
    dt = datetime.timedelta(hours=99) 

    for line in send_command("show ip bgp neighbor " + neighbor_ip).split("\n"):
        if line.strip().find("Last read") > -1:
            read_list = line.strip()[10:line.find(",") - 2].split(":")
            dt = datetime.timedelta(hours=int(read_list[0]),
                                    minutes=int(read_list[1]),
                                    seconds=int(read_list[2]))
            break

    return dt


def send_command(command):
    '''
    Send a command to Linux. Assumes Quagga will receive the command by default.

    Keyword Arguments:
    command - string to send. ex. "show ip bgp summary"

    Returns: string output of the command
    '''

    cmd = "vtysh -c '" + command + "'"
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)

    return p.communicate()[0]


def get_hold_time(neighbor_ip, test_output=None):
    '''
    Parses the output of "show ip bgp neighbor x.x.x.x" (only 1 neighbor)

    Keyword Arguments:
    neighbor - string IP of the neighbor. ex "192.168.1.1"
    (optional) test_output - String output of neighbor. Used in testing without Quagga

    Returns tuple of int, (holdtime, keepalive)
    '''

    '''
    Output Sample:
        BGP neighbor is 192.168.1.1, remote AS 65111, local AS 65222, external link
        BGP version 4, remote router ID 10.1.1.1
        BGP state = Established, up for 01w4d15h
        Last read 01:13:55, Last write 01w4d15h
        Hold time is 180, keepalive interval is 60 seconds
        Neighbor capabilities:
    '''

    if test_output is None:
        output = send_command("show ip bgp neighbor " + neighbor_ip)
    else:
        output = test_output

    hold_time = 0
    keepalive = 0

    for line in output.split("\n"):
        if line.find("Hold time") > 0:
            for word in line.split(" "):
                if len(word) > 0:
                    if word[0].isdigit():
                        if hold_time == 0:
                            hold_time = int(word[:len(word) - 1])
                        else:
                            keepalive = int(word)

    return (hold_time, keepalive)


def extract_established_neighbors(list_of_neighbor_lines):

    '''
    Finds all of the IPs of currently up BGP peers

    This is done by parsing a portion of the  output of "show ip bgp summary".

    To retrieve these lines from the larger output, use parse_bgp_summary()

    Keyword Arguments:
    list_of_neighbor_lines - the line from "show ip bgp sum" with the neighbor
     ex. "192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2"

    Returns list of IPs as string
    ["192.168.1.1", "10.1.1.1"]
    '''

    neighbor_list = []

    for line in list_of_neighbor_lines:
        temp_list = line.split(" ")

        if temp_list[len(temp_list) - 1].isdigit():
            neighbor_list.append(temp_list[0])

    return neighbor_list


def parse_bgp_summary(summary_output):

    '''
    Parses the output of "show ip bgp summary"

    Keyword Arguments:
    summary_output - string output of "show ip bgp sum"

    Returns list of string, each string is the neighbor line. 
    This can then be consumed by extract_established_neighbors()
    '''

    '''
    Sample Output:
        BGP router identifier 10.2.2.2, local AS number 65222
        RIB entries 7, using 784 bytes of memory
        Peers 2, using 17 KiB of memory

        Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
        192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2
        192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3
        192.168.2.3     4 65333      70      80        0    0    0 01w5d03h Active

        Total number of neighbors 3
    '''

    output_list = summary_output.split("\n")

    neighbor_line = 0
    last_neighbor = 0
    counting_neighbors = False
    neighbor_line_list = []

    for line in output_list:

        if line[:8] == "Neighbor":
            counting_neighbors = True

        if not line[:8] == "Neighbor":
            if not counting_neighbors:
                neighbor_line += 1
            last_neighbor += 1

        if line[:12] == "Total number":
            break

    last_neighbor -= 1  # Remove blank line before "Total number of neighbors" line

    counter = neighbor_line + 1

    while counter < last_neighbor:
        neighbor_line_list.append(output_list[counter])
        counter += 1

    return neighbor_line_list


def bgp_neighbor_up(neighbor_ip):
    '''
    Determines if a neighbor is operational (Established)

    Keyword Arguments:
    neighbor_ip - string IP address of the neighbor

    Returns True if neighbor is Established, else False
    '''

    output = send_command("show ip bgp neighbor " + neighbor_ip)

    for line in output.split("\n"):
        if line.find("BGP state") > 0:
            return line.strip().split(" ")[3] == "Established,"  # comma in output, easier than splicing


def main(argv):
    global debug

    options, remainder = getopt.getopt(sys.argv[1:], "", ["debug"])

    for opt, arg in options:
        if opt in "--debug":
            debug = True

    # Get a list of all Established neighbor IPs
    ip_list = extract_established_neighbors(
        parse_bgp_summary(
            send_command("show ip bgp summary")))

    list_of_neighbors = []

    if len(ip_list) < 1:
        print "No Up neighbors"
        return False

    # Build a Neighbor object out of each peer
    for ip in ip_list:
        neighbor = Neighbor(ip)
        neighbor.set_timers(get_hold_time(ip))
        list_of_neighbors.append(neighbor)

    # No thread support today, so neighbor is static. 
    # In the future a thread would be spawned for each Neighbor object
    neighbor1 = list_of_neighbors[0]

    if debug:
        print neighbor1

    # keep checking if the neighbor is alive, if not, bail.
    while(bgp_neighbor_up(neighbor1.ip)): 

        # Check if we heard a message from the neighbor
        if not neighbor_received_message(neighbor1):
            if debug:
                print "Troubleshooting Neighbor"
            start_troubleshooting(neighbor1)
        else:
            if debug:
                print "Neighbor alive, waiting"
            stop_troubleshooting(neighbor1)

        # Pause the loop for a keepalive
        time.sleep(neighbor1.keepalive.seconds)

    if debug:
        print "Neighbor down"

    stop_troubleshooting(neighbor1)


if __name__ == "__main__":
    main(sys.argv[1:])
