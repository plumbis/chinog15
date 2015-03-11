import unittest
import bgp_neighbor_capture as bgp
import datetime

three_valid_peers = """BGP router identifier 10.2.2.2, local AS number 65222
RIB entries 7, using 784 bytes of memory
Peers 2, using 17 KiB of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2
192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3
192.168.2.3     4 65333      70      80        0    0    0 01w5d03h       33

Total number of neighbors 3
"""

two_valid_one_invalid_peers = """BGP router identifier 10.2.2.2, local AS number 65222
RIB entries 7, using 784 bytes of memory
Peers 2, using 17 KiB of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2
192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3
192.168.2.3     4 65333      70      80        0    0    0 01w5d03h Active

Total number of neighbors 3
"""

two_valid_peers = """BGP router identifier 10.2.2.2, local AS number 65222
RIB entries 7, using 784 bytes of memory
Peers 2, using 17 KiB of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2
192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3

Total number of neighbors 2
"""

one_valid_one_invalid_peer = """BGP router identifier 10.2.2.2, local AS number 65222
RIB entries 7, using 784 bytes of memory
Peers 2, using 17 KiB of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2
192.168.2.3     4 65333      70      80        0    0    0 01w5d03h Active

Total number of neighbors 2
"""

one_valid_peer = """BGP router identifier 10.2.2.2, local AS number 65222
RIB entries 7, using 784 bytes of memory
Peers 2, using 17 KiB of memory

Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2

Total number of neighbors 1
"""

bgp_neighbor_output = """BGP neighbor is 192.168.1.1, remote AS 65111, local AS 65222, external link
  BGP version 4, remote router ID 10.1.1.1
  BGP state = Established, up for 01w4d15h
  Last read 00:00:55, Last write 01w4d15h
  Hold time is 180, keepalive interval is 60 seconds
  Neighbor capabilities:
    4 Byte AS: advertised and received
    Route refresh: advertised and received(old & new)
    Address family IPv4 Unicast: advertised and received
    Graceful Restart Capabilty: advertised and received
      Remote Restart timer is 120 seconds
      Address families by peer:
        none
  Graceful restart informations:
    End-of-RIB send: IPv4 Unicast
    End-of-RIB received: IPv4 Unicast
  Message statistics:
    Inq depth is 0
    Outq depth is 0
                         Sent       Rcvd
    Opens:                  4          4
    Notifications:          1          2
    Updates:               33          8
    Keepalives:         18986      18979
    Route Refresh:          0          0
    Capability:             0          0
    Total:              19024      18993
  Minimum time between advertisement runs is 30 seconds

 For address family: IPv4 Unicast
  Community attribute sent to this neighbor(both)
  2 accepted prefixes

  Connections established 4; dropped 3
  Last reset 01w4d15h, due to BGP Notification received
Local host: 192.168.1.2, Local port: 179
Foreign host: 192.168.1.1, Foreign port: 55771
Nexthop: 192.168.1.2
Nexthop global: fe80::202:ff:fe00:2
Nexthop local: ::
BGP connection: non shared network
Read thread: on  Write thread: off
"""

bgp_neighbor_hello2_output = """BGP neighbor is 192.168.1.1, remote AS 65111, local AS 65222, external link
  BGP version 4, remote router ID 10.1.1.1
  BGP state = Established, up for 01w4d15h
  Last read 00:00:55, Last write 01w4d15h
  Hold time is 6, keepalive interval is 2 seconds
  Neighbor capabilities:
    4 Byte AS: advertised and received
    Route refresh: advertised and received(old & new)
    Address family IPv4 Unicast: advertised and received
    Graceful Restart Capabilty: advertised and received
      Remote Restart timer is 120 seconds
      Address families by peer:
        none
  Graceful restart informations:
    End-of-RIB send: IPv4 Unicast
    End-of-RIB received: IPv4 Unicast
  Message statistics:
    Inq depth is 0
    Outq depth is 0
                         Sent       Rcvd
    Opens:                  4          4
    Notifications:          1          2
    Updates:               33          8
    Keepalives:         18986      18979
    Route Refresh:          0          0
    Capability:             0          0
    Total:              19024      18993
  Minimum time between advertisement runs is 30 seconds

 For address family: IPv4 Unicast
  Community attribute sent to this neighbor(both)
  2 accepted prefixes

  Connections established 4; dropped 3
  Last reset 01w4d15h, due to BGP Notification received
Local host: 192.168.1.2, Local port: 179
Foreign host: 192.168.1.1, Foreign port: 55771
Nexthop: 192.168.1.2
Nexthop global: fe80::202:ff:fe00:2
Nexthop local: ::
BGP connection: non shared network
Read thread: on  Write thread: off
"""

neighbor_up_read_3_min = """BGP neighbor is 192.168.1.1, remote AS 65111, local AS 65222, external link
  BGP version 4, remote router ID 10.1.1.1
  BGP state = Established, up for 01w4d15h
  Last read 00:03:55, Last write 01w4d15h
  Hold time is 180, keepalive interval is 60 seconds
  Neighbor capabilities:
    4 Byte AS: advertised and received
    Route refresh: advertised and received(old & new)
    Address family IPv4 Unicast: advertised and received
    Graceful Restart Capabilty: advertised and received
      Remote Restart timer is 120 seconds
      Address families by peer:
        none
  Graceful restart informations:
    End-of-RIB send: IPv4 Unicast
    End-of-RIB received: IPv4 Unicast
  Message statistics:
    Inq depth is 0
    Outq depth is 0
                         Sent       Rcvd
    Opens:                  4          4
    Notifications:          1          2
    Updates:               33          8
    Keepalives:         18986      18979
    Route Refresh:          0          0
    Capability:             0          0
    Total:              19024      18993
  Minimum time between advertisement runs is 30 seconds

 For address family: IPv4 Unicast
  Community attribute sent to this neighbor(both)
  2 accepted prefixes

  Connections established 4; dropped 3
  Last reset 01w4d15h, due to BGP Notification received
Local host: 192.168.1.2, Local port: 179
Foreign host: 192.168.1.1, Foreign port: 55771
Nexthop: 192.168.1.2
Nexthop global: fe80::202:ff:fe00:2
Nexthop local: ::
BGP connection: non shared network
Read thread: on  Write thread: off
"""

neighbor_up_read_1_hour = """BGP neighbor is 192.168.1.1, remote AS 65111, local AS 65222, external link
  BGP version 4, remote router ID 10.1.1.1
  BGP state = Established, up for 01w4d15h
  Last read 01:13:55, Last write 01w4d15h
  Hold time is 180, keepalive interval is 60 seconds
  Neighbor capabilities:
    4 Byte AS: advertised and received
    Route refresh: advertised and received(old & new)
    Address family IPv4 Unicast: advertised and received
    Graceful Restart Capabilty: advertised and received
      Remote Restart timer is 120 seconds
      Address families by peer:
        none
  Graceful restart informations:
    End-of-RIB send: IPv4 Unicast
    End-of-RIB received: IPv4 Unicast
  Message statistics:
    Inq depth is 0
    Outq depth is 0
                         Sent       Rcvd
    Opens:                  4          4
    Notifications:          1          2
    Updates:               33          8
    Keepalives:         18986      18979
    Route Refresh:          0          0
    Capability:             0          0
    Total:              19024      18993
  Minimum time between advertisement runs is 30 seconds

 For address family: IPv4 Unicast
  Community attribute sent to this neighbor(both)
  2 accepted prefixes

  Connections established 4; dropped 3
  Last reset 01w4d15h, due to BGP Notification received
Local host: 192.168.1.2, Local port: 179
Foreign host: 192.168.1.1, Foreign port: 55771
Nexthop: 192.168.1.2
Nexthop global: fe80::202:ff:fe00:2
Nexthop local: ::
BGP connection: non shared network
Read thread: on  Write thread: off
"""

class TestParseBGPSummary(unittest.TestCase):

    def test_three_valid_peers(self):
        neighbor_list = bgp.parse_bgp_summary(three_valid_peers)
        expected_list = []
        expected_list.append("192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2")
        expected_list.append("192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3")
        expected_list.append("192.168.2.3     4 65333      70      80        0    0    0 01w5d03h       33")
        self.assertEquals(neighbor_list, expected_list)

    def test_two_valid_one_invalid_peers(self):
        neighbor_list = bgp.parse_bgp_summary(two_valid_one_invalid_peers)
        expected_list = []
        expected_list.append("192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2")
        expected_list.append("192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3")
        expected_list.append("192.168.2.3     4 65333      70      80        0    0    0 01w5d03h Active")
        self.assertEquals(neighbor_list, expected_list)

    def test_two_valid(self):
        neighbor_list = bgp.parse_bgp_summary(two_valid_peers)
        expected_list = []
        expected_list.append("192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2")
        expected_list.append("192.168.2.2     4 65111   17758   17788        0    0    0 01w3d19h        3")
        self.assertEquals(neighbor_list, expected_list)

    def test_one_valid_one_invalid(self):
        neighbor_list = bgp.parse_bgp_summary(one_valid_one_invalid_peer)
        expected_list = []
        expected_list.append("192.168.1.1     4 65111   17758   17788        0    0    0 01w3d19h        2")
        expected_list.append("192.168.2.3     4 65333      70      80        0    0    0 01w5d03h Active")
        self.assertEquals(neighbor_list, expected_list)


class TestExtractNeighbors(unittest.TestCase):

    def test_three_valid_peers(self):
        neighbor_output_list = bgp.parse_bgp_summary(three_valid_peers)
        result = bgp.extract_established_neighbors(neighbor_output_list)
        expected_list = []
        expected_list.append("192.168.1.1")
        expected_list.append("192.168.2.2")
        expected_list.append("192.168.2.3")
        self.assertEqual(expected_list, result)

    def test_two_valid_one_invalid_peers(self):
        neighbor_output_list = bgp.parse_bgp_summary(two_valid_one_invalid_peers)
        result = bgp.extract_established_neighbors(neighbor_output_list)
        expected_list = []
        expected_list.append("192.168.1.1")
        expected_list.append("192.168.2.2")
        self.assertEqual(expected_list, result)

    def test_two_valid(self):
        neighbor_output_list = bgp.parse_bgp_summary(two_valid_peers)
        result = bgp.extract_established_neighbors(neighbor_output_list)
        expected_list = []
        expected_list.append("192.168.1.1")
        expected_list.append("192.168.2.2")
        self.assertEqual(expected_list, result)

    def test_one_valid_one_invalid(self):
        neighbor_output_list = bgp.parse_bgp_summary(one_valid_peer)
        result = bgp.extract_established_neighbors(neighbor_output_list)
        expected_list = []
        expected_list.append("192.168.1.1")
        self.assertEqual(expected_list, result)


class TestGetHoldTime(unittest.TestCase):

    def test_one_neighbor(self):
        result = bgp.get_hold_time("192.168.1.1", bgp_neighbor_output)
        expected_result = (180, 60)

        self.assertEqual(result, expected_result)

    def test_single_digit(self):
        result = bgp.get_hold_time("192.168.1.1", bgp_neighbor_hello2_output)
        expected_result = (6, 2)

        self.assertEqual(result, expected_result)

if __name__ == '__main__':
    unittest.main()
