#!/usr/bin/env python

import unittest
import dynamic_copp as copp
import shutil


class TestGetNeighborIPs(unittest.TestCase):

    def setUp(self):
        src = "Quagga.conf"
        dst = "/etc/quagga/Quagga.conf"
        shutil.copy(src, dst)

    def test_interface_peers(self):
        returned_value = copp.get_neighbor_ips(testing=True)
        expected_value = set(['172.16.2.65', '172.16.1.129', '172.16.32.1', '172.16.0.1', '172.16.1.1', '172.16.3.129', '172.16.2.193', '172.16.16.11', '172.16.16.13', '172.16.16.15', '172.16.16.17', '172.16.0.129', '172.16.1.193', '172.16.1.65', '172.16.16.21', '172.16.3.193', '172.16.3.65', '172.16.0.193', '172.16.2.1', '172.16.3.1', '172.16.16.19', '172.16.16.23', '172.16.16.25', '172.16.16.27', '172.16.16.29', '172.16.0.65', '172.16.16.9', '172.16.16.5', '172.16.2.129', '172.16.16.7', '172.16.16.1', '172.16.16.3'])

        self.assertEquals(returned_value, expected_value)


class TestInitalizeCopp(unittest.TestCase):

    def setUp(self):
        src = "orig.rules"
        dst = "/etc/cumulus/acl/policy.d/00.control_plane.rules"
        shutil.copy(src, dst)

    def test_basic_copp(self):
        returned_value = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = ['BGP4_PEERS = ""', 'BGP6_PEERS = ""', '', 'INGRESS_INTF = swp+\n', 'INGRESS_CHAIN = INPUT\n', 'INNFWD_CHAIN = INPUT,FORWARD\n', 'MARTIAN_SOURCES_4 = "240.0.0.0/5,127.0.0.0/8,224.0.0.0/8,255.255.255.255/32"\n', 'MARTIAN_SOURCES_6 = "ff00::/8,::/128,::ffff:0.0.0.0/96,::1/128"\n', 'CLAG_PORT = 5342\n', '[iptables]\n', '-A $INNFWD_CHAIN --in-interface $INGRESS_INTF -s $MARTIAN_SOURCES_4 -j DROP', '', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP4_PEERS -p tcp --dport bgp -j SETCLASS --class 7 --set-burst 2000', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP4_PEERS -p tcp --sport bgp -j SETCLASS --class 7 --set-burst 2000', '-A $INGRESS_CHAIN -p tcp --sport bgp -j DROP', '-A $INGRESS_CHAIN -p tcp --dport bgp -j DROP', '', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ospf -j SETCLASS --class 7\n', '-A $INGRESS_CHAIN -p ospf -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --dport $CLAG_PORT -j SETCLASS --class 7\n', '-A $INGRESS_CHAIN -p tcp --dport $CLAG_PORT -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --sport $CLAG_PORT -j SETCLASS --class 7\n', '-A $INGRESS_CHAIN -p tcp --sport $CLAG_PORT -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p icmp -j SETCLASS --class 2\n', '-A $INGRESS_CHAIN -p icmp -j POLICE --set-mode pkt --set-rate 100 --set-burst 40\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p udp --dport bootps:bootpc -j SETCLASS --class 2\n', '-A $INGRESS_CHAIN -p udp --dport bootps -j POLICE --set-mode pkt --set-rate 100 --set-burst 100\n', '-A $INGRESS_CHAIN -p udp --dport bootpc -j POLICE --set-mode pkt --set-rate 100 --set-burst 100\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --dport bootps:bootpc -j SETCLASS --class 2\n', '-A $INGRESS_CHAIN -p tcp --dport bootps -j POLICE --set-mode pkt --set-rate 100 --set-burst 100\n', '-A $INGRESS_CHAIN -p tcp --dport bootpc -j POLICE --set-mode pkt --set-rate 100 --set-burst 100\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p igmp -j SETCLASS --class 6\n', '-A $INGRESS_CHAIN -p igmp -j POLICE --set-mode pkt --set-rate 300 --set-burst 100\n', '[ip6tables]\n', '-A $INNFWD_CHAIN --in-interface $INGRESS_INTF -s $MARTIAN_SOURCES_6 -j DROP', '', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP6_PEERS -p tcp --dport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -s $BGP6_PEERS -p tcp --sport bgp -j POLICE --set-mode pkt --set-rate 2000 --set-burst', '-A $INGRESS_CHAIN -p tcp --sport bgp -j DROP', '-A $INGRESS_CHAIN -p tcp --dport bgp -j DROP', '', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ospf -j POLICE --set-mode pkt --set-rate 2000 --set-burst 2000 --set-class 7\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type router-solicitation -j POLICE --set-mode pkt --set-rate 100 --set-burst 100 --set-class 2\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type router-advertisement -j POLICE --set-mode pkt --set-rate 100 --set-burst 100 --set-class 2\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type neighbour-solicitation -j POLICE --set-mode pkt --set-rate 100 --set-burst 100 --set-class 2\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type neighbour-advertisement -j POLICE --set-mode pkt --set-rate 100 --set-burst 100 --set-class 2\n', '# link-local multicast receiver: Listener Query\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type 130 -j POLICE --set-mode pkt --set-rate 200 --set-burst 100 --set-class 6\n', '# link-local multicast receiver: Listener Reprot\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type 131 -j POLICE --set-mode pkt --set-rate 200 --set-burst 100 --set-class 6\n', '# link-local multicast receiver: Listener Done\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type 132 -j POLICE --set-mode pkt --set-rate 200 --set-burst 100 --set-class 6\n', '# link-local multicast receiver: Listener Report v2\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -m icmp6 --icmpv6-type 143 -j POLICE --set-mode pkt --set-rate 200 --set-burst 100 --set-class 6\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p ipv6-icmp -j POLICE --set-mode pkt --set-rate 64 --set-burst 40 --set-class 2\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p udp --dport dhcpv6-client:dhcpv6-server -j POLICE --set-mode pkt --set-rate 100 --set-burst 100 --set-class 2\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p tcp --dport dhcpv6-client:dhcpv6-server -j POLICE --set-mode pkt --set-rate 100 --set-burst 100 --set-class 2\n', '[ebtables]\n', '# BPDU\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -d 01:80:c2:00:00:00 -j setclass --class 7\n', '-A $INGRESS_CHAIN -d 01:80:c2:00:00:00 -j police --set-mode pkt --set-rate 2000 --set-burst 2000\n', '# LACP\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -d 01:80:c2:00:00:02 -j setclass --class 7\n', '-A $INGRESS_CHAIN -d 01:80:c2:00:00:02 -j police --set-mode pkt --set-rate 2000 --set-burst 2000\n', '# LLDP\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -d 01:80:c2:00:00:0e -j setclass --class 6\n', '-A $INGRESS_CHAIN -d 01:80:c2:00:00:0e -j police --set-mode pkt --set-rate 200 --set-burst 200\n', '# CDP\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -d 01:00:0c:cc:cc:cc -j setclass --class 6\n', '-A $INGRESS_CHAIN -d 01:00:0c:cc:cc:cc -j police --set-mode pkt --set-rate 200 --set-burst 200\n', '# ARP\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -p arp -j setclass --class 2\n', '-A $INGRESS_CHAIN -p arp -j police --set-mode pkt --set-rate 100 --set-burst 100\n', '# Cisco PVST\n', '-A $INGRESS_CHAIN --in-interface $INGRESS_INTF -d 01:00:0c:cc:cc:cd -j setclass --class 7\n', '-A $INGRESS_CHAIN -d 01:00:0c:cc:cc:cd -j police --set-mode pkt --set-rate 2000 --set-burst 2000']

        self.assertEqual(returned_value, expected_value)


class TestParseCoppPeers(unittest.TestCase):

    def test_blank_string(self):
        bgp_string = "BGP4_PEERS = \"\""
        returned_value = copp.parse_copp_peers(bgp_string)
        expected_value = set()

        self.assertEquals(returned_value, expected_value)

    def test_single_peer(self):
        bgp_string = "BGP4_PEERS = \"192.168.1.1\""

        returned_value = copp.parse_copp_peers(bgp_string)
        expected_value = set()
        expected_value.add("192.168.1.1")

        self.assertEquals(returned_value, expected_value)

    def test_two_peers(self):
        bgp_string = "BGP4_PEERS = \"192.168.1.1,192.168.1.2\""

        returned_value = copp.parse_copp_peers(bgp_string)
        expected_value = set()
        expected_value.add("192.168.1.1")
        expected_value.add("192.168.1.2")

        self.assertEquals(returned_value, expected_value)

    def test_three_peers(self):
        bgp_string = "BGP4_PEERS = \"192.168.1.1,192.168.1.2,192.168.1.3\""

        returned_value = copp.parse_copp_peers(bgp_string)
        expected_value = set()
        expected_value.add("192.168.1.1")
        expected_value.add("192.168.1.2")
        expected_value.add("192.168.1.3")

        self.assertEquals(returned_value, expected_value)


class TestAddtoCopp(unittest.TestCase):

    def setUp(self):
        src = "orig.rules"
        dst = "/etc/cumulus/acl/policy.d/00.control_plane.rules"
        shutil.copy(src, dst)

    def test_add_first_peer(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.1"'
        added_peer = set()
        added_peer.add("192.168.1.1")
        returned_value = copp.add_to_copp(added_peer, config)[0]

        self.assertEqual(returned_value, expected_value)

    def test_add_second_peer(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.2,192.168.1.1"'
        added_peer = set()
        added_peer.add("192.168.1.1")
        peer_1_config = copp.add_to_copp(added_peer, config)
        second_peer = set()
        second_peer.add("192.168.1.2")
        returned_value = copp.add_to_copp(second_peer, peer_1_config)[0]

        self.assertEqual(returned_value, expected_value)

    def test_add_two_peers(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.2,192.168.1.1"'
        added_peer = set()
        added_peer.add("192.168.1.1")
        added_peer.add("192.168.1.2")
        returned_value = copp.add_to_copp(added_peer, config)[0]

        self.assertEqual(returned_value, expected_value)

    def test_add_third_peer(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.3,192.168.1.2,192.168.1.1"'
        peer_1 = set()
        peer_1.add("192.168.1.1")
        peer_2 = set()
        peer_2.add("192.168.1.2")
        peer_3 = set()
        peer_3.add("192.168.1.3")
        peer_1_config = copp.add_to_copp(peer_1, config)
        peer_2_config = copp.add_to_copp(peer_2, peer_1_config)
        returned_value = copp.add_to_copp(peer_3, peer_2_config)[0]

        self.assertEqual(returned_value, expected_value)

    def test_add_existing_peer(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.1"'
        added_peer = set()
        added_peer.add("192.168.1.1")
        peer_1_config = copp.add_to_copp(added_peer, config)
        second_peer = set()
        second_peer.add("192.168.1.1")
        returned_value = copp.add_to_copp(second_peer, peer_1_config)[0]

        self.assertEqual(returned_value, expected_value)


class TestRemoveFromCopp(unittest.TestCase):

    def setUp(self):
        src = "orig.rules"
        dst = "/etc/cumulus/acl/policy.d/00.control_plane.rules"
        shutil.copy(src, dst)

    def test_remove_only_peer(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        first_peer = set()
        first_peer.add("192.168.1.1")
        peer_config = copp.add_to_copp(first_peer, config)
        returned_value = copp.remove_from_copp(first_peer, peer_config)[0]
        expected_value = "BGP4_PEERS = \"\""

        self.assertEqual(returned_value, expected_value)

    def test_remove_first_peer_two_peers(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.2"'
        original_peers = set()
        original_peers.add("192.168.1.1")
        original_peers.add("192.168.1.2")
        remove_peer = set()
        remove_peer.add("192.168.1.1")
        peer_1_config = copp.add_to_copp(original_peers, config)
        returned_value = copp.remove_from_copp(remove_peer, peer_1_config)[0]

        self.assertEqual(returned_value, expected_value)

    def test_remove_last_peer_two_peers(self):
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        expected_value = 'BGP4_PEERS = "192.168.1.1"'
        original_peers = set()
        original_peers.add("192.168.1.1")
        original_peers.add("192.168.1.2")
        remove_peer = set()
        remove_peer.add("192.168.1.2")
        peer_1_config = copp.add_to_copp(original_peers, config)
        returned_value = copp.remove_from_copp(remove_peer, peer_1_config)[0]

        self.assertEqual(returned_value, expected_value)

    def test_remove_all_peers(self):
        expected_value = "BGP4_PEERS = \"\""
        config = copp.initalize_copp_config("/etc/cumulus/acl/policy.d/00.control_plane.rules")
        original_peers = set()
        original_peers.add("192.168.1.1")
        original_peers.add("192.168.1.2")
        remove_peer = set()
        remove_peer.add("192.168.1.2")
        remove_peer.add("192.168.1.1")
        peer_1_config = copp.add_to_copp(original_peers, config)
        returned_value = copp.remove_from_copp(remove_peer, peer_1_config)[0]

        self.assertEqual(returned_value, expected_value)



if __name__ == '__main__':
    unittest.main()
