import unittest
import re
import juniper_parser

class TestJuniperParser(unittest.TestCase):
    def test_parse_ospf_neighbors(self):
        output = """
Address          Interface              State     ID               Pri  Dead
10.0.0.2         ge-0/0/0.0             Full      1.1.1.1          128    36
192.168.1.2      irb.10                 Full      2.2.2.2            1    38
"""
        res = juniper_parser.parse_juniper_ospf_neighbors(output)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["neighbor_address"], "10.0.0.2")
        self.assertEqual(res[0]["interface"], "ge-0/0/0.0")
        self.assertEqual(res[0]["state"], "Full")
        self.assertEqual(res[1]["neighbor_id"], "2.2.2.2")

    def test_parse_bgp_summary(self):
        output = """
Groups: 1 Peers: 2 Down peers: 0
Table          Tot Paths  Act Paths Suppressed    History Damp State    Pending
inet.0               2          2          0          0          0          0
Peer                     AS      InPkt     OutPkt    OutQ   Flaps Last Up/Dwn State|#Active/Received/Accepted/Damped
10.1.1.1              65001        100        105       0       1     1:20:15 Establ
192.168.2.1           65002         50         52       0       0       45:10 Establ
"""
        res = juniper_parser.parse_juniper_bgp_summary(output)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["peer"], "10.1.1.1")
        self.assertEqual(res[0]["as"], "65001")
        self.assertEqual(res[1]["state"], "Establ")

    def test_parse_security_zones(self):
        output = """
Security zone: trust
  Interfaces:
    ge-0/0/0.0
Security zone: untrust
  Interfaces:
    ge-0/0/1.0
    ge-0/0/2.0
"""
        res = juniper_parser.parse_juniper_security_zones(output)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0]["name"], "trust")
        self.assertEqual(res[0]["interfaces"], ["ge-0/0/0.0"])
        self.assertEqual(res[1]["name"], "untrust")
        self.assertEqual(res[1]["interfaces"], ["ge-0/0/1.0", "ge-0/0/2.0"])

    def test_parse_security_policies(self):
        output = """
From zone: trust, To zone: untrust
  Policy: default-permit, State: enabled
    Source addresses: any
    Destination addresses: any
    Applications: any
    Action: permit
"""
        res = juniper_parser.parse_juniper_security_policies(output)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["from_zone"], "trust")
        self.assertEqual(res[0]["to_zone"], "untrust")
        self.assertEqual(res[0]["name"], "default-permit")
        self.assertEqual(res[0]["action"], "permit")

if __name__ == '__main__':
    unittest.main()
