import tempfile
import unittest
from pathlib import Path

from src.sxnetwork import filter_packets, stats


class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.packets = [
            {"src":"10.0.0.2","dst":"1.1.1.1","protocol":"TCP","src_port":50000,"dst_port":443,"length":100},
            {"src":"1.1.1.1","dst":"10.0.0.2","protocol":"TCP","src_port":443,"dst_port":50000,"length":200},
            {"src":"10.0.0.2","dst":"8.8.8.8","protocol":"UDP","src_port":40000,"dst_port":53,"length":80},
        ]

    def test_stats(self):
        result = stats(self.packets)
        self.assertEqual(result["packets"], 3)
        self.assertEqual(result["bytes"], 380)
        self.assertEqual(result["protocols"]["TCP"], 2)

    def test_protocol_filter(self):
        result = filter_packets(self.packets, protocol="udp")
        self.assertEqual(len(result), 1)

    def test_host_filter(self):
        result = filter_packets(self.packets, host="1.1.1.1")
        self.assertEqual(len(result), 2)

    def test_port_filter(self):
        result = filter_packets(self.packets, port=53)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
