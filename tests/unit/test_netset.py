import unittest

from helpers import SRC  # noqa: F401  (sys.path 설정)

from iacpatch.verify.netset import CidrParseError, NetSet, parse_cidr, split_by_version


class NetSetTests(unittest.TestCase):
    def test_split_halves_collapse_to_everything(self):
        s = NetSet.from_cidrs(4, ["0.0.0.0/1", "128.0.0.0/1"])
        self.assertEqual(s.to_list(), ["0.0.0.0/0"])
        self.assertTrue(s.covers_everything())

    def test_quarter_split_also_collapses(self):
        s = NetSet.from_cidrs(4, ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"])
        self.assertTrue(s.covers_everything())

    def test_unordered_and_overlapping_inputs(self):
        s = NetSet.from_cidrs(4, ["192.0.0.0/2", "10.0.0.0/8", "0.0.0.0/1", "128.0.0.0/2", "64.0.0.0/2"])
        self.assertTrue(s.covers_everything())

    def test_difference_removes_approved(self):
        eff = NetSet.from_cidrs(4, ["0.0.0.0/0"])
        approved = NetSet.from_cidrs(4, ["10.0.0.0/8"])
        excess = eff.difference(approved)
        self.assertFalse(excess.is_empty())
        self.assertFalse(excess.covers_everything())
        self.assertEqual(excess.num_addresses(), 2 ** 32 - 2 ** 24)
        self.assertTrue(eff.difference(eff).is_empty())

    def test_difference_exact_match_is_empty(self):
        eff = NetSet.from_cidrs(4, ["10.1.0.0/16", "10.2.0.0/16"])
        approved = NetSet.from_cidrs(4, ["10.0.0.0/8"])
        self.assertTrue(eff.difference(approved).is_empty())

    def test_contains_network(self):
        s = NetSet.from_cidrs(4, ["10.0.0.0/9", "10.128.0.0/9"])
        self.assertTrue(s.contains_network(parse_cidr("10.0.0.0/8")))
        self.assertFalse(NetSet.from_cidrs(4, ["10.0.0.0/9"]).contains_network(parse_cidr("10.0.0.0/8")))

    def test_ipv6_separate(self):
        v6 = NetSet.from_cidrs(6, ["::/1", "8000::/1"])
        self.assertTrue(v6.covers_everything())
        with self.assertRaises(CidrParseError):
            NetSet.from_cidrs(4, ["::/0"])
        with self.assertRaises(ValueError):
            NetSet(4).union(NetSet(6))

    def test_strict_parse_rejects_host_bits(self):
        with self.assertRaises(CidrParseError):
            parse_cidr("10.0.0.1/8")
        with self.assertRaises(CidrParseError):
            parse_cidr("not-a-cidr")

    def test_split_by_version(self):
        v4, v6, bad = split_by_version(["10.0.0.0/8", "2001:db8::/32", "garbage"])
        self.assertEqual(v4.to_list(), ["10.0.0.0/8"])
        self.assertEqual(v6.to_list(), ["2001:db8::/32"])
        self.assertEqual(bad, ["garbage"])


if __name__ == "__main__":
    unittest.main()
