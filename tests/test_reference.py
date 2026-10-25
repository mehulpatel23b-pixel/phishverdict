import unittest

from phishverdict import reference as ref


class TestRegistrableDomain(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(ref.registrable_domain("mail.google.com"), "google.com")

    def test_two_level_cctld(self):
        self.assertEqual(ref.registrable_domain("www.bbc.co.uk"), "bbc.co.uk")

    def test_single_label(self):
        self.assertEqual(ref.registrable_domain("localhost"), "localhost")

    def test_two_labels(self):
        self.assertEqual(ref.registrable_domain("example.com"), "example.com")


class TestDeLeet(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(ref.de_leet("g00gle"), "google")
        self.assertEqual(ref.de_leet("paypa1"), "paypal")

    def test_ligatures(self):
        self.assertEqual(ref.de_leet("rnicrosoft"), "microsoft")
        self.assertEqual(ref.de_leet("vvellsfargo"), "wellsfargo")


class TestLevenshtein(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(ref.levenshtein("paypal", "paypal"), 0)

    def test_one_edit(self):
        self.assertEqual(ref.levenshtein("goggle", "google"), 1)

    def test_far(self):
        self.assertGreater(ref.levenshtein("banana", "mississippi"), 2)

    def test_cap(self):
        # distance is larger than the cap: returns cap+1 quickly
        self.assertEqual(ref.levenshtein("short", "a-much-longer-string", cap=2), 3)


if __name__ == "__main__":
    unittest.main()
