from electrum.version import ELECTRUM_VERSION, parse_version

from . import ElectrumTestCase


class TestParseVersion(ElectrumTestCase):

    def test_release_candidate_is_accepted(self):
        # StrictVersion rejected this, which crashed the update check
        self.assertEqual(((1, 3, 0, 0), 2, 3), parse_version("1.3.0rc3"))

    def test_client_version_is_parsable(self):
        parse_version(ELECTRUM_VERSION)

    def test_missing_components_are_padded(self):
        self.assertEqual(parse_version("1.3"), parse_version("1.3.0.0"))

    def test_four_components_are_accepted(self):
        self.assertEqual(((4, 4, 6, 0), 3, 0), parse_version("4.4.6.0"))

    def test_surrounding_whitespace_is_ignored(self):
        self.assertEqual(parse_version("1.3.0"), parse_version(" 1.3.0\n"))

    def test_prerelease_sorts_below_final(self):
        self.assertLess(parse_version("1.3.0rc3"), parse_version("1.3.0"))
        self.assertLess(parse_version("1.3.0rc3"), parse_version("1.3.1rc1"))

    def test_prerelease_stages_are_ordered(self):
        self.assertLess(parse_version("1.3.0a1"), parse_version("1.3.0b2"))
        self.assertLess(parse_version("1.3.0b2"), parse_version("1.3.0rc1"))
        self.assertLess(parse_version("1.3.0rc1"), parse_version("1.3.0rc2"))

    def test_invalid_versions_are_rejected(self):
        for bad in ("", "garbage", "1.3.0rc", "1.3.0-rc3", "v1.3.0", "1.3.0.rc3"):
            with self.subTest(version=bad):
                with self.assertRaises(ValueError):
                    parse_version(bad)
