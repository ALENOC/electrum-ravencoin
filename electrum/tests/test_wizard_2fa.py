"""Regression tests: 2FA/TrustedCoin seeds must be rejected cleanly.

The TrustedCoin plugin was removed from this Ravencoin fork, but the wallet
wizard's seed-restore path still routed 2FA-classified seeds into
load_2fa(), which crashed with ModuleNotFoundError trying to load the
missing plugin. The wizard must instead fail with a clear, user-facing
message, and no wizard path may load or route to trustedcoin anymore.
"""
import logging

from electrum import mnemonic
from electrum.base_wizard import BaseWizard
from electrum.mnemonic import Mnemonic, seed_type, is_any_2fa_seed_type
from electrum.wizard import NewWalletWizard

from . import ElectrumTestCase


def _minimal_wizard() -> BaseWizard:
    w = object.__new__(BaseWizard)
    w.data = {}
    w.logger = logging.getLogger("test_wizard_2fa")
    return w


class Test2faSeedRejection(ElectrumTestCase):

    def test_2fa_seed_still_classified(self):
        """Detection must keep working so such seeds get the explicit
        'not supported' message instead of 'unknown seed type'."""
        seed = Mnemonic('english').make_seed(seed_type='2fa')
        st = seed_type(seed)
        self.assertEqual('2fa', st)
        self.assertTrue(is_any_2fa_seed_type(st))

    def test_restore_of_2fa_seed_raises_clean_error(self):
        """The reproduced crash: restoring a 2FA seed used to die with
        ModuleNotFoundError('electrum.plugins.trustedcoin'). It must now
        raise the clear not-supported message instead."""
        seed = Mnemonic('english').make_seed(seed_type='2fa')
        w = _minimal_wizard()
        with self.assertRaises(Exception) as caught:
            w.on_restore_seed(seed, seed_type='electrum', is_ext=False)
        self.assertIn("not supported", str(caught.exception))
        self.assertNotIn("ModuleNotFoundError", type(caught.exception).__name__)

    def test_restore_of_2fa_segwit_seed_also_rejected(self):
        seed = Mnemonic('english').make_seed(seed_type='2fa_segwit')
        w = _minimal_wizard()
        with self.assertRaises(Exception) as caught:
            w.on_restore_seed(seed, seed_type='electrum', is_ext=False)
        self.assertIn("not supported", str(caught.exception))

    def test_no_wizard_path_loads_trustedcoin(self):
        """load_2fa is gone and no wizard route mentions trustedcoin."""
        self.assertFalse(hasattr(BaseWizard, 'load_2fa'))
        import inspect
        src = inspect.getsource(BaseWizard)
        self.assertNotIn('trustedcoin', src)
        wsrc = inspect.getsource(NewWalletWizard)
        self.assertNotIn('trustedcoin', wsrc)

    def test_new_wizard_has_no_2fa_route(self):
        wiz = object.__new__(NewWalletWizard)
        wiz.logger = logging.getLogger("test_wizard_2fa")
        self.assertIsNone(wiz.on_wallet_type({'wallet_type': '2fa'}))
        self.assertEqual('keystore_type', wiz.on_wallet_type({'wallet_type': 'standard'}))
