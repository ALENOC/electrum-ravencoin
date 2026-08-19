import sys
import os

# these are ~duplicated from run_electrum:
is_bundle = getattr(sys, 'frozen', False)
is_local = not is_bundle and os.path.exists(os.path.join(os.path.dirname(os.path.dirname(__file__)), "electrum-ravencoin.desktop"))

# when running from source, on Windows, also search for DLLs in inner 'electrum' folder
if is_local and os.name == 'nt':
    if hasattr(os, 'add_dll_directory'):  # requires python 3.8+
        os.add_dll_directory(os.path.dirname(__file__))


class GuiImportError(ImportError):
    pass


from .version import ELECTRUM_VERSION
from .util import format_satoshis
from .wallet import Wallet
from .storage import WalletStorage
from .coinchooser import COIN_CHOOSERS
from .network import Network, pick_random_server
from .interface import Interface
from .simple_config import SimpleConfig
from . import bitcoin
from . import transaction
from . import daemon
from .transaction import Transaction
from .plugin import BasePlugin
from .commands import Commands, known_commands
from .logging import get_logger


__version__ = ELECTRUM_VERSION

_logger = get_logger(__name__)


# Ensure that asserts are enabled. For sanity and paranoia, we require this.
# Code *should not rely* on asserts being enabled. In particular, safety and security checks should
# always explicitly raise exceptions. However, this rule is mistakenly broken occasionally...
try:
    assert False  # noqa: B011
except AssertionError:
    pass
else:
    raise ImportError("Running with asserts disabled. Refusing to continue. Exiting...")


# Keep the public ElectrumX discovery list fresh in already-compiled clients.
# The updater is deliberately availability-only: compiled server anchors and
# operator-group trust cannot be changed by the unsigned remote list.  Its
# daemon thread does not perform network I/O until a real Daemon-owned Network
# instance has actually been started, which also keeps ordinary library/test
# imports side-effect free.
from .server_list_updater import start_server_list_updater
start_server_list_updater()
