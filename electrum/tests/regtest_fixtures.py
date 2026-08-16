"""Test-only regtest-style network and self-consistent header fixtures.

The Ravencoin port removed regtest from production constants (the
``set_regtest`` startup path in ``run_electrum`` is commented out), but the
blockchain tests inherited from upstream Electrum were written against a
regtest network and rebuild their chain trees from hardcoded header
fixtures.

Those upstream fixtures are unusable here for two separate reasons:

1. they select the network through ``constants.set_regtest()``, an API the
   port deleted (commit b4749d264); and
2. their headers are Bitcoin regtest headers linked by sha256d hashes,
   while this project hashes headers with X16R/X16Rv2/KAWPOW (there is no
   sha256d path at all), so their prev-hash links can never be consistent
   under this codebase.

This module rebuilds the same header-tree *topology* as upstream -- the
tests exercise chain forks/swaps, whose outcomes depend only on heights
and the order headers are appended -- with prev-hash links computed by the
project's own ``hash_header`` under a checkpoint-free, TESTNET-style
regtest network whose activation timestamps keep every fixture on the
deterministic legacy (X16R) hashing path.  Under TESTNET=True the
verification shortcuts match upstream regtest semantics (no bits/PoW
check, chainwork == height), so the fork/swap behavior the tests assert is
preserved.

Nothing in this module may be imported by production code.
"""
import hashlib

from electrum import constants
from electrum.blockchain import hash_header


class RegtestNet(constants.AbstractNet):
    NET_NAME = "regtest"
    TESTNET = True
    WIF_PREFIX = 239
    ADDRTYPE_P2PKH = 111
    ADDRTYPE_P2SH = 196
    GENESIS = None  # filled in below, from the generated fixture chain
    SEGWIT_HRP = "bcrt"
    BOLT11_HRP = "bcrt"
    DEFAULT_PORTS = {'t': '51001', 's': '51002'}
    DEFAULT_SERVERS = {}
    CHECKPOINTS = []
    DGW_CHECKPOINTS = []
    DGW_CHECKPOINTS_SPACING = 2016
    DGW_CHECKPOINTS_START = 0
    MATURE = 100
    BIP44_COIN_TYPE = 1
    LN_REALM_BYTE = 1
    # Keep every fixture header below all activation thresholds: they must
    # take the deterministic legacy (X16R) hashing path at generation time
    # AND at test time, whatever the surrounding net state is.
    X16Rv2ActivationTS = 2**40
    KawpowActivationTS = 2**40
    KawpowActivationHeight = 2**40
    nDGWActivationBlock = 2**40
    DEFAULT_MESSAGE_CHANNELS = []
    ASSET_PREFIX = b'rvn'
    SHORT_NAME = 'tRVN'
    LONG_NAME = 'Ravencoin'
    MULTISIG_ASSETS = False
    XPRV_HEADERS = {
        'standard': 0x04358394,  # tprv
        'p2wpkh-p2sh': 0x044a4e28,  # uprv
        'p2wsh-p2sh': 0x024285b5,  # Uprv
        'p2wpkh': 0x045f18bc,  # vprv
        'p2wsh': 0x02575048,  # Vprv
    }
    XPRV_HEADERS_INV = constants.inv_dict(XPRV_HEADERS)
    XPUB_HEADERS = {
        'standard': 0x043587cf,  # tpub
        'p2wpkh-p2sh': 0x044a5262,  # upub
        'p2wsh-p2sh': 0x042289ef,  # Upub
        'p2wpkh': 0x045f1cf6,  # vpub
        'p2wsh': 0x02575483,  # Vpub
    }
    XPUB_HEADERS_INV = constants.inv_dict(XPUB_HEADERS)


# Upstream Electrum's fixture tree topology: main chain A..F,O..U with two
# forks, G..L forking at height 6 and M..Z forking at height 9.  (name,
# height, parent name; None parent = height-0 chain root)
_TREE = (
    ('A', 0, None),
    ('B', 1, 'A'), ('C', 2, 'B'), ('D', 3, 'C'), ('E', 4, 'D'), ('F', 5, 'E'),
    ('O', 6, 'F'), ('P', 7, 'O'), ('Q', 8, 'P'),
    ('R', 9, 'Q'), ('S', 10, 'R'), ('T', 11, 'S'), ('U', 12, 'T'),
    ('G', 6, 'F'), ('H', 7, 'G'), ('I', 8, 'H'),
    ('J', 9, 'I'), ('K', 10, 'J'), ('L', 11, 'K'),
    ('M', 9, 'I'), ('N', 10, 'M'), ('X', 11, 'N'), ('Y', 12, 'X'), ('Z', 13, 'Y'),
)

_EPOCH_TS = 1_296_688_602  # upstream fixture era; below all activation TSs


def _mk_header(name: str, height: int, prev_hash: str) -> dict:
    return {
        'version': 1,
        'prev_block_hash': prev_hash,
        'merkle_root': hashlib.sha256(
            b'electrum-ravencoin-regtest-fixture/' + name.encode()).hexdigest(),
        'timestamp': _EPOCH_TS + 600 * height + (ord(name) % 97),
        'bits': 0x207fffff,  # regtest-easy; content is irrelevant under TESTNET
        'nonce': 1000 * height + ord(name),
        'block_height': height,
    }


def _build_headers() -> dict:
    # hash_header's era selection depends on the active net, so pin the net
    # to RegtestNet while linking the tree: generation must use exactly the
    # same (X16R) path the tests will use at runtime.
    prev_net = constants.net
    constants.net = RegtestNet
    try:
        headers = {}
        for name, height, parent in _TREE:
            prev = '00' * 32 if parent is None else hash_header(headers[parent])
            headers[name] = _mk_header(name, height, prev)
        RegtestNet.GENESIS = hash_header(headers['A'])
    finally:
        constants.net = prev_net
    return headers


#: Self-consistent header fixtures keyed by upstream's letter names; see
#: the module docstring for why the upstream Bitcoin-serialized fixtures
#: cannot be reused.
HEADERS = _build_headers()

#: Hash of the height-0 fixture header; equals RegtestNet.GENESIS.
GENESIS = RegtestNet.GENESIS


def set_regtest():
    """Select the test-only regtest network (mirrors the deleted
    ``constants.set_regtest`` for the inherited upstream tests)."""
    constants.net = RegtestNet
