import shutil
import tempfile
import os

from electrum import constants, blockchain
from electrum.simple_config import SimpleConfig
from electrum.blockchain import (Blockchain, deserialize_header, hash_header,
                                 InvalidHeader, HEADER_SIZE)
from electrum.util import bfh, make_dir

from . import ElectrumTestCase
from . import regtest_fixtures


class TestBlockchain(ElectrumTestCase):

    # Fixture tree (rebuilt with this project's own hashing -- see
    # regtest_fixtures for why the upstream Bitcoin fixtures cannot be
    # reused):
    #                                            - M <- N <- X <- Y <- Z
    #                                          /
    #                             - G <- H <- I <- J <- K <- L
    #                           /
    # A <- B <- C <- D <- E <- F <- O <- P <- Q <- R <- S <- T <- U
    HEADERS = regtest_fixtures.HEADERS

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        regtest_fixtures.set_regtest()

    @classmethod
    def tearDownClass(cls):
        super().tearDownClass()
        constants.set_mainnet()

    def setUp(self):
        super().setUp()
        self.data_dir = self.electrum_path
        make_dir(os.path.join(self.data_dir, 'forks'))
        self.config = SimpleConfig({'electrum_path': self.data_dir})
        blockchain.blockchains = {}

    def _append_header(self, chain: Blockchain, header: dict):
        self.assertTrue(chain.can_connect(header))
        chain.save_header(header)

    def test_get_height_of_last_common_block_with_chain(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        self.assertEqual({chain_u:  8, chain_l: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11},             chain_l.get_parent_heights())

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual({chain_u:  8, chain_z: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11, chain_z: 8}, chain_l.get_parent_heights())
        self.assertEqual({chain_z: 13},             chain_z.get_parent_heights())
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_l))
        self.assertEqual(5, chain_l.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(5, chain_z.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(8, chain_l.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(8, chain_z.get_height_of_last_common_block_with_chain(chain_l))

        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])

        self.assertEqual({chain_u: 12, chain_z: 5}, chain_u.get_parent_heights())
        self.assertEqual({chain_l: 11, chain_z: 8}, chain_l.get_parent_heights())
        self.assertEqual({chain_z: 13},             chain_z.get_parent_heights())
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_l))
        self.assertEqual(5, chain_l.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(5, chain_u.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(5, chain_z.get_height_of_last_common_block_with_chain(chain_u))
        self.assertEqual(8, chain_l.get_height_of_last_common_block_with_chain(chain_z))
        self.assertEqual(8, chain_z.get_height_of_last_common_block_with_chain(chain_l))

    def test_parents_after_forking(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        self.assertEqual(None, chain_u.parent)

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        self.assertEqual(None,    chain_l.parent)
        self.assertEqual(chain_l, chain_u.parent)

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(None,    chain_z.parent)

        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])

        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(None,    chain_z.parent)

    def test_forking_and_swapping(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])
        self._append_header(chain_u, self.HEADERS['R'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])

        # do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(0, chain_u.forkpoint)
        self.assertEqual(None, chain_u.parent)
        self.assertEqual(constants.net.GENESIS, chain_u._forkpoint_hash)
        self.assertEqual(None, chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_u.path())
        self.assertEqual(10 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        self.assertEqual(6, chain_l.forkpoint)
        self.assertEqual(chain_u, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['G']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", f"fork2_6_{hash_header(self.HEADERS['F']).lstrip('0')}_{hash_header(self.HEADERS['G']).lstrip('0')}"), chain_l.path())
        self.assertEqual(4 * HEADER_SIZE, os.stat(chain_l.path()).st_size)

        self._append_header(chain_l, self.HEADERS['K'])

        # chains were swapped, do checks
        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_l, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", f"fork2_6_{hash_header(self.HEADERS['F']).lstrip('0')}_{hash_header(self.HEADERS['O']).lstrip('0')}"), chain_u.path())
        self.assertEqual(4 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        self.assertEqual(0, chain_l.forkpoint)
        self.assertEqual(None, chain_l.parent)
        self.assertEqual(constants.net.GENESIS, chain_l._forkpoint_hash)
        self.assertEqual(None, chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_l.path())
        self.assertEqual(11 * HEADER_SIZE, os.stat(chain_l.path()).st_size)
        for b in (chain_u, chain_l):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

        self._append_header(chain_u, self.HEADERS['S'])
        self._append_header(chain_u, self.HEADERS['T'])
        self._append_header(chain_u, self.HEADERS['U'])
        self._append_header(chain_l, self.HEADERS['L'])

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        # chain_z became best chain, do checks
        self.assertEqual(3, len(blockchain.blockchains))
        self.assertEqual(2, len(os.listdir(os.path.join(self.data_dir, "forks"))))
        self.assertEqual(0, chain_z.forkpoint)
        self.assertEqual(None, chain_z.parent)
        self.assertEqual(constants.net.GENESIS, chain_z._forkpoint_hash)
        self.assertEqual(None, chain_z._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_z.path())
        self.assertEqual(14 * HEADER_SIZE, os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", f"fork2_9_{hash_header(self.HEADERS['I']).lstrip('0')}_{hash_header(self.HEADERS['J']).lstrip('0')}"), chain_l.path())
        self.assertEqual(3 * HEADER_SIZE, os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", f"fork2_6_{hash_header(self.HEADERS['F']).lstrip('0')}_{hash_header(self.HEADERS['O']).lstrip('0')}"), chain_u.path())
        self.assertEqual(7 * HEADER_SIZE, os.stat(chain_u.path()).st_size)
        for b in (chain_u, chain_l, chain_z):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

        self.assertEqual(constants.net.GENESIS, chain_z.get_hash(0))
        self.assertEqual(hash_header(self.HEADERS['F']), chain_z.get_hash(5))
        self.assertEqual(hash_header(self.HEADERS['G']), chain_z.get_hash(6))
        self.assertEqual(hash_header(self.HEADERS['I']), chain_z.get_hash(8))
        self.assertEqual(hash_header(self.HEADERS['M']), chain_z.get_hash(9))
        self.assertEqual(hash_header(self.HEADERS['Z']), chain_z.get_hash(13))

    def test_doing_multiple_swaps_after_single_new_header(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()

        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])
        self._append_header(chain_u, self.HEADERS['R'])
        self._append_header(chain_u, self.HEADERS['S'])

        self.assertEqual(1, len(blockchain.blockchains))
        self.assertEqual(0, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        # now chain_u is best chain, but it's tied with chain_l

        self.assertEqual(2, len(blockchain.blockchains))
        self.assertEqual(1, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        chain_z = chain_l.fork(self.HEADERS['M'])
        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])

        self.assertEqual(3, len(blockchain.blockchains))
        self.assertEqual(2, len(os.listdir(os.path.join(self.data_dir, "forks"))))

        # chain_z became best chain, do checks
        self.assertEqual(0, chain_z.forkpoint)
        self.assertEqual(None, chain_z.parent)
        self.assertEqual(constants.net.GENESIS, chain_z._forkpoint_hash)
        self.assertEqual(None, chain_z._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "blockchain_headers"), chain_z.path())
        self.assertEqual(12 * HEADER_SIZE, os.stat(chain_z.path()).st_size)
        self.assertEqual(9, chain_l.forkpoint)
        self.assertEqual(chain_z, chain_l.parent)
        self.assertEqual(hash_header(self.HEADERS['J']), chain_l._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['I']), chain_l._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", f"fork2_9_{hash_header(self.HEADERS['I']).lstrip('0')}_{hash_header(self.HEADERS['J']).lstrip('0')}"), chain_l.path())
        self.assertEqual(2 * HEADER_SIZE, os.stat(chain_l.path()).st_size)
        self.assertEqual(6, chain_u.forkpoint)
        self.assertEqual(chain_z, chain_u.parent)
        self.assertEqual(hash_header(self.HEADERS['O']), chain_u._forkpoint_hash)
        self.assertEqual(hash_header(self.HEADERS['F']), chain_u._prev_hash)
        self.assertEqual(os.path.join(self.data_dir, "forks", f"fork2_6_{hash_header(self.HEADERS['F']).lstrip('0')}_{hash_header(self.HEADERS['O']).lstrip('0')}"), chain_u.path())
        self.assertEqual(5 * HEADER_SIZE, os.stat(chain_u.path()).st_size)

        self.assertEqual(constants.net.GENESIS, chain_z.get_hash(0))
        self.assertEqual(hash_header(self.HEADERS['F']), chain_z.get_hash(5))
        self.assertEqual(hash_header(self.HEADERS['G']), chain_z.get_hash(6))
        self.assertEqual(hash_header(self.HEADERS['I']), chain_z.get_hash(8))
        self.assertEqual(hash_header(self.HEADERS['M']), chain_z.get_hash(9))
        self.assertEqual(hash_header(self.HEADERS['X']), chain_z.get_hash(11))

        for b in (chain_u, chain_l, chain_z):
            self.assertTrue(all([b.can_connect(b.read_header(i), False) for i in range(b.height())]))

    def get_chains_that_contain_header_helper(self, header: dict):
        height = header['block_height']
        header_hash = hash_header(header)
        return blockchain.get_chains_that_contain_header(height, header_hash)

    def test_get_chains_that_contain_header(self):
        blockchain.blockchains[constants.net.GENESIS] = chain_u = Blockchain(
            config=self.config, forkpoint=0, parent=None,
            forkpoint_hash=constants.net.GENESIS, prev_hash=None)
        open(chain_u.path(), 'w+').close()
        self._append_header(chain_u, self.HEADERS['A'])
        self._append_header(chain_u, self.HEADERS['B'])
        self._append_header(chain_u, self.HEADERS['C'])
        self._append_header(chain_u, self.HEADERS['D'])
        self._append_header(chain_u, self.HEADERS['E'])
        self._append_header(chain_u, self.HEADERS['F'])
        self._append_header(chain_u, self.HEADERS['O'])
        self._append_header(chain_u, self.HEADERS['P'])
        self._append_header(chain_u, self.HEADERS['Q'])

        chain_l = chain_u.fork(self.HEADERS['G'])
        self._append_header(chain_l, self.HEADERS['H'])
        self._append_header(chain_l, self.HEADERS['I'])
        self._append_header(chain_l, self.HEADERS['J'])
        self._append_header(chain_l, self.HEADERS['K'])
        self._append_header(chain_l, self.HEADERS['L'])

        chain_z = chain_l.fork(self.HEADERS['M'])

        self.assertEqual([chain_l, chain_z, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['A']))
        self.assertEqual([chain_l, chain_z, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['C']))
        self.assertEqual([chain_l, chain_z, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['F']))
        self.assertEqual([chain_l, chain_z], self.get_chains_that_contain_header_helper(self.HEADERS['G']))
        self.assertEqual([chain_l, chain_z], self.get_chains_that_contain_header_helper(self.HEADERS['I']))
        self.assertEqual([chain_z], self.get_chains_that_contain_header_helper(self.HEADERS['M']))
        self.assertEqual([chain_l], self.get_chains_that_contain_header_helper(self.HEADERS['K']))

        self._append_header(chain_z, self.HEADERS['N'])
        self._append_header(chain_z, self.HEADERS['X'])
        self._append_header(chain_z, self.HEADERS['Y'])
        self._append_header(chain_z, self.HEADERS['Z'])

        self.assertEqual([chain_z, chain_l, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['A']))
        self.assertEqual([chain_z, chain_l, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['C']))
        self.assertEqual([chain_z, chain_l, chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['F']))
        self.assertEqual([chain_u], self.get_chains_that_contain_header_helper(self.HEADERS['O']))
        self.assertEqual([chain_z, chain_l], self.get_chains_that_contain_header_helper(self.HEADERS['I']))

    def test_target_to_bits(self):
        # https://github.com/bitcoin/bitcoin/blob/7fcf53f7b4524572d1d0c9a5fdc388e87eb02416/src/arith_uint256.h#L269
        self.assertEqual(0x05123456, Blockchain.target_to_bits(0x1234560000))
        self.assertEqual(0x0600c0de, Blockchain.target_to_bits(0xc0de000000))

        # tests from https://github.com/bitcoin/bitcoin/blob/a7d17daa5cd8bf6398d5f8d7e77290009407d6ea/src/test/arith_uint256_tests.cpp#L411
        tuples = (
            (0, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x00123456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x01003456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x02000056, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x03000000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x04000000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x00923456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x01803456, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x02800056, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x03800000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x04800000, 0x0000000000000000000000000000000000000000000000000000000000000000, 0),
            (0x01123456, 0x0000000000000000000000000000000000000000000000000000000000000012, 0x01120000),
            (0x02123456, 0x0000000000000000000000000000000000000000000000000000000000001234, 0x02123400),
            (0x03123456, 0x0000000000000000000000000000000000000000000000000000000000123456, 0x03123456),
            (0x04123456, 0x0000000000000000000000000000000000000000000000000000000012345600, 0x04123456),
            (0x05009234, 0x0000000000000000000000000000000000000000000000000000000092340000, 0x05009234),
            (0x20123456, 0x1234560000000000000000000000000000000000000000000000000000000000, 0x20123456),
        )
        for nbits1, target, nbits2 in tuples:
            with self.subTest(original_compact_nbits=nbits1.to_bytes(length=4, byteorder="big").hex()):
                num = Blockchain.bits_to_target(nbits1)
                self.assertEqual(target, num)
                self.assertEqual(nbits2, Blockchain.target_to_bits(num))

        # Make sure that we don't generate compacts with the 0x00800000 bit set
        self.assertEqual(0x02008000, Blockchain.target_to_bits(0x80))

        with self.assertRaises(InvalidHeader):  # target cannot be negative
            Blockchain.bits_to_target(0x01fedcba)
        with self.assertRaises(InvalidHeader):  # target cannot be negative
            Blockchain.bits_to_target(0x04923456)
        with self.assertRaises(InvalidHeader):  # overflow
            Blockchain.bits_to_target(0xff123456)


class TestVerifyHeader(ElectrumTestCase):

    # A legacy-era (X16R-hashed) header at height 100 that genuinely
    # satisfies its regtest-easy target under full mainnet verification.
    # bits 0x207fffff puts the target near 2^255, so most nonces pass but
    # some fail: nonce 1 below passes, nonce 0 (used by test_insufficient_pow)
    # does not.  The upstream Bitcoin block #100 fixture cannot be reused:
    # this project hashes legacy headers with X16R, not sha256d.
    valid_header = "01000000" + "00" * 32 + "11" * 32 + "dae5494d" + "ffff7f20" + "01000000"
    target = Blockchain.bits_to_target(0x207fffff)
    prev_hash = "00" * 32

    def setUp(self):
        super().setUp()
        self.header = deserialize_header(bfh(self.valid_header), 100)

    def test_valid_header(self):
        Blockchain.verify_header(self.header, self.prev_hash, self.target)

    def test_expected_hash_mismatch(self):
        with self.assertRaises(InvalidHeader):
            Blockchain.verify_header(self.header, self.prev_hash, self.target,
                                     expected_header_hash="foo")

    def test_prev_hash_mismatch(self):
        with self.assertRaises(InvalidHeader):
            Blockchain.verify_header(self.header, "foo", self.target)

    def test_target_mismatch(self):
        with self.assertRaises(InvalidHeader):
            other_target = Blockchain.bits_to_target(0x1d00eeee)
            Blockchain.verify_header(self.header, self.prev_hash, other_target)

    def test_insufficient_pow(self):
        with self.assertRaises(InvalidHeader):
            self.header["nonce"] = 0
            Blockchain.verify_header(self.header, self.prev_hash, self.target)


class TestKawpowNHeightValidation(ElectrumTestCase):
    """F3: a KAWPOW-era header's declared nheight must match its real chain
    position. Core treats a mismatch as consensus-invalid; the wallet's own
    light KAWPOW verification does not otherwise catch a forged value, since
    it trusts the header's own mix hash rather than recomputing it.
    """

    prev_hash = "00" * 32
    # A target large enough that any 256-bit hash satisfies the PoW check,
    # so these tests exercise only the nheight rule, not KAWPOW difficulty.
    _any_hash_target = (1 << 256) - 1

    @classmethod
    def _kawpow_header(cls, *, block_height, nheight):
        return {
            "version": 0x20000000,
            "prev_block_hash": cls.prev_hash,
            "merkle_root": "11" * 32,
            "timestamp": constants.net.KawpowActivationTS + 10_000_000,
            "bits": Blockchain.target_to_bits(cls._any_hash_target),
            "nheight": nheight,
            "nonce": 0,
            "mix_hash": "22" * 32,
            "block_height": block_height,
        }

    def _assert_accepted(self, *, block_height, nheight):
        header = self._kawpow_header(block_height=block_height, nheight=nheight)
        Blockchain.verify_header(header, self.prev_hash, self._any_hash_target)

    def _assert_rejected(self, *, block_height, nheight):
        header = self._kawpow_header(block_height=block_height, nheight=nheight)
        with self.assertRaises(InvalidHeader):
            Blockchain.verify_header(header, self.prev_hash, self._any_hash_target)

    def test_matching_nheight_is_accepted(self):
        height = constants.net.KawpowActivationHeight + 5
        self._assert_accepted(block_height=height, nheight=height)

    def test_forged_nheight_above_is_rejected(self):
        height = constants.net.KawpowActivationHeight + 5
        self._assert_rejected(block_height=height, nheight=height + 1)

    def test_forged_nheight_below_is_rejected(self):
        height = constants.net.KawpowActivationHeight + 5
        self._assert_rejected(block_height=height, nheight=height - 1)

    def test_august_2026_boundary_heights_pass_with_correct_nheight(self):
        # The incident boundary itself: honest headers must not be rejected.
        for height in (4487775, 4487776, 4487777):
            self._assert_accepted(block_height=height, nheight=height)

    def test_august_2026_boundary_forged_header_is_rejected(self):
        # The exact incident shape: a header claiming the boundary height
        # while actually sitting at a different chain position.
        self._assert_rejected(block_height=4487776, nheight=4487775)

    def test_later_header_with_wrong_nheight_is_rejected(self):
        self._assert_rejected(block_height=4600000, nheight=4599999)

    def test_pre_kawpow_headers_carry_no_nheight_field(self):
        # Legacy (pre-KAWPOW) headers never have the field at all; the check
        # must not require or invent one for them.
        legacy = deserialize_header(
            bfh(TestVerifyHeader.valid_header), 100)
        self.assertNotIn("nheight", legacy)

    def test_ambiguous_pre_activation_height_is_not_enforced(self):
        # A header below KawpowActivationHeight that nonetheless carries an
        # 'nheight' key (only possible via an inconsistent/edge parse, since
        # deserialize_header keys off the header's own timestamp rather than
        # the caller-supplied height) is left to the rest of validation
        # instead of being rejected on an ambiguous field.
        height = constants.net.KawpowActivationHeight - 1
        self._assert_accepted(block_height=height, nheight=height + 1)
