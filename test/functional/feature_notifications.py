#!/usr/bin/env python3
# Copyright (c) 2014-2020 The Bitcoin Core developers
# Copyright (c) 2023-2024 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the -alertnotify, -blocknotify, -chainlocknotify, -instantsendnotify and -walletnotify options."""
import os

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE, keyhash_to_p2pkh
from test_framework.test_framework import DashTestFramework

from test_framework.util import (
    assert_equal,
    force_finish_mnsync,
)

# Linux allow all characters other than \x00
# Windows disallow control characters (0-31) and /\?%:|"<>
FILE_CHAR_START = 32 if os.name == 'nt' else 1
FILE_CHAR_END = 128
FILE_CHARS_DISALLOWED = '/\\?%*:|"<>' if os.name == 'nt' else '/'
UNCONFIRMED_HASH_STRING = 'unconfirmed'

def notify_outputname(walletname, txid):
    return txid if os.name == 'nt' else '{}_{}'.format(walletname, txid)


class NotificationsTest(DashTestFramework):
    def set_test_params(self):
        self.set_dash_test_params(6, 4, fast_dip3_enforcement=True)

    def setup_network(self):
        self.wallet = ''.join(chr(i) for i in range(FILE_CHAR_START, FILE_CHAR_END) if chr(i) not in FILE_CHARS_DISALLOWED)
        self.alertnotify_dir = os.path.join(self.options.tmpdir, "alertnotify")
        self.blocknotify_dir = os.path.join(self.options.tmpdir, "blocknotify")
        self.walletnotify_dir = os.path.join(self.options.tmpdir, "walletnotify")
        self.chainlocknotify_dir = os.path.join(self.options.tmpdir, "chainlocknotify")
        self.instantsendnotify_dir = os.path.join(self.options.tmpdir, "instantsendnotify")
        os.mkdir(self.alertnotify_dir)
        os.mkdir(self.blocknotify_dir)
        os.mkdir(self.walletnotify_dir)
        os.mkdir(self.chainlocknotify_dir)
        os.mkdir(self.instantsendnotify_dir)

        # -alertnotify and -blocknotify on node0, walletnotify on node1
        self.extra_args[0].append("-alertnotify=echo > {}".format(os.path.join(self.alertnotify_dir, '%s')))
        self.extra_args[0].append("-blocknotify=echo > {}".format(os.path.join(self.blocknotify_dir, '%s')))
        self.extra_args[1].append("-rescan")
        self.extra_args[1].append("-walletnotify=echo %h_%b > {}".format(os.path.join(self.walletnotify_dir, notify_outputname('%w', '%s'))))

        # -chainlocknotify on node0, -instantsendnotify on node1
        self.extra_args[0].append("-chainlocknotify=echo > {}".format(os.path.join(self.chainlocknotify_dir, '%s')))
        self.extra_args[1].append("-instantsendnotify=echo > {}".format(os.path.join(self.instantsendnotify_dir, notify_outputname('%w', '%s'))))

        self.wallet_names = [self.default_wallet_name, self.wallet]
        super().setup_network()

    def run_test(self):
        # remove files created during network setup
        for block_file in os.listdir(self.blocknotify_dir):
            os.remove(os.path.join(self.blocknotify_dir, block_file))
        for tx_file in os.listdir(self.walletnotify_dir):
            os.remove(os.path.join(self.walletnotify_dir, tx_file))

        self.log.info("test -blocknotify")
        block_count = 10
        blocks = self.nodes[1].generatetoaddress(block_count, self.nodes[1].getnewaddress() if self.is_wallet_compiled() else ADDRESS_BCRT1_UNSPENDABLE)

        # wait at most 10 seconds for expected number of files before reading the content
        self.wait_until(lambda: len(os.listdir(self.blocknotify_dir)) == block_count, timeout=10)

        # directory content should equal the generated blocks hashes
        assert_equal(sorted(blocks), sorted(os.listdir(self.blocknotify_dir)))

        if self.is_wallet_compiled():
            self.log.info("test -walletnotify")
            # wait at most 10 seconds for expected number of files before reading the content
            self.wait_until(lambda: len(os.listdir(self.walletnotify_dir)) == block_count, timeout=10)

            # directory content should equal the generated transaction hashes
            tx_details = list(map(lambda t: (t['txid'], t['blockheight'], t['blockhash']), self.nodes[1].listtransactions("*", block_count)))
            self.stop_node(1)
            self.expect_wallet_notify(tx_details)

            self.log.info("test -walletnotify after rescan")
            # restart node to rescan to force wallet notifications
            self.start_node(1)
            force_finish_mnsync(self.nodes[1])
            self.connect_nodes(0, 1)

            self.wait_until(lambda: len(os.listdir(self.walletnotify_dir)) == block_count, timeout=10)

            # directory content should equal the generated transaction hashes
            tx_details = list(map(lambda t: (t['txid'], t['blockheight'], t['blockhash']), self.nodes[1].listtransactions("*", block_count)))
            self.expect_wallet_notify(tx_details)

            # Conflicting transactions tests. Give node 0 same wallet seed as
            # node 1, generate spends from node 0, and check notifications
            # triggered by node 1
            self.log.info("test -walletnotify with conflicting transactions")
            self.nodes[0].sethdseed(seed=self.nodes[1].dumpprivkey(keyhash_to_p2pkh(hex_str_to_bytes(self.nodes[1].getwalletinfo()['hdseedid'])[::-1])))
            self.nodes[0].rescanblockchain()
            self.nodes[0].generatetoaddress(100, ADDRESS_BCRT1_UNSPENDABLE)

            # Generate transaction on node 0, sync mempools, and check for
            # notification on node 1.
            tx1 = self.nodes[0].sendtoaddress(address=ADDRESS_BCRT1_UNSPENDABLE, amount=1, replaceable=True)
            assert_equal(tx1 in self.nodes[0].getrawmempool(), True)
            self.sync_mempools()
            self.expect_wallet_notify([(tx1, -1, UNCONFIRMED_HASH_STRING)])

            # Generate bump transaction, sync mempools, and check for bump1
            # notification. In the future, per
            # https://github.com/bitcoin/bitcoin/pull/9371, it might be better
            # to have notifications for both tx1 and bump1.
            bump1 = self.nodes[0].bumpfee(tx1)["txid"]
            assert_equal(bump1 in self.nodes[0].getrawmempool(), True)
            self.sync_mempools()
            self.expect_wallet_notify([(bump1, -1, UNCONFIRMED_HASH_STRING)])

            # Add bump1 transaction to new block, checking for a notification
            # and the correct number of confirmations.
            blockhash1 = self.nodes[0].generatetoaddress(1, ADDRESS_BCRT1_UNSPENDABLE)[0]
            blockheight1 = self.nodes[0].getblockcount()
            self.sync_blocks()
            self.expect_wallet_notify([(bump1, blockheight1, blockhash1)])
            assert_equal(self.nodes[1].gettransaction(bump1)["confirmations"], 1)

            # Generate a second transaction to be bumped.
            tx2 = self.nodes[0].sendtoaddress(address=ADDRESS_BCRT1_UNSPENDABLE, amount=1, replaceable=True)
            assert_equal(tx2 in self.nodes[0].getrawmempool(), True)
            self.sync_mempools()
            self.expect_wallet_notify([(tx2, -1, UNCONFIRMED_HASH_STRING)])

            # Bump tx2 as bump2 and generate a block on node 0 while
            # disconnected, then reconnect and check for notifications on node 1
            # about newly confirmed bump2 and newly conflicted tx2. Currently
            # only the bump2 notification is sent. Ideally, notifications would
            # be sent both for bump2 and tx2, which was the previous behavior
            # before being broken by an accidental change in PR
            # https://github.com/bitcoin/bitcoin/pull/16624. The bug is reported
            # in issue https://github.com/bitcoin/bitcoin/issues/18325.
            self.disconnect_nodes(self.nodes[0], 1)
            bump2 = self.nodes[0].bumpfee(tx2)["txid"]
            blockhash2 = self.nodes[0].generatetoaddress(1, ADDRESS_BCRT1_UNSPENDABLE)[0]
            blockheight2 = self.nodes[0].getblockcount()
            assert_equal(self.nodes[0].gettransaction(bump2)["confirmations"], 1)
            assert_equal(tx2 in self.nodes[1].getrawmempool(), True)
            self.connect_nodes(self.nodes[0], 1)
            self.sync_blocks()
            self.expect_wallet_notify([(bump2, blockheight2, blockhash2), (tx2, -1, UNCONFIRMED_HASH_STRING)])
            assert_equal(self.nodes[1].gettransaction(bump2)["confirmations"], 1)

        self.log.info("test -chainlocknotify")

        self.activate_v19(expected_activation_height=900)
        self.log.info("Activated v19 at height:" + str(self.nodes[0].getblockcount()))

        self.activate_dip8()
        self.nodes[0].sporkupdate("SPORK_17_QUORUM_DKG_ENABLED", 0)
        self.nodes[0].sporkupdate("SPORK_19_CHAINLOCKS_ENABLED", 4070908800)
        self.wait_for_sporks_same()
        self.move_to_next_cycle()
        self.log.info("Cycle H height:" + str(self.nodes[0].getblockcount()))
        self.move_to_next_cycle()
        self.log.info("Cycle H+C height:" + str(self.nodes[0].getblockcount()))
        self.move_to_next_cycle()
        self.log.info("Cycle H+2C height:" + str(self.nodes[0].getblockcount()))

        (quorum_info_i_0, quorum_info_i_1) = self.mine_cycle_quorum(llmq_type_name='llmq_test_dip0024', llmq_type=103)
        self.nodes[0].sporkupdate("SPORK_19_CHAINLOCKS_ENABLED", 0)
        self.wait_for_sporks_same()

        self.log.info("Mine single block, wait for chainlock")
        self.bump_mocktime(1)
        tip = self.nodes[0].generate(1)[-1]
        self.wait_for_chainlocked_block_all_nodes(tip)
        # directory content should equal the chainlocked block hash
        assert_equal([tip], sorted(os.listdir(self.chainlocknotify_dir)))

        if self.is_wallet_compiled():
            self.log.info("test -instantsendnotify")
            assert_equal(len(os.listdir(self.instantsendnotify_dir)), 0)

            tx_count = 10
            for _ in range(tx_count):
                txid = self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
                self.wait_for_instantlock(txid, self.nodes[1])

            # wait at most 10 seconds for expected number of files before reading the content
            self.wait_until(lambda: len(os.listdir(self.instantsendnotify_dir)) == tx_count, timeout=10)

            # directory content should equal the generated transaction hashes
            txids_rpc = list(map(lambda t: notify_outputname(self.wallet, t['txid']), self.nodes[1].listtransactions("*", tx_count)))
            assert_equal(sorted(txids_rpc), sorted(os.listdir(self.instantsendnotify_dir)))

        # TODO: add test for `-alertnotify` large fork notifications

    def expect_wallet_notify(self, tx_details):
        self.wait_until(lambda: len(os.listdir(self.walletnotify_dir)) >= len(tx_details), timeout=10)
        # Should have no more and no less files than expected
        assert_equal(sorted(notify_outputname(self.wallet, tx_id) for tx_id, _, _ in tx_details), sorted(os.listdir(self.walletnotify_dir)))
        # Should now verify contents of each file
        for tx_id, blockheight, blockhash in tx_details:
            fname = os.path.join(self.walletnotify_dir, notify_outputname(self.wallet, tx_id))
            with open(fname, 'rt', encoding='utf-8') as f:
                text = f.read()
                # Universal newline ensures '\n' on 'nt'
                assert_equal(text[-1], '\n')
                text = text[:-1]
                if os.name == 'nt':
                    # On Windows, echo as above will append a whitespace
                    assert_equal(text[-1], ' ')
                    text = text[:-1]
                expected = str(blockheight) + '_' + blockhash
                assert_equal(text, expected)

        for tx_file in os.listdir(self.walletnotify_dir):
            os.remove(os.path.join(self.walletnotify_dir, tx_file))


if __name__ == '__main__':
    NotificationsTest().main()
