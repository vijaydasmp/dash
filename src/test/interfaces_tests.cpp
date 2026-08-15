// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/validation.h>
#include <evo/providertx.h>
#include <interfaces/chain.h>
#include <interfaces/node.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

using interfaces::FoundBlock;

BOOST_FIXTURE_TEST_SUITE(interfaces_tests, TestChain100Setup)

BOOST_AUTO_TEST_CASE(findBlock)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    auto& chain = m_node.chain;
    const CChain& active = Assert(m_node.chainman)->ActiveChain();

    uint256 hash;
    BOOST_CHECK(chain->findBlock(active[10]->GetBlockHash(), FoundBlock().hash(hash)));
    BOOST_CHECK_EQUAL(hash, active[10]->GetBlockHash());

    int height = -1;
    BOOST_CHECK(chain->findBlock(active[20]->GetBlockHash(), FoundBlock().height(height)));
    BOOST_CHECK_EQUAL(height, active[20]->nHeight);

    CBlock data;
    BOOST_CHECK(chain->findBlock(active[30]->GetBlockHash(), FoundBlock().data(data)));
    BOOST_CHECK_EQUAL(data.GetHash(), active[30]->GetBlockHash());

    int64_t time = -1;
    BOOST_CHECK(chain->findBlock(active[40]->GetBlockHash(), FoundBlock().time(time)));
    BOOST_CHECK_EQUAL(time, active[40]->GetBlockTime());

    int64_t max_time = -1;
    BOOST_CHECK(chain->findBlock(active[50]->GetBlockHash(), FoundBlock().maxTime(max_time)));
    BOOST_CHECK_EQUAL(max_time, active[50]->GetBlockTimeMax());

    int64_t mtp_time = -1;
    BOOST_CHECK(chain->findBlock(active[60]->GetBlockHash(), FoundBlock().mtpTime(mtp_time)));
    BOOST_CHECK_EQUAL(mtp_time, active[60]->GetMedianTimePast());

    bool cur_active{false}, next_active{false};
    uint256 next_hash;
    BOOST_CHECK_EQUAL(active.Height(), 100);
    BOOST_CHECK(chain->findBlock(active[99]->GetBlockHash(), FoundBlock().inActiveChain(cur_active).nextBlock(FoundBlock().inActiveChain(next_active).hash(next_hash))));
    BOOST_CHECK(cur_active);
    BOOST_CHECK(next_active);
    BOOST_CHECK_EQUAL(next_hash, active[100]->GetBlockHash());
    cur_active = next_active = false;
    BOOST_CHECK(chain->findBlock(active[100]->GetBlockHash(), FoundBlock().inActiveChain(cur_active).nextBlock(FoundBlock().inActiveChain(next_active))));
    BOOST_CHECK(cur_active);
    BOOST_CHECK(!next_active);

    BOOST_CHECK(!chain->findBlock({}, FoundBlock()));
}

BOOST_AUTO_TEST_CASE(providerTxCapabilities)
{
    auto node{interfaces::MakeNode(m_node)};
    const auto capabilities{node->evo().getProviderTxCapabilities()};
    const uint16_t expected_version{
        WITH_LOCK(::cs_main, return DeploymentToProtxVersion(Assert(m_node.chainman)->ActiveChain().Tip(),
                                                             *Assert(m_node.chainman)))};
    BOOST_CHECK_EQUAL(capabilities.version, expected_version);
    BOOST_CHECK_EQUAL(capabilities.extended_addresses, expected_version >= ProTxVersion::ExtAddr);
}

BOOST_AUTO_TEST_CASE(providerNetInfoValidation)
{
    auto node{interfaces::MakeNode(m_node)};
    interfaces::ProviderNetInfo net_info{
        .core_p2p = {"1.1.1.1:9998"},
        .platform_p2p = std::vector<std::string>{"1.1.1.2:22200"},
        .platform_https = std::vector<std::string>{"server.example.com:443"},
    };

    BOOST_CHECK(!node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/false));

    net_info.platform_p2p = std::vector<std::string>{"server.example.com:22200"};
    auto error{node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/false)};
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->code, interfaces::ProviderTxErrorCode::INVALID_PARAMETER);
    BOOST_CHECK_EQUAL(error->message.original,
                      "Error setting platformP2PAddrs[0] to 'server.example.com:22200' (invalid input)");

    net_info.platform_p2p = std::vector<std::string>{"1.1.1.1:9998"};
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/false);
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->message.original, "Error setting platformP2PAddrs[0] to '1.1.1.1:9998' (duplicate)");

    net_info.platform_p2p = std::vector<std::string>{"1.1.1.2:22200", "1.1.1.3:22200", "1.1.1.4:22200", "1.1.1.5:22200",
                                                     "1.1.1.6:22200"};
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/false);
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->message.original,
                      "Error setting platformP2PAddrs[4] to '1.1.1.6:22200' (too many entries)");

    net_info.platform_p2p = uint16_t{22200};
    net_info.platform_https = uint16_t{22201};
    BOOST_CHECK(!node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::BasicBLS, /*optional=*/false));

    net_info.platform_p2p = std::vector<std::string>{"1.1.1.2:22200"};
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::BasicBLS, /*optional=*/false);
    BOOST_REQUIRE(error);
    BOOST_CHECK(error->message.original.find("only accepts a bare port number") != std::string::npos);

    net_info = {
        .core_p2p = {},
        .platform_p2p = std::vector<std::string>{"1.1.1.2:22200"},
        .platform_https = std::vector<std::string>{"server.example.com:443"},
    };
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/true);
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->reject_reason, "bad-protx-netinfo-empty");

    net_info = {
        .core_p2p = {"1.1.1.1:9998"},
        .platform_p2p = std::monostate{},
        .platform_https = std::monostate{},
    };
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/true);
    BOOST_REQUIRE(error);
    BOOST_CHECK(error->message.original.find("platformP2PAddrs, cannot be empty if other fields populated") !=
                std::string::npos);
    BOOST_CHECK(!node->evo().validateProviderNetInfo(net_info, MnType::Regular, ProTxVersion::ExtAddr, /*optional=*/true));

    net_info.platform_p2p = std::vector<std::string>{"1.1.1.2:22200"};
    error = node->evo().validateProviderNetInfo(net_info, MnType::Regular, ProTxVersion::ExtAddr, /*optional=*/true);
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->message.original, "Platform endpoints are only valid for an EvoNode");

    net_info = {
        .core_p2p = {"1.1.1.1:9998"},
        .platform_p2p = std::vector<std::string>{"1.1.1.2:22200"},
        .platform_https = std::monostate{},
    };
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::ExtAddr, /*optional=*/true);
    BOOST_REQUIRE(error);
    BOOST_CHECK(error->message.original.find("platformHTTPSAddrs, cannot be empty if other fields populated") !=
                std::string::npos);

    net_info = {
        .core_p2p = {"1.1.1.1:9998"},
        .platform_p2p = uint16_t{22200},
        .platform_https = uint16_t{22200},
    };
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::BasicBLS, /*optional=*/false);
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->reject_reason, "bad-protx-platform-dup-ports");

    net_info.platform_p2p = uint16_t{MainParams().GetDefaultPort()};
    net_info.platform_https = uint16_t{22201};
    error = node->evo().validateProviderNetInfo(net_info, MnType::Evo, ProTxVersion::BasicBLS, /*optional=*/false);
    BOOST_REQUIRE(error);
    BOOST_CHECK_EQUAL(error->reject_reason, "bad-protx-platform-p2p-port");
}

BOOST_AUTO_TEST_CASE(findFirstBlockWithTimeAndHeight)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    auto& chain = m_node.chain;
    const CChain& active = Assert(m_node.chainman)->ActiveChain();
    uint256 hash;
    int height;
    BOOST_CHECK(chain->findFirstBlockWithTimeAndHeight(/* min_time= */ 0, /* min_height= */ 5, FoundBlock().hash(hash).height(height)));
    BOOST_CHECK_EQUAL(hash, active[5]->GetBlockHash());
    BOOST_CHECK_EQUAL(height, 5);
    BOOST_CHECK(!chain->findFirstBlockWithTimeAndHeight(/* min_time= */ active.Tip()->GetBlockTimeMax() + 1, /* min_height= */ 0));
}

BOOST_AUTO_TEST_CASE(findAncestorByHeight)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    auto& chain = m_node.chain;
    const CChain& active = Assert(m_node.chainman)->ActiveChain();
    uint256 hash;
    BOOST_CHECK(chain->findAncestorByHeight(active[20]->GetBlockHash(), 10, FoundBlock().hash(hash)));
    BOOST_CHECK_EQUAL(hash, active[10]->GetBlockHash());
    BOOST_CHECK(!chain->findAncestorByHeight(active[10]->GetBlockHash(), 20));
}

BOOST_AUTO_TEST_CASE(findAncestorByHash)
{
    LOCK(Assert(m_node.chainman)->GetMutex());
    auto& chain = m_node.chain;
    const CChain& active = Assert(m_node.chainman)->ActiveChain();
    int height = -1;
    BOOST_CHECK(chain->findAncestorByHash(active[20]->GetBlockHash(), active[10]->GetBlockHash(), FoundBlock().height(height)));
    BOOST_CHECK_EQUAL(height, 10);
    BOOST_CHECK(!chain->findAncestorByHash(active[10]->GetBlockHash(), active[20]->GetBlockHash()));
}

BOOST_AUTO_TEST_CASE(findCommonAncestor)
{
    auto& chain = m_node.chain;
    const CChain& active = *WITH_LOCK(Assert(m_node.chainman)->GetMutex(), return &Assert(m_node.chainman)->ActiveChain());
    auto* orig_tip = active.Tip();
    for (int i = 0; i < 10; ++i) {
        BlockValidationState state;
        m_node.chainman->ActiveChainstate().InvalidateBlock(state, active.Tip());
    }
    BOOST_CHECK_EQUAL(active.Height(), orig_tip->nHeight - 10);
    coinbaseKey.MakeNewKey(true);
    for (int i = 0; i < 20; ++i) {
        CreateAndProcessBlock({}, GetScriptForRawPubKey(coinbaseKey.GetPubKey()));
    }
    BOOST_CHECK_EQUAL(active.Height(), orig_tip->nHeight + 10);
    uint256 fork_hash;
    int fork_height;
    int orig_height;
    BOOST_CHECK(chain->findCommonAncestor(orig_tip->GetBlockHash(), active.Tip()->GetBlockHash(), FoundBlock().height(fork_height).hash(fork_hash), FoundBlock().height(orig_height)));
    BOOST_CHECK_EQUAL(orig_height, orig_tip->nHeight);
    BOOST_CHECK_EQUAL(fork_height, orig_tip->nHeight - 10);
    BOOST_CHECK_EQUAL(fork_hash, active[fork_height]->GetBlockHash());

    uint256 active_hash, orig_hash;
    BOOST_CHECK(!chain->findCommonAncestor(active.Tip()->GetBlockHash(), {}, {}, FoundBlock().hash(active_hash), {}));
    BOOST_CHECK(!chain->findCommonAncestor({}, orig_tip->GetBlockHash(), {}, {}, FoundBlock().hash(orig_hash)));
    BOOST_CHECK_EQUAL(active_hash, active.Tip()->GetBlockHash());
    BOOST_CHECK_EQUAL(orig_hash, orig_tip->GetBlockHash());
}

BOOST_AUTO_TEST_CASE(hasBlocks)
{
    LOCK(::cs_main);
    auto& chain = m_node.chain;
    const CChain& active = Assert(m_node.chainman)->ActiveChain();

    // Test ranges
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 10, 90));
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 10, {}));
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 0, 90));
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 0, {}));
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), -1000, 1000));
    active[5]->nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 10, 90));
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 10, {}));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 0, 90));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 0, {}));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), -1000, 1000));
    active[95]->nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 10, 90));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 10, {}));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 0, 90));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 0, {}));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), -1000, 1000));
    active[50]->nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 10, 90));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 10, {}));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 0, 90));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 0, {}));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), -1000, 1000));

    // Test edge cases
    BOOST_CHECK(chain->hasBlocks(active.Tip()->GetBlockHash(), 6, 49));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 5, 49));
    BOOST_CHECK(!chain->hasBlocks(active.Tip()->GetBlockHash(), 6, 50));
}

BOOST_AUTO_TEST_SUITE_END()
