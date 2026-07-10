// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/bloom.h>
#include <governance/governance.h>
#include <governance/net_governance.h>
#include <governance/object.h>
#include <masternode/meta.h>
#include <masternode/sync.h>
#include <net.h>
#include <net_processing.h>
#include <netfulfilledman.h>
#include <node/connection_types.h>
#include <protocol.h>
#include <scheduler.h>
#include <streams.h>
#include <uint256.h>
#include <util/time.h>
#include <version.h>

#include <test/util/net.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {
struct GovernanceInvSetup : public TestingSetup {
    GovernanceInvSetup() : TestingSetup{CBaseChainParams::MAIN}
    {
        // ConfirmInventoryRequest and CheckAndRemove short-circuit on
        // !IsBlockchainSynced(); CheckAndRemove also asserts metaman.IsValid().
        // NetGovernance::AlreadyHave gates on m_gov_manager.IsValid().
        BOOST_REQUIRE(m_node.mn_sync);
        m_node.mn_sync->SwitchToNextAsset();
        BOOST_REQUIRE(m_node.mn_sync->IsBlockchainSynced());

        BOOST_REQUIRE(m_node.mn_metaman);
        BOOST_REQUIRE(m_node.mn_metaman->LoadCache(/*load_cache=*/false));

        BOOST_REQUIRE(m_node.govman);
        // Match runtime preconditions: NetGovernance::AlreadyHave claims we
        // already have the inv when governance isn't loaded (e.g.
        // -disablegovernance), so ConfirmInventoryRequest would never run.
        BOOST_REQUIRE(m_node.govman->LoadCache(/*load_cache=*/false));

        BOOST_REQUIRE(m_node.netfulfilledman);
        // Loaded here for the later test that advances GOVERNANCE -> FINISHED;
        // the sync notifier asserts netfulfilledman.IsValid().
        BOOST_REQUIRE(m_node.netfulfilledman->LoadCache(/*load_cache=*/false));
        BOOST_REQUIRE(m_node.connman);
        BOOST_REQUIRE(m_node.peerman);

        // Intentional unit-test boundary: TestingSetup does not run the
        // init.cpp/AppInit startup path that registers the Dash-specific
        // handlers, so the INV branch in PeerManagerImpl::AlreadyHave would not
        // route MSG_GOVERNANCE_OBJECT[_VOTE] anywhere. Install the same
        // NetGovernance handler init.cpp registers so a real INV reaches
        // CGovernanceManager::ConfirmInventoryRequest; the startup registration
        // itself stays outside this unit test.
        m_node.peerman->AddExtraHandler(std::make_unique<NetGovernance>(
            m_node.peerman.get(), *m_node.govman, *m_node.mn_sync,
            *m_node.netfulfilledman, *m_node.connman));

        // Anchor the mocked clock so SetMockTime advances are deterministic.
        SetMockTime(1'700'000'000s);
    }
};

size_t CountQueuedMessages(const CNode& peer, const std::string& msg_type)
{
    LOCK(peer.cs_vSend);
    size_t count{0};
    for (const auto& msg : peer.vSendMsg) {
        if (msg.m_type == msg_type) {
            ++count;
        }
    }
    return count;
}

size_t CountQueuedInventory(const CNode& peer, const CInv& expected_inv)
{
    LOCK(peer.cs_vSend);
    size_t count{0};
    for (const auto& msg : peer.vSendMsg) {
        if (msg.m_type != NetMsgType::INV) {
            continue;
        }
        CDataStream stream{msg.data, SER_NETWORK, PROTOCOL_VERSION};
        std::vector<CInv> invs;
        stream >> invs;
        for (const auto& inv : invs) {
            if (inv.type == expected_inv.type && inv.hash == expected_inv.hash) {
                ++count;
            }
        }
    }
    return count;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(governance_inv_tests, GovernanceInvSetup)

BOOST_AUTO_TEST_CASE(per_object_vote_sync_is_fulfilled_request_limited)
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    // NetGovernance::ProcessMessage ignores MNGOVERNANCESYNC until sync is
    // fully finished; advance from GOVERNANCE to FINISHED.
    m_node.mn_sync->SwitchToNextAsset();
    BOOST_REQUIRE(m_node.mn_sync->IsSynced());

    in_addr peer_in_addr{};
    peer_in_addr.s_addr = htonl(0x01020305);
    CNode peer{/*id=*/1,
               /*sock=*/nullptr,
               /*addrIn=*/CAddress{CService{peer_in_addr, 8333}, NODE_NETWORK},
               /*nKeyedNetGroupIn=*/0,
               /*nLocalHostNonceIn=*/0,
               /*addrBindIn=*/CAddress{},
               /*addrNameIn=*/std::string{},
               /*conn_type_in=*/ConnectionType::INBOUND,
               /*inbound_onion=*/false};
    peer.nVersion = PROTOCOL_VERSION;
    peer.SetCommonVersion(PROTOCOL_VERSION);
    m_node.peerman->InitializeNode(peer, NODE_NETWORK);
    peer.fSuccessfullyConnected = true;

    auto make_request_stream = [](const uint256& object_hash, const CBloomFilter& filter) {
        CDataStream stream{SER_NETWORK, PROTOCOL_VERSION};
        stream << object_hash << filter;
        return stream;
    };

    NetGovernance net_gov(m_node.peerman.get(), *m_node.govman, *m_node.mn_sync,
                          *m_node.netfulfilledman, *m_node.connman);
    auto& connman = static_cast<ConnmanTestMsg&>(*m_node.connman);
    CNodeStateStats stats;
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 0);

    const CBloomFilter vote_filter{1, 0.001, 0, BLOOM_UPDATE_NONE};
    CGovernanceObject postponed_object{uint256(), /*revision=*/1, GetTime(), uint256::ONE, /*data=*/{}};
    m_node.govman->AddPostponedObject(postponed_object);

    const uint256 postponed_object_hash{postponed_object.GetHash()};
    const std::string postponed_vote_sync_request{strprintf("%s-votes-%s", NetMsgType::MNGOVERNANCESYNC,
                                                            postponed_object_hash.ToString())};
    auto postponed_stream = make_request_stream(postponed_object_hash, vote_filter);
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, postponed_stream);

    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, postponed_vote_sync_request));
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 0);

    auto duplicate_postponed_stream = make_request_stream(postponed_object_hash, vote_filter);
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, duplicate_postponed_stream);

    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 0);

    CGovernanceObject syncable_object{uint256(), /*revision=*/1, GetTime() + 1, uint256S("02"), /*data=*/{}};
    m_node.govman->AddGovernanceObjectForTesting(syncable_object);

    const uint256 syncable_object_hash{syncable_object.GetHash()};
    const std::string syncable_vote_sync_request{strprintf("%s-votes-%s", NetMsgType::MNGOVERNANCESYNC,
                                                           syncable_object_hash.ToString())};
    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, syncable_vote_sync_request));

    connman.FlushSendBuffer(peer);
    auto syncable_object_fetch_stream = make_request_stream(syncable_object_hash, CBloomFilter{});
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, syncable_object_fetch_stream);

    BOOST_CHECK_EQUAL(CountQueuedInventory(peer, CInv{MSG_GOVERNANCE_OBJECT, syncable_object_hash}), 1U);
    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, syncable_vote_sync_request));
    BOOST_CHECK_EQUAL(CountQueuedMessages(peer, NetMsgType::SYNCSTATUSCOUNT), 0U);
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 0);

    connman.FlushSendBuffer(peer);
    auto duplicate_syncable_object_fetch_stream = make_request_stream(syncable_object_hash, CBloomFilter{});
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, duplicate_syncable_object_fetch_stream);

    BOOST_CHECK_EQUAL(CountQueuedInventory(peer, CInv{MSG_GOVERNANCE_OBJECT, syncable_object_hash}), 1U);
    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, syncable_vote_sync_request));
    BOOST_CHECK_EQUAL(CountQueuedMessages(peer, NetMsgType::SYNCSTATUSCOUNT), 0U);
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 0);

    connman.FlushSendBuffer(peer);
    auto syncable_stream = make_request_stream(syncable_object_hash, vote_filter);
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, syncable_stream);

    BOOST_CHECK(m_node.netfulfilledman->HasFulfilledRequest(peer.addr, syncable_vote_sync_request));
    BOOST_CHECK_EQUAL(CountQueuedMessages(peer, NetMsgType::SYNCSTATUSCOUNT), 1U);
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 0);

    auto duplicate_syncable_stream = make_request_stream(syncable_object_hash, vote_filter);
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, duplicate_syncable_stream);

    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    connman.FlushSendBuffer(peer);
    CGovernanceObject empty_filter_object{uint256(), /*revision=*/1, GetTime() + 2, uint256S("03"), /*data=*/{}};
    m_node.govman->AddPostponedObject(empty_filter_object);
    const uint256 empty_filter_object_hash{empty_filter_object.GetHash()};
    const std::string empty_filter_vote_request{strprintf("%s-votes-%s", NetMsgType::MNGOVERNANCESYNC,
                                                          empty_filter_object_hash.ToString())};
    auto empty_filter_stream = make_request_stream(empty_filter_object_hash, CBloomFilter{});
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, empty_filter_stream);

    BOOST_CHECK_EQUAL(CountQueuedInventory(peer, CInv{MSG_GOVERNANCE_OBJECT, empty_filter_object_hash}), 1U);
    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, empty_filter_vote_request));
    BOOST_CHECK_EQUAL(CountQueuedMessages(peer, NetMsgType::SYNCSTATUSCOUNT), 0U);
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    connman.FlushSendBuffer(peer);
    auto duplicate_empty_filter_stream = make_request_stream(empty_filter_object_hash, CBloomFilter{});
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, duplicate_empty_filter_stream);

    BOOST_CHECK_EQUAL(CountQueuedInventory(peer, CInv{MSG_GOVERNANCE_OBJECT, empty_filter_object_hash}), 1U);
    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, empty_filter_vote_request));
    BOOST_CHECK_EQUAL(CountQueuedMessages(peer, NetMsgType::SYNCSTATUSCOUNT), 0U);
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    const uint256 unknown_vote_hash{uint256S("09")};
    const std::string unknown_vote_request{strprintf("%s-votes-%s", NetMsgType::MNGOVERNANCESYNC,
                                                     unknown_vote_hash.ToString())};
    auto unknown_vote_stream = make_request_stream(unknown_vote_hash, vote_filter);
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, unknown_vote_stream);

    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, unknown_vote_request));
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    auto duplicate_unknown_vote_stream = make_request_stream(unknown_vote_hash, vote_filter);
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, duplicate_unknown_vote_stream);

    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, unknown_vote_request));
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    const uint256 object_fetch_hash{uint256S("0a")};
    const std::string object_fetch_request{strprintf("%s-votes-%s", NetMsgType::MNGOVERNANCESYNC,
                                                     object_fetch_hash.ToString())};
    auto object_fetch_stream = make_request_stream(object_fetch_hash, CBloomFilter{});
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, object_fetch_stream);

    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, object_fetch_request));
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    auto duplicate_object_fetch_stream = make_request_stream(object_fetch_hash, CBloomFilter{});
    net_gov.ProcessMessage(peer, NetMsgType::MNGOVERNANCESYNC, duplicate_object_fetch_stream);

    BOOST_CHECK(!m_node.netfulfilledman->HasFulfilledRequest(peer.addr, object_fetch_request));
    BOOST_REQUIRE(m_node.peerman->GetNodeStateStats(peer.GetId(), stats));
    BOOST_CHECK_EQUAL(stats.m_misbehavior_score, 20);

    m_node.peerman->FinalizeNode(peer);
}

BOOST_AUTO_TEST_SUITE_END()
