// Copyright (c) 2018-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LLMQ_UTILS_H
#define BITCOIN_LLMQ_UTILS_H

#include <gsl/pointers.h>
#include <llmq/params.h>
#include <saltedhasher.h>
#include <sync.h>
#include <uint256.h>

#include <map>
#include <set>
#include <unordered_set>
#include <vector>

class CConnman;
class CBlockIndex;
class CDeterministicMN;
class CDeterministicMNList;
class CDeterministicMNManager;
class CMasternodeMetaMan;
class CSporkManager;

using CDeterministicMNCPtr = std::shared_ptr<const CDeterministicMN>;

namespace llmq {
class CQuorumSnapshotManager;

namespace utils {
// includes members which failed DKG
std::vector<CDeterministicMNCPtr> GetAllQuorumMembers(Consensus::LLMQType llmqType, CDeterministicMNManager& dmnman,
                                                      CQuorumSnapshotManager& qsnapman,
                                                      gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex,
                                                      bool reset_cache = false);

uint256 DeterministicOutboundConnection(const uint256& proTxHash1, const uint256& proTxHash2);
std::unordered_set<uint256, StaticSaltedHasher> GetQuorumConnections(
    const Consensus::LLMQParams& llmqParams, CDeterministicMNManager& dmnman, CQuorumSnapshotManager& qsnapman,
    const CSporkManager& sporkman, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, const uint256& forMember,
    bool onlyOutbound);
std::unordered_set<uint256, StaticSaltedHasher> GetQuorumRelayMembers(
    const Consensus::LLMQParams& llmqParams, CDeterministicMNManager& dmnman, CQuorumSnapshotManager& qsnapman,
    gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, const uint256& forMember, bool onlyOutbound);
std::set<size_t> CalcDeterministicWatchConnections(Consensus::LLMQType llmqType, gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, size_t memberCount, size_t connectionCount);

bool EnsureQuorumConnections(const Consensus::LLMQParams& llmqParams, CConnman& connman,
                             CDeterministicMNManager& dmnman, const CSporkManager& sporkman,
                             CQuorumSnapshotManager& qsnapman, const CDeterministicMNList& tip_mn_list,
                             gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, const uint256& myProTxHash,
                             bool is_masternode);
void AddQuorumProbeConnections(const Consensus::LLMQParams& llmqParams, CConnman& connman, CDeterministicMNManager& dmnman,
                               CMasternodeMetaMan& mn_metaman, CQuorumSnapshotManager& qsnapman,
                               const CSporkManager& sporkman, const CDeterministicMNList& tip_mn_list,
                               gsl::not_null<const CBlockIndex*> pQuorumBaseBlockIndex, const uint256& myProTxHash);

template <typename CacheType>
void InitQuorumsCache(CacheType& cache, bool limit_by_connections = true);
} // namespace utils
} // namespace llmq

#endif // BITCOIN_LLMQ_UTILS_H
