// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <txorphanage.h>

#include <consensus/validation.h>
#include <logging.h>
#include <policy/policy.h>
#include <stats/client.h>

#include <cassert>

/** Expiration time for orphan transactions in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60;
/** Minimum time between orphan transactions expire time checks in seconds */
static constexpr int64_t ORPHAN_TX_EXPIRE_INTERVAL = 5 * 60;

RecursiveMutex g_cs_orphans;

bool TxOrphanage::AddTx(const CTransactionRef& tx, NodeId peer)
{
    AssertLockHeld(g_cs_orphans);

    const uint256& hash = tx->GetHash();
    if (m_orphans.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 100 orphans, each of which is at most 99,999 bytes big is
    // at most 10 megabytes of orphans and somewhat more byprev index (in the worst case):
    unsigned int sz = GetSerializeSize(*tx, CTransaction::CURRENT_VERSION);
    if (sz > MAX_STANDARD_TX_SIZE)
    {
        LogPrint(BCLog::MEMPOOL, "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    auto ret = m_orphans.emplace(hash, OrphanTx{tx, peer, GetTime() + ORPHAN_TX_EXPIRE_TIME, m_orphan_list.size(), sz});
    assert(ret.second);
    m_orphan_list.push_back(ret.first);
    for (const CTxIn& txin : tx->vin) {
        m_outpoint_to_orphan_it[txin.prevout].insert(ret.first);
    }

    m_orphan_tx_size += sz;

    LogPrint(BCLog::MEMPOOL, "stored orphan tx %s (mapsz %u outsz %u)\n", hash.ToString(),
             m_orphans.size(), m_outpoint_to_orphan_it.size());
    ::g_stats_client->inc("transactions.orphans.add", 1.0f);
    ::g_stats_client->gauge("transactions.orphans", m_orphans.size());

    return true;
}

int TxOrphanage::EraseTx(const uint256& txid)
{
    AssertLockHeld(g_cs_orphans);
    std::map<uint256, OrphanTx>::iterator it = m_orphans.find(txid);
    if (it == m_orphans.end())
        return 0;
    for (const CTxIn& txin : it->second.tx->vin)
    {
        auto itPrev = m_outpoint_to_orphan_it.find(txin.prevout);
        if (itPrev == m_outpoint_to_orphan_it.end())
            continue;
        itPrev->second.erase(it);
        if (itPrev->second.empty())
            m_outpoint_to_orphan_it.erase(itPrev);
    }

    size_t old_pos = it->second.list_pos;
    assert(m_orphan_list[old_pos] == it);
    if (old_pos + 1 != m_orphan_list.size()) {
        // Unless we're deleting the last entry in m_orphan_list, move the last
        // entry to the position we're deleting.
        auto it_last = m_orphan_list.back();
        m_orphan_list[old_pos] = it_last;
        it_last->second.list_pos = old_pos;
    }
    m_orphan_list.pop_back();

    assert(m_orphan_tx_size >= it->second.nTxSize);
    m_orphan_tx_size -= it->second.nTxSize;
    m_orphans.erase(it);
    ::g_stats_client->inc("transactions.orphans.remove", 1.0f);
    ::g_stats_client->gauge("transactions.orphans", m_orphans.size());
    return 1;
}

void TxOrphanage::EraseForPeer(NodeId peer)
{
    AssertLockHeld(g_cs_orphans);

    int nErased = 0;
    std::map<uint256, OrphanTx>::iterator iter = m_orphans.begin();
    while (iter != m_orphans.end())
    {
        std::map<uint256, OrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            nErased += EraseTx(maybeErase->second.tx->GetHash());
        }
    }
    if (nErased > 0) LogPrint(BCLog::MEMPOOL, "Erased %d orphan tx from peer=%d\n", nErased, peer);
}

unsigned int TxOrphanage::LimitOrphans(unsigned int max_orphans_size)
{
    AssertLockHeld(g_cs_orphans);

    unsigned int nEvicted = 0;
    static int64_t nNextSweep;
    int64_t nNow = GetTime();
    if (nNextSweep <= nNow) {
        // Sweep out expired orphan pool entries:
        int nErased = 0;
        int64_t nMinExpTime = nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL;
        std::map<uint256, OrphanTx>::iterator iter = m_orphans.begin();
        while (iter != m_orphans.end())
        {
            std::map<uint256, OrphanTx>::iterator maybeErase = iter++;
            if (maybeErase->second.nTimeExpire <= nNow) {
                nErased += EraseTx(maybeErase->second.tx->GetHash());
            } else {
                nMinExpTime = std::min(maybeErase->second.nTimeExpire, nMinExpTime);
            }
        }
        // Sweep again 5 minutes after the next entry that expires in order to batch the linear scan.
        nNextSweep = nMinExpTime + ORPHAN_TX_EXPIRE_INTERVAL;
        if (nErased > 0) LogPrint(BCLog::MEMPOOL, "Erased %d orphan tx due to expiration\n", nErased);
    }
    FastRandomContext rng;
    while (!m_orphans.empty() && m_orphan_tx_size > max_orphans_size)
    {
        // Evict a random orphan:
        size_t randompos = rng.randrange(m_orphan_list.size());
        EraseTx(m_orphan_list[randompos]->first);
        ++nEvicted;
    }
    return nEvicted;
}

void TxOrphanage::AddChildrenToWorkSet(const CTransaction& tx, std::set<uint256>& orphan_work_set) const
{
    AssertLockHeld(g_cs_orphans);
    for (unsigned int i = 0; i < tx.vout.size(); i++) {
        const auto it_by_prev = m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), i));
        if (it_by_prev != m_outpoint_to_orphan_it.end()) {
            for (const auto& elem : it_by_prev->second) {
                orphan_work_set.insert(elem->first);
            }
        }
    }
}

bool TxOrphanage::HaveTx(const uint256& txid) const
{
    LOCK(g_cs_orphans);
    return m_orphans.count(txid);
}

std::pair<CTransactionRef, NodeId> TxOrphanage::GetTx(const uint256& txid) const
{
    AssertLockHeld(g_cs_orphans);

    const auto it = m_orphans.find(txid);
    if (it == m_orphans.end()) return {nullptr, -1};
    return {it->second.tx, it->second.fromPeer};
}

std::set<uint256> TxOrphanage::GetCandidatesForBlock(const CBlock& block)
{
    AssertLockHeld(g_cs_orphans);

    std::set<uint256> orphanWorkSet;

    for (const CTransactionRef& ptx : block.vtx) {
        const CTransaction& tx = *ptx;

        // Which orphan pool entries we should reprocess and potentially try to accept into mempool again?
        for (size_t i = 0; i < tx.vin.size(); i++) {
            auto itByPrev = m_outpoint_to_orphan_it.find(COutPoint(tx.GetHash(), (uint32_t)i));
            if (itByPrev == m_outpoint_to_orphan_it.end()) continue;
            for (const auto& elem : itByPrev->second) {
                orphanWorkSet.insert(elem->first);
            }
        }
    }

    return orphanWorkSet;
}

void TxOrphanage::EraseForBlock(const CBlock& block)
{
    LOCK(g_cs_orphans);

    std::vector<uint256> vOrphanErase;

    for (const CTransactionRef& ptx : block.vtx) {
        const CTransaction& tx = *ptx;

        // Which orphan pool entries must we evict?
        for (const auto& txin : tx.vin) {
            auto itByPrev = m_outpoint_to_orphan_it.find(txin.prevout);
            if (itByPrev == m_outpoint_to_orphan_it.end()) continue;
            for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi) {
                const CTransaction& orphanTx = *(*mi)->second.tx;
                const uint256& orphanHash = orphanTx.GetHash();
                vOrphanErase.push_back(orphanHash);
            }
        }
    }

    // Erase orphan transactions included or precluded by this block
    if (vOrphanErase.size()) {
        int nErased = 0;
        for (const uint256& orphanHash : vOrphanErase) {
            nErased += EraseTx(orphanHash);
        }
        LogPrint(BCLog::MEMPOOL, "Erased %d orphan tx included or conflicted by block\n", nErased);
    }
}
