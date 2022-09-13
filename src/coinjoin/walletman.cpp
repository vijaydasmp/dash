// Copyright (c) 2023-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <coinjoin/walletman.h>

#include <net.h>
#include <scheduler.h>
#include <streams.h>

#include <evo/deterministicmns.h>

#ifdef ENABLE_WALLET
#include <coinjoin/client.h>
#endif // ENABLE_WALLET

#include <memory>

#ifdef ENABLE_WALLET
class CJWalletManagerImpl final : public CJWalletManager
{
public:
    CJWalletManagerImpl(ChainstateManager& chainman, CDeterministicMNManager& dmnman, CMasternodeMetaMan& mn_metaman,
                        CTxMemPool& mempool, const CMasternodeSync& mn_sync, const llmq::CInstantSendManager& isman,
                        bool relay_txes);
    virtual ~CJWalletManagerImpl() = default;

public:
    void Schedule(CConnman& connman, CScheduler& scheduler) override;

public:
    bool hasQueue(const uint256& hash) const override;
    CCoinJoinClientManager* getClient(const std::string& name) override EXCLUSIVE_LOCKS_REQUIRED(!cs_wallet_manager_map);
    MessageProcessingResult processMessage(CNode& peer, Chainstate& chainstate, CConnman& connman, CTxMemPool& mempool,
                                           std::string_view msg_type, CDataStream& vRecv) override EXCLUSIVE_LOCKS_REQUIRED(!cs_ProcessDSQueue, !cs_wallet_manager_map);
    std::optional<CCoinJoinQueue> getQueueFromHash(const uint256& hash) const override;
    std::optional<int> getQueueSize() const override;
    std::vector<CDeterministicMNCPtr> getMixingMasternodes() override;
    void addWallet(const std::shared_ptr<wallet::CWallet>& wallet) override;
    void removeWallet(const std::string& name) override;
    void flushWallet(const std::string& name) override;

protected:
    // CValidationInterface
    void UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload) override;

private:
    const bool m_relay_txes;

    CoinJoinWalletManager walletman;
    const std::unique_ptr<CCoinJoinClientQueueManager> queueman;
};

CJWalletManagerImpl::CJWalletManagerImpl(ChainstateManager& chainman, CDeterministicMNManager& dmnman,
                                         CMasternodeMetaMan& mn_metaman, CTxMemPool& mempool,
                                         const CMasternodeSync& mn_sync, const llmq::CInstantSendManager& isman,
                                         bool relay_txes) :
    m_relay_txes{relay_txes},
    walletman{chainman, dmnman, mn_metaman, mempool, mn_sync, isman, queueman},
    queueman{m_relay_txes ? std::make_unique<CCoinJoinClientQueueManager>(walletman, dmnman, mn_metaman, mn_sync) : nullptr}
{
}

void CJWalletManagerImpl::Schedule(CConnman& connman, CScheduler& scheduler)
{
    if (!m_relay_txes) return;
    scheduler.scheduleEvery(std::bind(&CCoinJoinClientQueueManager::DoMaintenance, std::ref(*queueman)),
                            std::chrono::seconds{1});
    scheduler.scheduleEvery(std::bind(&CoinJoinWalletManager::DoMaintenance, std::ref(walletman), std::ref(connman)),
                            std::chrono::seconds{1});
}

void CJWalletManagerImpl::UpdatedBlockTip(const CBlockIndex* pindexNew, const CBlockIndex* pindexFork, bool fInitialDownload)
{
    if (fInitialDownload || pindexNew == pindexFork) // In IBD or blocks were disconnected without any new ones
        return;

    walletman.ForEachCJClientMan(
        [&pindexNew](std::unique_ptr<CCoinJoinClientManager>& clientman) { clientman->UpdatedBlockTip(pindexNew); });
}

bool CJWalletManagerImpl::hasQueue(const uint256& hash) const
{
    if (queueman) {
        return queueman->HasQueue(hash);
    }
    return false;
}

CCoinJoinClientManager* CJWalletManagerImpl::getClient(const std::string& name)
{
    return walletman.Get(name);
}

MessageProcessingResult CJWalletManagerImpl::processMessage(CNode& pfrom, CChainState& chainstate, CConnman& connman,
                                                            CTxMemPool& mempool, std::string_view msg_type,
                                                            CDataStream& vRecv)
{
    walletman.ForEachCJClientMan([&](std::unique_ptr<CCoinJoinClientManager>& clientman) {
        clientman->ProcessMessage(pfrom, chainstate, connman, mempool, msg_type, vRecv);
    });
    if (queueman) {
        return queueman->ProcessMessage(pfrom.GetId(), connman, msg_type, vRecv);
    }
    return {};
}

std::optional<CCoinJoinQueue> CJWalletManagerImpl::getQueueFromHash(const uint256& hash) const
{
    if (queueman) {
        return queueman->GetQueueFromHash(hash);
    }
    return std::nullopt;
}

std::optional<int> CJWalletManagerImpl::getQueueSize() const
{
    if (queueman) {
        return queueman->GetQueueSize();
    }
    return std::nullopt;
}

std::vector<CDeterministicMNCPtr> CJWalletManagerImpl::getMixingMasternodes()
{
    std::vector<CDeterministicMNCPtr> ret{};
    walletman.ForEachCJClientMan(
        [&](const std::unique_ptr<CCoinJoinClientManager>& clientman) { clientman->GetMixingMasternodesInfo(ret); });
    return ret;
}

void CJWalletManagerImpl::addWallet(const std::shared_ptr<wallet::CWallet>& wallet)
{
    walletman.Add(wallet);
}

void CJWalletManagerImpl::flushWallet(const std::string& name)
{
    walletman.Flush(name);
}

void CJWalletManagerImpl::removeWallet(const std::string& name)
{
<<<<<<< HEAD
    walletman.Remove(name);
=======
    LOCK(cs_wallet_manager_map);
    m_wallet_manager_map.erase(name);
}

void CJWalletManagerImpl::DoMaintenance(CConnman& connman)
{
    if (m_queueman && m_mn_sync.IsBlockchainSynced() && !ShutdownRequested()) {
        m_queueman->CheckQueue();
    }
    LOCK(cs_wallet_manager_map);
    for (auto& [_, clientman] : m_wallet_manager_map) {
        clientman->DoMaintenance(m_chainman, connman, m_mempool);
    }
}

MessageProcessingResult CJWalletManagerImpl::processMessage(CNode& pfrom, Chainstate& chainstate, CConnman& connman,
                                                            CTxMemPool& mempool, std::string_view msg_type,
                                                            CDataStream& vRecv)
{
    ForEachCJClientMan([&](CCoinJoinClientManager& clientman) {
        clientman.ProcessMessage(pfrom, chainstate, connman, mempool, msg_type, vRecv);
    });
    if (m_queueman) {
        return ProcessDSQueue(pfrom.GetId(), connman, msg_type, vRecv);
    }
    return {};
}

MessageProcessingResult CJWalletManagerImpl::ProcessDSQueue(NodeId from, CConnman& connman, std::string_view msg_type,
                                                            CDataStream& vRecv)
{
    assert(m_queueman);

    if (msg_type != NetMsgType::DSQUEUE) {
        return {};
    }
    if (!m_mn_sync.IsBlockchainSynced()) return {};

    assert(m_mn_metaman.IsValid());

    CCoinJoinQueue dsq;
    vRecv >> dsq;

    MessageProcessingResult ret{};
    ret.m_to_erase = CInv{MSG_DSQ, dsq.GetHash()};

    if (dsq.masternodeOutpoint.IsNull() && dsq.m_protxHash.IsNull()) {
        ret.m_error = MisbehavingError{100};
        return ret;
    }

    const auto tip_mn_list = m_dmnman.GetListAtChainTip();
    if (dsq.masternodeOutpoint.IsNull()) {
        if (auto dmn = tip_mn_list.GetValidMN(dsq.m_protxHash)) {
            dsq.masternodeOutpoint = dmn->collateralOutpoint;
        } else {
            ret.m_error = MisbehavingError{10};
            return ret;
        }
    }

    {
        LOCK(cs_ProcessDSQueue);

        if (m_queueman->HasQueue(dsq.GetHash())) return ret;

        if (m_queueman->HasQueueFromMasternode(dsq.masternodeOutpoint, dsq.fReady)) {
            // no way the same mn can send another dsq with the same readiness this soon
            LogPrint(BCLog::COINJOIN, /* Continued */
                     "DSQUEUE -- Peer %d is sending WAY too many dsq messages for a masternode with collateral %s\n",
                     from, dsq.masternodeOutpoint.ToStringShort());
            return ret;
        }

        LogPrint(BCLog::COINJOIN, "DSQUEUE -- %s new\n", dsq.ToString());

        if (dsq.IsTimeOutOfBounds()) return ret;

        auto dmn = tip_mn_list.GetValidMNByCollateral(dsq.masternodeOutpoint);
        if (!dmn) return ret;

        if (dsq.m_protxHash.IsNull()) {
            dsq.m_protxHash = dmn->proTxHash;
        }

        if (!dsq.CheckSignature(dmn->pdmnState->pubKeyOperator.Get())) {
            ret.m_error = MisbehavingError{10};
            return ret;
        }

        // if the queue is ready, submit if we can
        if (dsq.fReady && ForAnyCJClientMan([&connman, &dmn](CCoinJoinClientManager& clientman) {
                return clientman.TrySubmitDenominate(dmn->proTxHash, connman);
            })) {
            LogPrint(BCLog::COINJOIN, "DSQUEUE -- CoinJoin queue is ready, masternode=%s, queue=%s\n",
                     dmn->proTxHash.ToString(), dsq.ToString());
            return ret;
        } else {
            if (m_mn_metaman.IsMixingThresholdExceeded(dmn->proTxHash, tip_mn_list.GetCounts().enabled())) {
                LogPrint(BCLog::COINJOIN, "DSQUEUE -- Masternode %s is sending too many dsq messages\n",
                         dmn->proTxHash.ToString());
                return ret;
            }
            m_mn_metaman.AllowMixing(dmn->proTxHash);

            LogPrint(BCLog::COINJOIN, "DSQUEUE -- new CoinJoin queue, masternode=%s, queue=%s\n",
                     dmn->proTxHash.ToString(), dsq.ToString());

            ForAnyCJClientMan(
                [&dsq](CCoinJoinClientManager& clientman) { return clientman.MarkAlreadyJoinedQueueAsTried(dsq); });

            m_queueman->AddQueue(dsq);
        }
    } // cs_ProcessDSQueue
    return ret;
>>>>>>> eea2ddd9d7 (Fixing CChainState in other places)
}
#endif // ENABLE_WALLET

std::unique_ptr<CJWalletManager> CJWalletManager::make(ChainstateManager& chainman, CDeterministicMNManager& dmnman,
                                                       CMasternodeMetaMan& mn_metaman, CTxMemPool& mempool,
                                                       const CMasternodeSync& mn_sync,
                                                       const llmq::CInstantSendManager& isman, bool relay_txes)
{
#ifdef ENABLE_WALLET
    return std::make_unique<CJWalletManagerImpl>(chainman, dmnman, mn_metaman, mempool, mn_sync, isman, relay_txes);
#else
    // Cannot be constructed if wallet support isn't built
    return nullptr;
#endif // ENABLE_WALLET
}
