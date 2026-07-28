// Copyright (c) 2018-2025 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_LLMQ_BLOCKPROCESSOR_H
#define BITCOIN_LLMQ_BLOCKPROCESSOR_H

#include <bls/bls.h>
#include <llmq/params.h>
#include <llmq/utils.h>
#include <msg_result.h>
#include <unordered_lru_cache.h>

#include <checkqueue.h>
#include <protocol.h>
#include <saltedhasher.h>
#include <sync.h>

#include <gsl/pointers.h>

#include <functional>
#include <optional>

class BlockValidationState;
class CBlock;
class CBlockIndex;
class CBLSSignature;
class CChain;
class Chainstate;
class CDataStream;
class CDeterministicMNManager;
class CEvoDB;
class CNode;

extern RecursiveMutex cs_main; // NOLINT(readability-redundant-declaration)

namespace llmq
{
class CFinalCommitment;
class CQuorumSnapshotManager;

class CQuorumBlockProcessor
{
private:
    Chainstate& m_chainstate;
    CDeterministicMNManager& m_dmnman;
    CEvoDB& m_evoDb;
    CQuorumSnapshotManager& m_qsnapman;

    CCheckQueue<utils::BlsCheck> m_bls_queue{4};

    mutable Mutex minableCommitmentsCs;
    std::map<std::pair<Consensus::LLMQType, uint256>, uint256> minableCommitmentsByQuorum GUARDED_BY(minableCommitmentsCs);
    std::map<uint256, CFinalCommitment> minableCommitments GUARDED_BY(minableCommitmentsCs);

    mutable std::map<Consensus::LLMQType, Uint256LruHashMap<bool>> mapHasMinedCommitmentCache GUARDED_BY(minableCommitmentsCs);

public:
    CQuorumBlockProcessor() = delete;
    CQuorumBlockProcessor(const CQuorumBlockProcessor&) = delete;
    CQuorumBlockProcessor& operator=(const CQuorumBlockProcessor&) = delete;
    explicit CQuorumBlockProcessor(Chainstate& chainstate, CDeterministicMNManager& dmnman, CEvoDB& evoDb,
                                   CQuorumSnapshotManager& qsnapman, int8_t bls_threads);
    ~CQuorumBlockProcessor();

    //! Predicate answering "do we have any record of asking this peer for the inv?", consuming that
    //! record as a side effect. An answer that is merely late or was superseded still returns true;
    //! false means we have nothing to show we asked, which is either because we did not or because
    //! the answer came too long after we did (see GetDataResponse). Passed in rather than reached
    //! through PeerManagerInternal because net_processing already depends on this header; see
    //! ProcessMessage for how it is used.
    //!
    //! Must be invoked without ::cs_main held -- the implementation takes it. Thread-safety
    //! analysis cannot check this through the type-erased std::function, so keep any call site
    //! outside ProcessMessage's own LOCK(::cs_main) block.
    using ConsumeRequestFn = std::function<bool(const CInv&)>;

    [[nodiscard]] MessageProcessingResult ProcessMessage(const CNode& peer, std::string_view msg_type,
                                                         CDataStream& vRecv,
                                                         const ConsumeRequestFn& consume_request)
        EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);

    bool ProcessBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex, BlockValidationState& state,
                      bool fJustCheck, bool fBLSChecks) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    bool UndoBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex)
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);

    //! it returns hash of commitment if it should be relay, otherwise nullopt
    std::optional<CInv> AddMineableCommitment(const CFinalCommitment& fqc) EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    bool HasMineableCommitment(const uint256& hash) const EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    bool GetMineableCommitmentByHash(const uint256& commitmentHash, CFinalCommitment& ret) const
        EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    std::optional<std::vector<CFinalCommitment>> GetMineableCommitments(const Consensus::LLMQParams& llmqParams,
                                                                        int nHeight) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    bool GetMineableCommitmentsTx(const Consensus::LLMQParams& llmqParams, int nHeight, std::vector<CTransactionRef>& ret) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    bool HasMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash) const
        EXCLUSIVE_LOCKS_REQUIRED(!minableCommitmentsCs);
    std::pair<CFinalCommitment, uint256> GetMinedCommitment(Consensus::LLMQType llmqType, const uint256& quorumHash) const;

    std::vector<const CBlockIndex*> GetMinedCommitmentsUntilBlock(Consensus::LLMQType llmqType, gsl::not_null<const CBlockIndex*> pindex, size_t maxCount) const;
    std::map<Consensus::LLMQType, std::vector<const CBlockIndex*>> GetMinedAndActiveCommitmentsUntilBlock(gsl::not_null<const CBlockIndex*> pindex) const;

    std::vector<const CBlockIndex*> GetMinedCommitmentsIndexedUntilBlock(Consensus::LLMQType llmqType, const CBlockIndex* pindex, size_t maxCount) const;
    std::vector<const CBlockIndex*> GetLastMinedCommitmentsPerQuorumIndexUntilBlock(Consensus::LLMQType llmqType,
                                                                                    const CBlockIndex* pindex,
                                                                                    size_t cycle) const;
    std::optional<const CBlockIndex*> GetLastMinedCommitmentsByQuorumIndexUntilBlock(Consensus::LLMQType llmqType, const CBlockIndex* pindex, int quorumIndex, size_t cycle) const;
private:
    static bool GetCommitmentsFromBlock(const CBlock& block, gsl::not_null<const CBlockIndex*> pindex, std::multimap<Consensus::LLMQType, CFinalCommitment>& ret, BlockValidationState& state) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
    bool ProcessCommitment(int nHeight, const uint256& blockHash, const CFinalCommitment& qc, BlockValidationState& state,
                           bool fJustCheck) EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    size_t GetNumCommitmentsRequired(const Consensus::LLMQParams& llmqParams, int nHeight) const
        EXCLUSIVE_LOCKS_REQUIRED(::cs_main, !minableCommitmentsCs);
    static uint256 GetQuorumBlockHash(const Consensus::LLMQParams& llmqParams, const CChain& active_chain, int nHeight, int quorumIndex) EXCLUSIVE_LOCKS_REQUIRED(::cs_main);
};
} // namespace llmq

#endif // BITCOIN_LLMQ_BLOCKPROCESSOR_H
