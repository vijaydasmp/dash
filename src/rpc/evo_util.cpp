// Copyright (c) 2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/evo_util.h>

#include <evo/deterministicmns.h>
#include <index/txindex.h>

#include <univalue.h>


UniValue CDeterministicMN::ToJson() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("type", std::string(GetMnType(nType).description));
    obj.pushKV("proTxHash", proTxHash.ToString());
    obj.pushKV("collateralHash", collateralOutpoint.hash.ToString());
    obj.pushKV("collateralIndex", collateralOutpoint.n);

    if (g_txindex) {
        CTransactionRef collateralTx;
        uint256 nBlockHash;
        g_txindex->FindTx(collateralOutpoint.hash, nBlockHash, collateralTx);
        if (collateralTx) {
            CTxDestination dest;
            if (ExtractDestination(collateralTx->vout[collateralOutpoint.n].scriptPubKey, dest)) {
                obj.pushKV("collateralAddress", EncodeDestination(dest));
            }
        }
    }

    obj.pushKV("operatorReward", (double)nOperatorReward / 100);
    obj.pushKV("state", pdmnState->ToJson(nType));
    return obj;
}
