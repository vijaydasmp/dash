// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/platformseed.h>

#include <uint256.h>
#include <wallet/bip39.h>
#include <wallet/platformkeys.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>

#include <array>
#include <map>
#include <optional>
#include <utility>

namespace wallet::platformkeys {

bool GetPlatformSeed(const CWallet& wallet, SecureVector& seed_out)
{
    LOCK(wallet.cs_wallet);
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) return false;

    if (wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) {
        std::optional<std::array<uint8_t, 8>> preferred_id;
        {
            const auto records{wallet.GetPlatformData("platform/seed-id")};
            const auto it{records.find("platform/seed-id")};
            if (it != records.end() && it->second.size() == 8) {
                std::array<uint8_t, 8> id;
                std::copy(it->second.begin(), it->second.end(), id.begin());
                preferred_id = id;
            }
        }
        std::map<uint256, SecureVector> candidates; // spk_man id -> seed
        for (const auto* spk_man : wallet.GetActiveScriptPubKeyMans()) {
            const auto* desc_spk_man = dynamic_cast<const DescriptorScriptPubKeyMan*>(spk_man);
            if (!desc_spk_man) continue;
            SecureString mnemonic, mnemonic_passphrase;
            if (!desc_spk_man->GetMnemonicString(mnemonic, mnemonic_passphrase)) continue;
            SecureVector seed;
            CMnemonic::ToSeed(mnemonic, mnemonic_passphrase, seed);
            if (seed.empty()) continue;
            if (preferred_id && SeedFingerprint(seed) == *preferred_id) {
                seed_out = std::move(seed);
                return true;
            }
            candidates.emplace(desc_spk_man->GetID(), std::move(seed));
        }
        if (candidates.empty()) return false;
        seed_out = std::move(candidates.begin()->second);
        return true;
    }

    const auto* spk_man = wallet.GetLegacyScriptPubKeyMan();
    if (!spk_man) return false;
    CHDChain hd_chain;
    if (!spk_man->GetHDChain(hd_chain)) return false;
    if (wallet.IsCrypted() && !spk_man->GetDecryptedHDChain(hd_chain)) return false;
    seed_out = hd_chain.GetSeed();
    return !seed_out.empty();
}

} // namespace wallet::platformkeys
