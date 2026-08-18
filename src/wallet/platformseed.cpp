// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/platformseed.h>

#include <uint256.h>
#include <wallet/bip39.h>
#include <wallet/platformkeys.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>

#include <algorithm>
#include <array>
#include <map>
#include <optional>
#include <utility>

namespace wallet::platformkeys {

bool GetPlatformSeed(const CWallet& wallet, SecureVector& seed_out)
{
    LOCK(wallet.cs_wallet);
    if (wallet.IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS)) return false;
    // DashPay is descriptor-wallet-only: a legacy wallet has no Platform key
    // universe, so it must fail here rather than serve its HD chain seed.
    if (!wallet.IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS)) return false;

    std::optional<std::array<uint8_t, 8>> preferred_id;
    {
        const auto records{wallet.GetPlatformData(PLATFORM_SEED_ID_RECORD)};
        const auto it{records.find(PLATFORM_SEED_ID_RECORD)};
        if (it != records.end()) {
            // A malformed pin fails closed like an unmatched one:
            // treating it as "no pin" could resume signing, ECDH and
            // friendship derivation under a different seed.
            if (it->second.size() != 8) return false;
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
        // Descriptors imported from a raw xprv store an empty mnemonic;
        // ToSeed("") would yield the publicly reproducible empty-mnemonic
        // seed rather than a wallet secret.
        if (mnemonic.empty()) continue;
        // ToSeed() hashes any string, so a corrupt stored mnemonic would
        // silently derive an unrelated Platform key universe; only a
        // phrase that passes BIP39 validation may become a candidate.
        if (!CMnemonic::Check(mnemonic)) continue;
        SecureVector seed;
        CMnemonic::ToSeed(mnemonic, mnemonic_passphrase, seed);
        if (seed.empty()) continue;
        if (preferred_id && SeedFingerprint(seed) == *preferred_id) {
            seed_out = std::move(seed);
            return true;
        }
        candidates.emplace(desc_spk_man->GetID(), std::move(seed));
    }
    // An unmatched pin must fail rather than silently fall back: platform
    // data created from the pinned seed must never be signed over with
    // another seed. The lowest-ID fallback is only for unpinned wallets.
    if (preferred_id || candidates.empty()) return false;
    seed_out = std::move(candidates.begin()->second);
    return true;
}

} // namespace wallet::platformkeys
