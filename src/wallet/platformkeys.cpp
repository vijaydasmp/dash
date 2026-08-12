// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/platformkeys.h>

#include <crypto/hmac_sha256.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include <cassert>

namespace wallet::platformkeys {

Path IdentityAuthKeyPath(uint32_t coin_type, uint32_t identity_index, uint32_t key_index)
{
    // dashj DerivationPathFactory.blockchainIdentityECDSADerivationPath(index):
    // m/9'/coin'/5'/0'(sub-feature)/0'(key type ECDSA)/identity'/key'
    return {
        PathElement::Hardened(FEATURE_PURPOSE),
        PathElement::Hardened(coin_type),
        PathElement::Hardened(FEATURE_IDENTITIES),
        PathElement::Hardened(IDENTITY_AUTHENTICATION),
        PathElement::Hardened(AUTH_KEY_TYPE_ECDSA),
        PathElement::Hardened(identity_index),
        PathElement::Hardened(key_index),
    };
}

Path IdentityFundingPath(uint32_t coin_type, uint32_t subfeature, uint32_t index)
{
    // dashj DerivationPathFactory.blockchainIdentity{Registration,Topup}Funding-
    // DerivationPath() / identityInvitationFundingDerivationPath(), plus the
    // hardened address index appended by AuthenticationKeyChain:
    // m/9'/coin'/5'/{1,2,3}'/index'
    assert(subfeature == IDENTITY_REGISTRATION_FUNDING || subfeature == IDENTITY_TOPUP_FUNDING ||
           subfeature == IDENTITY_INVITATION_FUNDING);
    return {
        PathElement::Hardened(FEATURE_PURPOSE),
        PathElement::Hardened(coin_type),
        PathElement::Hardened(FEATURE_IDENTITIES),
        PathElement::Hardened(subfeature),
        PathElement::Hardened(index),
    };
}

Path FriendshipPath(uint32_t coin_type, uint32_t account, Span<const uint8_t> user_a_id, Span<const uint8_t> user_b_id)
{
    // dashj FriendKeyChain.getContactPath():
    // m/9'/coin'/15'/account'/userA/userB with the two 256-bit identity ids
    // NOT hardened (DIP-14/DIP-15), enabling watch-only xpub derivation.
    assert(user_a_id.size() == 32);
    assert(user_b_id.size() == 32);
    std::array<uint8_t, 32> a, b;
    std::copy(user_a_id.begin(), user_a_id.end(), a.begin());
    std::copy(user_b_id.begin(), user_b_id.end(), b.begin());
    return {
        PathElement::Hardened(FEATURE_PURPOSE),
        PathElement::Hardened(coin_type),
        PathElement::Hardened(FEATURE_DASHPAY),
        PathElement::Hardened(account),
        PathElement::Normal256(a),
        PathElement::Normal256(b),
    };
}

bool DeriveExtKey(Span<const uint8_t> seed, const Path& path, ExtKey256& out)
{
    CExtKey master;
    master.SetSeed(MakeByteSpan(seed));
    if (!master.key.IsValid()) return false;

    CKey key{master.key};
    ChainCode chaincode{master.chaincode};

    for (const auto& element : path) {
        CKey child_key;
        ChainCode child_cc;
        bool ok{false};
        if (const auto* index32 = std::get_if<uint32_t>(&element.index)) {
            if (*index32 >> 31) return false; // must use the hardened flag instead
            ok = key.Derive(child_key, child_cc, *index32 | (element.hardened ? 0x80000000u : 0), chaincode);
        } else {
            const auto& index256 = std::get<std::array<uint8_t, 32>>(element.index);
            ok = key.Derive256(child_key, child_cc, index256, element.hardened, chaincode);
        }
        if (!ok) return false;
        key = child_key;
        chaincode = child_cc;
    }

    out.key = key;
    out.chaincode = chaincode;
    return true;
}

bool DerivePubKey(const ExtPubKey256& parent, const PathElement& element, ExtPubKey256& out)
{
    if (element.hardened) return false;
    if (const auto* index32 = std::get_if<uint32_t>(&element.index)) {
        if (*index32 >> 31) return false;
        return parent.pubkey.Derive(out.pubkey, out.chaincode, *index32, parent.chaincode);
    }
    const auto& index256 = std::get<std::array<uint8_t, 32>>(element.index);
    return parent.pubkey.Derive256(out.pubkey, out.chaincode, index256, parent.chaincode);
}

bool ComputeECDHSecret(const CKey& key, const CPubKey& counterparty, SecureVector& secret_out)
{
    if (!key.IsValid() || !counterparty.IsValid()) return false;

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(secp256k1_context_static, &pubkey, counterparty.data(), counterparty.size())) {
        return false;
    }

    secret_out.assign(32, 0);
    // Default KDF: SHA256 of the compressed shared point — identical to
    // dashj's Secp256k1ECDHAgreement (DashPay contact request encryption).
    if (!secp256k1_ecdh(secp256k1_context_static, secret_out.data(), &pubkey,
                        UCharCast(key.begin()), nullptr, nullptr)) {
        secret_out.clear();
        return false;
    }
    return true;
}

std::array<uint8_t, 8> SeedFingerprint(Span<const uint8_t> seed)
{
    static constexpr char DOMAIN_KEY[]{"DashPlatform/seed-id/v1"};
    unsigned char mac[CHMAC_SHA256::OUTPUT_SIZE];
    CHMAC_SHA256{reinterpret_cast<const unsigned char*>(DOMAIN_KEY), sizeof(DOMAIN_KEY) - 1}
        .Write(seed.data(), seed.size())
        .Finalize(mac);
    std::array<uint8_t, 8> out;
    std::copy(mac, mac + out.size(), out.begin());
    return out;
}

} // namespace wallet::platformkeys
