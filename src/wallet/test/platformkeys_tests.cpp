// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <interfaces/coinjoin.h>
#include <interfaces/wallet.h>
#include <key.h>
#include <key_io.h>
#include <script/standard.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <wallet/bip39.h>
#include <wallet/coincontrol.h>
#include <wallet/context.h>
#include <wallet/platformkeys.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/spend.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>
#include <set>
#include <vector>

using namespace wallet;
using namespace wallet::platformkeys;

BOOST_FIXTURE_TEST_SUITE(platformkeys_tests, BasicTestingSetup)

//! Seed shared by all DIP-14 test vectors (dashpay/dips dip-0014.md), from
//! mnemonic "birth kingdom trash renew flavor utility donkey gasp regular
//! alert pave layer".
static SecureVector Dip14Seed()
{
    const std::vector<unsigned char> seed{ParseHex(
        "b16d3782e714da7c55a397d5f19104cfed7ffa8036ac514509bbb50807f8ac59"
        "8eeb26f0797bd8cc221a6cbff2168d90a5e9ee025a5bd977977b9eccd97894bb")};
    return SecureVector{seed.begin(), seed.end()};
}

static std::array<uint8_t, 32> Arr32(const std::string& hex)
{
    const std::vector<unsigned char> v{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(v.size(), 32U);
    std::array<uint8_t, 32> out;
    std::copy(v.begin(), v.end(), out.begin());
    return out;
}

static std::string DerivedKeyHex(const Path& path)
{
    ExtKey256 out;
    BOOST_REQUIRE(DeriveExtKey(Dip14Seed(), path, out));
    return HexStr(Span{out.key.begin(), out.key.size()});
}

// DIP-14 test vector 1: m/<id1>/<id2>'/<id3>/0
BOOST_AUTO_TEST_CASE(dip14_vector_1)
{
    const Path path{
        PathElement::Normal256(Arr32("775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b")),
        PathElement{Arr32("f537439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89a6"), true},
        PathElement::Normal256(Arr32("4c4592ca670c983fc43397dfd21a6f427fac9b4ac53cb4dcdc6522ec51e81e79")),
        PathElement::Normal(0),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "e8781fdef72862968cd9a4d2df34edaf9dcc5b17629ec505f0d2d1a8ed6f9f09");
}

// DIP-14 test vector 2: m/9'/5'/15'/0'/<idA>'/<idB>'/0 (DIP-15 shape)
BOOST_AUTO_TEST_CASE(dip14_vector_2)
{
    const Path path{
        PathElement::Hardened(9),
        PathElement::Hardened(5),
        PathElement::Hardened(15),
        PathElement::Hardened(0),
        PathElement{Arr32("555d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3a"), true},
        PathElement{Arr32("a137439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89b5"), true},
        PathElement::Normal(0),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "fac40790776d171ee1db90899b5eb2df2f7d2aaf35ad56f07ffb8ed2c57f8e60");
}

// DIP-14 test vector 3: m/<id> (single 256-bit non-hardened step)
BOOST_AUTO_TEST_CASE(dip14_vector_3)
{
    const Path path{
        PathElement::Normal256(Arr32("775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b")),
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "f6a95ae75ea8362d9478932f71b262b3d981918fe030316686a475dea4889938");
}

// DIP-14 test vector 4: m/<id1>/<id2>'
BOOST_AUTO_TEST_CASE(dip14_vector_4)
{
    const Path path{
        PathElement::Normal256(Arr32("775d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3b")),
        PathElement{Arr32("f537439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89a6"), true},
    };
    BOOST_CHECK_EQUAL(DerivedKeyHex(path), "b898ad92d3a0698bc3117d3777d82676673816ce52f4fc2f1263a2f676825f90");
}

//! Non-hardened 256-bit public derivation must match private derivation
//! (this is what lets a contact derive our friendship addresses from an
//! exported xpub).
BOOST_AUTO_TEST_CASE(dip14_public_derivation_matches)
{
    const Path parent_path{
        PathElement::Hardened(9),
        PathElement::Hardened(1),
        PathElement::Hardened(15),
        PathElement::Hardened(0),
    };
    ExtKey256 parent;
    BOOST_REQUIRE(DeriveExtKey(Dip14Seed(), parent_path, parent));

    const auto id_a{Arr32("555d3854c910b7dee436869c4724bed2fe0784e198b8a39f02bbb49d8ebcfc3a")};
    const auto id_b{Arr32("a137439f36d04a15474ff7423e4b904a14373fafb37a41db74c84f1dbb5c89b5")};

    // Private side: parent/idA/idB
    Path leaf_path{parent_path};
    leaf_path.push_back(PathElement::Normal256(id_a));
    leaf_path.push_back(PathElement::Normal256(id_b));
    ExtKey256 leaf;
    BOOST_REQUIRE(DeriveExtKey(Dip14Seed(), leaf_path, leaf));

    // Public side: neuter parent, then derive idA/idB
    ExtPubKey256 pub_parent{parent.key.GetPubKey(), parent.chaincode};
    ExtPubKey256 pub_mid, pub_leaf;
    BOOST_REQUIRE(DerivePubKey(pub_parent, PathElement::Normal256(id_a), pub_mid));
    BOOST_REQUIRE(DerivePubKey(pub_mid, PathElement::Normal256(id_b), pub_leaf));

    BOOST_CHECK(pub_leaf.pubkey == leaf.key.GetPubKey());
    BOOST_CHECK(pub_leaf.chaincode == leaf.chaincode);

    // Hardened steps must be rejected on the public side.
    ExtPubKey256 unused;
    BOOST_CHECK(!DerivePubKey(pub_parent, PathElement{id_a, true}, unused));
    BOOST_CHECK(!DerivePubKey(pub_parent, PathElement::Hardened(0), unused));

    // Invalid or uncompressed parents (contact xpubs are externally supplied)
    // must fail instead of tripping CPubKey::Derive() asserts.
    const ExtPubKey256 invalid_parent{CPubKey{}, parent.chaincode};
    BOOST_CHECK(!DerivePubKey(invalid_parent, PathElement::Normal(0), unused));
    CKey uncompressed_key;
    uncompressed_key.MakeNewKey(/*fCompressed=*/false);
    const ExtPubKey256 uncompressed_parent{uncompressed_key.GetPubKey(), parent.chaincode};
    BOOST_CHECK(!DerivePubKey(uncompressed_parent, PathElement::Normal(0), unused));
    BOOST_CHECK(!DerivePubKey(uncompressed_parent, PathElement::Normal256(id_a), unused));
}

//! ECDH secrets must be symmetric and match the libsecp256k1 KDF
//! (SHA256 of compressed shared point), as used by DashPay contact requests.
BOOST_AUTO_TEST_CASE(ecdh_symmetry)
{
    CKey a, b;
    a.MakeNewKey(/*fCompressed=*/true);
    b.MakeNewKey(/*fCompressed=*/true);

    SecureVector s_ab, s_ba;
    BOOST_REQUIRE(ComputeECDHSecret(a, b.GetPubKey(), s_ab));
    BOOST_REQUIRE(ComputeECDHSecret(b, a.GetPubKey(), s_ba));
    BOOST_CHECK_EQUAL(s_ab.size(), 32U);
    BOOST_CHECK(s_ab == s_ba);
}

//! HMAC-SHA256 keyed fingerprints must be stable (the wallet's
//! "platform/seed-id" record depends on it) and sensitive to the seed.
BOOST_AUTO_TEST_CASE(seed_fingerprint_vector)
{
    const auto fingerprint{SeedFingerprint(Dip14Seed())};
    BOOST_CHECK_EQUAL(HexStr(fingerprint), "2e42d1b4f12197d1");

    SecureVector tweaked{Dip14Seed()};
    tweaked[0] ^= 1;
    BOOST_CHECK(SeedFingerprint(tweaked) != fingerprint);
}

//! Mnemonic behind Dip14Seed() above.
static constexpr const char* DIP14_MNEMONIC{
    "birth kingdom trash renew flavor utility donkey gasp regular alert pave layer"};

//! Descriptor wallet with a BIP39 mnemonic, wrapped in the interfaces::Wallet
//! the platform key provider is served through. getPlatformSeed() only serves
//! descriptor wallets it can recover a mnemonic from, so
//! SetupDescriptorScriptPubKeyMans() is a prerequisite for every friendship
//! keychain call below.
struct FriendshipWalletSetup : public TestChain100Setup {
    explicit FriendshipWalletSetup(const SecureString& mnemonic = "")
    {
        m_context.args = &m_args;
        m_context.chain = m_node.chain.get();
        m_context.coinjoin_loader = m_node.coinjoin_loader.get();
        std::tie(m_wallet, m_iface) = MakeSeededWallet(mnemonic);
    }

    //! An independent wallet instance (own mock database) set up from the
    //! given mnemonic — a fresh restore of that recovery phrase.
    std::pair<std::shared_ptr<CWallet>, std::unique_ptr<interfaces::Wallet>>
    MakeSeededWallet(const SecureString& mnemonic)
    {
        auto wallet = std::make_shared<CWallet>(m_node.chain.get(), m_node.coinjoin_loader.get(), "", m_args,
                                                CreateMockWalletDatabase());
        wallet->LoadWallet();
        {
            LOCK(wallet->cs_wallet);
            wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
            wallet->SetupDescriptorScriptPubKeyMans(mnemonic, "");
        }
        auto iface = interfaces::MakeWallet(m_context, wallet);
        return {std::move(wallet), std::move(iface)};
    }

    static isminetype IsMineIn(CWallet& wallet, const CTxDestination& destination)
    {
        LOCK(wallet.cs_wallet);
        return wallet.IsMine(GetScriptForDestination(destination));
    }

    isminetype IsMine(const CTxDestination& destination) { return IsMineIn(*m_wallet, destination); }

    //! Payment address `index` of the friendship chain rooted at (user_a, user_b),
    //! taken through the same xpub export the contact would receive.
    static CTxDestination PaymentDestinationVia(interfaces::Wallet& iface, const uint256& user_a,
                                                const uint256& user_b, uint32_t index)
    {
        CPubKey xpub;
        uint256 chaincode;
        BOOST_REQUIRE(iface.getFriendshipXpub(ACCOUNT, user_a, user_b, xpub, chaincode));
        CTxDestination destination;
        BOOST_REQUIRE(iface.getFriendshipPaymentDestination(xpub, chaincode, index, destination));
        return destination;
    }

    CTxDestination PaymentDestination(const uint256& user_a, const uint256& user_b, uint32_t index)
    {
        return PaymentDestinationVia(*m_iface, user_a, user_b, index);
    }

    static constexpr uint32_t ACCOUNT{0};
    const uint256 m_my_id{uint256S("1111111111111111111111111111111111111111111111111111111111111111")};
    const uint256 m_their_id{uint256S("2222222222222222222222222222222222222222222222222222222222222222")};

    WalletContext m_context;
    std::shared_ptr<CWallet> m_wallet;
    std::unique_ptr<interfaces::Wallet> m_iface;
};

//! Our own receiving chain for a friendship is imported as a private
//! descriptor: its addresses must be spendable, not watch-only, and coins paid
//! to them must count towards the spendable balance.
BOOST_FIXTURE_TEST_CASE(friendship_own_chain_is_spendable, FriendshipWalletSetup)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(m_iface->importFriendshipKeychains(ACCOUNT, m_my_id, m_their_id, /*creation_time=*/0, "DashPay friend", error),
                          error);

    // Reaching the destination through getFriendshipXpub also pins that the
    // exported xpub the contact pays to derives the very addresses the import
    // made ours.
    for (uint32_t index = 0; index < 5; ++index) {
        BOOST_CHECK_EQUAL(IsMine(PaymentDestination(m_my_id, m_their_id, index)), ISMINE_SPENDABLE);
    }

    const CScript script{GetScriptForDestination(PaymentDestination(m_my_id, m_their_id, 0))};
    CMutableTransaction payment;
    payment.vin.emplace_back(g_insecure_rand_ctx.rand256(), 0);
    payment.vout.emplace_back(COIN, script);

    LOCK(m_wallet->cs_wallet);
    m_wallet->AddToWallet(MakeTransactionRef(payment), TxStateInMempool{});

    CCoinControl coin_control;
    coin_control.m_include_unsafe_inputs = true;
    BOOST_CHECK_EQUAL(AvailableCoins(*m_wallet, &coin_control).size(), 1U);
}

//! The contact's receiving chain must never become ours. If it did, payments to
//! the contact would be classified as payments-to-self and their outputs would
//! be counted as our own coins.
BOOST_FIXTURE_TEST_CASE(friendship_contact_chain_is_not_ours, FriendshipWalletSetup)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(m_iface->importFriendshipKeychains(ACCOUNT, m_my_id, m_their_id, /*creation_time=*/0, "DashPay friend", error),
                          error);

    // The contact's receiving chain for this friendship is the reversed id
    // pair; importing our own chain must not have pulled it in.
    for (uint32_t index = 0; index < 5; ++index) {
        BOOST_CHECK_EQUAL(IsMine(PaymentDestination(m_their_id, m_my_id, index)), ISMINE_NO);
    }

    // A real contact derives that chain from their own seed, which our wallet
    // never sees; those destinations must be foreign too.
    CExtKey contact_key;
    const std::array<std::byte, 32> contact_seed{std::byte{7}};
    contact_key.SetSeed(contact_seed);
    const CExtPubKey contact_xpub{contact_key.Neuter()};
    for (uint32_t index = 0; index < 5; ++index) {
        CTxDestination destination;
        BOOST_REQUIRE(m_iface->getFriendshipPaymentDestination(contact_xpub.pubkey, contact_xpub.chaincode, index,
                                                               destination));
        BOOST_CHECK_EQUAL(IsMine(destination), ISMINE_NO);
    }
}

struct Dip14WalletSetup : public FriendshipWalletSetup {
    Dip14WalletSetup() : FriendshipWalletSetup(SecureString{DIP14_MNEMONIC}) {}
};

//! With active spk_mans holding different mnemonics the platform seed choice
//! must be deterministic (lowest spk_man ID) and the wallet's
//! "platform/seed-id" record must override it, so a restored backup keeps
//! deriving the platform universe its records were created from.
BOOST_FIXTURE_TEST_CASE(platform_seed_selection_deterministic, Dip14WalletSetup)
{
    const auto dip14_fingerprint{SeedFingerprint(Dip14Seed())};
    auto seed_id{m_iface->getPlatformSeedId()};
    BOOST_REQUIRE(seed_id);
    BOOST_CHECK(*seed_id == dip14_fingerprint);

    // Make the wallet multi-seed: a second setup replaces the active
    // spk_mans, then one of the original ones is re-activated, leaving
    // actives backed by two different mnemonics.
    std::set<uint256> first_ids;
    {
        LOCK(m_wallet->cs_wallet);
        for (auto* spk_man : m_wallet->GetActiveScriptPubKeyMans()) first_ids.insert(spk_man->GetID());
        m_wallet->SetupDescriptorScriptPubKeyMans(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "");
        m_wallet->AddActiveScriptPubKeyMan(*first_ids.begin(), /*internal=*/true);
    }

    std::map<uint256, std::array<uint8_t, 8>> candidates;
    {
        LOCK(m_wallet->cs_wallet);
        for (auto* spk_man : m_wallet->GetActiveScriptPubKeyMans()) {
            auto* desc_spk_man{dynamic_cast<DescriptorScriptPubKeyMan*>(spk_man)};
            BOOST_REQUIRE(desc_spk_man);
            SecureString mnemonic, passphrase;
            BOOST_REQUIRE(desc_spk_man->GetMnemonicString(mnemonic, passphrase));
            SecureVector seed;
            CMnemonic::ToSeed(mnemonic, passphrase, seed);
            candidates.emplace(desc_spk_man->GetID(), SeedFingerprint(seed));
        }
    }
    BOOST_REQUIRE_EQUAL(candidates.size(), 2U);
    const auto& lowest_id_fingerprint{candidates.begin()->second};
    const auto& other_fingerprint{std::next(candidates.begin())->second};
    BOOST_REQUIRE(lowest_id_fingerprint != other_fingerprint);

    // Without a pinned record, the candidate from the lowest spk_man ID wins.
    seed_id = m_iface->getPlatformSeedId();
    BOOST_REQUIRE(seed_id);
    BOOST_CHECK(*seed_id == lowest_id_fingerprint);

    // A pinned record redirects the choice to the seed it fingerprints.
    BOOST_REQUIRE(m_iface->writePlatformData("platform/seed-id",
                                             {other_fingerprint.begin(), other_fingerprint.end()}));
    seed_id = m_iface->getPlatformSeedId();
    BOOST_REQUIRE(seed_id);
    BOOST_CHECK(*seed_id == other_fingerprint);

    // A pin that matches no active seed must fail seed selection entirely
    // rather than silently fall back to a different seed's platform universe.
    auto unmatched{other_fingerprint};
    unmatched[0] ^= 0xff;
    BOOST_REQUIRE(m_iface->writePlatformData("platform/seed-id", {unmatched.begin(), unmatched.end()}));
    BOOST_CHECK(!m_iface->getPlatformSeedId());

    // Erasing the pin restores the deterministic fallback.
    BOOST_REQUIRE(m_iface->writePlatformData("platform/seed-id", {}));
    seed_id = m_iface->getPlatformSeedId();
    BOOST_REQUIRE(seed_id);
    BOOST_CHECK(*seed_id == lowest_id_fingerprint);
}

//! Two independent wallet instances restored from the same recovery phrase:
//! the second is what a seed-only restore produces (fresh wallet database, no
//! platform records). Everything DashPay derives from the seed must come out
//! identical on both.
struct SeededWalletPair : public Dip14WalletSetup {
    SeededWalletPair() { std::tie(m_wallet_b, m_iface_b) = MakeSeededWallet(SecureString{DIP14_MNEMONIC}); }

    std::shared_ptr<CWallet> m_wallet_b;
    std::unique_ptr<interfaces::Wallet> m_iface_b;
};

//! Identity authentication and funding pubkeys must rederive byte-identical
//! after a seed-only restore, and must equal the raw DIP-13 derivation from
//! the known seed (pinning the interface to the vector-backed path math).
BOOST_FIXTURE_TEST_CASE(recovery_auth_key_rederivation, SeededWalletPair)
{
    using KeyType = interfaces::Wallet::PlatformKeyType;
    const auto coin_type{static_cast<uint32_t>(Params().ExtCoinType())};
    for (uint32_t identity = 0; identity < 2; ++identity) {
        for (uint32_t key = 0; key < 5; ++key) {
            CPubKey original, restored;
            BOOST_REQUIRE(m_iface->getPlatformPubKey(KeyType::IdentityAuth, identity, key, original));
            BOOST_REQUIRE(m_iface_b->getPlatformPubKey(KeyType::IdentityAuth, identity, key, restored));
            BOOST_CHECK(original == restored);

            ExtKey256 expected;
            BOOST_REQUIRE(DeriveExtKey(Dip14Seed(), IdentityAuthKeyPath(coin_type, identity, key), expected));
            BOOST_CHECK(original == expected.key.GetPubKey());
        }
    }

    CPubKey funding_original, funding_restored;
    BOOST_REQUIRE(m_iface->getPlatformPubKey(KeyType::RegistrationFunding, 0, 0, funding_original));
    BOOST_REQUIRE(m_iface_b->getPlatformPubKey(KeyType::RegistrationFunding, 0, 0, funding_restored));
    BOOST_CHECK(funding_original == funding_restored);
}

//! Compact signatures from signPlatformDigest must recover to the pubkey
//! getPlatformPubKey reports for the same key, on both wallet instances.
BOOST_FIXTURE_TEST_CASE(sign_platform_digest_recovers_to_pubkey, SeededWalletPair)
{
    using KeyType = interfaces::Wallet::PlatformKeyType;
    const uint256 digest{g_insecure_rand_ctx.rand256()};

    std::vector<unsigned char> sig_original, sig_restored;
    BOOST_REQUIRE(m_iface->signPlatformDigest(KeyType::IdentityAuth, 0, 0, digest, sig_original));
    BOOST_REQUIRE(m_iface_b->signPlatformDigest(KeyType::IdentityAuth, 0, 0, digest, sig_restored));

    CPubKey auth_key;
    BOOST_REQUIRE(m_iface->getPlatformPubKey(KeyType::IdentityAuth, 0, 0, auth_key));

    CPubKey recovered;
    BOOST_REQUIRE(recovered.RecoverCompact(digest, sig_original));
    BOOST_CHECK(recovered == auth_key);
    BOOST_REQUIRE(recovered.RecoverCompact(digest, sig_restored));
    BOOST_CHECK(recovered == auth_key);
}

//! Friendship xpubs and the payment destinations derived from them must
//! rederive identically after restore, and stay direction-sensitive.
BOOST_FIXTURE_TEST_CASE(recovery_friendship_xpub_rederivation, SeededWalletPair)
{
    CPubKey xpub_a, xpub_b;
    uint256 chaincode_a, chaincode_b;
    BOOST_REQUIRE(m_iface->getFriendshipXpub(ACCOUNT, m_my_id, m_their_id, xpub_a, chaincode_a));
    BOOST_REQUIRE(m_iface_b->getFriendshipXpub(ACCOUNT, m_my_id, m_their_id, xpub_b, chaincode_b));
    BOOST_CHECK(xpub_a == xpub_b);
    BOOST_CHECK(chaincode_a == chaincode_b);

    for (uint32_t index = 0; index < 10; ++index) {
        BOOST_CHECK(PaymentDestinationVia(*m_iface, m_my_id, m_their_id, index) ==
                    PaymentDestinationVia(*m_iface_b, m_my_id, m_their_id, index));
    }

    CPubKey xpub_reversed;
    uint256 chaincode_reversed;
    BOOST_REQUIRE(m_iface_b->getFriendshipXpub(ACCOUNT, m_their_id, m_my_id, xpub_reversed, chaincode_reversed));
    BOOST_CHECK(!(xpub_reversed == xpub_a));
}

//! The ECDH secret used to decrypt incoming contact-request xpubs must
//! survive a restore and agree with the contact's own side — the precondition
//! for recovering contact xpubs from on-chain requests after a seed restore.
BOOST_FIXTURE_TEST_CASE(recovery_ecdh_symmetry_across_restore, SeededWalletPair)
{
    CKey contact_key;
    contact_key.MakeNewKey(/*fCompressed=*/true);

    SecureVector secret_original, secret_restored;
    BOOST_REQUIRE(m_iface->platformECDHSecret(0, 0, contact_key.GetPubKey(), secret_original));
    BOOST_REQUIRE(m_iface_b->platformECDHSecret(0, 0, contact_key.GetPubKey(), secret_restored));
    BOOST_CHECK(secret_original == secret_restored);

    CPubKey our_auth_key;
    BOOST_REQUIRE(m_iface->getPlatformPubKey(interfaces::Wallet::PlatformKeyType::IdentityAuth, 0, 0, our_auth_key));
    SecureVector secret_contact_side;
    BOOST_REQUIRE(ComputeECDHSecret(contact_key, our_auth_key, secret_contact_side));
    BOOST_CHECK(secret_contact_side == secret_original);
}

//! A payment received before the loss must become spendable again once the
//! restored wallet re-imports the friendship keychain: the recovery contract
//! for DIP-15 funds.
BOOST_FIXTURE_TEST_CASE(recovery_import_after_restore_is_spendable, SeededWalletPair)
{
    // The payment targets the xpub the contact holds — exported by wallet A
    // before the loss.
    const CScript script{GetScriptForDestination(PaymentDestinationVia(*m_iface, m_my_id, m_their_id, 0))};
    CMutableTransaction payment;
    payment.vin.emplace_back(g_insecure_rand_ctx.rand256(), 0);
    payment.vout.emplace_back(COIN, script);

    // Restored wallet B: not ours until the friendship keychain is back.
    BOOST_CHECK_EQUAL(IsMineIn(*m_wallet_b, PaymentDestinationVia(*m_iface_b, m_my_id, m_their_id, 0)), ISMINE_NO);

    std::string error;
    BOOST_REQUIRE_MESSAGE(m_iface_b->importFriendshipKeychains(ACCOUNT, m_my_id, m_their_id,
                                                               /*creation_time=*/0, "DashPay friend", error),
                          error);

    LOCK(m_wallet_b->cs_wallet);
    m_wallet_b->AddToWallet(MakeTransactionRef(payment), TxStateInMempool{});

    CCoinControl coin_control;
    coin_control.m_include_unsafe_inputs = true;
    BOOST_CHECK_EQUAL(AvailableCoins(*m_wallet_b, &coin_control).size(), 1U);
}

//! Recovery re-runs re-import friendships it already imported; that must
//! update in place rather than duplicate spk_mans or change ownership.
BOOST_FIXTURE_TEST_CASE(recovery_import_idempotent, SeededWalletPair)
{
    std::string error;
    BOOST_REQUIRE_MESSAGE(m_iface->importFriendshipKeychains(ACCOUNT, m_my_id, m_their_id,
                                                             /*creation_time=*/0, "DashPay friend", error),
                          error);
    size_t spk_mans_after_first;
    {
        LOCK(m_wallet->cs_wallet);
        spk_mans_after_first = m_wallet->GetAllScriptPubKeyMans().size();
    }

    BOOST_REQUIRE_MESSAGE(m_iface->importFriendshipKeychains(ACCOUNT, m_my_id, m_their_id,
                                                             /*creation_time=*/1'600'000'000, "DashPay friend",
                                                             error),
                          error);
    {
        LOCK(m_wallet->cs_wallet);
        BOOST_CHECK_EQUAL(m_wallet->GetAllScriptPubKeyMans().size(), spk_mans_after_first);
    }
    for (uint32_t index = 0; index < 5; ++index) {
        BOOST_CHECK_EQUAL(IsMine(PaymentDestination(m_my_id, m_their_id, index)), ISMINE_SPENDABLE);
    }
}

BOOST_AUTO_TEST_SUITE_END()
