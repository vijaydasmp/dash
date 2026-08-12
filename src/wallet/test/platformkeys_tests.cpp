// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <wallet/platformkeys.h>

#include <boost/test/unit_test.hpp>

#include <array>
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

BOOST_AUTO_TEST_SUITE_END()
