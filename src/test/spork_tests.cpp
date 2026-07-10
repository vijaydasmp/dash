// Copyright (c) 2026 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pubkey.h>
#include <serialize.h>
#include <spork.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(spork_tests, BasicTestingSetup)

namespace {
// Build a CSporkMessage wire encoding by hand: 4-byte SporkId, 8-byte value,
// 8-byte timestamp, then a CompactSize-prefixed signature vector.
CDataStream MakeSporkStream(int32_t sporkId, int64_t nValue, int64_t nTimeSigned,
                            uint64_t sig_compact_size, size_t sig_bytes_to_write)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << sporkId << nValue << nTimeSigned;
    WriteCompactSize(ss, sig_compact_size);
    for (size_t i = 0; i < sig_bytes_to_write; ++i) {
        ss << static_cast<uint8_t>(0xab);
    }
    return ss;
}

// Distinguishes the pre-allocation size-gate throw from a downstream stream underflow.
bool IsLimitExceededFailure(const std::ios_base::failure& e)
{
    return std::string_view{e.what()}.find("Vector length limit exceeded") != std::string_view::npos;
}
} // namespace

// The vulnerability report's exact trigger: a canonical CompactSize(MAX_SIZE)
// with no signature bytes. On the vulnerable implementation this reaches the
// stock vector Unserialize path, which resizes the destination in chunks
// (allocating before it discovers there is no data) and then throws a generic
// stream underflow. On the fix, LimitedVectorFormatter rejects the count
// before any allocation via ios_base::failure.
BOOST_AUTO_TEST_CASE(spork_signature_max_size_rejected_before_allocation)
{
    CDataStream ss = MakeSporkStream(/*sporkId=*/10001, 0, 0,
                                     /*sig_compact_size=*/MAX_SIZE,
                                     /*sig_bytes_to_write=*/0);
    CSporkMessage spork;
    BOOST_CHECK_EXCEPTION(ss >> spork, std::ios_base::failure, IsLimitExceededFailure);
}

// A +1 boundary with a full payload — the bound must short-circuit before
// element decoding even when every promised byte is on the wire.
BOOST_AUTO_TEST_CASE(spork_signature_oversized_rejected)
{
    CDataStream ss = MakeSporkStream(/*sporkId=*/10001, 0, 0,
                                     /*sig_compact_size=*/CPubKey::COMPACT_SIGNATURE_SIZE + 1,
                                     /*sig_bytes_to_write=*/CPubKey::COMPACT_SIGNATURE_SIZE + 1);
    CSporkMessage spork;
    BOOST_CHECK_EXCEPTION(ss >> spork, std::ios_base::failure, IsLimitExceededFailure);
}

// A valid 65-byte signature vector round-trips through serialize/unserialize
// with the wire bytes unchanged — the fix must not have moved the wire format
// for legit messages.
BOOST_AUTO_TEST_CASE(spork_signature_exact_size_roundtrip)
{
    CDataStream ss = MakeSporkStream(/*sporkId=*/10001, /*nValue=*/123456789,
                                     /*nTimeSigned=*/1'700'000'000,
                                     /*sig_compact_size=*/CPubKey::COMPACT_SIGNATURE_SIZE,
                                     /*sig_bytes_to_write=*/CPubKey::COMPACT_SIGNATURE_SIZE);
    const std::vector<std::byte> wire(ss.begin(), ss.end());

    CSporkMessage decoded;
    BOOST_REQUIRE_NO_THROW(ss >> decoded);
    BOOST_CHECK_EQUAL(ss.size(), 0U);
    BOOST_CHECK_EQUAL(decoded.nSporkID, static_cast<SporkId>(10001));
    BOOST_CHECK_EQUAL(decoded.nValue, 123456789);
    BOOST_CHECK_EQUAL(decoded.nTimeSigned, 1'700'000'000);

    CDataStream re(SER_NETWORK, PROTOCOL_VERSION);
    re << decoded;
    BOOST_REQUIRE_EQUAL(re.size(), wire.size());
    BOOST_CHECK(std::equal(re.begin(), re.end(), wire.begin()));
}

BOOST_AUTO_TEST_SUITE_END()
