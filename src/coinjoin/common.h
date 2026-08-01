// Copyright (c) 2014-2024 The Dash Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINJOIN_COMMON_H
#define BITCOIN_COINJOIN_COMMON_H

#include <util/helpers.h>

#include <consensus/amount.h>
#include <primitives/transaction.h>

#include <array>
#include <cstdint>
#include <string>

/** Holds a mixing input
 */
class CTxDSIn : public CTxIn
{
public:
    // memory only
    CScript prevPubKey;
    bool fHasSig{false}; // flag to indicate if signed
    int nRounds{-10};

    CTxDSIn(const CTxIn& txin, CScript script, int nRounds) :
        CTxIn(txin),
        prevPubKey(std::move(script)),
        nRounds(nRounds)
    {
    }

    CTxDSIn() = default;
};

namespace CoinJoin
{

constexpr std::array<CAmount, 5> vecStandardDenominations{
        (10 * COIN) + 10000,
        (1 * COIN) + 1000,
        (COIN / 10) + 100,
        (COIN / 100) + 10,
        (COIN / 1000) + 1,
};

constexpr std::array<CAmount, 5> GetStandardDenominations() { return vecStandardDenominations; }
constexpr CAmount GetSmallestDenomination() { return vecStandardDenominations.back(); }

/**
 * Get the index of a denomination in vecStandardDenominations (0=largest, 4=smallest)
 * Returns -1 if not a valid denomination
 */
constexpr int GetDenominationIndex(int nDenom)
{
    if (nDenom <= 0) return -1;
    for (size_t i = 0; i < vecStandardDenominations.size(); ++i) {
        if (nDenom == (1 << i)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

/*
    Return a bitshifted integer representing a denomination in vecStandardDenominations
    or 0 if none was found
*/
constexpr int AmountToDenomination(CAmount nInputAmount)
{
    for (size_t i = 0; i < vecStandardDenominations.size(); ++i) {
        if (nInputAmount == vecStandardDenominations[i]) {
            return 1 << i;
        }
    }
    return 0;
}

/*
    Returns:
    - one of standard denominations from vecStandardDenominations based on the provided bitshifted integer
    - 0 for non-initialized sessions (nDenom = 0)
    - a value below 0 if an error occurred while converting from one to another
*/
constexpr CAmount DenominationToAmount(int nDenom)
{
    if (nDenom == 0) {
        // not initialized
        return 0;
    }

    if (nDenom >= (1 << vecStandardDenominations.size()) || nDenom < 0) {
        // out of bounds
        return -1;
    }

    if ((nDenom & (nDenom - 1)) != 0) {
        // non-denom
        return -2;
    }

    const int idx = GetDenominationIndex(nDenom);
    return idx >= 0 ? vecStandardDenominations[idx] : -3;
}


constexpr bool IsDenominatedAmount(CAmount nInputAmount) { return AmountToDenomination(nInputAmount) > 0; }
constexpr bool IsValidDenomination(int nDenom) { return DenominationToAmount(nDenom) > 0; }

/*
Same as DenominationToAmount but returns a string representation
*/
std::string DenominationToString(int nDenom);

constexpr CAmount GetCollateralAmount() { return GetSmallestDenomination() / 10; }
constexpr CAmount GetMaxCollateralAmount() { return GetCollateralAmount() * 4; }

// Promotion/demotion constants (post-V24 feature)
constexpr int PROMOTION_RATIO = 10;   // 10 smaller denomination coins = 1 larger denomination coin
constexpr int GAP_THRESHOLD = 10;     // Deficit gap required to trigger promotion/demotion

/**
 * Which side(s) of the session denomination a participant occupies. A standard entry mixes at
 * the session denomination on both sides. A promotion spends PROMOTION_RATIO session-denom
 * inputs for one larger-denom output, so it only occupies the input side; a demotion is the
 * mirror image. UNKNOWN is for empty or malformed entries, which occupy neither.
 */
enum class MixShape : uint8_t { UNKNOWN, STANDARD, PROMOTION, DEMOTION };

/**
 * How many participants occupy each side of the session denomination.
 *
 * Mixing only conceals a participant when someone else holds coins of the same size on the
 * same side: a group of session-denom coins is hidden by the other session-denom coins it
 * could be confused with. A participant holding a single coin at the larger denomination has
 * no group to hide, which is why only the session denomination is counted here.
 */
struct MixSideCounts {
    int inputs{0};  //!< participants contributing session-denom inputs (standard + promotions)
    int outputs{0}; //!< participants receiving session-denom outputs (standard + demotions)

    constexpr void Add(MixShape shape)
    {
        switch (shape) {
        case MixShape::STANDARD:
            ++inputs;
            ++outputs;
            break;
        case MixShape::PROMOTION:
            ++inputs;
            break;
        case MixShape::DEMOTION:
            ++outputs;
            break;
        case MixShape::UNKNOWN:
            break;
        }
    }

    /**
     * Each side must be occupied by nobody or by at least two participants. Exactly one is the
     * only forbidden count: that participant's session-denom coins would be the only ones of
     * their size on that side and so would be trivially identifiable on-chain.
     */
    [[nodiscard]] constexpr bool IsCovered() const { return inputs != 1 && outputs != 1; }
};

/// How many coins of a final transaction sit at the session denomination on each side
struct SessionDenomCounts {
    size_t inputs{0};
    size_t outputs{0};
};

/**
 * Check if two denominations are adjacent (one step apart in the denom list)
 * Used for validating promotion/demotion entries post-V24
 */
constexpr bool AreAdjacentDenominations(int nDenom1, int nDenom2)
{
    int idx1 = GetDenominationIndex(nDenom1);
    int idx2 = GetDenominationIndex(nDenom2);
    if (idx1 < 0 || idx2 < 0) return false;
    return (idx1 == idx2 + 1) || (idx1 == idx2 - 1);
}

/**
 * Get the larger adjacent denomination (returns 0 if none exists or invalid)
 */
constexpr int GetLargerAdjacentDenom(int nDenom)
{
    int idx = GetDenominationIndex(nDenom);
    if (idx <= 0) return 0;  // Already largest or invalid
    return 1 << (idx - 1);
}

/**
 * Get the smaller adjacent denomination (returns 0 if none exists or invalid)
 */
constexpr int GetSmallerAdjacentDenom(int nDenom)
{
    int idx = GetDenominationIndex(nDenom);
    if (idx < 0 || idx >= static_cast<int>(vecStandardDenominations.size()) - 1) return 0;
    return 1 << (idx + 1);
}

/**
 * Core promotion decision (post-V24): combine PROMOTION_RATIO fully-mixed coins of the
 * smaller denomination into one coin of the larger adjacent denomination when the larger
 * denomination is further from the per-denom goal by more than GAP_THRESHOLD (the gap
 * prevents promote/demote oscillation). Callers resolve wallet counts and validate that
 * the denominations are adjacent.
 */
constexpr bool ShouldPromoteDenoms(int nSmallerCount, int nLargerCount, int nSmallerFullyMixedCount, int nGoal)
{
    // Don't sacrifice a denomination that's still being built up
    if (nSmallerCount < nGoal / 2) return false;
    // A promotion consumes PROMOTION_RATIO fully-mixed coins
    if (nSmallerFullyMixedCount < PROMOTION_RATIO) return false;
    const int nSmallerDeficit = nSmallerCount < nGoal ? nGoal - nSmallerCount : 0;
    const int nLargerDeficit = nLargerCount < nGoal ? nGoal - nLargerCount : 0;
    return nLargerDeficit > nSmallerDeficit + GAP_THRESHOLD;
}

/**
 * Core demotion decision (post-V24): split one coin of the larger denomination into
 * PROMOTION_RATIO coins of the smaller adjacent denomination when the smaller denomination
 * is further from the per-denom goal by more than GAP_THRESHOLD.
 */
constexpr bool ShouldDemoteDenoms(int nLargerCount, int nSmallerCount, int nGoal)
{
    // Don't sacrifice a denomination that's still being built up
    if (nLargerCount < nGoal / 2) return false;
    const int nSmallerDeficit = nSmallerCount < nGoal ? nGoal - nSmallerCount : 0;
    const int nLargerDeficit = nLargerCount < nGoal ? nGoal - nLargerCount : 0;
    return nSmallerDeficit > nLargerDeficit + GAP_THRESHOLD;
}

constexpr bool IsCollateralAmount(CAmount nInputAmount)
{
    // collateral input can be anything between 1x and "max" (including both)
    return (nInputAmount >= GetCollateralAmount() && nInputAmount <= GetMaxCollateralAmount());
}

constexpr int CalculateAmountPriority(CAmount nInputAmount)
{
    if (nInputAmount < 0 || nInputAmount > MAX_MONEY) return 0;
    if (auto optDenom = util::find_if_opt(GetStandardDenominations(),
                                          [&nInputAmount](const auto& denom) { return nInputAmount == denom; })) {
        return static_cast<float>(COIN) / *optDenom * 10000;
    }
    if (nInputAmount < COIN) {
        return 20000;
    }

    //nondenom return largest first
    return -1 * (nInputAmount / COIN);
}

} // namespace CoinJoin

#endif // BITCOIN_COINJOIN_COMMON_H
