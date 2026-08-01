P2P and network changes
-----------------------

- The protocol version was bumped to 70241. Mixing sessions that may
  contain promotion/demotion entries are only formed by, and only admit,
  peers at protocol 70241 or newer: the `dsa` message gained a
  version-gated flags field declaring which mixing direction a
  participant intends, and the session creator's protocol version fixes
  the session's capability. Older clients are rejected from such sessions
  at acceptance time (before any collateral is committed) and continue to
  mix normally in sessions created by older peers, which newer clients
  still join for standard mixing. Unbalanced (promotion/demotion) DSTXes
  are likewise only announced to peers at protocol 70241 or newer; older
  peers would reject them as structurally invalid and penalize the
  relayer, and instead see the transaction on block inclusion. (#7052)

- A mixing session only completes once each side of its denomination is
  occupied by nobody or by at least two participants, since coins are
  only concealed by other coins of the same size on the same side. A
  session that attracts a lone promotion or demotion participant and no
  counterpart therefore waits, and expires in the queue stage without
  charging anyone's collateral, rather than publishing a transaction that
  would identify that participant's coins. Because admission relies on
  the declared directions, a participant whose entry deviates from what
  it declared has its collateral consumed. (#7052)

Wallet
------

- CoinJoin can now promote and demote between adjacent standard
  denominations within a mixing session after V24 activation.
  Promotion combines 10 inputs of one denomination into 1 output of the
  next larger denomination, while demotion splits 1 input into 10
  outputs of the next smaller denomination. Pre-V24 behavior remains
  unchanged. (#7052)
