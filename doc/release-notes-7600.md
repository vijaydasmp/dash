RPC changes
-----------

- Normal and Evo `protx` registration and maintenance commands now share a
  typed provider-transaction implementation with other wallet frontends. RPC
  names and successful result formats are unchanged.
  `protx update_service` on a masternode whose state does not yield a usable
  default fee source now returns an explicit "specify feeSourceAddress"
  parameter error instead of an internal error. (#7600)
