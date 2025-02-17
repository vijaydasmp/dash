// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2014-2025 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#include <net.h>
#include <netmessagemaker.h>

#include <addrdb.h>
#include <addrman.h>
#include <banman.h>
#include <clientversion.h>
#include <compat/compat.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#include <node/eviction.h>
#include <fs.h>
#include <i2p.h>
#include <memusage.h>
#include <net_permissions.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/interface_ui.h>
#include <protocol.h>
#include <random.h>
#include <scheduler.h>
#include <util/sock.h>
#include <util/strencodings.h>
#include <util/system.h>
#include <util/thread.h>
#include <util/time.h>
#include <util/trace.h>
#include <util/translation.h>
#include <util/vector.h>
#include <util/wpipe.h>

#include <masternode/meta.h>
#include <masternode/sync.h>
#include <coinjoin/coinjoin.h>
#include <evo/deterministicmns.h>

#include <stats/client.h>

#ifdef WIN32
#include <string.h>
#else
#include <fcntl.h>
#endif

#if HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS
#include <ifaddrs.h>
#endif

#ifdef USE_POLL
#include <poll.h>
#endif

#ifdef USE_EPOLL
#include <sys/epoll.h>
#endif

#ifdef USE_KQUEUE
#include <sys/event.h>
#endif

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <unordered_map>

#include <math.h>

/** Maximum number of block-relay-only anchor connections */
static constexpr size_t MAX_BLOCK_RELAY_ONLY_ANCHORS = 2;
static_assert (MAX_BLOCK_RELAY_ONLY_ANCHORS <= static_cast<size_t>(MAX_BLOCK_RELAY_ONLY_CONNECTIONS), "MAX_BLOCK_RELAY_ONLY_ANCHORS must not exceed MAX_BLOCK_RELAY_ONLY_CONNECTIONS.");
/** Anchor IP address database file name */
const char* const ANCHORS_DATABASE_FILENAME = "anchors.dat";

// How often to dump addresses to peers.dat
static constexpr std::chrono::minutes DUMP_PEERS_INTERVAL{15};

/** Number of DNS seeds to query when the number of connections is low. */
static constexpr int DNSSEEDS_TO_QUERY_AT_ONCE = 3;

/** How long to delay before querying DNS seeds
 *
 * If we have more than THRESHOLD entries in addrman, then it's likely
 * that we got those addresses from having previously connected to the P2P
 * network, and that we'll be able to successfully reconnect to the P2P
 * network via contacting one of them. So if that's the case, spend a
 * little longer trying to connect to known peers before querying the
 * DNS seeds.
 */
static constexpr std::chrono::seconds DNSSEEDS_DELAY_FEW_PEERS{11};
static constexpr std::chrono::minutes DNSSEEDS_DELAY_MANY_PEERS{5};
static constexpr int DNSSEEDS_DELAY_PEER_THRESHOLD = 1000; // "many" vs "few" peers

/** The default timeframe for -maxuploadtarget. 1 day. */
static constexpr std::chrono::seconds MAX_UPLOAD_TIMEFRAME{60 * 60 * 24};

// A random time period (0 to 1 seconds) is added to feeler connections to prevent synchronization.
static constexpr auto FEELER_SLEEP_WINDOW{1s};

/** Frequency to attempt extra connections to reachable networks we're not connected to yet **/
static constexpr auto EXTRA_NETWORK_PEER_INTERVAL{5min};

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE         = 0,
    BF_REPORT_ERROR = (1U << 0),
    /**
     * Do not call AddLocal() for our special addresses, e.g., for incoming
     * Tor connections, to prevent gossiping them over the network.
     */
    BF_DONT_ADVERTISE = (1U << 1),
};

#ifndef USE_WAKEUP_PIPE
// The set of sockets cannot be modified while waiting
// The sleep time needs to be small to avoid new sockets stalling
static const uint64_t SELECT_TIMEOUT_MILLISECONDS = 50;
#else
// select() is woken up through the wakeup pipe whenever a new node is added, so we can wait much longer.
// We are however still somewhat limited in how long we can sleep as there is periodic work (cleanup) to be done in
// the socket handler thread
static const uint64_t SELECT_TIMEOUT_MILLISECONDS = 500;
#endif /* USE_WAKEUP_PIPE */

const std::string NET_MESSAGE_TYPE_OTHER = "*other*";

constexpr const CConnman::CFullyConnectedOnly CConnman::FullyConnectedOnly;
constexpr const CConnman::CAllNodes CConnman::AllNodes;

static const uint64_t RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036ULL; // SHA256("netgroup")[0:8]
static const uint64_t RANDOMIZER_ID_LOCALHOSTNONCE = 0xd93e69e2bbfa5735ULL; // SHA256("localhostnonce")[0:8]
static const uint64_t RANDOMIZER_ID_ADDRCACHE = 0x1cf2e4ddd306dda9ULL; // SHA256("addrcache")[0:8]
//
// Global state variables
//
bool fDiscover = true;
bool fListen = true;
Mutex g_maplocalhost_mutex;
std::map<CNetAddr, LocalServiceInfo> mapLocalHost GUARDED_BY(g_maplocalhost_mutex);
static bool vfLimited[NET_MAX] GUARDED_BY(g_maplocalhost_mutex) = {};
std::string strSubVersion;

size_t CSerializedNetMsg::GetMemoryUsage() const noexcept
{
    // Don't count the dynamic memory used for the m_type string, by assuming it fits in the
    // "small string" optimization area (which stores data inside the object itself, up to some
    // size; 15 bytes in modern libstdc++).
    return sizeof(*this) + memusage::DynamicUsage(data);
}

void CConnman::AddAddrFetch(const std::string& strDest)
{
    LOCK(m_addr_fetches_mutex);
    m_addr_fetches.push_back(strDest);
}

uint16_t GetListenPort()
{
    // If -bind= is provided with ":port" part, use that (first one if multiple are provided).
    for (const std::string& bind_arg : gArgs.GetArgs("-bind")) {
        constexpr uint16_t dummy_port = 0;

        const std::optional<CService> bind_addr{Lookup(bind_arg, dummy_port, /*fAllowLookup=*/false)};
        if (bind_addr.has_value() && bind_addr->GetPort() != dummy_port) return bind_addr->GetPort();
    }

    // Otherwise, if -whitebind= without NetPermissionFlags::NoBan is provided, use that
    // (-whitebind= is required to have ":port").
    for (const std::string& whitebind_arg : gArgs.GetArgs("-whitebind")) {
        NetWhitebindPermissions whitebind;
        bilingual_str error;
        if (NetWhitebindPermissions::TryParse(whitebind_arg, whitebind, error)) {
            if (!NetPermissions::HasFlag(whitebind.m_flags, NetPermissionFlags::NoBan)) {
                return whitebind.m_service.GetPort();
            }
        }
    }

    // Otherwise, if -port= is provided, use that. Otherwise use the default port.
    return static_cast<uint16_t>(gArgs.GetArg("-port", Params().GetDefaultPort()));
}

// find 'best' local address for a particular peer
bool GetLocal(CService& addr, const CNode& peer)
{
    if (!fListen)
        return false;

    int nBestScore = -1;
    int nBestReachability = -1;
    {
        LOCK(g_maplocalhost_mutex);
        for (const auto& entry : mapLocalHost)
        {
            // For privacy reasons, don't advertise our privacy-network address
            // to other networks and don't advertise our other-network address
            // to privacy networks.
            const Network our_net{entry.first.GetNetwork()};
            const Network peers_net{peer.ConnectedThroughNetwork()};
            if (our_net != peers_net &&
                (our_net == NET_ONION || our_net == NET_I2P ||
                 peers_net == NET_ONION || peers_net == NET_I2P)) {
                continue;
            }
            int nScore = entry.second.nScore;
            int nReachability = entry.first.GetReachabilityFrom(peer.addr);
            if (nReachability > nBestReachability || (nReachability == nBestReachability && nScore > nBestScore))
            {
                addr = CService(entry.first, entry.second.nPort);
                nBestReachability = nReachability;
                nBestScore = nScore;
            }
        }
    }
    return nBestScore >= 0;
}

//! Convert the serialized seeds into usable address objects.
static std::vector<CAddress> ConvertSeeds(const std::vector<uint8_t> &vSeedsIn)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const auto one_week{7 * 24h};
    std::vector<CAddress> vSeedsOut;
    FastRandomContext rng;
    CDataStream s(vSeedsIn, SER_NETWORK, PROTOCOL_VERSION | ADDRV2_FORMAT);
    while (!s.eof()) {
        CService endpoint;
        s >> endpoint;
        CAddress addr{endpoint, GetDesirableServiceFlags(NODE_NONE)};
        addr.nTime = rng.rand_uniform_delay(Now<NodeSeconds>() - one_week, -one_week);
        LogPrint(BCLog::NET, "Added hardcoded seed: %s\n", addr.ToStringAddrPort());
        vSeedsOut.push_back(addr);
    }
    return vSeedsOut;
}

// get best local address for a particular peer as a CAddress
// Otherwise, return the unroutable 0.0.0.0 but filled in with
// the normal parameters, since the IP may be changed to a useful
// one by discovery.
CService GetLocalAddress(const CNode& peer)
{
    CService addr;
    if (GetLocal(addr, peer)) {
        return addr;
    }
    return CService{CNetAddr(), GetListenPort()};
}

static int GetnScore(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    const auto it = mapLocalHost.find(addr);
    return (it != mapLocalHost.end()) ? it->second.nScore : 0;
}

// Is our peer's addrLocal potentially useful as an external IP source?
bool IsPeerAddrLocalGood(CNode *pnode)
{
    CService addrLocal = pnode->GetAddrLocal();
    return fDiscover && pnode->addr.IsRoutable() && addrLocal.IsRoutable() &&
           IsReachable(addrLocal.GetNetwork());
}

std::optional<CService> GetLocalAddrForPeer(CNode& node)
{
    CService addrLocal{GetLocalAddress(node)};
    // If discovery is enabled, sometimes give our peer the address it
    // tells us that it sees us as in case it has a better idea of our
    // address than we do.
    FastRandomContext rng;
    if (IsPeerAddrLocalGood(&node) && (!addrLocal.IsRoutable() ||
         rng.randbits((GetnScore(addrLocal) > LOCAL_MANUAL) ? 3 : 1) == 0))
    {
        if (node.IsInboundConn()) {
            // For inbound connections, assume both the address and the port
            // as seen from the peer.
            addrLocal = CService{node.GetAddrLocal()};
        } else {
            // For outbound connections, assume just the address as seen from
            // the peer and leave the port in `addrLocal` as returned by
            // `GetLocalAddress()` above. The peer has no way to observe our
            // listening port when we have initiated the connection.
            addrLocal.SetIP(node.GetAddrLocal());
        }
    }
    if (addrLocal.IsRoutable())
    {
        LogPrint(BCLog::NET, "Advertising address %s to peer=%d\n", addrLocal.ToStringAddrPort(), node.GetId());
        return addrLocal;
    }
    // Address is unroutable. Don't advertise.
    return std::nullopt;
}

/**
 * If an IPv6 address belongs to the address range used by the CJDNS network and
 * the CJDNS network is reachable (-cjdnsreachable config is set), then change
 * the type from NET_IPV6 to NET_CJDNS.
 * @param[in] service Address to potentially convert.
 * @return a copy of `service` either unmodified or changed to CJDNS.
 */
CService MaybeFlipIPv6toCJDNS(const CService& service)
{
    CService ret{service};
    if (ret.m_net == NET_IPV6 && ret.m_addr[0] == 0xfc && IsReachable(NET_CJDNS)) {
        ret.m_net = NET_CJDNS;
    }
    return ret;
}

// learn a new local address
bool AddLocal(const CService& addr_, int nScore)
{
    CService addr{MaybeFlipIPv6toCJDNS(addr_)};

    if (!addr.IsRoutable() && Params().RequireRoutableExternalIP())
        return false;

    if (!fDiscover && nScore < LOCAL_MANUAL)
        return false;

    if (!IsReachable(addr))
        return false;

    LogPrintf("AddLocal(%s,%i)\n", addr.ToStringAddrPort(), nScore);

    {
        LOCK(g_maplocalhost_mutex);
        const auto [it, is_newly_added] = mapLocalHost.emplace(addr, LocalServiceInfo());
        LocalServiceInfo &info = it->second;
        if (is_newly_added || nScore >= info.nScore) {
            info.nScore = nScore + (is_newly_added ? 0 : 1);
            info.nPort = addr.GetPort();
        }
    }

    return true;
}

bool AddLocal(const CNetAddr &addr, int nScore)
{
    return AddLocal(CService(addr, GetListenPort()), nScore);
}

void RemoveLocal(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    LogPrintf("RemoveLocal(%s)\n", addr.ToStringAddrPort());
    mapLocalHost.erase(addr);
}

void SetReachable(enum Network net, bool reachable)
{
    if (net == NET_UNROUTABLE || net == NET_INTERNAL)
        return;
    LOCK(g_maplocalhost_mutex);
    vfLimited[net] = !reachable;
}

bool IsReachable(enum Network net)
{
    LOCK(g_maplocalhost_mutex);
    return !vfLimited[net];
}

bool IsReachable(const CNetAddr &addr)
{
    return IsReachable(addr.GetNetwork());
}

/** vote for a local address */
bool SeenLocal(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    const auto it = mapLocalHost.find(addr);
    if (it == mapLocalHost.end()) return false;
    ++it->second.nScore;
    return true;
}


/** check whether a given address is potentially local */
bool IsLocal(const CService& addr)
{
    LOCK(g_maplocalhost_mutex);
    return mapLocalHost.count(addr) > 0;
}

CNode* CConnman::FindNode(const CNetAddr& ip, bool fExcludeDisconnecting)
{
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (fExcludeDisconnecting && pnode->fDisconnect) {
            continue;
        }
        if (static_cast<CNetAddr>(pnode->addr) == ip) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const CSubNet& subNet, bool fExcludeDisconnecting)
{
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (fExcludeDisconnecting && pnode->fDisconnect) {
            continue;
        }
        if (subNet.Match(static_cast<CNetAddr>(pnode->addr))) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const std::string& addrName, bool fExcludeDisconnecting)
{
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (fExcludeDisconnecting && pnode->fDisconnect) {
            continue;
        }
        if (pnode->m_addr_name == addrName) {
            return pnode;
        }
    }
    return nullptr;
}

CNode* CConnman::FindNode(const CService& addr, bool fExcludeDisconnecting)
{
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (fExcludeDisconnecting && pnode->fDisconnect) {
            continue;
        }
        if (static_cast<CService>(pnode->addr) == addr) {
            return pnode;
        }
    }
    return nullptr;
}

bool CConnman::AlreadyConnectedToAddress(const CAddress& addr)
{
    return FindNode(addr.ToStringAddrPort());
}

bool CConnman::CheckIncomingNonce(uint64_t nonce)
{
    LOCK(m_nodes_mutex);
    for (const CNode* pnode : m_nodes) {
        if (!pnode->fSuccessfullyConnected && !pnode->IsInboundConn() && pnode->GetLocalNonce() == nonce)
            return false;
    }
    return true;
}

/** Get the bind address for a socket as CAddress */
static CAddress GetBindAddress(const Sock& sock)
{
    CAddress addr_bind;
    struct sockaddr_storage sockaddr_bind;
    socklen_t sockaddr_bind_len = sizeof(sockaddr_bind);
    if (sock.Get() != INVALID_SOCKET) {
        if (!sock.GetSockName((struct sockaddr*)&sockaddr_bind, &sockaddr_bind_len)) {
            addr_bind.SetSockAddr((const struct sockaddr*)&sockaddr_bind);
        } else {
            LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "getsockname failed\n");
        }
    }
    return addr_bind;
}

CNode* CConnman::ConnectNode(CAddress addrConnect, const char *pszDest, bool fCountFailure, ConnectionType conn_type, bool use_v2transport)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    assert(conn_type != ConnectionType::INBOUND);

    if (pszDest == nullptr) {
        if (addrConnect.GetPort() == GetListenPort() && IsLocal(addrConnect)) {
            return nullptr;
        }

        // Look for an existing connection
        CNode* pnode = FindNode(static_cast<CService>(addrConnect));
        if (pnode)
        {
            LogPrintf("Failed to open new connection, already connected\n");
            return nullptr;
        }
    }

    /// debug print
    if (fLogIPs) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "trying %s connection %s lastseen=%.1fhrs\n",
                      use_v2transport ? "v2" : "v1",
                      pszDest ? pszDest : addrConnect.ToStringAddrPort(),
                      Ticks<HoursDouble>(pszDest ? 0h : Now<NodeSeconds>() - addrConnect.nTime));
    } else {
        LogPrintLevel(BCLog::NET, BCLog::Level::Debug, "trying %s connection lastseen=%.1fhrs\n",
                      use_v2transport ? "v2" : "v1",
                      Ticks<HoursDouble>(pszDest ? 0h : Now<NodeSeconds>() - addrConnect.nTime));
    }

    // Resolve
    const uint16_t default_port{pszDest != nullptr ? Params().GetDefaultPort(pszDest) :
                                                     Params().GetDefaultPort()};
    if (pszDest) {
        std::vector<CService> resolved{Lookup(pszDest, default_port, fNameLookup && !HaveNameProxy(), 256)};
        if (!resolved.empty()) {
            Shuffle(resolved.begin(), resolved.end(), FastRandomContext());
            // If the connection is made by name, it can be the case that the name resolves to more than one address.
            // We don't want to connect any more of them if we are already connected to one
            for (const auto& r : resolved) {
                addrConnect = CAddress{MaybeFlipIPv6toCJDNS(r), NODE_NONE};
                if (!addrConnect.IsValid()) {
                    LogPrint(BCLog::NET, "Resolver returned invalid address %s for %s\n", addrConnect.ToStringAddrPort(), pszDest);
                    return nullptr;
                }
                // It is possible that we already have a connection to the IP/port pszDest resolved to.
                // In that case, drop the connection that was just created.
                LOCK(m_nodes_mutex);
                CNode* pnode = FindNode(static_cast<CService>(addrConnect));
                if (pnode) {
                    LogPrintf("Not opening a connection to %s, already connected to %s\n", pszDest, addrConnect.ToStringAddrPort());
                    return nullptr;
                }
            }
        }
    }

    // Connect
    bool connected = false;
    std::unique_ptr<Sock> sock;
    Proxy proxy;
    CAddress addr_bind;
    assert(!addr_bind.IsValid());
    std::unique_ptr<i2p::sam::Session> i2p_transient_session;

    if (addrConnect.IsValid()) {
        const bool use_proxy{GetProxy(addrConnect.GetNetwork(), proxy)};
        bool proxyConnectionFailed = false;

        if (addrConnect.GetNetwork() == NET_I2P && use_proxy) {
            i2p::Connection conn;

            if (m_i2p_sam_session) {
                connected = m_i2p_sam_session->Connect(addrConnect, conn, proxyConnectionFailed);
            } else {
                {
                    LOCK(m_unused_i2p_sessions_mutex);
                    if (m_unused_i2p_sessions.empty()) {
                        i2p_transient_session =
                            std::make_unique<i2p::sam::Session>(proxy.proxy, &interruptNet);
                    } else {
                        i2p_transient_session.swap(m_unused_i2p_sessions.front());
                        m_unused_i2p_sessions.pop();
                    }
                }
                connected = i2p_transient_session->Connect(addrConnect, conn, proxyConnectionFailed);
                if (!connected) {
                    LOCK(m_unused_i2p_sessions_mutex);
                    if (m_unused_i2p_sessions.size() < MAX_UNUSED_I2P_SESSIONS_SIZE) {
                        m_unused_i2p_sessions.emplace(i2p_transient_session.release());
                    }
                }
            }

            if (connected) {
                sock = std::move(conn.sock);
                addr_bind = CAddress{conn.me, NODE_NONE};
            }
        } else if (use_proxy) {
            sock = CreateSock(proxy.proxy);
            if (!sock) {
                return nullptr;
            }
            connected = ConnectThroughProxy(proxy, addrConnect.ToStringAddr(), addrConnect.GetPort(),
                                            *sock, nConnectTimeout, proxyConnectionFailed);
        } else {
            // no proxy needed (none set for target network)
            sock = CreateSock(addrConnect);
            if (!sock) {
                return nullptr;
            }
            connected = ConnectSocketDirectly(addrConnect, *sock, nConnectTimeout, conn_type == ConnectionType::MANUAL);
        }
        if (!proxyConnectionFailed) {
            // If a connection to the node was attempted, and failure (if any) is not caused by a problem connecting to
            // the proxy, mark this as an attempt.
            addrman.Attempt(addrConnect, fCountFailure);
        }
    } else if (pszDest && GetNameProxy(proxy)) {
        sock = CreateSock(proxy.proxy);
        if (!sock) {
            return nullptr;
        }
        std::string host;
        uint16_t port{default_port};
        SplitHostPort(std::string(pszDest), port, host);
        bool proxyConnectionFailed;
        connected = ConnectThroughProxy(proxy, host, port, *sock, nConnectTimeout,
                                        proxyConnectionFailed);
    }
    if (!connected) {
        return nullptr;
    }

    // Add node
    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE).Write(id).Finalize();
    if (!addr_bind.IsValid()) {
        addr_bind = GetBindAddress(*sock);
    }
    CNode* pnode = new CNode(id,
                             std::move(sock),
                             addrConnect,
                             CalculateKeyedNetGroup(addrConnect),
                             nonce,
                             addr_bind,
                             pszDest ? pszDest : "",
                             conn_type,
                             /*inbound_onion=*/false,
                             CNodeOptions{
                                 .i2p_sam_session = std::move(i2p_transient_session),
                                 .recv_flood_size = nReceiveFloodSize,
                                 .use_v2transport = use_v2transport,
                             });
    pnode->AddRef();
    ::g_stats_client->inc("peers.connect", 1.0f);

    // We're making a new connection, harvest entropy from the time (and our peer count)
    RandAddEvent((uint32_t)id);

    return pnode;
}

void CNode::CloseSocketDisconnect(CConnman* connman)
{
    fDisconnect = true;
    LOCK2(connman->cs_mapSocketToNode, m_sock_mutex);
    if (!m_sock) {
        return;
    }

    fHasRecvData = false;
    fCanSendData = false;

    connman->mapSocketToNode.erase(m_sock->Get());
    {
        LOCK(connman->cs_sendable_receivable_nodes);
        connman->mapReceivableNodes.erase(GetId());
        connman->mapSendableNodes.erase(GetId());
    }

    if (connman->m_edge_trig_events) {
        connman->m_edge_trig_events->UnregisterEvents(m_sock->Get());
    }

    LogPrint(BCLog::NET, "disconnecting peer=%d\n", id);
    m_sock.reset();
    m_i2p_sam_session.reset();

    ::g_stats_client->inc("peers.disconnect", 1.0f);
}

void CConnman::AddWhitelistPermissionFlags(NetPermissionFlags& flags, const CNetAddr &addr) const {
    for (const auto& subnet : vWhitelistedRange) {
        if (subnet.m_subnet.Match(addr)) NetPermissions::AddFlag(flags, subnet.m_flags);
    }
}

bool CNode::IsBlockRelayOnly() const {
    bool ignores_incoming_txs{gArgs.GetBoolArg("-blocksonly", DEFAULT_BLOCKSONLY)};
    // Stop processing non-block data early if
    // 1) We are in blocks only mode and peer has no relay permission
    // 2) This peer is a block-relay-only peer
    return (ignores_incoming_txs && !HasPermission(NetPermissionFlags::Relay)) || IsBlockOnlyConn();
}

CService CNode::GetAddrLocal() const
{
    AssertLockNotHeld(m_addr_local_mutex);
    LOCK(m_addr_local_mutex);
    return addrLocal;
}

void CNode::SetAddrLocal(const CService& addrLocalIn) {
    AssertLockNotHeld(m_addr_local_mutex);
    LOCK(m_addr_local_mutex);
    if (addrLocal.IsValid()) {
        error("Addr local already set for node: %i. Refusing to change from %s to %s", id, addrLocal.ToStringAddrPort(), addrLocalIn.ToStringAddrPort());
    } else {
        addrLocal = addrLocalIn;
    }
}

std::string CNode::GetLogString() const
{
    return fLogIPs ? addr.ToStringAddrPort() : strprintf("%d", id);
}

Network CNode::ConnectedThroughNetwork() const
{
    return m_inbound_onion ? NET_ONION : addr.GetNetClass();
}

#undef X
#define X(name) stats.name = name
void CNode::CopyStats(CNodeStats& stats)
{
    stats.nodeid = this->GetId();
    X(addr);
    X(addrBind);
    stats.m_network = ConnectedThroughNetwork();
    X(m_last_send);
    X(m_last_recv);
    X(m_last_tx_time);
    X(m_last_block_time);
    X(m_connected);
    X(nTimeOffset);
    X(m_addr_name);
    X(nVersion);
    {
        LOCK(m_subver_mutex);
        X(cleanSubVer);
    }
    stats.fInbound = IsInboundConn();
    X(m_bip152_highbandwidth_to);
    X(m_bip152_highbandwidth_from);
    {
        LOCK(cs_vSend);
        X(mapSendBytesPerMsgType);
        X(nSendBytes);
    }
    {
        LOCK(cs_vRecv);
        X(mapRecvBytesPerMsgType);
        X(nRecvBytes);
        Transport::Info info = m_transport->GetInfo();
        stats.m_transport_type = info.transport_type;
        if (info.session_id) stats.m_session_id = HexStr(*info.session_id);
    }
    X(m_permission_flags);

    X(m_last_ping_time);
    X(m_min_ping_time);

    // Leave string empty if addrLocal invalid (not filled in yet)
    CService addrLocalUnlocked = GetAddrLocal();
    stats.addrLocal = addrLocalUnlocked.IsValid() ? addrLocalUnlocked.ToStringAddrPort() : "";

    {
        LOCK(cs_mnauth);
        X(verifiedProRegTxHash);
        X(verifiedPubKeyHash);
    }
    X(m_masternode_connection);
    X(m_conn_type);
}
#undef X

bool CNode::ReceiveMsgBytes(Span<const uint8_t> msg_bytes, bool& complete)
{
    complete = false;
    const auto time = GetTime<std::chrono::microseconds>();
    LOCK(cs_vRecv);
    m_last_recv = std::chrono::duration_cast<std::chrono::seconds>(time);
    nRecvBytes += msg_bytes.size();
    while (msg_bytes.size() > 0) {
        // absorb network data
        if (!m_transport->ReceivedBytes(msg_bytes)) {
            // Serious transport problem, disconnect from the peer.
            return false;
        }

        if (m_transport->ReceivedMessageComplete()) {
            // decompose a transport agnostic CNetMessage from the deserializer
            bool reject_message{false};
            CNetMessage msg = m_transport->GetReceivedMessage(time, reject_message);
            if (reject_message) {
                // Message deserialization failed. Drop the message but don't disconnect the peer.
                // store the size of the corrupt message
                mapRecvBytesPerMsgType.at(NET_MESSAGE_TYPE_OTHER) += msg.m_raw_message_size;
                continue;
            }

            // Store received bytes per message type.
            // To prevent a memory DOS, only allow known message types.
            auto i = mapRecvBytesPerMsgType.find(msg.m_type);
            if (i == mapRecvBytesPerMsgType.end()) {
                i = mapRecvBytesPerMsgType.find(NET_MESSAGE_TYPE_OTHER);
            }
            assert(i != mapRecvBytesPerMsgType.end());
            i->second += msg.m_raw_message_size;
            ::g_stats_client->count("bandwidth.message." + std::string(msg.m_type) + ".bytesReceived", msg.m_raw_message_size, 1.0f);

            // push the message to the process queue,
            vRecvMsg.push_back(std::move(msg));

            complete = true;
        }
    }

    return true;
}

V1Transport::V1Transport(const NodeId node_id, int nTypeIn, int nVersionIn) noexcept :
    m_node_id(node_id), hdrbuf(nTypeIn, nVersionIn), vRecv(nTypeIn, nVersionIn)
{
    assert(std::size(Params().MessageStart()) == std::size(m_magic_bytes));
    std::copy(std::begin(Params().MessageStart()), std::end(Params().MessageStart()), m_magic_bytes);
    LOCK(m_recv_mutex);
    Reset();
}

Transport::Info V1Transport::GetInfo() const noexcept
{
    return {.transport_type = TransportProtocolType::V1, .session_id = {}};
}

int V1Transport::readHeader(Span<const uint8_t> msg_bytes)
{
    AssertLockHeld(m_recv_mutex);
    // copy data to temporary parsing buffer
    unsigned int nRemaining = CMessageHeader::HEADER_SIZE - nHdrPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    memcpy(&hdrbuf[nHdrPos], msg_bytes.data(), nCopy);
    nHdrPos += nCopy;

    // if header incomplete, exit
    if (nHdrPos < CMessageHeader::HEADER_SIZE)
        return nCopy;

    // deserialize to CMessageHeader
    try {
        hdrbuf >> hdr;
    }
    catch (const std::exception&) {
        LogPrint(BCLog::NET, "Header error: Unable to deserialize, peer=%d\n", m_node_id);
        return -1;
    }

    // Check start string, network magic
    if (memcmp(hdr.pchMessageStart, m_magic_bytes, CMessageHeader::MESSAGE_START_SIZE) != 0) {
        LogPrint(BCLog::NET, "Header error: Wrong MessageStart %s received, peer=%d\n", HexStr(hdr.pchMessageStart), m_node_id);
        return -1;
    }

    // reject messages larger than MAX_SIZE or MAX_PROTOCOL_MESSAGE_LENGTH
    if (hdr.nMessageSize > MAX_SIZE || hdr.nMessageSize > MAX_PROTOCOL_MESSAGE_LENGTH) {
        LogPrint(BCLog::NET, "Header error: Size too large (%s, %u bytes), peer=%d\n", SanitizeString(hdr.GetCommand()), hdr.nMessageSize, m_node_id);
        return -1;
    }

    // switch state to reading message data
    in_data = true;

    return nCopy;
}

int V1Transport::readData(Span<const uint8_t> msg_bytes)
{
    AssertLockHeld(m_recv_mutex);
    unsigned int nRemaining = hdr.nMessageSize - nDataPos;
    unsigned int nCopy = std::min<unsigned int>(nRemaining, msg_bytes.size());

    if (vRecv.size() < nDataPos + nCopy) {
        // Allocate up to 256 KiB ahead, but never more than the total message size.
        vRecv.resize(std::min(hdr.nMessageSize, nDataPos + nCopy + 256 * 1024));
    }

    hasher.Write(msg_bytes.first(nCopy));
    memcpy(&vRecv[nDataPos], msg_bytes.data(), nCopy);
    nDataPos += nCopy;

    return nCopy;
}

const uint256& V1Transport::GetMessageHash() const
{
    AssertLockHeld(m_recv_mutex);
    assert(CompleteInternal());
    if (data_hash.IsNull())
        hasher.Finalize(data_hash);
    return data_hash;
}

CNetMessage V1Transport::GetReceivedMessage(const std::chrono::microseconds time, bool& reject_message)
{
    AssertLockNotHeld(m_recv_mutex);
    // Initialize out parameter
    reject_message = false;
    // decompose a single CNetMessage from the TransportDeserializer
    LOCK(m_recv_mutex);
    CNetMessage msg(std::move(vRecv));

    // store message type string, time, and sizes
    msg.m_type = hdr.GetCommand();
    msg.m_time = time;
    msg.m_message_size = hdr.nMessageSize;
    msg.m_raw_message_size = hdr.nMessageSize + CMessageHeader::HEADER_SIZE;

    uint256 hash = GetMessageHash();

    // We just received a message off the wire, harvest entropy from the time (and the message checksum)
    RandAddEvent(ReadLE32(hash.begin()));

    // Check checksum and header message type string
    if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0) {
        LogPrint(BCLog::NET, "Header error: Wrong checksum (%s, %u bytes), expected %s was %s, peer=%d\n",
                 SanitizeString(msg.m_type), msg.m_message_size,
                 HexStr(Span{hash}.first(CMessageHeader::CHECKSUM_SIZE)),
                 HexStr(hdr.pchChecksum),
                 m_node_id);
        reject_message = true;
    } else if (!hdr.IsCommandValid()) {
        LogPrint(BCLog::NET, "Header error: Invalid message type (%s, %u bytes), peer=%d\n",
                 SanitizeString(hdr.GetCommand()), msg.m_message_size, m_node_id);
        reject_message = true;
    }

    // Always reset the network deserializer (prepare for the next message)
    Reset();
    return msg;
}

bool V1Transport::SetMessageToSend(CSerializedNetMsg& msg) noexcept
{
    AssertLockNotHeld(m_send_mutex);
    // Determine whether a new message can be set.
    LOCK(m_send_mutex);
    if (m_sending_header || m_bytes_sent < m_message_to_send.data.size()) return false;

    // create dbl-sha256 checksum
    uint256 hash = Hash(msg.data);

    // create header
    CMessageHeader hdr(m_magic_bytes, msg.m_type.c_str(), msg.data.size());
    memcpy(hdr.pchChecksum, hash.begin(), CMessageHeader::CHECKSUM_SIZE);

    // serialize header
    m_header_to_send.clear();
    CVectorWriter{SER_NETWORK, INIT_PROTO_VERSION, m_header_to_send, 0, hdr};

    // update state
    m_message_to_send = std::move(msg);
    m_sending_header = true;
    m_bytes_sent = 0;
    return true;
}

Transport::BytesToSend V1Transport::GetBytesToSend(bool have_next_message) const noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    if (m_sending_header) {
        return {Span{m_header_to_send}.subspan(m_bytes_sent),
                // We have more to send after the header if the message has payload, or if there
                // is a next message after that.
                have_next_message || !m_message_to_send.data.empty(),
                m_message_to_send.m_type
               };
    } else {
        return {Span{m_message_to_send.data}.subspan(m_bytes_sent),
                // We only have more to send after this message's payload if there is another
                // message.
                have_next_message,
                m_message_to_send.m_type
               };
    }
}

void V1Transport::MarkBytesSent(size_t bytes_sent) noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    m_bytes_sent += bytes_sent;
    if (m_sending_header && m_bytes_sent == m_header_to_send.size()) {
        // We're done sending a message's header. Switch to sending its data bytes.
        m_sending_header = false;
        m_bytes_sent = 0;
    } else if (!m_sending_header && m_bytes_sent == m_message_to_send.data.size()) {
        // We're done sending a message's data. Wipe the data vector to reduce memory consumption.
        ClearShrink(m_message_to_send.data);
        m_bytes_sent = 0;
    }
}

size_t V1Transport::GetSendMemoryUsage() const noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    // Don't count sending-side fields besides m_message_to_send, as they're all small and bounded.
    return m_message_to_send.GetMemoryUsage();
}

namespace {

/** List of short messages as defined in BIP324, in order.
 *
 * Only message types that are actually implemented in this codebase need to be listed, as other
 * messages get ignored anyway - whether we know how to decode them or not.
 */
const std::array<std::string, 33> V2_BITCOIN_IDS = {
    "", // 12 bytes follow encoding the message type like in V1
    NetMsgType::ADDR,
    NetMsgType::BLOCK,
    NetMsgType::BLOCKTXN,
    NetMsgType::CMPCTBLOCK,
    "", /* FEEFILTER is not implemented in Dash */
    NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR,
    NetMsgType::FILTERLOAD,
    NetMsgType::GETBLOCKS,
    NetMsgType::GETBLOCKTXN,
    NetMsgType::GETDATA,
    NetMsgType::GETHEADERS,
    NetMsgType::HEADERS,
    NetMsgType::INV,
    NetMsgType::MEMPOOL,
    NetMsgType::MERKLEBLOCK,
    NetMsgType::NOTFOUND,
    NetMsgType::PING,
    NetMsgType::PONG,
    NetMsgType::SENDCMPCT,
    NetMsgType::TX,
    NetMsgType::GETCFILTERS,
    NetMsgType::CFILTER,
    NetMsgType::GETCFHEADERS,
    NetMsgType::CFHEADERS,
    NetMsgType::GETCFCHECKPT,
    NetMsgType::CFCHECKPT,
    NetMsgType::ADDRV2,
    // Unimplemented message types that are assigned in BIP324:
    "",
    "",
    "",
    ""
};

/** List of short messages allocated in Dash's reserved namespace, in order.
 *
 * Slots should not be reused unless the switchover has already been done
 * by a protocol upgrade, the old message is no longer supported by the client
 * and a new slot wasn't already allotted for the message.
 */
const std::array<std::string, 40> V2_DASH_IDS = {
    NetMsgType::SPORK,
    NetMsgType::GETSPORKS,
    NetMsgType::SENDDSQUEUE,
    NetMsgType::DSACCEPT,
    NetMsgType::DSVIN,
    NetMsgType::DSFINALTX,
    NetMsgType::DSSIGNFINALTX,
    NetMsgType::DSCOMPLETE,
    NetMsgType::DSSTATUSUPDATE,
    NetMsgType::DSTX,
    NetMsgType::DSQUEUE,
    NetMsgType::SYNCSTATUSCOUNT,
    NetMsgType::MNGOVERNANCESYNC,
    NetMsgType::MNGOVERNANCEOBJECT,
    NetMsgType::MNGOVERNANCEOBJECTVOTE,
    NetMsgType::GETMNLISTDIFF,
    NetMsgType::MNLISTDIFF,
    NetMsgType::QSENDRECSIGS,
    NetMsgType::QFCOMMITMENT,
    NetMsgType::QCONTRIB,
    NetMsgType::QCOMPLAINT,
    NetMsgType::QJUSTIFICATION,
    NetMsgType::QPCOMMITMENT,
    NetMsgType::QWATCH,
    NetMsgType::QSIGSESANN,
    NetMsgType::QSIGSHARESINV,
    NetMsgType::QGETSIGSHARES,
    NetMsgType::QBSIGSHARES,
    NetMsgType::QSIGREC,
    NetMsgType::QSIGSHARE,
    NetMsgType::QGETDATA,
    NetMsgType::QDATA,
    NetMsgType::CLSIG,
    NetMsgType::ISDLOCK,
    NetMsgType::MNAUTH,
    NetMsgType::GETHEADERS2,
    NetMsgType::SENDHEADERS2,
    NetMsgType::HEADERS2,
    NetMsgType::GETQUORUMROTATIONINFO,
    NetMsgType::QUORUMROTATIONINFO
};

/** A complete set of short IDs
 *
 * Bitcoin takes up short IDs upto 128 (lower half) while Dash can take
 * up short IDs between 128 and 256 (upper half) most of the array will
 * have entries that correspond to nothing.
 *
 * To distinguish between entries that are *meant* to correspond to
 * nothing versus empty space, use IsValidV2ShortID()
 */
constexpr std::array<std::string_view, 256> V2ShortIDs() {
    static_assert(std::size(V2_BITCOIN_IDS) <= 128);
    static_assert(std::size(V2_DASH_IDS) <= 128);

    std::array<std::string_view, 256> ret{};
    for (size_t idx{0}; idx < std::size(ret); idx++) {
        if (idx < 128 && idx < std::size(V2_BITCOIN_IDS)) {
            ret[idx] = V2_BITCOIN_IDS[idx];
        } else if (idx >= 128 && idx - 128 < std::size(V2_DASH_IDS)) {
            ret[idx] = V2_DASH_IDS[idx - 128];
        } else {
            ret[idx] = "";
        }
    }

    return ret;
}

bool IsValidV2ShortID(uint8_t first_byte) {
    // Since we have filled the namespace of short IDs, we have to preserve
    // the expected behaviour of coming up short when going beyond Bitcoin's
    // and Dash's *used* slots. We do this by checking if the byte is within
    // the range where a valid message is expected to reside.
    return first_byte < std::size(V2_BITCOIN_IDS) ||
           (first_byte >= 128 && static_cast<uint8_t>(first_byte - 128) < std::size(V2_DASH_IDS));
}

class V2MessageMap
{
    std::unordered_map<std::string, uint8_t> m_map;

public:
    V2MessageMap() noexcept
    {
        for (size_t i = 1; i < std::size(V2ShortIDs()); ++i) {
            if (IsValidV2ShortID(i)) {
                m_map.emplace(V2ShortIDs()[i], i);
            }
        }
    }

    std::optional<uint8_t> operator()(const std::string& message_name) const noexcept
    {
        auto it = m_map.find(message_name);
        if (it == m_map.end()) return std::nullopt;
        return it->second;
    }
};

const V2MessageMap V2_MESSAGE_MAP;

CKey GenerateRandomKey() noexcept
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    return key;
}

std::vector<uint8_t> GenerateRandomGarbage() noexcept
{
    std::vector<uint8_t> ret;
    FastRandomContext rng;
    ret.resize(rng.randrange(V2Transport::MAX_GARBAGE_LEN + 1));
    rng.fillrand(MakeWritableByteSpan(ret));
    return ret;
}

} // namespace

void V2Transport::StartSendingHandshake() noexcept
{
    AssertLockHeld(m_send_mutex);
    Assume(m_send_state == SendState::AWAITING_KEY);
    Assume(m_send_buffer.empty());
    // Initialize the send buffer with ellswift pubkey + provided garbage.
    m_send_buffer.resize(EllSwiftPubKey::size() + m_send_garbage.size());
    std::copy(std::begin(m_cipher.GetOurPubKey()), std::end(m_cipher.GetOurPubKey()), MakeWritableByteSpan(m_send_buffer).begin());
    std::copy(m_send_garbage.begin(), m_send_garbage.end(), m_send_buffer.begin() + EllSwiftPubKey::size());
    // We cannot wipe m_send_garbage as it will still be used as AAD later in the handshake.
}

V2Transport::V2Transport(NodeId nodeid, bool initiating, int type_in, int version_in, const CKey& key, Span<const std::byte> ent32, std::vector<uint8_t> garbage) noexcept :
    m_cipher{key, ent32}, m_initiating{initiating}, m_nodeid{nodeid},
    m_v1_fallback{nodeid, type_in, version_in}, m_recv_type{type_in}, m_recv_version{version_in},
    m_recv_state{initiating ? RecvState::KEY : RecvState::KEY_MAYBE_V1},
    m_send_garbage{std::move(garbage)},
    m_send_state{initiating ? SendState::AWAITING_KEY : SendState::MAYBE_V1}
{
    Assume(m_send_garbage.size() <= MAX_GARBAGE_LEN);
    // Start sending immediately if we're the initiator of the connection.
    if (initiating) {
        LOCK(m_send_mutex);
        StartSendingHandshake();
    }
}

V2Transport::V2Transport(NodeId nodeid, bool initiating, int type_in, int version_in) noexcept :
    V2Transport{nodeid, initiating, type_in, version_in, GenerateRandomKey(),
                MakeByteSpan(GetRandHash()), GenerateRandomGarbage()} { }

void V2Transport::SetReceiveState(RecvState recv_state) noexcept
{
    AssertLockHeld(m_recv_mutex);
    // Enforce allowed state transitions.
    switch (m_recv_state) {
    case RecvState::KEY_MAYBE_V1:
        Assume(recv_state == RecvState::KEY || recv_state == RecvState::V1);
        break;
    case RecvState::KEY:
        Assume(recv_state == RecvState::GARB_GARBTERM);
        break;
    case RecvState::GARB_GARBTERM:
        Assume(recv_state == RecvState::VERSION);
        break;
    case RecvState::VERSION:
        Assume(recv_state == RecvState::APP);
        break;
    case RecvState::APP:
        Assume(recv_state == RecvState::APP_READY);
        break;
    case RecvState::APP_READY:
        Assume(recv_state == RecvState::APP);
        break;
    case RecvState::V1:
        Assume(false); // V1 state cannot be left
        break;
    }
    // Change state.
    m_recv_state = recv_state;
}

void V2Transport::SetSendState(SendState send_state) noexcept
{
    AssertLockHeld(m_send_mutex);
    // Enforce allowed state transitions.
    switch (m_send_state) {
    case SendState::MAYBE_V1:
        Assume(send_state == SendState::V1 || send_state == SendState::AWAITING_KEY);
        break;
    case SendState::AWAITING_KEY:
        Assume(send_state == SendState::READY);
        break;
    case SendState::READY:
    case SendState::V1:
        Assume(false); // Final states
        break;
    }
    // Change state.
    m_send_state = send_state;
}

bool V2Transport::ReceivedMessageComplete() const noexcept
{
    AssertLockNotHeld(m_recv_mutex);
    LOCK(m_recv_mutex);
    if (m_recv_state == RecvState::V1) return m_v1_fallback.ReceivedMessageComplete();

    return m_recv_state == RecvState::APP_READY;
}

void V2Transport::ProcessReceivedMaybeV1Bytes() noexcept
{
    AssertLockHeld(m_recv_mutex);
    AssertLockNotHeld(m_send_mutex);
    Assume(m_recv_state == RecvState::KEY_MAYBE_V1);
    // We still have to determine if this is a v1 or v2 connection. The bytes being received could
    // be the beginning of either a v1 packet (network magic + "version\x00\x00\x00\x00\x00"), or
    // of a v2 public key. BIP324 specifies that a mismatch with this 16-byte string should trigger
    // sending of the key.
    std::array<uint8_t, V1_PREFIX_LEN> v1_prefix = {0, 0, 0, 0, 'v', 'e', 'r', 's', 'i', 'o', 'n', 0, 0, 0, 0, 0};
    std::copy(std::begin(Params().MessageStart()), std::end(Params().MessageStart()), v1_prefix.begin());
    Assume(m_recv_buffer.size() <= v1_prefix.size());
    if (!std::equal(m_recv_buffer.begin(), m_recv_buffer.end(), v1_prefix.begin())) {
        // Mismatch with v1 prefix, so we can assume a v2 connection.
        SetReceiveState(RecvState::KEY); // Convert to KEY state, leaving received bytes around.
        // Transition the sender to AWAITING_KEY state and start sending.
        LOCK(m_send_mutex);
        SetSendState(SendState::AWAITING_KEY);
        StartSendingHandshake();
    } else if (m_recv_buffer.size() == v1_prefix.size()) {
        // Full match with the v1 prefix, so fall back to v1 behavior.
        LOCK(m_send_mutex);
        Span<const uint8_t> feedback{m_recv_buffer};
        // Feed already received bytes to v1 transport. It should always accept these, because it's
        // less than the size of a v1 header, and these are the first bytes fed to m_v1_fallback.
        bool ret = m_v1_fallback.ReceivedBytes(feedback);
        Assume(feedback.empty());
        Assume(ret);
        SetReceiveState(RecvState::V1);
        SetSendState(SendState::V1);
        // Reset v2 transport buffers to save memory.
        ClearShrink(m_recv_buffer);
        ClearShrink(m_send_buffer);
    } else {
        // We have not received enough to distinguish v1 from v2 yet. Wait until more bytes come.
    }
}

bool V2Transport::ProcessReceivedKeyBytes() noexcept
{
    AssertLockHeld(m_recv_mutex);
    AssertLockNotHeld(m_send_mutex);
    Assume(m_recv_state == RecvState::KEY);
    Assume(m_recv_buffer.size() <= EllSwiftPubKey::size());

    // As a special exception, if bytes 4-16 of the key on a responder connection match the
    // corresponding bytes of a V1 version message, but bytes 0-4 don't match the network magic
    // (if they did, we'd have switched to V1 state already), assume this is a peer from
    // another network, and disconnect them. They will almost certainly disconnect us too when
    // they receive our uniformly random key and garbage, but detecting this case specially
    // means we can log it.
    static constexpr std::array<uint8_t, 12> MATCH = {'v', 'e', 'r', 's', 'i', 'o', 'n', 0, 0, 0, 0, 0};
    static constexpr size_t OFFSET = sizeof(CMessageHeader::MessageStartChars);
    if (!m_initiating && m_recv_buffer.size() >= OFFSET + MATCH.size()) {
        if (std::equal(MATCH.begin(), MATCH.end(), m_recv_buffer.begin() + OFFSET)) {
            LogPrint(BCLog::NET, "V2 transport error: V1 peer with wrong MessageStart %s\n",
                     HexStr(Span(m_recv_buffer).first(OFFSET)));
            return false;
        }
    }

    if (m_recv_buffer.size() == EllSwiftPubKey::size()) {
        // Other side's key has been fully received, and can now be Diffie-Hellman combined with
        // our key to initialize the encryption ciphers.

        // Initialize the ciphers.
        EllSwiftPubKey ellswift(MakeByteSpan(m_recv_buffer));
        LOCK(m_send_mutex);
        m_cipher.Initialize(ellswift, m_initiating);

        // Switch receiver state to GARB_GARBTERM.
        SetReceiveState(RecvState::GARB_GARBTERM);
        m_recv_buffer.clear();

        // Switch sender state to READY.
        SetSendState(SendState::READY);

        // Append the garbage terminator to the send buffer.
        m_send_buffer.resize(m_send_buffer.size() + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
        std::copy(m_cipher.GetSendGarbageTerminator().begin(),
                  m_cipher.GetSendGarbageTerminator().end(),
                  MakeWritableByteSpan(m_send_buffer).last(BIP324Cipher::GARBAGE_TERMINATOR_LEN).begin());

        // Construct version packet in the send buffer, with the sent garbage data as AAD.
        m_send_buffer.resize(m_send_buffer.size() + BIP324Cipher::EXPANSION + VERSION_CONTENTS.size());
        m_cipher.Encrypt(
            /*contents=*/VERSION_CONTENTS,
            /*aad=*/MakeByteSpan(m_send_garbage),
            /*ignore=*/false,
            /*output=*/MakeWritableByteSpan(m_send_buffer).last(BIP324Cipher::EXPANSION + VERSION_CONTENTS.size()));
        // We no longer need the garbage.
        ClearShrink(m_send_garbage);
    } else {
        // We still have to receive more key bytes.
    }
    return true;
}

bool V2Transport::ProcessReceivedGarbageBytes() noexcept
{
    AssertLockHeld(m_recv_mutex);
    Assume(m_recv_state == RecvState::GARB_GARBTERM);
    Assume(m_recv_buffer.size() <= MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
    if (m_recv_buffer.size() >= BIP324Cipher::GARBAGE_TERMINATOR_LEN) {
        if (MakeByteSpan(m_recv_buffer).last(BIP324Cipher::GARBAGE_TERMINATOR_LEN) == m_cipher.GetReceiveGarbageTerminator()) {
            // Garbage terminator received. Store garbage to authenticate it as AAD later.
            m_recv_aad = std::move(m_recv_buffer);
            m_recv_aad.resize(m_recv_aad.size() - BIP324Cipher::GARBAGE_TERMINATOR_LEN);
            m_recv_buffer.clear();
            SetReceiveState(RecvState::VERSION);
        } else if (m_recv_buffer.size() == MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN) {
            // We've reached the maximum length for garbage + garbage terminator, and the
            // terminator still does not match. Abort.
            LogPrint(BCLog::NET, "V2 transport error: missing garbage terminator, peer=%d\n", m_nodeid);
            return false;
        } else {
            // We still need to receive more garbage and/or garbage terminator bytes.
        }
    } else {
        // We have less than GARBAGE_TERMINATOR_LEN (16) bytes, so we certainly need to receive
        // more first.
    }
    return true;
}

bool V2Transport::ProcessReceivedPacketBytes() noexcept
{
    AssertLockHeld(m_recv_mutex);
    Assume(m_recv_state == RecvState::VERSION || m_recv_state == RecvState::APP);

    // The maximum permitted contents length for a packet, consisting of:
    // - 0x00 byte: indicating long message type encoding
    // - 12 bytes of message type
    // - payload
    static constexpr size_t MAX_CONTENTS_LEN =
        1 + CMessageHeader::COMMAND_SIZE +
        std::min<size_t>(MAX_SIZE, MAX_PROTOCOL_MESSAGE_LENGTH);

    if (m_recv_buffer.size() == BIP324Cipher::LENGTH_LEN) {
        // Length descriptor received.
        m_recv_len = m_cipher.DecryptLength(MakeByteSpan(m_recv_buffer));
        if (m_recv_len > MAX_CONTENTS_LEN) {
            LogPrint(BCLog::NET, "V2 transport error: packet too large (%u bytes), peer=%d\n", m_recv_len, m_nodeid);
            return false;
        }
    } else if (m_recv_buffer.size() > BIP324Cipher::LENGTH_LEN && m_recv_buffer.size() == m_recv_len + BIP324Cipher::EXPANSION) {
        // Ciphertext received, decrypt it into m_recv_decode_buffer.
        // Note that it is impossible to reach this branch without hitting the branch above first,
        // as GetMaxBytesToProcess only allows up to LENGTH_LEN into the buffer before that point.
        m_recv_decode_buffer.resize(m_recv_len);
        bool ignore{false};
        bool ret = m_cipher.Decrypt(
            /*input=*/MakeByteSpan(m_recv_buffer).subspan(BIP324Cipher::LENGTH_LEN),
            /*aad=*/MakeByteSpan(m_recv_aad),
            /*ignore=*/ignore,
            /*contents=*/MakeWritableByteSpan(m_recv_decode_buffer));
        if (!ret) {
            LogPrint(BCLog::NET, "V2 transport error: packet decryption failure (%u bytes), peer=%d\n", m_recv_len, m_nodeid);
            return false;
        }
        // We have decrypted a valid packet with the AAD we expected, so clear the expected AAD.
        ClearShrink(m_recv_aad);
        // Feed the last 4 bytes of the Poly1305 authentication tag (and its timing) into our RNG.
        RandAddEvent(ReadLE32(m_recv_buffer.data() + m_recv_buffer.size() - 4));

        // At this point we have a valid packet decrypted into m_recv_decode_buffer. If it's not a
        // decoy, which we simply ignore, use the current state to decide what to do with it.
        if (!ignore) {
            switch (m_recv_state) {
            case RecvState::VERSION:
                // Version message received; transition to application phase. The contents is
                // ignored, but can be used for future extensions.
                SetReceiveState(RecvState::APP);
                break;
            case RecvState::APP:
                // Application message decrypted correctly. It can be extracted using GetMessage().
                SetReceiveState(RecvState::APP_READY);
                break;
            default:
                // Any other state is invalid (this function should not have been called).
                Assume(false);
            }
        }
        // Wipe the receive buffer where the next packet will be received into.
        ClearShrink(m_recv_buffer);
        // In all but APP_READY state, we can wipe the decoded contents.
        if (m_recv_state != RecvState::APP_READY) ClearShrink(m_recv_decode_buffer);
    } else {
        // We either have less than 3 bytes, so we don't know the packet's length yet, or more
        // than 3 bytes but less than the packet's full ciphertext. Wait until those arrive.
    }
    return true;
}

size_t V2Transport::GetMaxBytesToProcess() noexcept
{
    AssertLockHeld(m_recv_mutex);
    switch (m_recv_state) {
    case RecvState::KEY_MAYBE_V1:
        // During the KEY_MAYBE_V1 state we do not allow more than the length of v1 prefix into the
        // receive buffer.
        Assume(m_recv_buffer.size() <= V1_PREFIX_LEN);
        // As long as we're not sure if this is a v1 or v2 connection, don't receive more than what
        // is strictly necessary to distinguish the two (16 bytes). If we permitted more than
        // the v1 header size (24 bytes), we may not be able to feed the already-received bytes
        // back into the m_v1_fallback V1 transport.
        return V1_PREFIX_LEN - m_recv_buffer.size();
    case RecvState::KEY:
        // During the KEY state, we only allow the 64-byte key into the receive buffer.
        Assume(m_recv_buffer.size() <= EllSwiftPubKey::size());
        // As long as we have not received the other side's public key, don't receive more than
        // that (64 bytes), as garbage follows, and locating the garbage terminator requires the
        // key exchange first.
        return EllSwiftPubKey::size() - m_recv_buffer.size();
    case RecvState::GARB_GARBTERM:
        // Process garbage bytes one by one (because terminator may appear anywhere).
        return 1;
    case RecvState::VERSION:
    case RecvState::APP:
        // These three states all involve decoding a packet. Process the length descriptor first,
        // so that we know where the current packet ends (and we don't process bytes from the next
        // packet or decoy yet). Then, process the ciphertext bytes of the current packet.
        if (m_recv_buffer.size() < BIP324Cipher::LENGTH_LEN) {
            return BIP324Cipher::LENGTH_LEN - m_recv_buffer.size();
        } else {
            // Note that BIP324Cipher::EXPANSION is the total difference between contents size
            // and encoded packet size, which includes the 3 bytes due to the packet length.
            // When transitioning from receiving the packet length to receiving its ciphertext,
            // the encrypted packet length is left in the receive buffer.
            return BIP324Cipher::EXPANSION + m_recv_len - m_recv_buffer.size();
        }
    case RecvState::APP_READY:
        // No bytes can be processed until GetMessage() is called.
        return 0;
    case RecvState::V1:
        // Not allowed (must be dealt with by the caller).
        Assume(false);
        return 0;
    }
    Assume(false); // unreachable
    return 0;
}

bool V2Transport::ReceivedBytes(Span<const uint8_t>& msg_bytes) noexcept
{
    AssertLockNotHeld(m_recv_mutex);
    /** How many bytes to allocate in the receive buffer at most above what is received so far. */
    static constexpr size_t MAX_RESERVE_AHEAD = 256 * 1024;

    LOCK(m_recv_mutex);
    if (m_recv_state == RecvState::V1) return m_v1_fallback.ReceivedBytes(msg_bytes);

    // Process the provided bytes in msg_bytes in a loop. In each iteration a nonzero number of
    // bytes (decided by GetMaxBytesToProcess) are taken from the beginning om msg_bytes, and
    // appended to m_recv_buffer. Then, depending on the receiver state, one of the
    // ProcessReceived*Bytes functions is called to process the bytes in that buffer.
    while (!msg_bytes.empty()) {
        // Decide how many bytes to copy from msg_bytes to m_recv_buffer.
        size_t max_read = GetMaxBytesToProcess();

        // Reserve space in the buffer if there is not enough.
        if (m_recv_buffer.size() + std::min(msg_bytes.size(), max_read) > m_recv_buffer.capacity()) {
            switch (m_recv_state) {
            case RecvState::KEY_MAYBE_V1:
            case RecvState::KEY:
            case RecvState::GARB_GARBTERM:
                // During the initial states (key/garbage), allocate once to fit the maximum (4111
                // bytes).
                m_recv_buffer.reserve(MAX_GARBAGE_LEN + BIP324Cipher::GARBAGE_TERMINATOR_LEN);
                break;
            case RecvState::VERSION:
            case RecvState::APP: {
                // During states where a packet is being received, as much as is expected but never
                // more than MAX_RESERVE_AHEAD bytes in addition to what is received so far.
                // This means attackers that want to cause us to waste allocated memory are limited
                // to MAX_RESERVE_AHEAD above the largest allowed message contents size, and to
                // MAX_RESERVE_AHEAD more than they've actually sent us.
                size_t alloc_add = std::min(max_read, msg_bytes.size() + MAX_RESERVE_AHEAD);
                m_recv_buffer.reserve(m_recv_buffer.size() + alloc_add);
                break;
            }
            case RecvState::APP_READY:
                // The buffer is empty in this state.
                Assume(m_recv_buffer.empty());
                break;
            case RecvState::V1:
                // Should have bailed out above.
                Assume(false);
                break;
            }
        }

        // Can't read more than provided input.
        max_read = std::min(msg_bytes.size(), max_read);
        // Copy data to buffer.
        m_recv_buffer.insert(m_recv_buffer.end(), UCharCast(msg_bytes.data()), UCharCast(msg_bytes.data() + max_read));
        msg_bytes = msg_bytes.subspan(max_read);

        // Process data in the buffer.
        switch (m_recv_state) {
        case RecvState::KEY_MAYBE_V1:
            ProcessReceivedMaybeV1Bytes();
            if (m_recv_state == RecvState::V1) return true;
            break;

        case RecvState::KEY:
            if (!ProcessReceivedKeyBytes()) return false;
            break;

        case RecvState::GARB_GARBTERM:
            if (!ProcessReceivedGarbageBytes()) return false;
            break;

        case RecvState::VERSION:
        case RecvState::APP:
            if (!ProcessReceivedPacketBytes()) return false;
            break;

        case RecvState::APP_READY:
            return true;

        case RecvState::V1:
            // We should have bailed out before.
            Assume(false);
            break;
        }
        // Make sure we have made progress before continuing.
        Assume(max_read > 0);
    }

    return true;
}

std::optional<std::string> V2Transport::GetMessageType(Span<const uint8_t>& contents) noexcept
{
    if (contents.size() == 0) return std::nullopt; // Empty contents
    uint8_t first_byte = contents[0];
    contents = contents.subspan(1); // Strip first byte.

    if (first_byte != 0) {
        // Short (1 byte) encoding.
        if (IsValidV2ShortID(first_byte)) {
            // Valid short message id.
            return std::string{V2ShortIDs()[first_byte]};
        } else {
            // Unknown short message id.
            return std::nullopt;
        }
    }

    if (contents.size() < CMessageHeader::COMMAND_SIZE) {
        return std::nullopt; // Long encoding needs 12 message type bytes.
    }

    size_t msg_type_len{0};
    while (msg_type_len < CMessageHeader::COMMAND_SIZE && contents[msg_type_len] != 0) {
        // Verify that message type bytes before the first 0x00 are in range.
        if (contents[msg_type_len] < ' ' || contents[msg_type_len] > 0x7F) {
            return {};
        }
        ++msg_type_len;
    }
    std::string ret{reinterpret_cast<const char*>(contents.data()), msg_type_len};
    while (msg_type_len < CMessageHeader::COMMAND_SIZE) {
        // Verify that message type bytes after the first 0x00 are also 0x00.
        if (contents[msg_type_len] != 0) return {};
        ++msg_type_len;
    }
    // Strip message type bytes of contents.
    contents = contents.subspan(CMessageHeader::COMMAND_SIZE);
    return {std::move(ret)};
}

CNetMessage V2Transport::GetReceivedMessage(std::chrono::microseconds time, bool& reject_message) noexcept
{
    AssertLockNotHeld(m_recv_mutex);
    LOCK(m_recv_mutex);
    if (m_recv_state == RecvState::V1) return m_v1_fallback.GetReceivedMessage(time, reject_message);

    Assume(m_recv_state == RecvState::APP_READY);
    Span<const uint8_t> contents{m_recv_decode_buffer};
    auto msg_type = GetMessageType(contents);
    CDataStream ret(m_recv_type, m_recv_version);
    CNetMessage msg{std::move(ret)};
    // Note that BIP324Cipher::EXPANSION also includes the length descriptor size.
    msg.m_raw_message_size = m_recv_decode_buffer.size() + BIP324Cipher::EXPANSION;
    if (msg_type) {
        reject_message = false;
        msg.m_type = std::move(*msg_type);
        msg.m_time = time;
        msg.m_message_size = contents.size();
        msg.m_recv.resize(contents.size());
        std::copy(contents.begin(), contents.end(), UCharCast(msg.m_recv.data()));
    } else {
        LogPrint(BCLog::NET, "V2 transport error: invalid message type (%u bytes contents), peer=%d\n", m_recv_decode_buffer.size(), m_nodeid);
        reject_message = true;
    }
    ClearShrink(m_recv_decode_buffer);
    SetReceiveState(RecvState::APP);

    return msg;
}

bool V2Transport::SetMessageToSend(CSerializedNetMsg& msg) noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    if (m_send_state == SendState::V1) return m_v1_fallback.SetMessageToSend(msg);
    // We only allow adding a new message to be sent when in the READY state (so the packet cipher
    // is available) and the send buffer is empty. This limits the number of messages in the send
    // buffer to just one, and leaves the responsibility for queueing them up to the caller.
    if (!(m_send_state == SendState::READY && m_send_buffer.empty())) return false;
    // Construct contents (encoding message type + payload).
    std::vector<uint8_t> contents;
    auto short_message_id = V2_MESSAGE_MAP(msg.m_type);
    if (short_message_id) {
        contents.resize(1 + msg.data.size());
        contents[0] = *short_message_id;
        std::copy(msg.data.begin(), msg.data.end(), contents.begin() + 1);
    } else {
        // Initialize with zeroes, and then write the message type string starting at offset 1.
        // This means contents[0] and the unused positions in contents[1..13] remain 0x00.
        contents.resize(1 + CMessageHeader::COMMAND_SIZE + msg.data.size(), 0);
        std::copy(msg.m_type.begin(), msg.m_type.end(), contents.data() + 1);
        std::copy(msg.data.begin(), msg.data.end(), contents.begin() + 1 + CMessageHeader::COMMAND_SIZE);
    }
    // Construct ciphertext in send buffer.
    m_send_buffer.resize(contents.size() + BIP324Cipher::EXPANSION);
    m_cipher.Encrypt(MakeByteSpan(contents), {}, false, MakeWritableByteSpan(m_send_buffer));
    m_send_type = msg.m_type;
    // Release memory
    ClearShrink(msg.data);
    return true;
}

Transport::BytesToSend V2Transport::GetBytesToSend(bool have_next_message) const noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    if (m_send_state == SendState::V1) return m_v1_fallback.GetBytesToSend(have_next_message);

    if (m_send_state == SendState::MAYBE_V1) Assume(m_send_buffer.empty());
    Assume(m_send_pos <= m_send_buffer.size());
    return {
        Span{m_send_buffer}.subspan(m_send_pos),
        // We only have more to send after the current m_send_buffer if there is a (next)
        // message to be sent, and we're capable of sending packets. */
        have_next_message && m_send_state == SendState::READY,
        m_send_type
    };
}

void V2Transport::MarkBytesSent(size_t bytes_sent) noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    if (m_send_state == SendState::V1) return m_v1_fallback.MarkBytesSent(bytes_sent);

    if (m_send_state == SendState::AWAITING_KEY && m_send_pos == 0 && bytes_sent > 0) {
        LogPrint(BCLog::NET, "start sending v2 handshake to peer=%d\n", m_nodeid);
    }

    m_send_pos += bytes_sent;
    Assume(m_send_pos <= m_send_buffer.size());
    if (m_send_pos >= CMessageHeader::HEADER_SIZE) {
        m_sent_v1_header_worth = true;
    }
    // Wipe the buffer when everything is sent.
    if (m_send_pos == m_send_buffer.size()) {
        m_send_pos = 0;
        ClearShrink(m_send_buffer);
    }
}

bool V2Transport::ShouldReconnectV1() const noexcept
{
    AssertLockNotHeld(m_send_mutex);
    AssertLockNotHeld(m_recv_mutex);
    // Only outgoing connections need reconnection.
    if (!m_initiating) return false;

    LOCK(m_recv_mutex);
    // We only reconnect in the very first state and when the receive buffer is empty. Together
    // these conditions imply nothing has been received so far.
    if (m_recv_state != RecvState::KEY) return false;
    if (!m_recv_buffer.empty()) return false;
    // Check if we've sent enough for the other side to disconnect us (if it was V1).
    LOCK(m_send_mutex);
    return m_sent_v1_header_worth;
}

size_t V2Transport::GetSendMemoryUsage() const noexcept
{
    AssertLockNotHeld(m_send_mutex);
    LOCK(m_send_mutex);
    if (m_send_state == SendState::V1) return m_v1_fallback.GetSendMemoryUsage();

    return sizeof(m_send_buffer) + memusage::DynamicUsage(m_send_buffer);
}

Transport::Info V2Transport::GetInfo() const noexcept
{
    AssertLockNotHeld(m_recv_mutex);
    LOCK(m_recv_mutex);
    if (m_recv_state == RecvState::V1) return m_v1_fallback.GetInfo();

    Transport::Info info;

    // Do not report v2 and session ID until the version packet has been received
    // and verified (confirming that the other side very likely has the same keys as us).
    if (m_recv_state != RecvState::KEY_MAYBE_V1 && m_recv_state != RecvState::KEY &&
        m_recv_state != RecvState::GARB_GARBTERM && m_recv_state != RecvState::VERSION) {
        info.transport_type = TransportProtocolType::V2;
        info.session_id = uint256(MakeUCharSpan(m_cipher.GetSessionID()));
    } else {
        info.transport_type = TransportProtocolType::DETECTING;
    }

    return info;
}

std::pair<size_t, bool> CConnman::SocketSendData(CNode& node) const
{
    auto it = node.vSendMsg.begin();
    size_t nSentSize = 0;
    bool data_left{false}; //!< second return value (whether unsent data remains)
    std::optional<bool> expected_more;

    while (true) {
        if (it != node.vSendMsg.end()) {
            // If possible, move one message from the send queue to the transport. This fails when
            // there is an existing message still being sent, or (for v2 transports) when the
            // handshake has not yet completed.
            size_t memusage = it->GetMemoryUsage();
            if (node.m_transport->SetMessageToSend(*it)) {
                // Update memory usage of send buffer (as *it will be deleted).
                node.m_send_memusage -= memusage;
                ++it;
            }
        }
        const auto& [data, more, msg_type] = node.m_transport->GetBytesToSend(it != node.vSendMsg.end());
        // We rely on the 'more' value returned by GetBytesToSend to correctly predict whether more
        // bytes are still to be sent, to correctly set the MSG_MORE flag. As a sanity check,
        // verify that the previously returned 'more' was correct.
        if (expected_more.has_value()) Assume(!data.empty() == *expected_more);
        expected_more = more;
        data_left = !data.empty(); // will be overwritten on next loop if all of data gets sent
        int nBytes = 0;
        if (!data.empty()) {
            LOCK(node.m_sock_mutex);
            // There is no socket in case we've already disconnected, or in test cases without
            // real connections. In these cases, we bail out immediately and just leave things
            // in the send queue and transport.
            if (!node.m_sock) {
                break;
            }
            int flags = MSG_NOSIGNAL | MSG_DONTWAIT;
#ifdef MSG_MORE
            if (more) {
                flags |= MSG_MORE;
            }
#endif
            nBytes = node.m_sock->Send(reinterpret_cast<const char*>(data.data()), data.size(), flags);
        }
        if (nBytes > 0) {
            node.m_last_send = GetTime<std::chrono::seconds>();
            node.nSendBytes += nBytes;
            // Notify transport that bytes have been processed.
            node.m_transport->MarkBytesSent(nBytes);
            // Update statistics per message type.
            if (!msg_type.empty()) { // don't report v2 handshake bytes for now
                node.AccountForSentBytes(msg_type, nBytes);
            }
            nSentSize += nBytes;
            if ((size_t)nBytes != data.size()) {
                // could not send full message; stop sending more
                node.fCanSendData = false;
                break;
            }
        } else {
            if (nBytes < 0) {
                // error
                int nErr = WSAGetLastError();
                if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS) {
                    LogPrint(BCLog::NET, "socket send error for peer=%d: %s\n", node.GetId(), NetworkErrorString(nErr));
                    node.fDisconnect = true;
                }
            }
            break;
        }
    }

    node.fPauseSend = node.m_send_memusage + node.m_transport->GetSendMemoryUsage() > nSendBufferMaxSize;

    if (it == node.vSendMsg.end()) {
        assert(node.m_send_memusage == 0);
    }
    node.vSendMsg.erase(node.vSendMsg.begin(), it);
    node.nSendMsgSize = node.vSendMsg.size();
    return {nSentSize, data_left};
}

/** Try to find a connection to evict when the node is full.
 *  Extreme care must be taken to avoid opening the node to attacker
 *   triggered network partitioning.
 *  The strategy used here is to protect a small number of peers
 *   for each of several distinct characteristics which are difficult
 *   to forge.  In order to partition a node the attacker must be
 *   simultaneously better at all of them than honest peers.
 */
bool CConnman::AttemptToEvictConnection()
{
    std::vector<NodeEvictionCandidate> vEvictionCandidates;
    {
        LOCK(m_nodes_mutex);

        for (const CNode* node : m_nodes) {
            if (node->fDisconnect)
                continue;

            if (fMasternodeMode) {
                // This handles eviction protected nodes. Nodes are always protected for a short time after the connection
                // was accepted. This short time is meant for the VERSION/VERACK exchange and the possible MNAUTH that might
                // follow when the incoming connection is from another masternode. When a message other than MNAUTH
                // is received after VERSION/VERACK, the protection is lifted immediately.
                bool isProtected = GetTime<std::chrono::seconds>() - node->m_connected < INBOUND_EVICTION_PROTECTION_TIME;
                if (node->nTimeFirstMessageReceived.load() != 0s && !node->fFirstMessageIsMNAUTH) {
                    isProtected = false;
                }
                // if MNAUTH was valid, the node is always protected (and at the same time not accounted when
                // checking incoming connection limits)
                if (!node->GetVerifiedProRegTxHash().IsNull()) {
                    isProtected = true;
                }
                if (isProtected) {
                    continue;
                }
            }

            NodeEvictionCandidate candidate{
                .id = node->GetId(),
                .m_connected = node->m_connected,
                .m_min_ping_time = node->m_min_ping_time,
                .m_last_block_time = node->m_last_block_time,
                .m_last_tx_time = node->m_last_tx_time,
                .fRelevantServices = node->m_has_all_wanted_services,
                .m_relay_txs = node->m_relays_txs.load(),
                .fBloomFilter = node->m_bloom_filter_loaded.load(),
                .nKeyedNetGroup = node->nKeyedNetGroup,
                .prefer_evict = node->m_prefer_evict,
                .m_is_local = node->addr.IsLocal(),
                .m_network = node->ConnectedThroughNetwork(),
                .m_noban = node->HasPermission(NetPermissionFlags::NoBan),
                .m_conn_type = node->m_conn_type,
            };
            vEvictionCandidates.push_back(candidate);
        }
    }
    const std::optional<NodeId> node_id_to_evict = SelectNodeToEvict(std::move(vEvictionCandidates));
    if (!node_id_to_evict) {
        return false;
    }
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (pnode->GetId() == *node_id_to_evict) {
            LogPrint(BCLog::NET_NETCONN, "selected %s connection for eviction peer=%d; disconnecting\n", pnode->ConnectionTypeAsString(), pnode->GetId());
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CConnman::AcceptConnection(const ListenSocket& hListenSocket, CMasternodeSync& mn_sync) {
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    auto sock = hListenSocket.sock->Accept((struct sockaddr*)&sockaddr, &len);
    CAddress addr;

    if (!sock) {
        const int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK) {
            LogPrintf("socket error accept failed: %s\n", NetworkErrorString(nErr));
        }
        return;
    }

    if (!addr.SetSockAddr((const struct sockaddr*)&sockaddr)) {
        LogPrintLevel(BCLog::NET, BCLog::Level::Warning, "Unknown socket family\n");
    } else {
        addr = CAddress{MaybeFlipIPv6toCJDNS(addr), NODE_NONE};
    }

    const CAddress addr_bind{MaybeFlipIPv6toCJDNS(GetBindAddress(*sock)), NODE_NONE};

    NetPermissionFlags permission_flags = NetPermissionFlags::None;
    hListenSocket.AddSocketPermissionFlags(permission_flags);

    CreateNodeFromAcceptedSocket(std::move(sock), permission_flags, addr_bind, addr, mn_sync);
}

void CConnman::CreateNodeFromAcceptedSocket(std::unique_ptr<Sock>&& sock,
                                            NetPermissionFlags permission_flags,
                                            const CAddress& addr_bind,
                                            const CAddress& addr,
                                            CMasternodeSync& mn_sync)
{
    int nInbound = 0;
    int nVerifiedInboundMasternodes = 0;
    int nMaxInbound = nMaxConnections - m_max_outbound;

    AddWhitelistPermissionFlags(permission_flags, addr);
    if (NetPermissions::HasFlag(permission_flags, NetPermissionFlags::Implicit)) {
        NetPermissions::ClearFlag(permission_flags, NetPermissionFlags::Implicit);
        if (gArgs.GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) NetPermissions::AddFlag(permission_flags, NetPermissionFlags::ForceRelay);
        if (gArgs.GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY)) NetPermissions::AddFlag(permission_flags, NetPermissionFlags::Relay);
        NetPermissions::AddFlag(permission_flags, NetPermissionFlags::Mempool);
        NetPermissions::AddFlag(permission_flags, NetPermissionFlags::NoBan);
    }

    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->IsInboundConn()) {
                nInbound++;
                if (!pnode->GetVerifiedProRegTxHash().IsNull()) {
                    nVerifiedInboundMasternodes++;
                }
            }
        }

    }

    std::string strDropped;
    if (fLogIPs) {
        strDropped = strprintf("connection from %s dropped", addr.ToStringAddrPort());
    } else {
        strDropped = "connection dropped";
    }

    if (!fNetworkActive) {
        LogPrint(BCLog::NET_NETCONN, "%s: not accepting new connections\n", strDropped);
        return;
    }

    if (!sock->IsSelectable()) {
        LogPrintf("%s: non-selectable socket\n", strDropped);
        return;
    }

    // According to the internet TCP_NODELAY is not carried into accepted sockets
    // on all platforms.  Set it again here just to be sure.
    const int on{1};
    if (sock->SetSockOpt(IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == SOCKET_ERROR) {
        LogPrint(BCLog::NET, "connection from %s: unable to set TCP_NODELAY, continuing anyway\n",
                 addr.ToStringAddrPort());
    }

    // Don't accept connections from banned peers.
    bool banned = m_banman && m_banman->IsBanned(addr);
    if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan) && banned)
    {
        LogPrint(BCLog::NET, "%s (banned)\n", strDropped);
        return;
    }

    // Only accept connections from discouraged peers if our inbound slots aren't (almost) full.
    bool discouraged = m_banman && m_banman->IsDiscouraged(addr);
    if (!NetPermissions::HasFlag(permission_flags, NetPermissionFlags::NoBan) && nInbound + 1 >= nMaxInbound && discouraged)
    {
        LogPrint(BCLog::NET, "connection from %s dropped (discouraged)\n", addr.ToStringAddrPort());
        return;
    }

    // Evict connections until we are below nMaxInbound. In case eviction protection resulted in nodes to not be evicted
    // before, they might get evicted in batches now (after the protection timeout).
    // We don't evict verified MN connections and also don't take them into account when checking limits. We can do this
    // because we know that such connections are naturally limited by the total number of MNs, so this is not usable
    // for attacks.
    while (nInbound - nVerifiedInboundMasternodes >= nMaxInbound)
    {
        if (!AttemptToEvictConnection()) {
            // No connection to evict, disconnect the new connection
            LogPrint(BCLog::NET, "failed to find an eviction candidate - connection dropped (full)\n");
            return;
        }
        nInbound--;
    }

    // don't accept incoming connections until blockchain is synced
    if (fMasternodeMode && !mn_sync.IsBlockchainSynced()) {
        LogPrint(BCLog::NET, "AcceptConnection -- blockchain is not synced yet, skipping inbound connection attempt\n");
        return;
    }

    NodeId id = GetNewNodeId();
    uint64_t nonce = GetDeterministicRandomizer(RANDOMIZER_ID_LOCALHOSTNONCE).Write(id).Finalize();

    ServiceFlags nodeServices = nLocalServices;
    if (NetPermissions::HasFlag(permission_flags, NetPermissionFlags::BloomFilter)) {
        nodeServices = static_cast<ServiceFlags>(nodeServices | NODE_BLOOM);
    }

    const bool inbound_onion = std::find(m_onion_binds.begin(), m_onion_binds.end(), addr_bind) != m_onion_binds.end();
    // The V2Transport transparently falls back to V1 behavior when an incoming V1 connection is
    // detected, so use it whenever we signal NODE_P2P_V2.
    const bool use_v2transport(nodeServices & NODE_P2P_V2);

    CNode* pnode = new CNode(id,
                             std::move(sock),
                             addr,
                             CalculateKeyedNetGroup(addr),
                             nonce,
                             addr_bind,
                             /*addrNameIn=*/"",
                             ConnectionType::INBOUND,
                             inbound_onion,
                             CNodeOptions{
                                 .permission_flags = permission_flags,
                                 .prefer_evict = discouraged,
                                 .recv_flood_size = nReceiveFloodSize,
                                 .use_v2transport = use_v2transport,
                             });
    pnode->AddRef();
    m_msgproc->InitializeNode(*pnode, nodeServices);

    {
        LOCK(pnode->m_sock_mutex);
        if (fLogIPs) {
            LogPrint(BCLog::NET_NETCONN, "connection from %s accepted, sock=%d, peer=%d\n", addr.ToStringAddrPort(), pnode->m_sock->Get(), pnode->GetId());
        } else {
            LogPrint(BCLog::NET_NETCONN, "connection accepted, sock=%d, peer=%d\n", pnode->m_sock->Get(), pnode->GetId());
        }
    }

    {
        LOCK(m_nodes_mutex);
        m_nodes.push_back(pnode);
    }
    {
        LOCK2(cs_mapSocketToNode, pnode->m_sock_mutex);
        mapSocketToNode.emplace(pnode->m_sock->Get(), pnode);
        if (m_edge_trig_events) {
            if (!m_edge_trig_events->RegisterEvents(pnode->m_sock->Get())) {
                LogPrint(BCLog::NET, "EdgeTriggeredEvents::RegisterEvents() failed\n");
            }
        }
        if (m_wakeup_pipe) {
            m_wakeup_pipe->Write();
        }
    }

    // We received a new connection, harvest entropy from the time (and our peer count)
    RandAddEvent((uint32_t)id);
}

bool CConnman::AddConnection(const std::string& address, ConnectionType conn_type, bool use_v2transport = false)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    std::optional<int> max_connections;
    switch (conn_type) {
    case ConnectionType::INBOUND:
    case ConnectionType::MANUAL:
        return false;
    case ConnectionType::OUTBOUND_FULL_RELAY:
        max_connections = m_max_outbound_full_relay;
        break;
    case ConnectionType::BLOCK_RELAY:
        max_connections = m_max_outbound_block_relay;
        break;
    // no limit for ADDR_FETCH because -seednode has no limit either
    case ConnectionType::ADDR_FETCH:
        break;
    // no limit for FEELER connections since they're short-lived
    case ConnectionType::FEELER:
        break;
    } // no default case, so the compiler can warn about missing cases

    // Count existing connections
    int existing_connections = WITH_LOCK(m_nodes_mutex,
                                         return std::count_if(m_nodes.begin(), m_nodes.end(), [conn_type](CNode* node) { return node->m_conn_type == conn_type; }););

    // Max connections of specified type already exist
    if (max_connections != std::nullopt && existing_connections >= max_connections) return false;

    // Max total outbound connections already exist
    CSemaphoreGrant grant(*semOutbound, true);
    if (!grant) return false;

    OpenNetworkConnection(CAddress(), false, std::move(grant), address.c_str(), conn_type, /*use_v2transport=*/use_v2transport);
    return true;
}

void CConnman::DisconnectNodes()
{
    AssertLockNotHeld(m_nodes_mutex);
    AssertLockNotHeld(m_reconnections_mutex);

    // Use a temporary variable to accumulate desired reconnections, so we don't need
    // m_reconnections_mutex while holding m_nodes_mutex.
    decltype(m_reconnections) reconnections_to_add;

    {
        LOCK(m_nodes_mutex);

        if (!fNetworkActive) {
            // Disconnect any connected nodes
            for (CNode* pnode : m_nodes) {
                if (!pnode->fDisconnect) {
                    LogPrint(BCLog::NET, "Network not active, dropping peer=%d\n", pnode->GetId());
                    pnode->fDisconnect = true;
                }
            }
        }

        // Disconnect unused nodes
        for (auto it = m_nodes.begin(); it != m_nodes.end(); )
        {
            CNode* pnode = *it;
            if (pnode->fDisconnect)
            {
                // If we were the ones who initiated the disconnect, we must assume that the other side wants to see
                // pending messages. If the other side initiated the disconnect (or disconnected after we've shutdown
                // the socket), we can be pretty sure that they are not interested in any pending messages anymore and
                // thus can immediately close the socket.
                if (!pnode->fOtherSideDisconnected) {
                    if (pnode->nDisconnectLingerTime == 0) {
                        // let's not immediately close the socket but instead wait for at least 100ms so that there is a
                        // chance to flush all/some pending data. Otherwise the other side might not receive REJECT messages
                        // that were pushed right before setting fDisconnect=true
                        // Flushing must happen in two places to ensure data can be received by the other side:
                        //   1. vSendMsg must be empty and all messages sent via send(). This is ensured by SocketHandler()
                        //      being called before DisconnectNodes and also by the linger time
                        //   2. Internal socket send buffers must be flushed. This is ensured solely by the linger time
                        pnode->nDisconnectLingerTime = GetTimeMillis() + 100;
                    }
                    if (GetTimeMillis() < pnode->nDisconnectLingerTime) {
                        // everything flushed to the kernel?
                        const auto& [to_send, more, _msg_type] = pnode->m_transport->GetBytesToSend(pnode->nSendMsgSize != 0);
                        const bool queue_is_empty{to_send.empty() && !more};
                        if (!pnode->fSocketShutdown && queue_is_empty) {
                            LOCK(pnode->m_sock_mutex);
                            if (pnode->m_sock) {
                                // Give the other side a chance to detect the disconnect as early as possible (recv() will return 0)
                                ::shutdown(pnode->m_sock->Get(), SD_SEND);
                            }
                            pnode->fSocketShutdown = true;
                        }
                        ++it;
                        continue;
                    }
                }

                if (fLogIPs) {
                    LogPrintf("ThreadSocketHandler -- removing node: peer=%d addr=%s nRefCount=%d fInbound=%d m_masternode_connection=%d m_masternode_iqr_connection=%d\n",
                          pnode->GetId(), pnode->addr.ToStringAddrPort(), pnode->GetRefCount(), pnode->IsInboundConn(), pnode->m_masternode_connection, pnode->m_masternode_iqr_connection);
                } else {
                    LogPrintf("ThreadSocketHandler -- removing node: peer=%d nRefCount=%d fInbound=%d m_masternode_connection=%d m_masternode_iqr_connection=%d\n",
                          pnode->GetId(), pnode->GetRefCount(), pnode->IsInboundConn(), pnode->m_masternode_connection, pnode->m_masternode_iqr_connection);
                }

                // remove from m_nodes
                it = m_nodes.erase(it);

                // Add to reconnection list if appropriate. We don't reconnect right here, because
                // the creation of a connection is a blocking operation (up to several seconds),
                // and we don't want to hold up the socket handler thread for that long.
                if (pnode->m_transport->ShouldReconnectV1()) {
                    reconnections_to_add.push_back({
                        .addr_connect = pnode->addr,
                        .grant = std::move(pnode->grantOutbound),
                        .destination = pnode->m_dest,
                        .conn_type = pnode->m_conn_type,
                        .use_v2transport = false});
                    LogPrint(BCLog::NET, "retrying with v1 transport protocol for peer=%d\n", pnode->GetId());
                }

                // release outbound grant (if any)
                pnode->grantOutbound.Release();

                // close socket and cleanup
                pnode->CloseSocketDisconnect(this);

                // update connection count by network
                if (pnode->IsManualOrFullOutboundConn()) --m_network_conn_counts[pnode->addr.GetNetwork()];

                // hold in disconnected pool until all refs are released
                pnode->Release();
                m_nodes_disconnected.push_back(pnode);
            } else {
                ++it;
            }
        }
    }
    {
        // Delete disconnected nodes
        std::list<CNode*> nodes_disconnected_copy = m_nodes_disconnected;
        for (auto it = m_nodes_disconnected.begin(); it != m_nodes_disconnected.end(); )
        {
            CNode* pnode = *it;
            // Destroy the object only after other threads have stopped using it.
            if (pnode->GetRefCount() <= 0) {
                it = m_nodes_disconnected.erase(it);
                DeleteNode(pnode);
            } else {
                ++it;
            }
        }
    }
    {
        // Move entries from reconnections_to_add to m_reconnections.
        LOCK(m_reconnections_mutex);
        m_reconnections.splice(m_reconnections.end(), std::move(reconnections_to_add));
    }
}

void CConnman::NotifyNumConnectionsChanged(CMasternodeSync& mn_sync)
{
    size_t nodes_size;
    {
        LOCK(m_nodes_mutex);
        nodes_size = m_nodes.size();
    }

    // If we had zero connections before and new connections now or if we just dropped
    // to zero connections reset the sync process if its outdated.
    if ((nodes_size > 0 && nPrevNodeCount == 0) || (nodes_size == 0 && nPrevNodeCount > 0)) {
        mn_sync.Reset();
    }

    if (nodes_size != nPrevNodeCount) {
        nPrevNodeCount = nodes_size;
        if (m_client_interface) {
            m_client_interface->NotifyNumConnectionsChanged(nodes_size);
        }

        CalculateNumConnectionsChangedStats();
    }
}

void CConnman::CalculateNumConnectionsChangedStats()
{
    if (!::g_stats_client->active()) {
        return;
    }

    // count various node attributes for statsD
    int fullNodes = 0;
    int spvNodes = 0;
    int inboundNodes = 0;
    int outboundNodes = 0;
    int ipv4Nodes = 0;
    int ipv6Nodes = 0;
    int torNodes = 0;
    mapMsgTypeSize mapRecvBytesMsgStats;
    mapMsgTypeSize mapSentBytesMsgStats;
    for (const std::string &msg : getAllNetMessageTypes()) {
        mapRecvBytesMsgStats[msg] = 0;
        mapSentBytesMsgStats[msg] = 0;
    }
    mapRecvBytesMsgStats[NET_MESSAGE_TYPE_OTHER] = 0;
    mapSentBytesMsgStats[NET_MESSAGE_TYPE_OTHER] = 0;
    const NodesSnapshot snap{*this, /* filter = */ CConnman::FullyConnectedOnly};
    for (auto pnode : snap.Nodes()) {
        WITH_LOCK(pnode->cs_vRecv, pnode->UpdateRecvMapWithStats(mapRecvBytesMsgStats));
        WITH_LOCK(pnode->cs_vSend, pnode->UpdateSentMapWithStats(mapSentBytesMsgStats));
        if (pnode->m_bloom_filter_loaded.load()) {
            spvNodes++;
        } else {
            fullNodes++;
        }
        if(pnode->IsInboundConn())
            inboundNodes++;
        else
            outboundNodes++;
        if(pnode->addr.IsIPv4())
            ipv4Nodes++;
        if(pnode->addr.IsIPv6())
            ipv6Nodes++;
        if(pnode->addr.IsTor())
            torNodes++;
        const auto last_ping_time = count_microseconds(pnode->m_last_ping_time);
        if (last_ping_time > 0)
            ::g_stats_client->timing("peers.ping_us", last_ping_time, 1.0f);
    }
    for (const std::string &msg : getAllNetMessageTypes()) {
        ::g_stats_client->gauge("bandwidth.message." + msg + ".totalBytesReceived", mapRecvBytesMsgStats[msg], 1.0f);
        ::g_stats_client->gauge("bandwidth.message." + msg + ".totalBytesSent", mapSentBytesMsgStats[msg], 1.0f);
    }
    ::g_stats_client->gauge("peers.totalConnections", nPrevNodeCount, 1.0f);
    ::g_stats_client->gauge("peers.spvNodeConnections", spvNodes, 1.0f);
    ::g_stats_client->gauge("peers.fullNodeConnections", fullNodes, 1.0f);
    ::g_stats_client->gauge("peers.inboundConnections", inboundNodes, 1.0f);
    ::g_stats_client->gauge("peers.outboundConnections", outboundNodes, 1.0f);
    ::g_stats_client->gauge("peers.ipv4Connections", ipv4Nodes, 1.0f);
    ::g_stats_client->gauge("peers.ipv6Connections", ipv6Nodes, 1.0f);
    ::g_stats_client->gauge("peers.torConnections", torNodes, 1.0f);
}

bool CConnman::ShouldRunInactivityChecks(const CNode& node, std::chrono::seconds now) const
{
    return node.m_connected + m_peer_connect_timeout < now;
}

bool CConnman::InactivityCheck(const CNode& node) const
{
    // Tests that see disconnects after using mocktime can start nodes with a
    // large timeout. For example, -peertimeout=999999999.
    const auto now{GetTime<std::chrono::seconds>()};
    const auto last_send{node.m_last_send.load()};
    const auto last_recv{node.m_last_recv.load()};

    if (!ShouldRunInactivityChecks(node, now)) return false;

    if (last_recv.count() == 0 || last_send.count() == 0) {
        LogPrint(BCLog::NET, "socket no message in first %i seconds, %d %d peer=%d\n", count_seconds(m_peer_connect_timeout), last_recv.count() != 0, last_send.count() != 0, node.GetId());
        return true;
    }

    if (now > last_send + TIMEOUT_INTERVAL) {
        LogPrint(BCLog::NET, "socket sending timeout: %is peer=%d\n", count_seconds(now - last_send), node.GetId());
        return true;
    }

    if (now > last_recv + TIMEOUT_INTERVAL) {
        LogPrint(BCLog::NET, "socket receive timeout: %is peer=%d\n", count_seconds(now - last_recv), node.GetId());
        return true;
    }

    if (!node.fSuccessfullyConnected) {
        if (node.m_transport->GetInfo().transport_type == TransportProtocolType::DETECTING) {
            LogPrint(BCLog::NET, "V2 handshake timeout peer=%d\n", node.GetId());
        } else {
            LogPrint(BCLog::NET, "version handshake timeout peer=%d\n", node.GetId());
        }
        return true;
    }

    return false;
}

bool CConnman::GenerateSelectSet(const std::vector<CNode*>& nodes,
                                 std::set<SOCKET>& recv_set,
                                 std::set<SOCKET>& send_set,
                                 std::set<SOCKET>& error_set)
{
    for (const ListenSocket& hListenSocket : vhListenSocket) {
        recv_set.insert(hListenSocket.sock->Get());
    }

    for (CNode* pnode : nodes) {
        bool select_recv = !pnode->fHasRecvData;
        bool select_send = !pnode->fCanSendData;
        if (!select_recv && !select_send) continue;

        LOCK(pnode->m_sock_mutex);
        if (!pnode->m_sock) {
            continue;
        }

        error_set.insert(pnode->m_sock->Get());
        if (select_send) {
            send_set.insert(pnode->m_sock->Get());
        }
        if (select_recv) {
            recv_set.insert(pnode->m_sock->Get());
        }
    }

    if (m_wakeup_pipe) {
        // We add a pipe to the read set so that the select() call can be woken up from the outside
        // This is done when data is added to send buffers (vSendMsg) or when new peers are added
        // This is currently only implemented for POSIX compliant systems. This means that Windows will fall back to
        // timing out after 50ms and then trying to send. This is ok as we assume that heavy-load daemons are usually
        // run on Linux and friends.
        recv_set.insert(m_wakeup_pipe->m_pipe[0]);
    }

    return !recv_set.empty() || !send_set.empty() || !error_set.empty();
}

#ifdef USE_KQUEUE
void CConnman::SocketEventsKqueue(std::set<SOCKET>& recv_set,
                                  std::set<SOCKET>& send_set,
                                  std::set<SOCKET>& error_set,
                                  bool only_poll)
{
    const size_t maxEvents = 64;
    struct kevent events[maxEvents];

    struct timespec timeout;
    timeout.tv_sec = only_poll ? 0 : SELECT_TIMEOUT_MILLISECONDS / 1000;
    timeout.tv_nsec = (only_poll ? 0 : SELECT_TIMEOUT_MILLISECONDS % 1000) * 1000 * 1000;

    int n{-1};
    ToggleWakeupPipe([&](){n = kevent(Assert(m_edge_trig_events)->GetFileDescriptor(), nullptr, 0, events, maxEvents, &timeout);});
    if (n == -1) {
        LogPrintf("kevent wait error\n");
    } else if (n > 0) {
        for (int i = 0; i < n; i++) {
            auto& event = events[i];
            if ((event.flags & EV_ERROR) || (event.flags & EV_EOF)) {
                error_set.insert((SOCKET)event.ident);
                continue;
            }

            if (event.filter == EVFILT_READ) {
                recv_set.insert((SOCKET)event.ident);
            }

            if (event.filter == EVFILT_WRITE) {
                send_set.insert((SOCKET)event.ident);
            }
        }
    }
}
#endif

#ifdef USE_EPOLL
void CConnman::SocketEventsEpoll(std::set<SOCKET>& recv_set,
                                 std::set<SOCKET>& send_set,
                                 std::set<SOCKET>& error_set,
                                 bool only_poll)
{
    const size_t maxEvents = 64;
    epoll_event events[maxEvents];

    int n{-1};
    ToggleWakeupPipe([&](){n = epoll_wait(Assert(m_edge_trig_events)->GetFileDescriptor(), events, maxEvents, only_poll ? 0 : SELECT_TIMEOUT_MILLISECONDS);});
    for (int i = 0; i < n; i++) {
        auto& e = events[i];
        if((e.events & EPOLLERR) || (e.events & EPOLLHUP)) {
            error_set.insert((SOCKET)e.data.fd);
            continue;
        }

        if (e.events & EPOLLIN) {
            recv_set.insert((SOCKET)e.data.fd);
        }

        if (e.events & EPOLLOUT) {
            send_set.insert((SOCKET)e.data.fd);
        }
    }
}
#endif

#ifdef USE_POLL
void CConnman::SocketEventsPoll(const std::vector<CNode*>& nodes,
                                std::set<SOCKET>& recv_set,
                                std::set<SOCKET>& send_set,
                                std::set<SOCKET>& error_set,
                                bool only_poll)
{
    std::set<SOCKET> recv_select_set, send_select_set, error_select_set;
    if (!GenerateSelectSet(nodes, recv_select_set, send_select_set, error_select_set)) {
        if (!only_poll) interruptNet.sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS));
        return;
    }

    std::unordered_map<SOCKET, struct pollfd> pollfds;
    for (SOCKET socket_id : recv_select_set) {
        pollfds[socket_id].fd = socket_id;
        pollfds[socket_id].events |= POLLIN;
    }

    for (SOCKET socket_id : send_select_set) {
        pollfds[socket_id].fd = socket_id;
        pollfds[socket_id].events |= POLLOUT;
    }

    for (SOCKET socket_id : error_select_set) {
        pollfds[socket_id].fd = socket_id;
        // These flags are ignored, but we set them for clarity
        pollfds[socket_id].events |= POLLERR|POLLHUP;
    }

    std::vector<struct pollfd> vpollfds;
    vpollfds.reserve(pollfds.size());
    for (auto it : pollfds) {
        vpollfds.push_back(std::move(it.second));
    }

    int r{-1};
    ToggleWakeupPipe([&](){r = poll(vpollfds.data(), vpollfds.size(), only_poll ? 0 : SELECT_TIMEOUT_MILLISECONDS);});
    if (r < 0) {
        return;
    }

    if (interruptNet) return;

    for (struct pollfd pollfd_entry : vpollfds) {
        if (pollfd_entry.revents & POLLIN)            recv_set.insert(pollfd_entry.fd);
        if (pollfd_entry.revents & POLLOUT)           send_set.insert(pollfd_entry.fd);
        if (pollfd_entry.revents & (POLLERR|POLLHUP)) error_set.insert(pollfd_entry.fd);
    }
}
#endif

void CConnman::SocketEventsSelect(const std::vector<CNode*>& nodes,
                                  std::set<SOCKET>& recv_set,
                                  std::set<SOCKET>& send_set,
                                  std::set<SOCKET>& error_set,
                                  bool only_poll)
{
    std::set<SOCKET> recv_select_set, send_select_set, error_select_set;
    if (!GenerateSelectSet(nodes, recv_select_set, send_select_set, error_select_set)) {
        interruptNet.sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS));
        return;
    }

    //
    // Find which sockets have data to receive
    //
    struct timeval timeout;
    timeout.tv_sec  = 0;
    timeout.tv_usec = only_poll ? 0 : SELECT_TIMEOUT_MILLISECONDS * 1000; // frequency to poll pnode->vSend

    fd_set fdsetRecv;
    fd_set fdsetSend;
    fd_set fdsetError;
    FD_ZERO(&fdsetRecv);
    FD_ZERO(&fdsetSend);
    FD_ZERO(&fdsetError);
    SOCKET hSocketMax = 0;

    for (SOCKET hSocket : recv_select_set) {
        FD_SET(hSocket, &fdsetRecv);
        hSocketMax = std::max(hSocketMax, hSocket);
    }

    for (SOCKET hSocket : send_select_set) {
        FD_SET(hSocket, &fdsetSend);
        hSocketMax = std::max(hSocketMax, hSocket);
    }

    for (SOCKET hSocket : error_select_set) {
        FD_SET(hSocket, &fdsetError);
        hSocketMax = std::max(hSocketMax, hSocket);
    }

    int nSelect{-1};
    ToggleWakeupPipe([&](){nSelect = select(hSocketMax + 1, &fdsetRecv, &fdsetSend, &fdsetError, &timeout);});
    if (interruptNet)
        return;

    if (nSelect == SOCKET_ERROR)
    {
        int nErr = WSAGetLastError();
        LogPrintf("socket select error %s\n", NetworkErrorString(nErr));
        for (unsigned int i = 0; i <= hSocketMax; i++)
            FD_SET(i, &fdsetRecv);
        FD_ZERO(&fdsetSend);
        FD_ZERO(&fdsetError);
        if (!interruptNet.sleep_for(std::chrono::milliseconds(SELECT_TIMEOUT_MILLISECONDS)))
            return;
    }

    for (SOCKET hSocket : recv_select_set) {
        if (FD_ISSET(hSocket, &fdsetRecv)) {
            recv_set.insert(hSocket);
        }
    }

    for (SOCKET hSocket : send_select_set) {
        if (FD_ISSET(hSocket, &fdsetSend)) {
            send_set.insert(hSocket);
        }
    }

    for (SOCKET hSocket : error_select_set) {
        if (FD_ISSET(hSocket, &fdsetError)) {
            error_set.insert(hSocket);
        }
    }
}

void CConnman::SocketEvents(const std::vector<CNode*>& nodes,
                            std::set<SOCKET>& recv_set,
                            std::set<SOCKET>& send_set,
                            std::set<SOCKET>& error_set,
                            bool only_poll)
{
    switch (socketEventsMode) {
#ifdef USE_KQUEUE
        case SocketEventsMode::KQueue:
            SocketEventsKqueue(recv_set, send_set, error_set, only_poll);
            break;
#endif
#ifdef USE_EPOLL
        case SocketEventsMode::EPoll:
            SocketEventsEpoll(recv_set, send_set, error_set, only_poll);
            break;
#endif
#ifdef USE_POLL
        case SocketEventsMode::Poll:
            SocketEventsPoll(nodes, recv_set, send_set, error_set, only_poll);
            break;
#endif
        case SocketEventsMode::Select:
            SocketEventsSelect(nodes, recv_set, send_set, error_set, only_poll);
            break;
        default:
            assert(false);
    }
}

void CConnman::SocketHandler(CMasternodeSync& mn_sync)
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);

    std::set<SOCKET> recv_set;
    std::set<SOCKET> send_set;
    std::set<SOCKET> error_set;

    bool only_poll = [this]() {
        // Check if we have work to do and thus should avoid waiting for events
        LOCK2(m_nodes_mutex, cs_sendable_receivable_nodes);
        if (!mapReceivableNodes.empty()) {
            return true;
        }
        for (const auto& p : mapSendableNodes) {
            const auto& [to_send, more, _msg_type] = p.second->m_transport->GetBytesToSend(p.second->nSendMsgSize != 0);
            if (!to_send.empty()) {
                return true;
            }
        }
        return false;
    }();

    {
        const NodesSnapshot snap{*this, /* filter = */ CConnman::AllNodes, /* shuffle = */ false};

        // Check for the readiness of the already connected sockets and the
        // listening sockets in one call ("readiness" as in poll(2) or
        // select(2)). If none are ready, wait for a short while and return
        // empty sets.
        SocketEvents(snap.Nodes(), recv_set, send_set, error_set, only_poll);

    // Drain the wakeup pipe
    if (m_wakeup_pipe && recv_set.count(m_wakeup_pipe->m_pipe[0])) {
        m_wakeup_pipe->Drain();
    }

        // Service (send/receive) each of the already connected nodes.
        SocketHandlerConnected(recv_set, send_set, error_set);
    }

    // Accept new connections from listening sockets.
    SocketHandlerListening(recv_set, mn_sync);
}

void CConnman::SocketHandlerConnected(const std::set<SOCKET>& recv_set,
                                      const std::set<SOCKET>& send_set,
                                      const std::set<SOCKET>& error_set)
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);

    if (interruptNet) return;

    std::set<CNode*> vErrorNodes;
    std::set<CNode*> vReceivableNodes;
    std::set<CNode*> vSendableNodes;
    {
        LOCK(cs_mapSocketToNode);
        for (auto hSocket : error_set) {
            auto it = mapSocketToNode.find(hSocket);
            if (it == mapSocketToNode.end()) {
                continue;
            }
            it->second->AddRef();
            vErrorNodes.emplace(it->second);
        }
        for (auto hSocket : recv_set) {
            if (error_set.count(hSocket)) {
                // no need to handle it twice
                continue;
            }

            auto it = mapSocketToNode.find(hSocket);
            if (it == mapSocketToNode.end()) {
                continue;
            }

            LOCK(cs_sendable_receivable_nodes);
            auto jt = mapReceivableNodes.emplace(it->second->GetId(), it->second);
            assert(jt.first->second == it->second);
            it->second->fHasRecvData = true;
        }
        for (auto hSocket : send_set) {
            auto it = mapSocketToNode.find(hSocket);
            if (it == mapSocketToNode.end()) {
                continue;
            }

            LOCK(cs_sendable_receivable_nodes);
            auto jt = mapSendableNodes.emplace(it->second->GetId(), it->second);
            assert(jt.first->second == it->second);
            it->second->fCanSendData = true;
        }
    }

    ForEachNode(AllNodes, [&](CNode* pnode) {
        const auto& [to_send, more, _msg_type] = pnode->m_transport->GetBytesToSend(pnode->nSendMsgSize != 0);
        // Collect nodes that have a receivable socket, implement the following logic:
        // * If there is data to send, try sending data. As this only
        //   happens when optimistic write failed, we choose to first drain the
        //   write buffer in this case before receiving more. This avoids
        //   needlessly queueing received data, if the remote peer is not themselves
        //   receiving data. This means properly utilizing TCP flow control signalling.
        // * Otherwise, if there is space left in the receive buffer (!fPauseRecv), try
        //   receiving data (which should succeed as the socket signalled as receivable).
        if (pnode->fHasRecvData && !pnode->fPauseRecv && !pnode->fDisconnect &&
            (!pnode->m_transport->ReceivedMessageComplete() || to_send.empty())) {
            pnode->AddRef();
            vReceivableNodes.emplace(pnode);
        }

        // Collect nodes that have data to send and have a socket with non-empty write buffers
        if (pnode->fCanSendData && (!pnode->m_transport->ReceivedMessageComplete() || !to_send.empty())) {
            pnode->AddRef();
            vSendableNodes.emplace(pnode);
        }
    });

    for (CNode* pnode : vSendableNodes) {
        if (interruptNet) {
            break;
        }

        // Send data
        auto [bytes_sent, data_left] = WITH_LOCK(pnode->cs_vSend, return SocketSendData(*pnode));
        if (bytes_sent) {
            RecordBytesSent(bytes_sent);

            // If both receiving and (non-optimistic) sending were possible, we first attempt
            // sending. If that succeeds, but does not fully drain the send queue, do not
            // attempt to receive. This avoids needlessly queueing data if the remote peer
            // is slow at receiving data, by means of TCP flow control. We only do this when
            // sending actually succeeded to make sure progress is always made; otherwise a
            // deadlock would be possible when both sides have data to send, but neither is
            // receiving.
            if (data_left && vReceivableNodes.erase(pnode)) {
                pnode->Release();
            }
        }
    }

    for (CNode* pnode : vErrorNodes)
    {
        if (interruptNet) {
            break;
        }
        // let recv() return errors and then handle it
        SocketRecvData(pnode);
    }

    for (CNode* pnode : vReceivableNodes)
    {
        if (interruptNet) {
            break;
        }
        if (pnode->fPauseRecv) {
            continue;
        }

        SocketRecvData(pnode);
    }

    for (auto& node : vErrorNodes) {
        node->Release();
    }
    for (auto& node : vReceivableNodes) {
        node->Release();
    }
    for (auto& node : vSendableNodes) {
        node->Release();
    }

    if (interruptNet) {
        return;
    }

    {
        LOCK(cs_sendable_receivable_nodes);
        // remove nodes from mapSendableNodes, so that the next iteration knows that there is no work to do
        // (even if there are pending messages to be sent)
        for (auto it = mapSendableNodes.begin(); it != mapSendableNodes.end(); ) {
            if (!it->second->fCanSendData) {
                LogPrint(BCLog::NET, "%s -- remove mapSendableNodes, peer=%d\n", __func__, it->second->GetId());
                it = mapSendableNodes.erase(it);
            } else {
                ++it;
            }
        }
        // clean up mapReceivableNodes from nodes that were receivable in the last iteration but aren't anymore
        for (auto it = mapReceivableNodes.begin(); it != mapReceivableNodes.end(); ) {
            if (!it->second->fHasRecvData) {
                LogPrint(BCLog::NET, "%s -- remove mapReceivableNodes, peer=%d\n", __func__, it->second->GetId());
                it = mapReceivableNodes.erase(it);
            } else {
                ++it;
            }
        }
    }
}

void CConnman::SocketHandlerListening(const std::set<SOCKET>& recv_set, CMasternodeSync& mn_sync)
{
    for (const ListenSocket& listen_socket : vhListenSocket) {
        if (interruptNet) {
            return;
        }
        if (recv_set.count(listen_socket.sock->Get()) > 0) {
            AcceptConnection(listen_socket, mn_sync);
        }
    }
}

size_t CConnman::SocketRecvData(CNode *pnode)
{
    // typical socket buffer is 8K-64K
    uint8_t pchBuf[0x10000];
    int nBytes = 0;
    {
        LOCK(pnode->m_sock_mutex);
        if (!pnode->m_sock)
            return 0;
        nBytes = recv(pnode->m_sock->Get(), (char*)pchBuf, sizeof(pchBuf), MSG_DONTWAIT);
        if (nBytes < (int)sizeof(pchBuf)) {
            pnode->fHasRecvData = false;
        }
    }
    if (nBytes > 0)
    {
        bool notify = false;
        if (!pnode->ReceiveMsgBytes(Span<const uint8_t>(pchBuf, nBytes), notify)) {
            LOCK(m_nodes_mutex);
            pnode->CloseSocketDisconnect(this);
        }
        RecordBytesRecv(nBytes);
        if (notify) {
            pnode->MarkReceivedMsgsForProcessing();
            WakeMessageHandler();
        }
    }
    else if (nBytes == 0)
    {
        // socket closed gracefully
        if (!pnode->fDisconnect) {
            LogPrint(BCLog::NET, "socket closed for peer=%d\n", pnode->GetId());
        }
        LOCK(m_nodes_mutex);
        pnode->fOtherSideDisconnected = true; // avoid lingering
        pnode->CloseSocketDisconnect(this);
    }
    else if (nBytes < 0)
    {
        // error
        int nErr = WSAGetLastError();
        if (nErr != WSAEWOULDBLOCK && nErr != WSAEMSGSIZE && nErr != WSAEINTR && nErr != WSAEINPROGRESS)
        {
            if (!pnode->fDisconnect){
                LogPrint(BCLog::NET, "socket recv error for peer=%d: %s\n", pnode->GetId(), NetworkErrorString(nErr));
            }
            LOCK(m_nodes_mutex);
            pnode->fOtherSideDisconnected = true; // avoid lingering
            pnode->CloseSocketDisconnect(this);
        }
    }
    if (nBytes < 0) {
        return 0;
    }
    return (size_t)nBytes;
}

void CConnman::ThreadSocketHandler(CMasternodeSync& mn_sync)
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);

    int64_t nLastCleanupNodes = 0;

    while (!interruptNet)
    {
        // Handle sockets before we do the next round of disconnects. This allows us to flush send buffers one last time
        // before actually closing sockets. Receiving is however skipped in case a peer is pending to be disconnected
        SocketHandler(mn_sync);
        if (GetTimeMillis() - nLastCleanupNodes > 1000) {
            ForEachNode(AllNodes, [&](CNode* pnode) {
                if (InactivityCheck(*pnode)) pnode->fDisconnect = true;
            });
            nLastCleanupNodes = GetTimeMillis();
        }
        DisconnectNodes();
        NotifyNumConnectionsChanged(mn_sync);
    }
}

void CConnman::WakeMessageHandler()
{
    {
        LOCK(mutexMsgProc);
        fMsgProcWake = true;
    }
    condMsgProc.notify_one();
}

void CConnman::ThreadDNSAddressSeed()
{
    FastRandomContext rng;
    std::vector<std::string> seeds = Params().DNSSeeds();
    Shuffle(seeds.begin(), seeds.end(), rng);
    int seeds_right_now = 0; // Number of seeds left before testing if we have enough connections
    int found = 0;

    if (gArgs.GetBoolArg("-forcednsseed", DEFAULT_FORCEDNSSEED)) {
        // When -forcednsseed is provided, query all.
        seeds_right_now = seeds.size();
    } else if (addrman.Size() == 0) {
        // If we have no known peers, query all.
        // This will occur on the first run, or if peers.dat has been
        // deleted.
        seeds_right_now = seeds.size();
    }

    // goal: only query DNS seed if address need is acute
    // * If we have a reasonable number of peers in addrman, spend
    //   some time trying them first. This improves user privacy by
    //   creating fewer identifying DNS requests, reduces trust by
    //   giving seeds less influence on the network topology, and
    //   reduces traffic to the seeds.
    // * When querying DNS seeds query a few at once, this ensures
    //   that we don't give DNS seeds the ability to eclipse nodes
    //   that query them.
    // * If we continue having problems, eventually query all the
    //   DNS seeds, and if that fails too, also try the fixed seeds.
    //   (done in ThreadOpenConnections)
    const std::chrono::seconds seeds_wait_time = (addrman.Size() >= DNSSEEDS_DELAY_PEER_THRESHOLD ? DNSSEEDS_DELAY_MANY_PEERS : DNSSEEDS_DELAY_FEW_PEERS);

    for (const std::string& seed : seeds) {
        if (seeds_right_now == 0) {
            seeds_right_now += DNSSEEDS_TO_QUERY_AT_ONCE;

            if (addrman.Size() > 0) {
                LogPrintf("Waiting %d seconds before querying DNS seeds.\n", seeds_wait_time.count());
                std::chrono::seconds to_wait = seeds_wait_time;
                while (to_wait.count() > 0) {
                    // if sleeping for the MANY_PEERS interval, wake up
                    // early to see if we have enough peers and can stop
                    // this thread entirely freeing up its resources
                    std::chrono::seconds w = std::min(DNSSEEDS_DELAY_FEW_PEERS, to_wait);
                    if (!interruptNet.sleep_for(w)) return;
                    to_wait -= w;

                    int nRelevant = 0;
                    {
                        LOCK(m_nodes_mutex);
                        for (const CNode* pnode : m_nodes) {
                            if (pnode->fSuccessfullyConnected && !pnode->IsFullOutboundConn() && !pnode->m_masternode_probe_connection) ++nRelevant;
                        }
                    }
                    if (nRelevant >= 2) {
                        if (found > 0) {
                            LogPrintf("%d addresses found from DNS seeds\n", found);
                            LogPrintf("P2P peers available. Finished DNS seeding.\n");
                        } else {
                            LogPrintf("P2P peers available. Skipped DNS seeding.\n");
                        }
                        return;
                    }
                }
            }
        }

        if (interruptNet) return;

        // hold off on querying seeds if P2P network deactivated
        if (!fNetworkActive) {
            LogPrintf("Waiting for network to be reactivated before querying DNS seeds.\n");
            do {
                if (!interruptNet.sleep_for(std::chrono::seconds{1})) return;
            } while (!fNetworkActive);
        }

        LogPrintf("Loading addresses from DNS seed %s\n", seed);
        // If -proxy is in use, we make an ADDR_FETCH connection to the DNS resolved peer address
        // for the base dns seed domain in chainparams
        if (HaveNameProxy()) {
            AddAddrFetch(seed);
        } else {
            std::vector<CAddress> vAdd;
            ServiceFlags requiredServiceBits = GetDesirableServiceFlags(NODE_NONE);
            std::string host = strprintf("x%x.%s", requiredServiceBits, seed);
            CNetAddr resolveSource;
            if (!resolveSource.SetInternal(host)) {
                continue;
            }
            // Limit number of IPs learned from a single DNS seed. This limit exists to prevent the results from
            // one DNS seed from dominating AddrMan. Note that the number of results from a UDP DNS query is
            // bounded to 33 already, but it is possible for it to use TCP where a larger number of results can be
            // returned.
            unsigned int nMaxIPs = 32;
            const auto addresses{LookupHost(host, nMaxIPs, true)};
            if (!addresses.empty()) {
                for (const CNetAddr& ip : addresses) {
                    CAddress addr = CAddress(CService(ip, Params().GetDefaultPort()), requiredServiceBits);
                    addr.nTime = rng.rand_uniform_delay(Now<NodeSeconds>() - 3 * 24h, -4 * 24h); // use a random age between 3 and 7 days old
                    vAdd.push_back(addr);
                    found++;
                }
                addrman.Add(vAdd, resolveSource);
            } else {
                // If the seed does not support a subdomain with our desired service bits,
                // we make an ADDR_FETCH connection to the DNS resolved peer address for the
                // base dns seed domain in chainparams
                AddAddrFetch(seed);
            }
        }
        --seeds_right_now;
    }
    LogPrintf("%d addresses found from DNS seeds\n", found);
}

void CConnman::DumpAddresses()
{
    const auto start{SteadyClock::now()};

    DumpPeerAddresses(::gArgs, addrman);

    LogPrint(BCLog::NET, "Flushed %d addresses to peers.dat  %dms\n",
             addrman.Size(), Ticks<std::chrono::milliseconds>(SteadyClock::now() - start));
}

void CConnman::ProcessAddrFetch()
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    std::string strDest;
    {
        LOCK(m_addr_fetches_mutex);
        if (m_addr_fetches.empty())
            return;
        strDest = m_addr_fetches.front();
        m_addr_fetches.pop_front();
    }
    // Attempt v2 connection if we support v2 - we'll reconnect with v1 if our
    // peer doesn't support it or immediately disconnects us for another reason.
    const bool use_v2transport(GetLocalServices() & NODE_P2P_V2);
    CAddress addr;
    CSemaphoreGrant grant(*semOutbound, /*fTry=*/true);
    if (grant) {
        OpenNetworkConnection(addr, false, std::move(grant), strDest.c_str(), ConnectionType::ADDR_FETCH, use_v2transport);
    }
}

bool CConnman::GetTryNewOutboundPeer() const
{
    return m_try_another_outbound_peer;
}

void CConnman::SetTryNewOutboundPeer(bool flag)
{
    m_try_another_outbound_peer = flag;
    LogPrint(BCLog::NET, "net: setting try another outbound peer=%s\n", flag ? "true" : "false");
}

void CConnman::StartExtraBlockRelayPeers()
{
    LogPrint(BCLog::NET, "net: enabling extra block-relay-only peers\n");
    m_start_extra_block_relay_peers = true;
}

// Return the number of peers we have over our outbound connection limit
// Exclude peers that are marked for disconnect, or are going to be
// disconnected soon (eg ADDR_FETCH and FEELER)
// Also exclude peers that haven't finished initial connection handshake yet
// (so that we don't decide we're over our desired connection limit, and then
// evict some peer that has finished the handshake)
int CConnman::GetExtraFullOutboundCount() const
{
    int full_outbound_peers = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            // don't count outbound masternodes
            if (pnode->m_masternode_connection) {
                continue;
            }
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect && pnode->IsFullOutboundConn() && !pnode->m_masternode_probe_connection) {
                ++full_outbound_peers;
            }
        }
    }
    return std::max(full_outbound_peers - m_max_outbound_full_relay, 0);
}

int CConnman::GetExtraBlockRelayCount() const
{
    int block_relay_peers = 0;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->fSuccessfullyConnected && !pnode->fDisconnect && pnode->IsBlockOnlyConn()) {
                ++block_relay_peers;
            }
        }
    }
    return std::max(block_relay_peers - m_max_outbound_block_relay, 0);
}

std::unordered_set<Network> CConnman::GetReachableEmptyNetworks() const
{
    std::unordered_set<Network> networks{};
    for (int n = 0; n < NET_MAX; n++) {
        enum Network net = (enum Network)n;
        if (net == NET_UNROUTABLE || net == NET_INTERNAL) continue;
        if (IsReachable(net) && addrman.Size(net, std::nullopt) == 0) {
            networks.insert(net);
        }
    }
    return networks;
}

bool CConnman::MultipleManualOrFullOutboundConns(Network net) const
{
    AssertLockHeld(m_nodes_mutex);
    return m_network_conn_counts[net] > 1;
}

bool CConnman::MaybePickPreferredNetwork(std::optional<Network>& network)
{
    std::array<Network, 5> nets{NET_IPV4, NET_IPV6, NET_ONION, NET_I2P, NET_CJDNS};
    Shuffle(nets.begin(), nets.end(), FastRandomContext());

    LOCK(m_nodes_mutex);
    for (const auto net : nets) {
        if (IsReachable(net) && m_network_conn_counts[net] == 0 && addrman.Size(net) != 0) {
            network = net;
            return true;
        }
    }

    return false;
}

void CConnman::ThreadOpenConnections(const std::vector<std::string> connect, CDeterministicMNManager& dmnman)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    AssertLockNotHeld(m_reconnections_mutex);
    FastRandomContext rng;
    // Connect to specific addresses
    if (!connect.empty())
    {
        // Attempt v2 connection if we support v2 - we'll reconnect with v1 if our
        // peer doesn't support it or immediately disconnects us for another reason.
        const bool use_v2transport(GetLocalServices() & NODE_P2P_V2);
        for (int64_t nLoop = 0;; nLoop++)
        {
            for (const std::string& strAddr : connect)
            {
                CAddress addr(CService(), NODE_NONE);
                OpenNetworkConnection(addr, false, {}, strAddr.c_str(), ConnectionType::MANUAL, /*use_v2transport=*/use_v2transport);
                for (int i = 0; i < 10 && i < nLoop; i++)
                {
                    if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
                        return;
                }
            }
            if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
                return;
            PerformReconnections();
        }
    }

    // Initiate network connections
    auto start = GetTime<std::chrono::microseconds>();

    // Minimum time before next feeler connection (in microseconds).
    auto next_feeler = GetExponentialRand(start, FEELER_INTERVAL);
    auto next_extra_block_relay = GetExponentialRand(start, EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
    auto next_extra_network_peer{GetExponentialRand(start, EXTRA_NETWORK_PEER_INTERVAL)};
    const bool dnsseed = gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED);
    bool add_fixed_seeds = gArgs.GetBoolArg("-fixedseeds", DEFAULT_FIXEDSEEDS);
    const bool use_seednodes{gArgs.IsArgSet("-seednode")};

    if (!add_fixed_seeds) {
        LogPrintf("Fixed seeds are disabled\n");
    }

    while (!interruptNet)
    {
        ProcessAddrFetch();

        if (!interruptNet.sleep_for(std::chrono::milliseconds(500)))
            return;

        PerformReconnections();

        CSemaphoreGrant grant(*semOutbound);
        if (interruptNet)
            return;

        const std::unordered_set<Network> fixed_seed_networks{GetReachableEmptyNetworks()};
        if (add_fixed_seeds && !fixed_seed_networks.empty()) {
            // When the node starts with an empty peers.dat, there are a few other sources of peers before
            // we fallback on to fixed seeds: -dnsseed, -seednode, -addnode
            // If none of those are available, we fallback on to fixed seeds immediately, else we allow
            // 60 seconds for any of those sources to populate addrman.
            bool add_fixed_seeds_now = false;
            // It is cheapest to check if enough time has passed first.
            if (GetTime<std::chrono::seconds>() > start + std::chrono::minutes{1}) {
                add_fixed_seeds_now = true;
                LogPrintf("Adding fixed seeds as 60 seconds have passed and addrman is empty for at least one reachable network\n");
            }

            // Perform cheap checks before locking a mutex.
            else if (!dnsseed && !use_seednodes) {
                LOCK(m_added_nodes_mutex);
                if (m_added_node_params.empty()) {
                    add_fixed_seeds_now = true;
                    LogPrintf("Adding fixed seeds as -dnsseed=0 (or IPv4/IPv6 connections are disabled via -onlynet) and neither -addnode nor -seednode are provided\n");
                }
            }

            if (add_fixed_seeds_now) {
                std::vector<CAddress> seed_addrs{ConvertSeeds(Params().FixedSeeds())};
                // We will not make outgoing connections to peers that are unreachable
                // (e.g. because of -onlynet configuration).
                // Therefore, we do not add them to addrman in the first place.
                // In case previously unreachable networks become reachable
                // (e.g. in case of -onlynet changes by the user), fixed seeds will
                // be loaded only for networks for which we have no addresses.
                seed_addrs.erase(std::remove_if(seed_addrs.begin(), seed_addrs.end(),
                                                [&fixed_seed_networks](const CAddress& addr) { return fixed_seed_networks.count(addr.GetNetwork()) == 0; }),
                                 seed_addrs.end());
                CNetAddr local;
                local.SetInternal("fixedseeds");
                addrman.Add(seed_addrs, local);
                add_fixed_seeds = false;
                LogPrintf("Added %d fixed seeds from reachable networks.\n", seed_addrs.size());
            }
        }

        //
        // Choose an address to connect to based on most recently seen
        //
        CAddress addrConnect;

        // Only connect out to one peer per ipv4/ipv6 network group (/16 for IPv4).
        // This is only done for mainnet and testnet
        int nOutboundFullRelay = 0;
        int nOutboundBlockRelay = 0;
        int nOutboundOnionRelay = 0;
        int outbound_privacy_network_peers = 0;
        std::set<std::vector<unsigned char>> outbound_ipv46_peer_netgroups;

        if (!Params().AllowMultipleAddressesFromGroup()) {
            LOCK(m_nodes_mutex);
            for (const CNode* pnode : m_nodes) {
                if (pnode->IsFullOutboundConn() && !pnode->m_masternode_connection) nOutboundFullRelay++;
                if (pnode->IsBlockOnlyConn()) nOutboundBlockRelay++;
                if (pnode->IsFullOutboundConn() && pnode->ConnectedThroughNetwork() == Network::NET_ONION) nOutboundOnionRelay++;

                // Make sure our persistent outbound slots to ipv4/ipv6 peers belong to different netgroups.
                switch (pnode->m_conn_type) {
                    // We currently don't take inbound connections into account. Since they are
                    // free to make, an attacker could make them to prevent us from connecting to
                    // certain peers.
                    case ConnectionType::INBOUND:
                    // Short-lived outbound connections should not affect how we select outbound
                    // peers from addrman.
                    case ConnectionType::ADDR_FETCH:
                    case ConnectionType::FEELER:
                        break;
                    case ConnectionType::MANUAL:
                    case ConnectionType::OUTBOUND_FULL_RELAY:
                    case ConnectionType::BLOCK_RELAY:
                        const CAddress address{pnode->addr};
                        if (address.IsTor() || address.IsI2P() || address.IsCJDNS()) {
                            // Since our addrman-groups for these networks are
                            // random, without relation to the route we
                            // take to connect to these peers or to the
                            // difficulty in obtaining addresses with diverse
                            // groups, we don't worry about diversity with
                            // respect to our addrman groups when connecting to
                            // these networks.
                            ++outbound_privacy_network_peers;
                        } else {
                            outbound_ipv46_peer_netgroups.insert(m_netgroupman.GetGroup(address));
                        }
                } // no default case, so the compiler can warn about missing cases
            }
        }

        std::set<uint256> setConnectedMasternodes;
        {
            LOCK(m_nodes_mutex);
            for (CNode* pnode : m_nodes) {
                auto verifiedProRegTxHash = pnode->GetVerifiedProRegTxHash();
                if (!verifiedProRegTxHash.IsNull()) {
                    setConnectedMasternodes.emplace(verifiedProRegTxHash);
                }
            }
        }

        ConnectionType conn_type = ConnectionType::OUTBOUND_FULL_RELAY;
        auto now = GetTime<std::chrono::microseconds>();
        bool anchor = false;
        bool fFeeler = false;
        std::optional<Network> preferred_net;
        bool onion_only = false;

        // Determine what type of connection to open. Opening
        // BLOCK_RELAY connections to addresses from anchors.dat gets the highest
        // priority. Then we open OUTBOUND_FULL_RELAY priority until we
        // meet our full-relay capacity. Then we open BLOCK_RELAY connection
        // until we hit our block-relay-only peer limit.
        // GetTryNewOutboundPeer() gets set when a stale tip is detected, so we
        // try opening an additional OUTBOUND_FULL_RELAY connection. If none of
        // these conditions are met, check to see if it's time to try an extra
        // block-relay-only peer (to confirm our tip is current, see below) or the next_feeler
        // timer to decide if we should open a FEELER.

        if (!m_anchors.empty() && (nOutboundBlockRelay < m_max_outbound_block_relay)) {
            conn_type = ConnectionType::BLOCK_RELAY;
            anchor = true;
        } else if (nOutboundFullRelay < m_max_outbound_full_relay) {
            // OUTBOUND_FULL_RELAY
        } else if (nOutboundBlockRelay < m_max_outbound_block_relay) {
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (GetTryNewOutboundPeer()) {
            // OUTBOUND_FULL_RELAY
        } else if (now > next_extra_block_relay && m_start_extra_block_relay_peers) {
            // Periodically connect to a peer (using regular outbound selection
            // methodology from addrman) and stay connected long enough to sync
            // headers, but not much else.
            //
            // Then disconnect the peer, if we haven't learned anything new.
            //
            // The idea is to make eclipse attacks very difficult to pull off,
            // because every few minutes we're finding a new peer to learn headers
            // from.
            //
            // This is similar to the logic for trying extra outbound (full-relay)
            // peers, except:
            // - we do this all the time on an exponential timer, rather than just when
            //   our tip is stale
            // - we potentially disconnect our next-youngest block-relay-only peer, if our
            //   newest block-relay-only peer delivers a block more recently.
            //   See the eviction logic in net_processing.cpp.
            //
            // Because we can promote these connections to block-relay-only
            // connections, they do not get their own ConnectionType enum
            // (similar to how we deal with extra outbound peers).
            next_extra_block_relay = GetExponentialRand(now, EXTRA_BLOCK_RELAY_ONLY_PEER_INTERVAL);
            conn_type = ConnectionType::BLOCK_RELAY;
        } else if (now > next_feeler) {
            next_feeler = GetExponentialRand(now, FEELER_INTERVAL);
            conn_type = ConnectionType::FEELER;
            fFeeler = true;
        } else if (nOutboundFullRelay == m_max_outbound_full_relay &&
                   m_max_outbound_full_relay == MAX_OUTBOUND_FULL_RELAY_CONNECTIONS &&
                   now > next_extra_network_peer &&
                   MaybePickPreferredNetwork(preferred_net)) {
            // Full outbound connection management: Attempt to get at least one
            // outbound peer from each reachable network by making extra connections
            // and then protecting "only" peers from a network during outbound eviction.
            // This is not attempted if the user changed -maxconnections to a value
            // so low that less than MAX_OUTBOUND_FULL_RELAY_CONNECTIONS are made,
            // to prevent interactions with otherwise protected outbound peers.
            next_extra_network_peer = GetExponentialRand(now, EXTRA_NETWORK_PEER_INTERVAL);
        } else if (nOutboundOnionRelay < m_max_outbound_onion && IsReachable(Network::NET_ONION)) {
            onion_only = true;
        } else {
            // skip to next iteration of while loop
            continue;
        }

        addrman.ResolveCollisions();

        auto mnList = dmnman.GetListAtChainTip();

        const auto current_time{NodeClock::now()};
        int nTries = 0;
        while (!interruptNet)
        {
            if (anchor && !m_anchors.empty()) {
                const CAddress addr = m_anchors.back();
                m_anchors.pop_back();
                if (!addr.IsValid() || IsLocal(addr) || !IsReachable(addr) ||
                    !HasAllDesirableServiceFlags(addr.nServices) ||
                    outbound_ipv46_peer_netgroups.count(m_netgroupman.GetGroup(addr))) continue;
                addrConnect = addr;
                LogPrint(BCLog::NET, "Trying to make an anchor connection to %s\n", addrConnect.ToStringAddrPort());
                break;
            }

            // If we didn't find an appropriate destination after trying 100 addresses fetched from addrman,
            // stop this loop, and let the outer loop run again (which sleeps, adds seed nodes, recalculates
            // already-connected network ranges, ...) before trying new addrman addresses.
            nTries++;
            if (nTries > 100)
                break;

            CAddress addr;
            NodeSeconds addr_last_try{0s};

            if (fFeeler) {
                // First, try to get a tried table collision address. This returns
                // an empty (invalid) address if there are no collisions to try.
                std::tie(addr, addr_last_try) = addrman.SelectTriedCollision();

                if (!addr.IsValid()) {
                    // No tried table collisions. Select a new table address
                    // for our feeler.
                    std::tie(addr, addr_last_try) = addrman.Select(true);
                } else if (AlreadyConnectedToAddress(addr)) {
                    // If test-before-evict logic would have us connect to a
                    // peer that we're already connected to, just mark that
                    // address as Good(). We won't be able to initiate the
                    // connection anyway, so this avoids inadvertently evicting
                    // a currently-connected peer.
                    addrman.Good(addr);
                    // Select a new table address for our feeler instead.
                    std::tie(addr, addr_last_try) = addrman.Select(true);
                }
            } else {
                // Not a feeler
                // If preferred_net has a value set, pick an extra outbound
                // peer from that network. The eviction logic in net_processing
                // ensures that a peer from another network will be evicted.
                std::tie(addr, addr_last_try) = addrman.Select(false, preferred_net);
            }

            // Require outbound IPv4/IPv6 connections, other than feelers, to be to distinct network groups
            if (!fFeeler && outbound_ipv46_peer_netgroups.count(m_netgroupman.GetGroup(addr))) {
                continue;
            }

            // if we selected an invalid address, restart
            if (!addr.IsValid()) {
                break;
            }

            // don't connect to ourselves
            if (addr.GetPort() == GetListenPort() && IsLocal(addr)) {
                break;
            }

            if (!IsReachable(addr))
                continue;
            if (onion_only && !addr.IsTor()) continue;

            // only consider very recently tried nodes after 30 failed attempts
            if (current_time - addr_last_try < 10min && nTries < 30) {
                continue;
            }

            // for non-feelers, require all the services we'll want,
            // for feelers, only require they be a full node (only because most
            // SPV clients don't have a good address DB available)
            if (!fFeeler && !HasAllDesirableServiceFlags(addr.nServices)) {
                continue;
            } else if (fFeeler && !MayHaveUsefulAddressDB(addr.nServices)) {
                continue;
            }

            // Do not connect to prohibited ports, unless 50 invalid addresses have been selected already.
            if (nTries < 50 && IsBadPort(addr.GetPort())) {
                continue;
            }

            // Do not make automatic outbound connections to addnode peers, to
            // not use our limited outbound slots for them and to ensure
            // addnode connections benefit from their intended protections.
            if (AddedNodesContain(addr)) {
                LogPrint(BCLog::NET, "Not making automatic %s%s connection to %s peer selected for manual (addnode) connection%s\n",
                         preferred_net.has_value() ? "network-specific " : "",
                         ConnectionTypeAsString(conn_type), GetNetworkName(addr.GetNetwork()),
                         fLogIPs ? strprintf(": %s", addr.ToStringAddrPort()) : "");
                continue;
            }

            // don't try to connect to masternodes that we already have a connection to (most likely inbound)
            if (auto dmn = mnList.GetMNByService(addr); dmn && setConnectedMasternodes.count(dmn->proTxHash)) {
                continue;
            }

            addrConnect = addr;
            break;
        }

        if (addrConnect.IsValid()) {
            if (fFeeler) {
                // Add small amount of random noise before connection to avoid synchronization.
                if (!interruptNet.sleep_for(rng.rand_uniform_duration<CThreadInterrupt::Clock>(FEELER_SLEEP_WINDOW))) {
                    return;
                }
                if (fLogIPs) {
                    LogPrint(BCLog::NET, "Making feeler connection to %s\n", addrConnect.ToStringAddrPort());
                } else {
                    LogPrint(BCLog::NET, "Making feeler connection\n");
                }
            }

            if (preferred_net != std::nullopt) LogPrint(BCLog::NET, "Making network specific connection to %s on %s.\n", addrConnect.ToStringAddrPort(), GetNetworkName(preferred_net.value()));

            // Record addrman failure attempts when node has at least 2 persistent outbound connections to peers with
            // different netgroups in ipv4/ipv6 networks + all peers in Tor/I2P/CJDNS networks.
            // Don't record addrman failure attempts when node is offline. This can be identified since all local
            // network connections (if any) belong in the same netgroup, and the size of `outbound_ipv46_peer_netgroups` would only be 1.
            const bool count_failures{((int)outbound_ipv46_peer_netgroups.size() + outbound_privacy_network_peers) >= std::min(nMaxConnections - 1, 2)};
            // Use BIP324 transport when both us and them have NODE_V2_P2P set.
            const bool use_v2transport(addrConnect.nServices & GetLocalServices() & NODE_P2P_V2);
            OpenNetworkConnection(addrConnect, count_failures, std::move(grant), /*strDest=*/nullptr, conn_type, use_v2transport);
        }
    }
}

std::vector<CAddress> CConnman::GetCurrentBlockRelayOnlyConns() const
{
    std::vector<CAddress> ret;
    LOCK(m_nodes_mutex);
    for (const CNode* pnode : m_nodes) {
        if (pnode->IsBlockRelayOnly()) {
            ret.push_back(pnode->addr);
        }
    }

    return ret;
}

std::vector<AddedNodeInfo> CConnman::GetAddedNodeInfo(bool include_connected) const
{
    std::vector<AddedNodeInfo> ret;

    std::list<AddedNodeParams> lAddresses(0);
    {
        LOCK(m_added_nodes_mutex);
        ret.reserve(m_added_node_params.size());
        std::copy(m_added_node_params.cbegin(), m_added_node_params.cend(), std::back_inserter(lAddresses));
    }


    // Build a map of all already connected addresses (by IP:port and by name) to inbound/outbound and resolved CService
    std::map<CService, bool> mapConnected;
    std::map<std::string, std::pair<bool, CService>> mapConnectedByName;
    {
        LOCK(m_nodes_mutex);
        for (const CNode* pnode : m_nodes) {
            if (pnode->addr.IsValid()) {
                mapConnected[pnode->addr] = pnode->IsInboundConn();
            }
            std::string addrName{pnode->m_addr_name};
            if (!addrName.empty()) {
                mapConnectedByName[std::move(addrName)] = std::make_pair(pnode->IsInboundConn(), static_cast<const CService&>(pnode->addr));
            }
        }
    }

    for (const auto& addr : lAddresses) {
        CService service(LookupNumeric(addr.m_added_node, Params().GetDefaultPort(addr.m_added_node)));
        AddedNodeInfo addedNode{addr, CService(), false, false};
        if (service.IsValid()) {
            // strAddNode is an IP:port
            auto it = mapConnected.find(service);
            if (it != mapConnected.end()) {
                if (!include_connected) {
                    continue;
                }
                addedNode.resolvedAddress = service;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second;
            }
        } else {
            // strAddNode is a name
            auto it = mapConnectedByName.find(addr.m_added_node);
            if (it != mapConnectedByName.end()) {
                if (!include_connected) {
                    continue;
                }
                addedNode.resolvedAddress = it->second.second;
                addedNode.fConnected = true;
                addedNode.fInbound = it->second.first;
            }
        }
        ret.emplace_back(std::move(addedNode));
    }

    return ret;
}

void CConnman::ThreadOpenAddedConnections()
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    AssertLockNotHeld(m_reconnections_mutex);
    while (true)
    {
        CSemaphoreGrant grant(*semAddnode);
        std::vector<AddedNodeInfo> vInfo = GetAddedNodeInfo(/*include_connected=*/false);
        bool tried = false;
        for (const AddedNodeInfo& info : vInfo) {
            if (!grant) {
                // If we've used up our semaphore and need a new one, let's not wait here since while we are waiting
                // the addednodeinfo state might change.
                break;
            }
            tried = true;
            CAddress addr(CService(), NODE_NONE);
            OpenNetworkConnection(addr, false, std::move(grant), info.m_params.m_added_node.c_str(), ConnectionType::MANUAL, info.m_params.m_use_v2transport);
            if (!interruptNet.sleep_for(std::chrono::milliseconds(500))) return;
            grant = CSemaphoreGrant(*semAddnode, /*fTry=*/true);
        }
        // See if any reconnections are desired.
        PerformReconnections();
        // Retry every 60 seconds if a connection was attempted, otherwise two seconds
        if (!interruptNet.sleep_for(std::chrono::seconds(tried ? 60 : 2)))
            return;
    }
}

void CConnman::ThreadOpenMasternodeConnections(CDeterministicMNManager& dmnman, CMasternodeMetaMan& mn_metaman,
                                               CMasternodeSync& mn_sync)
{
    // Connecting to specific addresses, no masternode connections available
    if (gArgs.IsArgSet("-connect") && gArgs.GetArgs("-connect").size() > 0)
        return;

    auto& chainParams = Params();

    bool didConnect = false;
    while (!interruptNet)
    {
        auto sleepTime = std::chrono::milliseconds(1000);
        if (didConnect) {
            sleepTime = std::chrono::milliseconds(100);
        }
        if (!interruptNet.sleep_for(sleepTime))
            return;

        didConnect = false;

        if (!fNetworkActive || !m_masternode_thread_active || !mn_sync.IsBlockchainSynced()) continue;

        std::unordered_set<CService, CServiceHash> connectedNodes;
        std::unordered_map<uint256 /*proTxHash*/, bool /*fInbound*/, StaticSaltedHasher> connectedProRegTxHashes;
        ForEachNode([&](const CNode* pnode) {
            connectedNodes.emplace(pnode->addr);
            if (auto verifiedProRegTxHash = pnode->GetVerifiedProRegTxHash(); !verifiedProRegTxHash.IsNull()) {
                connectedProRegTxHashes.emplace(verifiedProRegTxHash, pnode->IsInboundConn());
            }
        });

        auto mnList = dmnman.GetListAtChainTip();

        if (interruptNet)
            return;

        int64_t nANow = GetTime<std::chrono::seconds>().count();
        constexpr const auto &_func_ = __func__;

        // NOTE: Process only one pending masternode at a time

        MasternodeProbeConn isProbe = MasternodeProbeConn::IsNotConnection;

        const auto getPendingQuorumNodes = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_vPendingMasternodes) {
            AssertLockHeld(cs_vPendingMasternodes);
            std::vector<CDeterministicMNCPtr> ret;
            for (const auto& group : masternodeQuorumNodes) {
                for (const auto& proRegTxHash : group.second) {
                    auto dmn = mnList.GetMN(proRegTxHash);
                    if (!dmn) {
                        continue;
                    }
                    const auto& addr2 = dmn->pdmnState->addr;
                    if (connectedNodes.count(addr2) && !connectedProRegTxHashes.count(proRegTxHash)) {
                        // we probably connected to it before it became a masternode
                        // or maybe we are still waiting for mnauth
                        (void)ForNode(addr2, [&](CNode* pnode) {
                            if (pnode->nTimeFirstMessageReceived.load() != 0s && GetTime<std::chrono::seconds>() - pnode->nTimeFirstMessageReceived.load() > 5s) {
                                // clearly not expecting mnauth to take that long even if it wasn't the first message
                                // we received (as it should normally), disconnect
                                LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- dropping non-mnauth connection to %s, service=%s\n", _func_, proRegTxHash.ToString(), addr2.ToStringAddrPort());
                                pnode->fDisconnect = true;
                                return true;
                            }
                            return false;
                        });
                        // either way - it's not ready, skip it for now
                        continue;
                    }
                    if (!connectedNodes.count(addr2) && !IsMasternodeOrDisconnectRequested(addr2) && !connectedProRegTxHashes.count(proRegTxHash)) {
                        int64_t lastAttempt = mn_metaman.GetMetaInfo(dmn->proTxHash)->GetLastOutboundAttempt();
                        // back off trying connecting to an address if we already tried recently
                        if (nANow - lastAttempt < chainParams.LLMQConnectionRetryTimeout()) {
                            continue;
                        }
                        ret.emplace_back(dmn);
                    }
                }
            }
            return ret;
        };

        const auto getPendingProbes = [&]() EXCLUSIVE_LOCKS_REQUIRED(cs_vPendingMasternodes) {
            AssertLockHeld(cs_vPendingMasternodes);
            std::vector<CDeterministicMNCPtr> ret;
            for (auto it = masternodePendingProbes.begin(); it != masternodePendingProbes.end(); ) {
                auto dmn = mnList.GetMN(*it);
                if (!dmn) {
                    it = masternodePendingProbes.erase(it);
                    continue;
                }
                bool connectedAndOutbound = connectedProRegTxHashes.count(dmn->proTxHash) && !connectedProRegTxHashes[dmn->proTxHash];
                if (connectedAndOutbound) {
                    // we already have an outbound connection to this MN so there is no theed to probe it again
                    mn_metaman.GetMetaInfo(dmn->proTxHash)->SetLastOutboundSuccess(nANow);
                    it = masternodePendingProbes.erase(it);
                    continue;
                }

                ++it;

                int64_t lastAttempt = mn_metaman.GetMetaInfo(dmn->proTxHash)->GetLastOutboundAttempt();
                // back off trying connecting to an address if we already tried recently
                if (nANow - lastAttempt < chainParams.LLMQConnectionRetryTimeout()) {
                    continue;
                }
                ret.emplace_back(dmn);
            }
            return ret;
        };

        auto getConnectToDmn = [&]() -> CDeterministicMNCPtr {
            // don't hold lock while calling OpenMasternodeConnection as cs_main is locked deep inside
            LOCK2(m_nodes_mutex, cs_vPendingMasternodes);

            if (!vPendingMasternodes.empty()) {
                auto dmn = mnList.GetValidMN(vPendingMasternodes.front());
                vPendingMasternodes.erase(vPendingMasternodes.begin());
                if (dmn && !connectedNodes.count(dmn->pdmnState->addr) && !IsMasternodeOrDisconnectRequested(dmn->pdmnState->addr)) {
                    LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- opening pending masternode connection to %s, service=%s\n", _func_, dmn->proTxHash.ToString(), dmn->pdmnState->addr.ToStringAddrPort());
                    return dmn;
                }
            }

            if (const auto pending = getPendingQuorumNodes(); !pending.empty()) {
                // not-null
                auto dmn = pending[GetRand(pending.size())];
                LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- opening quorum connection to %s, service=%s\n",
                         _func_, dmn->proTxHash.ToString(), dmn->pdmnState->addr.ToStringAddrPort());
                return dmn;
            }

            if (const auto pending = getPendingProbes(); !pending.empty()) {
                // not-null
                auto dmn = pending[GetRand(pending.size())];
                masternodePendingProbes.erase(dmn->proTxHash);
                isProbe = MasternodeProbeConn::IsConnection;

                LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- probing masternode %s, service=%s\n", _func_, dmn->proTxHash.ToString(), dmn->pdmnState->addr.ToStringAddrPort());
                return dmn;
            }
            return nullptr;
        };

        CDeterministicMNCPtr connectToDmn = getConnectToDmn();

        if (connectToDmn == nullptr) {
            continue;
        }

        didConnect = true;

        mn_metaman.GetMetaInfo(connectToDmn->proTxHash)->SetLastOutboundAttempt(nANow);

        OpenMasternodeConnection(CAddress(connectToDmn->pdmnState->addr, NODE_NETWORK), /*use_v2transport=*/GetLocalServices() & NODE_P2P_V2, isProbe);
        // should be in the list now if connection was opened
        bool connected = ForNode(connectToDmn->pdmnState->addr, CConnman::AllNodes, [&](CNode* pnode) {
            if (pnode->fDisconnect) {
                return false;
            }
            return true;
        });
        if (!connected) {
            LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- connection failed for masternode  %s, service=%s\n", __func__, connectToDmn->proTxHash.ToString(), connectToDmn->pdmnState->addr.ToStringAddrPort());
            // Will take a few consequent failed attempts to PoSe-punish a MN.
            if (mn_metaman.GetMetaInfo(connectToDmn->proTxHash)->OutboundFailedTooManyTimes()) {
                LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- failed to connect to masternode %s too many times\n", __func__, connectToDmn->proTxHash.ToString());
            }
        }
    }
}

// if successful, this moves the passed grant to the constructed node
void CConnman::OpenNetworkConnection(const CAddress& addrConnect, bool fCountFailure, CSemaphoreGrant&& grant_outbound,
                                     const char *pszDest, ConnectionType conn_type, bool use_v2transport,
                                     MasternodeConn masternode_connection, MasternodeProbeConn masternode_probe_connection)
{
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    assert(conn_type != ConnectionType::INBOUND);

    //
    // Initiate outbound network connection
    //
    if (interruptNet) {
        return;
    }
    if (!fNetworkActive) {
        return;
    }

    auto getIpStr = [&]() {
        if (fLogIPs) {
            return addrConnect.ToStringAddrPort();
        } else {
            return std::string("new peer");
        }
    };

    if (!pszDest) {
        // banned, discouraged or exact match?
        if ((m_banman && (m_banman->IsDiscouraged(addrConnect) || m_banman->IsBanned(addrConnect))) || AlreadyConnectedToAddress(addrConnect))
            return;
        // connecting to ourselves?
        if (addrConnect.GetPort() == GetListenPort() && IsLocal(addrConnect)) {
            return;
        }
    } else if (FindNode(std::string(pszDest)))
        return;

    LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- connecting to %s\n", __func__, getIpStr());
    CNode* pnode = ConnectNode(addrConnect, pszDest, fCountFailure, conn_type, use_v2transport);

    if (!pnode) {
        LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- ConnectNode failed for %s\n", __func__, getIpStr());
        return;
    }

    {
        LOCK(pnode->m_sock_mutex);
        LogPrint(BCLog::NET_NETCONN, "CConnman::%s -- successfully connected to %s, sock=%d, peer=%d\n", __func__, getIpStr(), pnode->m_sock->Get(), pnode->GetId());
    }

    pnode->grantOutbound = std::move(grant_outbound);

    if (masternode_connection == MasternodeConn::IsConnection)
        pnode->m_masternode_connection = true;
    if (masternode_probe_connection == MasternodeProbeConn::IsConnection)
        pnode->m_masternode_probe_connection = true;

    {
        LOCK2(cs_mapSocketToNode, pnode->m_sock_mutex);
        mapSocketToNode.emplace(pnode->m_sock->Get(), pnode);
    }

    m_msgproc->InitializeNode(*pnode, nLocalServices);
    {
        LOCK(m_nodes_mutex);
        m_nodes.push_back(pnode);

        // update connection count by network
        if (pnode->IsManualOrFullOutboundConn()) ++m_network_conn_counts[pnode->addr.GetNetwork()];
    }
    {
        if (m_edge_trig_events) {
            LOCK(pnode->m_sock_mutex);
            if (!m_edge_trig_events->RegisterEvents(pnode->m_sock->Get())) {
                LogPrint(BCLog::NET, "EdgeTriggeredEvents::RegisterEvents() failed\n");
            }
        }
        if (m_wakeup_pipe) {
            m_wakeup_pipe->Write();
        }
    }
}

void CConnman::OpenMasternodeConnection(const CAddress &addrConnect, bool use_v2transport, MasternodeProbeConn probe) {
    OpenNetworkConnection(addrConnect, false, {}, /*strDest=*/nullptr, ConnectionType::OUTBOUND_FULL_RELAY,
                          use_v2transport, MasternodeConn::IsConnection, probe);
}

Mutex NetEventsInterface::g_msgproc_mutex;

void CConnman::ThreadMessageHandler()
{
    LOCK(NetEventsInterface::g_msgproc_mutex);

    int64_t nLastSendMessagesTimeMasternodes = 0;

    FastRandomContext rng;
    while (!flagInterruptMsgProc)
    {
        bool fMoreWork = false;

        bool fSkipSendMessagesForMasternodes = true;
        if (GetTimeMillis() - nLastSendMessagesTimeMasternodes >= 100) {
            fSkipSendMessagesForMasternodes = false;
            nLastSendMessagesTimeMasternodes = GetTimeMillis();
        }

        // Randomize the order in which we process messages from/to our peers.
        // This prevents attacks in which an attacker exploits having multiple
        // consecutive connections in the m_nodes list.
        const NodesSnapshot snap{*this, /* filter = */ CConnman::AllNodes, /* shuffle = */ true};

        for (CNode* pnode : snap.Nodes()) {
            if (pnode->fDisconnect)
                continue;

            // Receive messages
            bool fMoreNodeWork = m_msgproc->ProcessMessages(pnode, flagInterruptMsgProc);
            fMoreWork |= (fMoreNodeWork && !pnode->fPauseSend);
            if (flagInterruptMsgProc)
                return;
            // Send messages
            if (!fSkipSendMessagesForMasternodes || !pnode->m_masternode_connection) {
                m_msgproc->SendMessages(pnode);
            }

            if (flagInterruptMsgProc)
                return;
        }

        WAIT_LOCK(mutexMsgProc, lock);
        if (!fMoreWork) {
            condMsgProc.wait_until(lock, std::chrono::steady_clock::now() + std::chrono::milliseconds(100), [this]() EXCLUSIVE_LOCKS_REQUIRED(mutexMsgProc) { return fMsgProcWake; });
        }
        fMsgProcWake = false;
    }
}

void CConnman::ThreadI2PAcceptIncoming(CMasternodeSync& mn_sync)
{
    static constexpr auto err_wait_begin = 1s;
    static constexpr auto err_wait_cap = 5min;
    auto err_wait = err_wait_begin;

    bool advertising_listen_addr = false;
    i2p::Connection conn;

    while (!interruptNet) {

        if (!m_i2p_sam_session->Listen(conn)) {
            if (advertising_listen_addr && conn.me.IsValid()) {
                RemoveLocal(conn.me);
                advertising_listen_addr = false;
            }

            interruptNet.sleep_for(err_wait);
            if (err_wait < err_wait_cap) {
                err_wait *= 2;
            }

            continue;
        }

        if (!advertising_listen_addr) {
            AddLocal(conn.me, LOCAL_MANUAL);
            advertising_listen_addr = true;
        }

        if (!m_i2p_sam_session->Accept(conn)) {
            continue;
        }

        CreateNodeFromAcceptedSocket(std::move(conn.sock), NetPermissionFlags::None,
                                     CAddress{conn.me, NODE_NONE}, CAddress{conn.peer, NODE_NONE}, mn_sync);
    }
}

bool CConnman::BindListenPort(const CService& addrBind, bilingual_str& strError, NetPermissionFlags permissions)
{
    int nOne = 1;

    // Create socket for listening for incoming connections
    struct sockaddr_storage sockaddr;
    socklen_t len = sizeof(sockaddr);
    if (!addrBind.GetSockAddr((struct sockaddr*)&sockaddr, &len))
    {
        strError = strprintf(Untranslated("Error: Bind address family for %s not supported"), addrBind.ToStringAddrPort());
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n", strError.original);
        return false;
    }

    std::unique_ptr<Sock> sock = CreateSock(addrBind);
    if (!sock) {
        strError = strprintf(Untranslated("Couldn't open socket for incoming connections (socket returned error %s)"), NetworkErrorString(WSAGetLastError()));
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n", strError.original);
        return false;
    }

    // Allow binding if the port is still in TIME_WAIT state after
    // the program was closed and restarted.
    if (sock->SetSockOpt(SOL_SOCKET, SO_REUSEADDR, (sockopt_arg_type)&nOne, sizeof(int)) == SOCKET_ERROR) {
        strError = strprintf(Untranslated("Error setting SO_REUSEADDR on socket: %s, continuing anyway"), NetworkErrorString(WSAGetLastError()));
        LogPrintf("%s\n", strError.original);
    }

    // some systems don't have IPV6_V6ONLY but are always v6only; others do have the option
    // and enable it by default or not. Try to enable it, if possible.
    if (addrBind.IsIPv6()) {
#ifdef IPV6_V6ONLY
        if (sock->SetSockOpt(IPPROTO_IPV6, IPV6_V6ONLY, (sockopt_arg_type)&nOne, sizeof(int)) == SOCKET_ERROR) {
            strError = strprintf(Untranslated("Error setting IPV6_V6ONLY on socket: %s, continuing anyway"), NetworkErrorString(WSAGetLastError()));
            LogPrintf("%s\n", strError.original);
        }
#endif
#ifdef WIN32
        int nProtLevel = PROTECTION_LEVEL_UNRESTRICTED;
        if (sock->SetSockOpt(IPPROTO_IPV6, IPV6_PROTECTION_LEVEL, (const char*)&nProtLevel, sizeof(int)) == SOCKET_ERROR) {
            strError = strprintf(Untranslated("Error setting IPV6_PROTECTION_LEVEL on socket: %s, continuing anyway"), NetworkErrorString(WSAGetLastError()));
            LogPrintf("%s\n", strError.original);
        }
#endif
    }

    if (sock->Bind(reinterpret_cast<struct sockaddr*>(&sockaddr), len) == SOCKET_ERROR) {
        int nErr = WSAGetLastError();
        if (nErr == WSAEADDRINUSE)
            strError = strprintf(_("Unable to bind to %s on this computer. %s is probably already running."), addrBind.ToStringAddrPort(), PACKAGE_NAME);
        else
            strError = strprintf(_("Unable to bind to %s on this computer (bind returned error %s)"), addrBind.ToStringAddrPort(), NetworkErrorString(nErr));
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n", strError.original);
        return false;
    }
    LogPrintf("Bound to %s\n", addrBind.ToStringAddrPort());

    // Listen for incoming connections
    if (sock->Listen(SOMAXCONN) == SOCKET_ERROR)
    {
        strError = strprintf(_("Listening for incoming connections failed (listen returned error %s)"), NetworkErrorString(WSAGetLastError()));
        LogPrintLevel(BCLog::NET, BCLog::Level::Error, "%s\n", strError.original);
        return false;
    }

    if (m_edge_trig_events && !m_edge_trig_events->AddSocket(sock->Get())) {
        LogPrintf("Error: EdgeTriggeredEvents::AddSocket() failed\n");
        return false;
    }

    vhListenSocket.emplace_back(std::move(sock), permissions);

    return true;
}

void Discover()
{
    if (!fDiscover)
        return;

#ifdef WIN32
    // Get local host IP
    char pszHostName[256] = "";
    if (gethostname(pszHostName, sizeof(pszHostName)) != SOCKET_ERROR)
    {
        const std::vector<CNetAddr> addresses{LookupHost(pszHostName, 0, true)};
        for (const CNetAddr& addr : addresses)
        {
            if (AddLocal(addr, LOCAL_IF))
                LogPrintf("%s: %s - %s\n", __func__, pszHostName, addr.ToStringAddr());
        }
    }
#elif (HAVE_DECL_GETIFADDRS && HAVE_DECL_FREEIFADDRS)
    // Get local host ip
    struct ifaddrs* myaddrs;
    if (getifaddrs(&myaddrs) == 0)
    {
        for (struct ifaddrs* ifa = myaddrs; ifa != nullptr; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_addr == nullptr) continue;
            if ((ifa->ifa_flags & IFF_UP) == 0) continue;
            if ((ifa->ifa_flags & IFF_LOOPBACK) != 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                struct sockaddr_in* s4 = (struct sockaddr_in*)(ifa->ifa_addr);
                CNetAddr addr(s4->sin_addr);
                if (AddLocal(addr, LOCAL_IF))
                    LogPrintf("%s: IPv4 %s: %s\n", __func__, ifa->ifa_name, addr.ToStringAddr());
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct sockaddr_in6* s6 = (struct sockaddr_in6*)(ifa->ifa_addr);
                CNetAddr addr(s6->sin6_addr);
                if (AddLocal(addr, LOCAL_IF))
                    LogPrintf("%s: IPv6 %s: %s\n", __func__, ifa->ifa_name, addr.ToStringAddr());
            }
        }
        freeifaddrs(myaddrs);
    }
#endif
}

void CConnman::SetNetworkActive(bool active, CMasternodeSync* const mn_sync)
{
    LogPrintf("%s: %s\n", __func__, active);

    if (fNetworkActive == active) {
        return;
    }

    fNetworkActive = active;

    // mn_sync is nullptr during app initialization with `-networkactive=`
    if (mn_sync) {
        // Always call the Reset() if the network gets enabled/disabled to make sure the sync process
        // gets a reset if its outdated..
        mn_sync->Reset();
    }

    if (m_client_interface) {
        m_client_interface->NotifyNetworkActiveChanged(fNetworkActive);
    }
}

CConnman::CConnman(uint64_t nSeed0In, uint64_t nSeed1In, AddrMan& addrman_in,
                   const NetGroupManager& netgroupman, bool network_active)
    : addrman(addrman_in)
    , m_netgroupman{netgroupman}
    , nSeed0(nSeed0In)
    , nSeed1(nSeed1In)
{
    // Make sure we never set the default port to a bad port
    for (int n = 0; n < NET_MAX; ++n) {
        const bool is_bad_port = IsBadPort(Params().GetDefaultPort(static_cast<Network>(n)));
        assert(!is_bad_port);
    }

    SetTryNewOutboundPeer(false);

    Options connOptions;
    Init(connOptions);
    SetNetworkActive(network_active, /* mn_sync = */ nullptr);
}

NodeId CConnman::GetNewNodeId()
{
    return nLastNodeId.fetch_add(1, std::memory_order_relaxed);
}


bool CConnman::Bind(const CService& addr_, unsigned int flags, NetPermissionFlags permissions)
{
    const CService addr{MaybeFlipIPv6toCJDNS(addr_)};

    bilingual_str strError;
    if (!BindListenPort(addr, strError, permissions)) {
        if ((flags & BF_REPORT_ERROR) && m_client_interface) {
            m_client_interface->ThreadSafeMessageBox(strError, "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }

    if (addr.IsRoutable() && fDiscover && !(flags & BF_DONT_ADVERTISE) && !NetPermissions::HasFlag(permissions, NetPermissionFlags::NoBan)) {
        AddLocal(addr, LOCAL_BIND);
    }

    return true;
}

bool CConnman::InitBinds(const Options& options)
{
    bool fBound = false;
    for (const auto& addrBind : options.vBinds) {
        fBound |= Bind(addrBind, BF_REPORT_ERROR, NetPermissionFlags::None);
    }
    for (const auto& addrBind : options.vWhiteBinds) {
        fBound |= Bind(addrBind.m_service, BF_REPORT_ERROR, addrBind.m_flags);
    }
    for (const auto& addr_bind : options.onion_binds) {
        fBound |= Bind(addr_bind, BF_DONT_ADVERTISE, NetPermissionFlags::None);
    }
    if (options.bind_on_any) {
        struct in_addr inaddr_any;
        inaddr_any.s_addr = htonl(INADDR_ANY);
        struct in6_addr inaddr6_any = IN6ADDR_ANY_INIT;
        fBound |= Bind(CService(inaddr6_any, GetListenPort()), BF_NONE, NetPermissionFlags::None);
        fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE, NetPermissionFlags::None);
    }
    return fBound;
}

bool CConnman::Start(CDeterministicMNManager& dmnman, CMasternodeMetaMan& mn_metaman, CMasternodeSync& mn_sync,
                     CScheduler& scheduler, const Options& connOptions)
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    Init(connOptions);

    if (socketEventsMode == SocketEventsMode::EPoll || socketEventsMode == SocketEventsMode::KQueue) {
        m_edge_trig_events = std::make_unique<EdgeTriggeredEvents>(socketEventsMode);
        if (!m_edge_trig_events->IsValid()) {
            LogPrintf("Unable to initialize EdgeTriggeredEvents instance\n");
            m_edge_trig_events.reset();
            return false;
        }
    }

    if (fListen && !InitBinds(connOptions)) {
        if (m_client_interface) {
            m_client_interface->ThreadSafeMessageBox(
                _("Failed to listen on any port. Use -listen=0 if you want this."),
                "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }

    Proxy i2p_sam;
    if (GetProxy(NET_I2P, i2p_sam) && connOptions.m_i2p_accept_incoming) {
        m_i2p_sam_session = std::make_unique<i2p::sam::Session>(gArgs.GetDataDirNet() / "i2p_private_key",
                                                                i2p_sam.proxy, &interruptNet);
    }

    for (const auto& strDest : connOptions.vSeedNodes) {
        AddAddrFetch(strDest);
    }

    if (m_use_addrman_outgoing) {
        // Load addresses from anchors.dat
        m_anchors = ReadAnchors(gArgs.GetDataDirNet() / ANCHORS_DATABASE_FILENAME);
        if (m_anchors.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
            m_anchors.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
        }
        LogPrintf("%i block-relay-only anchors will be tried for connections.\n", m_anchors.size());
    }

    if (m_client_interface) {
        m_client_interface->InitMessage(_("Starting network threads…").translated);
    }

    fAddressesInitialized = true;

    if (semOutbound == nullptr) {
        // initialize semaphore
        semOutbound = std::make_unique<CSemaphore>(std::min(m_max_outbound, nMaxConnections));
    }
    if (semAddnode == nullptr) {
        // initialize semaphore
        semAddnode = std::make_unique<CSemaphore>(nMaxAddnode);
    }

    //
    // Start threads
    //
    assert(m_msgproc);
    InterruptSocks5(false);
    interruptNet.reset();
    flagInterruptMsgProc = false;

    {
        LOCK(mutexMsgProc);
        fMsgProcWake = false;
    }

#ifdef USE_WAKEUP_PIPE
    m_wakeup_pipe = std::make_unique<WakeupPipe>(m_edge_trig_events.get());
    if (!m_wakeup_pipe->IsValid()) {
        /* We log the error but do not halt initialization */
        LogPrintf("Unable to initialize WakeupPipe instance\n");
        m_wakeup_pipe.reset();
    }
#endif /* USE_WAKEUP_PIPE */

    // Send and receive from sockets, accept connections
    threadSocketHandler = std::thread(&util::TraceThread, "net", [this, &mn_sync] { ThreadSocketHandler(mn_sync); });

    if (!gArgs.GetBoolArg("-dnsseed", DEFAULT_DNSSEED))
        LogPrintf("DNS seeding disabled\n");
    else
        threadDNSAddressSeed = std::thread(&util::TraceThread, "dnsseed", [this] { ThreadDNSAddressSeed(); });

    // Initiate manual connections
    threadOpenAddedConnections = std::thread(&util::TraceThread, "addcon", [this] { ThreadOpenAddedConnections(); });

    if (connOptions.m_use_addrman_outgoing && !connOptions.m_specified_outgoing.empty()) {
        if (m_client_interface) {
            m_client_interface->ThreadSafeMessageBox(
                _("Cannot provide specific connections and have addrman find outgoing connections at the same time."),
                "", CClientUIInterface::MSG_ERROR);
        }
        return false;
    }
    if (connOptions.m_use_addrman_outgoing || !connOptions.m_specified_outgoing.empty()) {
        threadOpenConnections = std::thread(
            &util::TraceThread, "opencon",
            [this, connect = connOptions.m_specified_outgoing, &dmnman] { ThreadOpenConnections(connect, dmnman); });
    }

    // Initiate masternode connections
    threadOpenMasternodeConnections = std::thread(&util::TraceThread, "mncon", [this, &dmnman, &mn_metaman, &mn_sync] {
        ThreadOpenMasternodeConnections(dmnman, mn_metaman, mn_sync);
    });

    // Process messages
    threadMessageHandler = std::thread(&util::TraceThread, "msghand", [this] { ThreadMessageHandler(); });

    if (m_i2p_sam_session) {
        threadI2PAcceptIncoming =
            std::thread(&util::TraceThread, "i2paccept", [this, &mn_sync] { ThreadI2PAcceptIncoming(mn_sync); });
    }

    // Dump network addresses
    scheduler.scheduleEvery([this] { DumpAddresses(); }, DUMP_PEERS_INTERVAL);

    return true;
}

class CNetCleanup
{
public:
    CNetCleanup() {}

    ~CNetCleanup()
    {
#ifdef WIN32
        // Shutdown Windows Sockets
        WSACleanup();
#endif
    }
};
static CNetCleanup instance_of_cnetcleanup;

void CExplicitNetCleanup::callCleanup()
{
    // Explicit call to destructor of CNetCleanup because it's not implicitly called
    // when the wallet is restarted from within the wallet itself.
    CNetCleanup tmp;
}

void CConnman::Interrupt()
{
    {
        LOCK(mutexMsgProc);
        flagInterruptMsgProc = true;
    }
    condMsgProc.notify_all();

    interruptNet();
    InterruptSocks5(true);

    if (semOutbound) {
        for (int i=0; i<m_max_outbound; i++) {
            semOutbound->post();
        }
    }

    if (semAddnode) {
        for (int i=0; i<nMaxAddnode; i++) {
            semAddnode->post();
        }
    }
}

void CConnman::StopThreads()
{
    if (threadI2PAcceptIncoming.joinable()) {
        threadI2PAcceptIncoming.join();
    }
    if (threadMessageHandler.joinable())
        threadMessageHandler.join();
    if (threadOpenMasternodeConnections.joinable())
        threadOpenMasternodeConnections.join();
    if (threadOpenConnections.joinable())
        threadOpenConnections.join();
    if (threadOpenAddedConnections.joinable())
        threadOpenAddedConnections.join();
    if (threadDNSAddressSeed.joinable())
        threadDNSAddressSeed.join();
    if (threadSocketHandler.joinable())
        threadSocketHandler.join();
}

void CConnman::StopNodes()
{
    if (fAddressesInitialized) {
        DumpAddresses();
        fAddressesInitialized = false;

        if (m_use_addrman_outgoing) {
            // Anchor connections are only dumped during clean shutdown.
            std::vector<CAddress> anchors_to_dump = GetCurrentBlockRelayOnlyConns();
            if (anchors_to_dump.size() > MAX_BLOCK_RELAY_ONLY_ANCHORS) {
                anchors_to_dump.resize(MAX_BLOCK_RELAY_ONLY_ANCHORS);
            }
            DumpAnchors(gArgs.GetDataDirNet() / ANCHORS_DATABASE_FILENAME, anchors_to_dump);
        }
    }

    // Delete peer connections.
    std::vector<CNode*> nodes;
    WITH_LOCK(m_nodes_mutex, nodes.swap(m_nodes));
    for (CNode *pnode : nodes) {
        pnode->CloseSocketDisconnect(this);
        DeleteNode(pnode);
    }

    // Close listening sockets.
    if (m_edge_trig_events) {
        for (ListenSocket& hListenSocket : vhListenSocket) {
            if (hListenSocket.sock) {
                m_edge_trig_events->RemoveSocket(hListenSocket.sock->Get());
            }
        }
    }

    for (CNode* pnode : m_nodes_disconnected) {
        DeleteNode(pnode);
    }
    WITH_LOCK(cs_mapSocketToNode, mapSocketToNode.clear());
    {
        LOCK(cs_sendable_receivable_nodes);
        mapReceivableNodes.clear();
    }
    m_nodes_disconnected.clear();
    vhListenSocket.clear();
    semOutbound.reset();
    semAddnode.reset();
    /**
     * m_wakeup_pipe must be reset *before* m_edge_trig_events as it may
     * attempt to call EdgeTriggeredEvents::UnregisterPipe() in its destructor
     */
    m_wakeup_pipe.reset();
    m_edge_trig_events.reset();
}

void CConnman::DeleteNode(CNode* pnode)
{
    assert(pnode);
    m_msgproc->FinalizeNode(*pnode);
    delete pnode;
}

CConnman::~CConnman()
{
    Interrupt();
    Stop();
}

std::vector<CAddress> CConnman::GetAddresses(size_t max_addresses, size_t max_pct, std::optional<Network> network) const
{
    std::vector<CAddress> addresses = addrman.GetAddr(max_addresses, max_pct, network);
    if (m_banman) {
        addresses.erase(std::remove_if(addresses.begin(), addresses.end(),
                        [this](const CAddress& addr){return m_banman->IsDiscouraged(addr) || m_banman->IsBanned(addr);}),
                        addresses.end());
    }
    return addresses;
}

std::vector<CAddress> CConnman::GetAddresses(CNode& requestor, size_t max_addresses, size_t max_pct)
{
    auto local_socket_bytes = requestor.addrBind.GetAddrBytes();
    uint64_t cache_id = GetDeterministicRandomizer(RANDOMIZER_ID_ADDRCACHE)
        .Write(requestor.ConnectedThroughNetwork())
        .Write(local_socket_bytes.data(), local_socket_bytes.size())
        // For outbound connections, the port of the bound address is randomly
        // assigned by the OS and would therefore not be useful for seeding.
        .Write(requestor.IsInboundConn() ? requestor.addrBind.GetPort() : 0)
        .Finalize();
    const auto current_time = GetTime<std::chrono::microseconds>();
    auto r = m_addr_response_caches.emplace(cache_id, CachedAddrResponse{});
    CachedAddrResponse& cache_entry = r.first->second;
    if (cache_entry.m_cache_entry_expiration < current_time) { // If emplace() added new one it has expiration 0.
        cache_entry.m_addrs_response_cache = GetAddresses(max_addresses, max_pct, /* network */ std::nullopt);
        // Choosing a proper cache lifetime is a trade-off between the privacy leak minimization
        // and the usefulness of ADDR responses to honest users.
        //
        // Longer cache lifetime makes it more difficult for an attacker to scrape
        // enough AddrMan data to maliciously infer something useful.
        // By the time an attacker scraped enough AddrMan records, most of
        // the records should be old enough to not leak topology info by
        // e.g. analyzing real-time changes in timestamps.
        //
        // It takes only several hundred requests to scrape everything from an AddrMan containing 100,000 nodes,
        // so ~24 hours of cache lifetime indeed makes the data less inferable by the time
        // most of it could be scraped (considering that timestamps are updated via
        // ADDR self-announcements and when nodes communicate).
        // We also should be robust to those attacks which may not require scraping *full* victim's AddrMan
        // (because even several timestamps of the same handful of nodes may leak privacy).
        //
        // On the other hand, longer cache lifetime makes ADDR responses
        // outdated and less useful for an honest requestor, e.g. if most nodes
        // in the ADDR response are no longer active.
        //
        // However, the churn in the network is known to be rather low. Since we consider
        // nodes to be "terrible" (see IsTerrible()) if the timestamps are older than 30 days,
        // max. 24 hours of "penalty" due to cache shouldn't make any meaningful difference
        // in terms of the freshness of the response.
        cache_entry.m_cache_entry_expiration = current_time + std::chrono::hours(21) + GetRandMillis(std::chrono::hours(6));
    }
    return cache_entry.m_addrs_response_cache;
}

bool CConnman::AddNode(const AddedNodeParams& add)
{
    const CService resolved(LookupNumeric(add.m_added_node, Params().GetDefaultPort(add.m_added_node)));
    const bool resolved_is_valid{resolved.IsValid()};

    LOCK(m_added_nodes_mutex);
    for (const auto& it : m_added_node_params) {
        if (add.m_added_node == it.m_added_node || (resolved_is_valid && resolved == LookupNumeric(it.m_added_node, Params().GetDefaultPort(it.m_added_node)))) return false;
    }

    m_added_node_params.push_back(add);
    return true;
}

bool CConnman::RemoveAddedNode(const std::string& strNode)
{
    LOCK(m_added_nodes_mutex);
    for (auto it = m_added_node_params.begin(); it != m_added_node_params.end(); ++it) {
        if (strNode == it->m_added_node) {
            m_added_node_params.erase(it);
            return true;
        }
    }
    return false;
}

bool CConnman::AddedNodesContain(const CAddress& addr) const
{
    AssertLockNotHeld(m_added_nodes_mutex);
    const std::string addr_str{addr.ToStringAddr()};
    const std::string addr_port_str{addr.ToStringAddrPort()};
    LOCK(m_added_nodes_mutex);
    return (m_added_node_params.size() < 24 // bound the query to a reasonable limit
            && std::any_of(m_added_node_params.cbegin(), m_added_node_params.cend(),
                           [&](const auto& p) { return p.m_added_node == addr_str || p.m_added_node == addr_port_str; }));
}

bool CConnman::AddPendingMasternode(const uint256& proTxHash)
{
    LOCK(cs_vPendingMasternodes);
    if (std::find(vPendingMasternodes.begin(), vPendingMasternodes.end(), proTxHash) != vPendingMasternodes.end()) {
        return false;
    }

    vPendingMasternodes.push_back(proTxHash);
    return true;
}

void CConnman::SetMasternodeQuorumNodes(Consensus::LLMQType llmqType, const uint256& quorumHash, const std::unordered_set<uint256, StaticSaltedHasher>& proTxHashes)
{
    LOCK(cs_vPendingMasternodes);
    auto it = masternodeQuorumNodes.emplace(std::make_pair(llmqType, quorumHash), proTxHashes);
    if (!it.second) {
        it.first->second = proTxHashes;
    }
}

void CConnman::SetMasternodeQuorumRelayMembers(Consensus::LLMQType llmqType, const uint256& quorumHash, const std::unordered_set<uint256, StaticSaltedHasher>& proTxHashes)
{
    {
        LOCK(cs_vPendingMasternodes);
        auto it = masternodeQuorumRelayMembers.emplace(std::make_pair(llmqType, quorumHash), proTxHashes);
        if (!it.second) {
            it.first->second = proTxHashes;
        }
    }

    // Update existing connections
    ForEachNode([&](CNode* pnode) {
        auto verifiedProRegTxHash = pnode->GetVerifiedProRegTxHash();
        if (!verifiedProRegTxHash.IsNull() && !pnode->m_masternode_iqr_connection && IsMasternodeQuorumRelayMember(verifiedProRegTxHash)) {
            // Tell our peer that we're interested in plain LLMQ recovered signatures.
            // Otherwise the peer would only announce/send messages resulting from QRECSIG,
            // e.g. InstantSend locks or ChainLocks. SPV and regular full nodes should not send
            // this message as they are usually only interested in the higher level messages.
            const CNetMsgMaker msgMaker(pnode->GetCommonVersion());
            PushMessage(pnode, msgMaker.Make(NetMsgType::QSENDRECSIGS, true));
            pnode->m_masternode_iqr_connection = true;
        }
    });
}

bool CConnman::HasMasternodeQuorumNodes(Consensus::LLMQType llmqType, const uint256& quorumHash) const
{
    LOCK(cs_vPendingMasternodes);
    return masternodeQuorumNodes.count(std::make_pair(llmqType, quorumHash));
}

std::unordered_set<uint256, StaticSaltedHasher> CConnman::GetMasternodeQuorums(Consensus::LLMQType llmqType) const
{
    LOCK(cs_vPendingMasternodes);
    std::unordered_set<uint256, StaticSaltedHasher> result;
    for (const auto& p : masternodeQuorumNodes) {
        if (p.first.first != llmqType) {
            continue;
        }
        result.emplace(p.first.second);
    }
    return result;
}

std::unordered_set<NodeId> CConnman::GetMasternodeQuorumNodes(Consensus::LLMQType llmqType, const uint256& quorumHash) const
{
    LOCK2(m_nodes_mutex, cs_vPendingMasternodes);
    auto it = masternodeQuorumNodes.find(std::make_pair(llmqType, quorumHash));
    if (it == masternodeQuorumNodes.end()) {
        return {};
    }
    const auto& proRegTxHashes = it->second;

    std::unordered_set<NodeId> nodes;
    for (const auto pnode : m_nodes) {
        if (pnode->fDisconnect) {
            continue;
        }
        auto verifiedProRegTxHash = pnode->GetVerifiedProRegTxHash();
        if (!pnode->qwatch && (verifiedProRegTxHash.IsNull() || !proRegTxHashes.count(verifiedProRegTxHash))) {
            continue;
        }
        nodes.emplace(pnode->GetId());
    }
    return nodes;
}

void CConnman::RemoveMasternodeQuorumNodes(Consensus::LLMQType llmqType, const uint256& quorumHash)
{
    LOCK(cs_vPendingMasternodes);
    masternodeQuorumNodes.erase(std::make_pair(llmqType, quorumHash));
    masternodeQuorumRelayMembers.erase(std::make_pair(llmqType, quorumHash));
}

bool CConnman::IsMasternodeQuorumNode(const CNode* pnode, const CDeterministicMNList& tip_mn_list) const
{
    // Let's see if this is an outgoing connection to an address that is known to be a masternode
    // We however only need to know this if the node did not authenticate itself as a MN yet
    uint256 assumedProTxHash;
    if (pnode->GetVerifiedProRegTxHash().IsNull() && !pnode->IsInboundConn()) {
        auto dmn = tip_mn_list.GetMNByService(pnode->addr);
        if (dmn == nullptr) {
            // This is definitely not a masternode
            return false;
        }
        assumedProTxHash = dmn->proTxHash;
    }

    LOCK(cs_vPendingMasternodes);
    for (const auto& p : masternodeQuorumNodes) {
        if (!pnode->GetVerifiedProRegTxHash().IsNull()) {
            if (p.second.count(pnode->GetVerifiedProRegTxHash())) {
                return true;
            }
        } else if (!assumedProTxHash.IsNull()) {
            if (p.second.count(assumedProTxHash)) {
                return true;
            }
        }
    }
    return false;
}

bool CConnman::IsMasternodeQuorumRelayMember(const uint256& protxHash)
{
    if (protxHash.IsNull()) {
        return false;
    }
    LOCK(cs_vPendingMasternodes);
    for (const auto& p : masternodeQuorumRelayMembers) {
        if (p.second.count(protxHash)) {
            return true;
        }
    }
    return false;
}

void CConnman::AddPendingProbeConnections(const std::set<uint256> &proTxHashes)
{
    LOCK(cs_vPendingMasternodes);
    masternodePendingProbes.insert(proTxHashes.begin(), proTxHashes.end());
}

size_t CConnman::GetNodeCount(ConnectionDirection flags) const
{
    LOCK(m_nodes_mutex);

    int nNum = 0;
    for (const auto& pnode : m_nodes) {
        if (pnode->fDisconnect) {
            continue;
        }
        if ((flags & ConnectionDirection::Verified) && pnode->GetVerifiedProRegTxHash().IsNull()) {
            continue;
        }
        if (flags & (pnode->IsInboundConn() ? ConnectionDirection::In : ConnectionDirection::Out)) {
            nNum++;
        } else if (flags == ConnectionDirection::Verified) {
            nNum++;
        }
    }

    return nNum;
}

size_t CConnman::GetMaxOutboundNodeCount()
{
    return m_max_outbound;
}
size_t CConnman::GetMaxOutboundOnionNodeCount()
{
    return m_max_outbound_onion;
}

void CConnman::GetNodeStats(std::vector<CNodeStats>& vstats) const
{
    vstats.clear();
    LOCK(m_nodes_mutex);
    vstats.reserve(m_nodes.size());
    for (CNode* pnode : m_nodes) {
        if (pnode->fDisconnect) {
            continue;
        }
        vstats.emplace_back();
        pnode->CopyStats(vstats.back());
        vstats.back().m_mapped_as = m_netgroupman.GetMappedAS(pnode->addr);
    }
}

bool CConnman::DisconnectNode(const std::string& strNode)
{
    LOCK(m_nodes_mutex);
    if (CNode* pnode = FindNode(strNode)) {
        LogPrint(BCLog::NET_NETCONN, "disconnect by address%s matched peer=%d; disconnecting\n", (fLogIPs ? strprintf("=%s", strNode) : ""), pnode->GetId());
        pnode->fDisconnect = true;
        return true;
    }
    return false;
}

bool CConnman::DisconnectNode(const CSubNet& subnet)
{
    bool disconnected = false;
    LOCK(m_nodes_mutex);
    for (CNode* pnode : m_nodes) {
        if (subnet.Match(pnode->addr)) {
            LogPrint(BCLog::NET_NETCONN, "disconnect by subnet%s matched peer=%d; disconnecting\n", (fLogIPs ? strprintf("=%s", subnet.ToString()) : ""), pnode->GetId());
            pnode->fDisconnect = true;
            disconnected = true;
        }
    }
    return disconnected;
}

bool CConnman::DisconnectNode(const CNetAddr& addr)
{
    return DisconnectNode(CSubNet(addr));
}

bool CConnman::DisconnectNode(NodeId id)
{
    LOCK(m_nodes_mutex);
    for(CNode* pnode : m_nodes) {
        if (id == pnode->GetId()) {
            LogPrint(BCLog::NET_NETCONN, "disconnect by id peer=%d; disconnecting\n", pnode->GetId());
            pnode->fDisconnect = true;
            return true;
        }
    }
    return false;
}

void CConnman::RecordBytesRecv(uint64_t bytes)
{
    nTotalBytesRecv += bytes;
    ::g_stats_client->count("bandwidth.bytesReceived", bytes, 0.1f);
    ::g_stats_client->gauge("bandwidth.totalBytesReceived", nTotalBytesRecv.load(), 0.01f);
}

void CConnman::RecordBytesSent(uint64_t bytes)
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    LOCK(m_total_bytes_sent_mutex);

    nTotalBytesSent += bytes;
    ::g_stats_client->count("bandwidth.bytesSent", bytes, 0.01f);
    ::g_stats_client->gauge("bandwidth.totalBytesSent", nTotalBytesSent, 0.01f);

    const auto now = GetTime<std::chrono::seconds>();
    if (nMaxOutboundCycleStartTime + MAX_UPLOAD_TIMEFRAME < now)
    {
        // timeframe expired, reset cycle
        nMaxOutboundCycleStartTime = now;
        nMaxOutboundTotalBytesSentInCycle = 0;
    }

    nMaxOutboundTotalBytesSentInCycle += bytes;
}

uint64_t CConnman::GetMaxOutboundTarget() const
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    LOCK(m_total_bytes_sent_mutex);
    return nMaxOutboundLimit;
}

std::chrono::seconds CConnman::GetMaxOutboundTimeframe() const
{
    return MAX_UPLOAD_TIMEFRAME;
}

std::chrono::seconds CConnman::GetMaxOutboundTimeLeftInCycle() const
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    LOCK(m_total_bytes_sent_mutex);
    return GetMaxOutboundTimeLeftInCycle_();
}

std::chrono::seconds CConnman::GetMaxOutboundTimeLeftInCycle_() const
{
    AssertLockHeld(m_total_bytes_sent_mutex);

    if (nMaxOutboundLimit == 0)
        return 0s;

    if (nMaxOutboundCycleStartTime.count() == 0)
        return MAX_UPLOAD_TIMEFRAME;

    const std::chrono::seconds cycleEndTime = nMaxOutboundCycleStartTime + MAX_UPLOAD_TIMEFRAME;
    const auto now = GetTime<std::chrono::seconds>();
    return (cycleEndTime < now) ? 0s : cycleEndTime - now;
}

bool CConnman::OutboundTargetReached(bool historicalBlockServingLimit) const
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    LOCK(m_total_bytes_sent_mutex);
    if (nMaxOutboundLimit == 0)
        return false;

    if (historicalBlockServingLimit)
    {
        // keep a large enough buffer to at least relay each block once
        const std::chrono::seconds timeLeftInCycle = GetMaxOutboundTimeLeftInCycle_();
        const uint64_t buffer = timeLeftInCycle / std::chrono::minutes{10} * MaxBlockSize();
        if (buffer >= nMaxOutboundLimit || nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit - buffer)
            return true;
    }
    else if (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit)
        return true;

    return false;
}

uint64_t CConnman::GetOutboundTargetBytesLeft() const
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    LOCK(m_total_bytes_sent_mutex);
    if (nMaxOutboundLimit == 0)
        return 0;

    return (nMaxOutboundTotalBytesSentInCycle >= nMaxOutboundLimit) ? 0 : nMaxOutboundLimit - nMaxOutboundTotalBytesSentInCycle;
}

uint64_t CConnman::GetTotalBytesRecv() const
{
    return nTotalBytesRecv;
}

uint64_t CConnman::GetTotalBytesSent() const
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    LOCK(m_total_bytes_sent_mutex);
    return nTotalBytesSent;
}

ServiceFlags CConnman::GetLocalServices() const
{
    return nLocalServices;
}

static std::unique_ptr<Transport> MakeTransport(NodeId id, bool use_v2transport, bool inbound) noexcept
{
    if (use_v2transport) {
        return std::make_unique<V2Transport>(id, /*initiating=*/!inbound, SER_NETWORK, INIT_PROTO_VERSION);
    } else {
        return std::make_unique<V1Transport>(id, SER_NETWORK, INIT_PROTO_VERSION);
    }
}

CNode::CNode(NodeId idIn,
             std::shared_ptr<Sock> sock,
             const CAddress& addrIn,
             uint64_t nKeyedNetGroupIn,
             uint64_t nLocalHostNonceIn,
             const CAddress& addrBindIn,
             const std::string& addrNameIn,
             ConnectionType conn_type_in,
             bool inbound_onion,
             CNodeOptions&& node_opts)
    : m_transport{MakeTransport(idIn, node_opts.use_v2transport, conn_type_in == ConnectionType::INBOUND)},
      m_permission_flags{node_opts.permission_flags},
      m_sock{sock},
      m_connected{GetTime<std::chrono::seconds>()},
      addr{addrIn},
      addrBind{addrBindIn},
      m_addr_name{addrNameIn.empty() ? addr.ToStringAddrPort() : addrNameIn},
      m_dest(addrNameIn),
      m_inbound_onion{inbound_onion},
      m_prefer_evict{node_opts.prefer_evict},
      nKeyedNetGroup{nKeyedNetGroupIn},
      m_conn_type{conn_type_in},
      id{idIn},
      nLocalHostNonce{nLocalHostNonceIn},
      m_recv_flood_size{node_opts.recv_flood_size},
      m_i2p_sam_session{std::move(node_opts.i2p_sam_session)}
{
    if (inbound_onion) assert(conn_type_in == ConnectionType::INBOUND);

    for (const std::string &msg : getAllNetMessageTypes())
        mapRecvBytesPerMsgType[msg] = 0;
    mapRecvBytesPerMsgType[NET_MESSAGE_TYPE_OTHER] = 0;

    if (fLogIPs) {
        LogPrint(BCLog::NET, "Added connection to %s peer=%d\n", m_addr_name, id);
    } else {
        LogPrint(BCLog::NET, "Added connection peer=%d\n", id);
    }
}

void CNode::MarkReceivedMsgsForProcessing()
{
    AssertLockNotHeld(m_msg_process_queue_mutex);

    size_t nSizeAdded = 0;
    for (const auto& msg : vRecvMsg) {
        // vRecvMsg contains only completed CNetMessage
        // the single possible partially deserialized message are held by TransportDeserializer
        nSizeAdded += msg.m_raw_message_size;
    }

    LOCK(m_msg_process_queue_mutex);
    m_msg_process_queue.splice(m_msg_process_queue.end(), vRecvMsg);
    m_msg_process_queue_size += nSizeAdded;
    fPauseRecv = m_msg_process_queue_size > m_recv_flood_size;
}

std::optional<std::pair<CNetMessage, bool>> CNode::PollMessage()
{
    LOCK(m_msg_process_queue_mutex);
    if (m_msg_process_queue.empty()) return std::nullopt;

    std::list<CNetMessage> msgs;
    // Just take one message
    msgs.splice(msgs.begin(), m_msg_process_queue, m_msg_process_queue.begin());
    m_msg_process_queue_size -= msgs.front().m_raw_message_size;
    fPauseRecv = m_msg_process_queue_size > m_recv_flood_size;

    return std::make_pair(std::move(msgs.front()), !m_msg_process_queue.empty());
}

bool CConnman::NodeFullyConnected(const CNode* pnode)
{
    return pnode && pnode->fSuccessfullyConnected && !pnode->fDisconnect;
}

void CConnman::PushMessage(CNode* pnode, CSerializedNetMsg&& msg)
{
    AssertLockNotHeld(m_total_bytes_sent_mutex);
    size_t nMessageSize = msg.data.size();
    LogPrint(BCLog::NET, "sending %s (%d bytes) peer=%d\n", msg.m_type, nMessageSize, pnode->GetId());
    if (gArgs.GetBoolArg("-capturemessages", false)) {
        CaptureMessage(pnode->addr, msg.m_type, msg.data, /*is_incoming=*/false);
    }

    TRACE6(net, outbound_message,
        pnode->GetId(),
        pnode->m_addr_name.c_str(),
        pnode->ConnectionTypeAsString().c_str(),
        msg.m_type.c_str(),
        msg.data.size(),
        msg.data.data()
    );

    ::g_stats_client->count(strprintf("bandwidth.message.%s.bytesSent", msg.m_type), nMessageSize, 1.0f);
    ::g_stats_client->inc(strprintf("message.sent.%s", msg.m_type), 1.0f);

    {
        LOCK(pnode->cs_vSend);
        // Check if the transport still has unsent bytes, and indicate to it that we're about to
        // give it a message to send.
        const auto& [to_send, more, _msg_type] =
            pnode->m_transport->GetBytesToSend(/*have_next_message=*/true);
        const bool queue_was_empty{to_send.empty() && pnode->vSendMsg.empty()};

        // Update memory usage of send buffer.
        pnode->m_send_memusage += msg.GetMemoryUsage();
        if (pnode->m_send_memusage + pnode->m_transport->GetSendMemoryUsage() > nSendBufferMaxSize) pnode->fPauseSend = true;
        // Move message to vSendMsg queue.
        pnode->vSendMsg.push_back(std::move(msg));
        pnode->nSendMsgSize = pnode->vSendMsg.size();

        // If there was nothing to send before, and there is now (predicted by the "more" value
        // returned by the GetBytesToSend call above), attempt "optimistic write":
        // because the poll/select loop may pause for SELECT_TIMEOUT_MILLISECONDS before actually
        // doing a send, try sending from the calling thread if the queue was empty before.
        // With a V1Transport, more will always be true here, because adding a message always
        // results in sendable bytes there, but with V2Transport this is not the case (it may
        // still be in the handshake).
        if (queue_was_empty && more) {
            if (m_wakeup_pipe && m_wakeup_pipe->m_need_wakeup.load()) {
                m_wakeup_pipe->Write();
            }
        }
    }
}

bool CConnman::ForNode(const CService& addr, std::function<bool(const CNode* pnode)> cond, std::function<bool(CNode* pnode)> func)
{
    CNode* found = nullptr;
    LOCK(m_nodes_mutex);
    for (auto&& pnode : m_nodes) {
        if((CService)pnode->addr == addr) {
            found = pnode;
            break;
        }
    }
    return found != nullptr && cond(found) && func(found);
}

bool CConnman::ForNode(NodeId id, std::function<bool(const CNode* pnode)> cond, std::function<bool(CNode* pnode)> func)
{
    CNode* found = nullptr;
    LOCK(m_nodes_mutex);
    for (auto&& pnode : m_nodes) {
        if(pnode->GetId() == id) {
            found = pnode;
            break;
        }
    }
    return found != nullptr && cond(found) && func(found);
}

bool CConnman::IsMasternodeOrDisconnectRequested(const CService& addr) {
    return ForNode(addr, AllNodes, [](CNode* pnode){
        return pnode->m_masternode_connection || pnode->fDisconnect;
    });
}

CConnman::NodesSnapshot::NodesSnapshot(const CConnman& connman, std::function<bool(const CNode* pnode)> filter,
                                       bool shuffle)
{
    {
        LOCK(connman.m_nodes_mutex);
        m_nodes_copy.reserve(connman.m_nodes.size());

        for (auto& node : connman.m_nodes) {
            if (!filter(node)) continue;
            node->AddRef();
            m_nodes_copy.push_back(node);
        }
    }
    if (shuffle) {
        Shuffle(m_nodes_copy.begin(), m_nodes_copy.end(), FastRandomContext{});
    }
}

CConnman::NodesSnapshot::~NodesSnapshot()
{
    for (auto& node : m_nodes_copy) {
        node->Release();
    }
}

CSipHasher CConnman::GetDeterministicRandomizer(uint64_t id) const
{
    return CSipHasher(nSeed0, nSeed1).Write(id);
}

uint64_t CConnman::CalculateKeyedNetGroup(const CAddress& address) const
{
    std::vector<unsigned char> vchNetGroup(m_netgroupman.GetGroup(address));

    return GetDeterministicRandomizer(RANDOMIZER_ID_NETGROUP).Write(vchNetGroup.data(), vchNetGroup.size()).Finalize();
}

void CConnman::PerformReconnections()
{
    AssertLockNotHeld(m_reconnections_mutex);
    AssertLockNotHeld(m_unused_i2p_sessions_mutex);
    while (true) {
        // Move first element of m_reconnections to todo (avoiding an allocation inside the lock).
        decltype(m_reconnections) todo;
        {
            LOCK(m_reconnections_mutex);
            if (m_reconnections.empty()) break;
            todo.splice(todo.end(), m_reconnections, m_reconnections.begin());
        }

        auto& item = *todo.begin();
        OpenNetworkConnection(item.addr_connect,
                              // We only reconnect if the first attempt to connect succeeded at
                              // connection time, but then failed after the CNode object was
                              // created. Since we already know connecting is possible, do not
                              // count failure to reconnect.
                              /*fCountFailure=*/false,
                              std::move(item.grant),
                              item.destination.empty() ? nullptr : item.destination.c_str(),
                              item.conn_type,
                              item.use_v2transport);
    }
}

void CaptureMessageToFile(const CAddress& addr,
                          const std::string& msg_type,
                          Span<const unsigned char> data,
                          bool is_incoming)
{
    // Note: This function captures the message at the time of processing,
    // not at socket receive/send time.
    // This ensures that the messages are always in order from an application
    // layer (processing) perspective.
    auto now = GetTime<std::chrono::microseconds>();

    // Windows folder names cannot include a colon
    std::string clean_addr = addr.ToStringAddrPort();
    std::replace(clean_addr.begin(), clean_addr.end(), ':', '_');

    fs::path base_path = gArgs.GetDataDirNet() / "message_capture" / clean_addr;
    fs::create_directories(base_path);

    fs::path path = base_path / (is_incoming ? "msgs_recv.dat" : "msgs_sent.dat");
    CAutoFile f(fsbridge::fopen(path, "ab"), SER_DISK, CLIENT_VERSION);

    ser_writedata64(f, now.count());
    f.write(MakeByteSpan(msg_type));
    for (auto i = msg_type.length(); i < CMessageHeader::COMMAND_SIZE; ++i) {
        f << uint8_t{'\0'};
    }
    uint32_t size = data.size();
    ser_writedata32(f, size);
    f.write(AsBytes(data));
}

std::function<void(const CAddress& addr,
                   const std::string& msg_type,
                   Span<const unsigned char> data,
                   bool is_incoming)>
    CaptureMessage = CaptureMessageToFile;
