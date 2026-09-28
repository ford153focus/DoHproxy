using System.Net;
using System.Net.Sockets;
using DoHproxy.Data;
using DoHproxy.Logging;
using DoHproxy.Models;
using Microsoft.EntityFrameworkCore;

namespace DoHproxy;

internal static class Program
{
    private static readonly IPAddress TargetIp = IPAddress.Parse(Config.ipAddr); // specific IP address to bind to

    public static readonly UdpClient _udpClient = new(new IPEndPoint(TargetIp, Config.dnsPort));
    public static readonly TcpListener _tcpListener = new(TargetIp, Config.dnsPort);

    public static readonly HttpClient _http = new();

    public static BlueLogger2 logger = new(true);

    public static Dictionary<ushort,string> DnsRecordTypes = new ()
    {
        {1, "A"},
        {2, "NS"},
        {3, "MD"},
        {4, "MF"},
        {5, "CNAME"},
        {6, "SOA"},
        {7, "MB"},
        {8, "MG"},
        {9, "MR"},
        {10, "NULL"},
        {11, "WKS"},
        {12, "PTR"},
        {13, "HINFO"},
        {14, "MINFO"},
        {15, "MX"},
        {16, "TXT"},
        {17, "RP"},
        {18, "AFSDB"},
        {19, "X25"},
        {20, "ISDN"},
        {21, "RT"},
        {22, "NSAP"},
        {23, "NSAP-PTR"},
        {24, "SIG"},
        {25, "KEY"},
        {26, "PX"},
        {27, "GPOS"},
        {28, "AAAA"},
        {29, "LOC"},
        {30, "NXT"},
        {31, "EID"},
        {32, "NB"},
        // {32, "NIMLOC"},
        {33, "SRV"},
        // {33, "NBSTAT"},
        {34, "ATMA"},
        {35, "NAPTR"},
        {36, "KX"},
        {37, "CERT"},
        {38, "A6"},
        {39, "DNAME"},
        {40, "SINK"},
        {41, "OPT"},
        {42, "APL"},
        {43, "DS"},
        {44, "SSHFP"},
        {45, "IPSECKEY"},
        {46, "RRSIG"},
        {47, "NSEC"},
        {48, "DNSKEY"},
        {49, "DHCID"},
        {50, "NSEC3"},
        {51, "NSEC3PARAM"},
        {52, "TLSA"},
        {53, "SMIMEA"},
        {55, "HIP"},
        {56, "NINFO"},
        {57, "RKEY"},
        {58, "TALINK"},
        {59, "CDS"},
        {60, "CDNSKEY"},
        {61, "OPENPGPKEY"},
        {62, "CSYNC"},
        {63, "ZONEMD"},
        {64, "SVCB"},
        {65, "HTTPS"},
        {99, "SPF"},
        {100, "UINFO"},
        {101, "UID"},
        {102, "GID"},
        {103, "UNSPEC"},
        {104, "NID"},
        {105, "L32"},
        {106, "L64"},
        {107, "LP"},
        {108, "EUI48"},
        {109, "EUI64"},
        {249, "TKEY"},
        {250, "TSIG"},
        {251, "IXFR"},
        {252, "AXFR"},
        {253, "MAILB"},
        {254, "MAILA"},
        {255, "*"},
        {256, "URI"},
        {257, "CAA"},
        {259, "DOA"},
        {32768, "TA"},
        {32769, "DLV"},
    };

    private static async Task Main()
    {
        Console.WriteLine("DNS → DoH proxy running on UDP port 53");
        await Start();
    }

    public static async Task Start()
    {
        _tcpListener.Start();

        _ = Task.Run(HandleUdpLoop);
        _ = Task.Run(HandleTcpLoop);

        await Task.Delay(-1);
    }

    /// <summary>
    /// UDP HANDLER
    /// </summary>
    private static async Task HandleUdpLoop()
    {
        while (true)
        {
            UdpReceiveResult request = await _udpClient.ReceiveAsync();
            _ = Task.Run(() => ProcessDnsQuery(request.Buffer, request.RemoteEndPoint, isTcp: false));
        }
    }

    /// <summary>
    /// TCP HANDLER
    /// </summary>
    private static async Task HandleTcpLoop()
    {
        while (true)
        {
            TcpClient client = await _tcpListener.AcceptTcpClientAsync();
            _ = Task.Run(() => HandleTcpClient(client));
        }
    }

    private static async Task HandleTcpClient(TcpClient client)
    {
        using NetworkStream stream = client.GetStream();

        byte[] lenBuf = new byte[2];
        await stream.ReadExactlyAsync(lenBuf, 0, 2); /** Read the 2-byte length prefix exactly */

        int length = (lenBuf[0] << 8) | lenBuf[1];
        byte[] dnsRequest = new byte[length];

        await stream.ReadExactlyAsync(dnsRequest, 0, length); /** Read the full DNS payload exactly */

        byte[]? response = await ProcessDnsQuery(dnsRequest, null, isTcp: true);

        if (response != null)
        {
            byte[] outLen = { (byte)(response.Length >> 8), (byte)(response.Length & 0xFF) };
            await stream.WriteAsync(outLen);
            await stream.WriteAsync(response);
        }
    }

    /// <summary>
    /// CORE PROCESSOR
    /// </summary>
    private static async Task<byte[]?> ProcessDnsQuery(byte[] dnsRequest, IPEndPoint? remote, bool isTcp)
    {
        (string? qname, ushort qtype, ushort qclass) = DnsParser.ExtractQueryIdentity(dnsRequest);
        if (qname == "<parse-error>") return null;

        logger.LogDebug($"Query for {DnsRecordTypes[qtype]} of {qname} via {(isTcp ? "TCP" : "UDP")}");

        using ApplicationDbContext dbContext = Db.GetDatabaseContext();

        DnsResponseOverride? dnsResponseOverride = await dbContext.DnsResponseOverrides.FirstOrDefaultAsync(c => c.QueryName == qname && c.QueryType == qtype);
        if (dnsResponseOverride is not null)
        {
            logger.LogSuccess($"[LOCAL OVERRIDE] Resolving {qname} → {dnsResponseOverride.Response}");

            // Generate the custom packet dynamically mapping the active Transaction ID
            byte[] localResponse = DnsParser.GenerateLocalARecordResponse(dnsRequest, dnsResponseOverride.Response);

            // Ship response back to UDP client immediately if applicable
            if (!isTcp && remote != null)
            {
                await _udpClient.SendAsync(localResponse, localResponse.Length, remote);
            }
            return localResponse;
        }

        DnsCachedResponse dnsCachedResponse = (await dbContext.DnsCachedResponses.FirstOrDefaultAsync(c => c.QueryName == qname && c.QueryType == qtype && c.QueryClass == qclass)) ?? new();

        if (dnsCachedResponse.Id > 0 && dnsCachedResponse.ExpiresAt > DateTime.UtcNow)
        {
            logger.LogSuccess($"DB Cache hit! #{dnsCachedResponse.Id}");
            byte[] cachedResponse = dnsCachedResponse.RawResponse;

            byte[] tailoredResponse = (byte[])dnsCachedResponse.RawResponse.Clone();
            tailoredResponse[0] = dnsRequest[0];
            tailoredResponse[1] = dnsRequest[1];

            if (!isTcp) await _udpClient.SendAsync(tailoredResponse, tailoredResponse.Length, remote);
            return tailoredResponse;
        }

        byte[]? dohResponse = await Resolve(dnsRequest);

        if (dohResponse == null)
        {
            logger.LogError("All upstreams failed");
            return null;
        }

        int ttl = DnsParser.ExtractTTL(dohResponse);
        DateTime expiresAt = DateTime.UtcNow.AddSeconds(ttl);

        dnsCachedResponse.QueryName = qname;
        dnsCachedResponse.QueryType = qtype;
        dnsCachedResponse.QueryClass = qclass;
        dnsCachedResponse.RawResponse = dohResponse;
        dnsCachedResponse.ExpiresAt = expiresAt;

        try
        {
            if (dnsCachedResponse.Id == 0)
            {
                await dbContext.DnsCachedResponses.AddAsync(dnsCachedResponse);
            }
            else
            {
                dbContext.DnsCachedResponses.Update(dnsCachedResponse);
            }

            int rowsAffected = await dbContext.SaveChangesAsync();
            // logger.Debug($"► ACTUAL DB ROWS WRITTEN: {rowsAffected}, SAVED ID: {dnsCachedResponse.Id}");
        }
        catch (Exception dbEx)
        {
            logger.LogError($"!!! CRITICAL DB ATTEMPT FAILED: {dbEx.Message}");
            if (dbEx.InnerException != null)
            {
                logger.LogError($"!!! INNER ENGINE ERROR: {dbEx.InnerException.Message}");
            }
        }

        if (!isTcp) await _udpClient.SendAsync(dohResponse, dohResponse.Length, remote);
        return dohResponse;
    }

    public static async Task<byte[]?> Resolve(byte[] dnsRequest)
    {
        #region Try modern DNS-over-HTTPS Upstreams first
        foreach (string upstream in Config.WebProtocolUpstreams)
        {
            try
            {
                using CancellationTokenSource cts = new(TimeSpan.FromSeconds(2)); // Prevent hanging on bad networks
                ByteArrayContent content = new(dnsRequest);
                content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/dns-message");

                HttpResponseMessage resp = await _http.PostAsync(upstream, content, cts.Token);

                if (resp.IsSuccessStatusCode)
                {
                    logger.LogSuccess($"Resolved via DoH DNS upstream: {upstream}");
                    return await resp.Content.ReadAsByteArrayAsync(cts.Token);
                }
            }
            catch
            {
                // try next Web upstream
            }
        }
        #endregion Try modern DNS-over-HTTPS Upstreams first

        #region Fallback: Try Classic UDP DNS Upstreams
        logger.LogError("All DoH upstreams failed. Attempting classic DNS fallback...");
        using UdpClient fallbackClient = new();

        // Configure a strict network timeout so a single dead IP won't lock up thread
        fallbackClient.Client.ReceiveTimeout = 2000;
        fallbackClient.Client.SendTimeout = 2000;

        foreach (string upstreamIp in Config.ClassicProtocolUpstreams)
        {
            try
            {
                // Send raw query over traditional port 53
                await fallbackClient.SendAsync(dnsRequest, dnsRequest.Length, upstreamIp, 53);

                // Receive raw byte response directly back from the public resolver
                UdpReceiveResult fallbackResult = await fallbackClient.ReceiveAsync();

                logger.LogSuccess($"Resolved via classic DNS upstream: {upstreamIp}");
                return fallbackResult.Buffer;
            }
            catch
            {
                // try next Classic upstream
            }
        }
        #endregion Fallback: Try Classic UDP DNS Upstreams

        return null;
    }
}
