namespace DoHproxy;

static class Config
{
    public const string ipAddr = "192.168.1.44";
    public const int dnsPort = 53;

    public static readonly List<string> WebProtocolUpstreams = [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/dns-query",
        "https://dns.quad9.net/dns-query",
    ];

    public static readonly List<string> ClassicProtocolUpstreams = [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "9.9.9.9",
    ];
}
