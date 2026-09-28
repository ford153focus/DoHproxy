namespace DoHproxy.Models;

/// <summary>
/// Cached upstream DNS response, keyed by the full query identity.
/// (copied from fb7965sk/Models/DnsCachedResponse.cs, mapped to the fb7965sk "dns_responses_cache" table)
/// </summary>
public partial class DnsCachedResponse
{
    public uint Id { get; set; } = 0;

    public string QueryName { get; set; } = string.Empty;
    public ushort QueryType { get; set; } = 0;
    public ushort QueryClass { get; set; } = 0;

    public byte[] RawResponse { get; set; } = [];

    public DateTime ExpiresAt { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
