namespace DoHproxy.Models;

/// <summary>
/// Locally forced answer (A record) for a query, keyed by name + type.
/// (copied from fb7965sk/Models/DnsResponseOverride.cs, mapped to the fb7965sk "dns_response_overrides" table)
/// </summary>
public partial class DnsResponseOverride
{
    public uint Id { get; set; } = 0;

    public string QueryName { get; set; } = string.Empty;
    public ushort QueryType { get; set; } = 0;

    public string Response { get; set; } = string.Empty;

    public DateTime ExpiresAt { get; set; } = DateTime.UtcNow.AddSeconds(5*60);
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}
