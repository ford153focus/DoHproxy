using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using DoHproxy.Models;

namespace DoHproxy.Data;

/// <summary>
/// Minimal data context holding only the two DNS tables this proxy needs.
/// The table/column names and MySQL store types are copied verbatim from
/// fb7965sk/Data/ApplicationDbContext.cs so this project can talk to the same
/// database (the "dns_responses_cache" and "dns_response_overrides" tables).
/// </summary>
public class ApplicationDbContext : DbContext
{
    public DbSet<DnsCachedResponse> DnsCachedResponses { get; set; }
    public DbSet<DnsResponseOverride> DnsResponseOverrides { get; set; }

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options): base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // SQLite cannot express MySQL's column types / collation / ON UPDATE defaults,
        // so those are applied only for the MySQL provider.
        bool isMySql = !Database.IsSqlite();

        if (isMySql)
        {
            modelBuilder.UseCollation("utf8mb4_general_ci");
        }

        modelBuilder.Entity<DnsResponseOverride>(entity =>
        {
            entity.ToTable("dns_response_overrides");

            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.HasIndex(e => new { e.QueryName, e.QueryType }).IsUnique().HasDatabaseName("IX_ckey_query_name_and_type");

            PropertyBuilder<uint> id = entity.Property(e => e.Id).HasColumnName("id").IsRequired().ValueGeneratedOnAdd();
            if (isMySql) id.HasColumnType("smallint unsigned");

            PropertyBuilder<string> queryName = entity.Property(e => e.QueryName).HasColumnName("query_name").HasMaxLength(253).IsRequired();
            if (isMySql) queryName.HasColumnType("varchar(253) character set ascii collate ascii_bin");

            PropertyBuilder<ushort> queryType = entity.Property(e => e.QueryType).HasColumnName("query_type").IsRequired();
            if (isMySql) queryType.HasColumnType("smallint unsigned");

            PropertyBuilder<string> response = entity.Property(e => e.Response).HasColumnName("response").HasMaxLength(253).IsRequired();
            if (isMySql) response.HasColumnType("varchar(253) character set ascii collate ascii_bin");

            PropertyBuilder<DateTime> expiresAt = entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
            if (isMySql) expiresAt.HasColumnType("datetime");

            PropertyBuilder<DateTime> createdAt = entity.Property(e => e.CreatedAt).HasColumnName("created_at");
            PropertyBuilder<DateTime> updatedAt = entity.Property(e => e.UpdatedAt).HasColumnName("updated_at");

            if (isMySql)
            {
                createdAt.HasColumnType("datetime").ValueGeneratedOnAdd().HasDefaultValueSql("CURRENT_TIMESTAMP");
                updatedAt.HasColumnType("datetime").ValueGeneratedOnAddOrUpdate().HasDefaultValueSql("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
            }
        });

        modelBuilder.Entity<DnsCachedResponse>(entity =>
        {
            entity.ToTable("dns_responses_cache");

            entity.HasKey(e => e.Id).HasName("PRIMARY");

            entity.HasIndex(e => new { e.QueryName, e.QueryType, e.QueryClass }).IsUnique().HasDatabaseName("IX_dns_cache_lookup");

            PropertyBuilder<uint> id = entity.Property(e => e.Id).HasColumnName("id").IsRequired().ValueGeneratedOnAdd();
            if (isMySql) id.HasColumnType("mediumint unsigned");

            PropertyBuilder<string> queryName = entity.Property(e => e.QueryName).HasColumnName("query_name").HasMaxLength(253).IsRequired();
            if (isMySql) queryName.HasColumnType("varchar(253) character set ascii collate ascii_bin");

            PropertyBuilder<ushort> queryType = entity.Property(e => e.QueryType).HasColumnName("query_type").IsRequired();
            if (isMySql) queryType.HasColumnType("smallint unsigned");

            PropertyBuilder<ushort> queryClass = entity.Property(e => e.QueryClass).HasColumnName("query_class").IsRequired();
            if (isMySql) queryClass.HasColumnType("smallint unsigned");

            PropertyBuilder<byte[]> rawResponse = entity.Property(e => e.RawResponse).HasColumnName("raw_response").IsRequired();
            if (isMySql) rawResponse.HasColumnType("varbinary(4096)");

            PropertyBuilder<DateTime> expiresAt = entity.Property(e => e.ExpiresAt).HasColumnName("expires_at").IsRequired();
            if (isMySql) expiresAt.HasColumnType("datetime");

            PropertyBuilder<DateTime> createdAt = entity.Property(e => e.CreatedAt).HasColumnName("created_at");
            PropertyBuilder<DateTime> updatedAt = entity.Property(e => e.UpdatedAt).HasColumnName("updated_at");

            if (isMySql)
            {
                createdAt.HasColumnType("datetime").ValueGeneratedOnAdd().HasDefaultValueSql("CURRENT_TIMESTAMP");
                updatedAt.HasColumnType("datetime").ValueGeneratedOnAddOrUpdate().HasDefaultValueSql("CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP");
            }
        });
    }
}
