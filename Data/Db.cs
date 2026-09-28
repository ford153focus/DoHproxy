using Microsoft.EntityFrameworkCore;

namespace DoHproxy.Data;

/// <summary>
/// Creates <see cref="ApplicationDbContext"/> instances for the DNS override/cache store.
///
/// MySQL is used when the DOHPROXY_MYSQL_CONNECTION environment variable holds a connection
/// string (the very same database fb7965sk serves from), e.g.
///   DOHPROXY_MYSQL_CONNECTION="Server=127.0.0.1; Port=3306; Database=fb7965sk; User=root; Password=..."
///
/// When that variable is not set, a local SQLite database is created next to the executable,
/// so the proxy stays fully functional without any external database.
/// </summary>
public static class Db
{
    /// <summary>Set this environment variable to point the proxy at the MySQL database.</summary>
    public const string MySqlConnectionEnvVar = "DOHPROXY_MYSQL_CONNECTION";

    /// <summary>Name of the local SQLite fallback database file.</summary>
    public const string SqliteFileName = "dohproxy.db";

    /// <summary>Tables for the local SQLite fallback (mirrors the MySQL schema).</summary>
    private const string SqliteSchemaSql = """
        CREATE TABLE IF NOT EXISTS "dns_response_overrides" (
            "id"         INTEGER NOT NULL CONSTRAINT "PK_dns_response_overrides" PRIMARY KEY AUTOINCREMENT,
            "query_name" TEXT NOT NULL,
            "query_type" INTEGER NOT NULL,
            "response"   TEXT NOT NULL,
            "expires_at" TEXT NOT NULL,
            "created_at" TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            "updated_at" TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE UNIQUE INDEX IF NOT EXISTS "IX_ckey_query_name_and_type" ON "dns_response_overrides" ("query_name", "query_type");

        CREATE TABLE IF NOT EXISTS "dns_responses_cache" (
            "id"           INTEGER NOT NULL CONSTRAINT "PK_dns_responses_cache" PRIMARY KEY AUTOINCREMENT,
            "query_name"   TEXT NOT NULL,
            "query_type"   INTEGER NOT NULL,
            "query_class"  INTEGER NOT NULL,
            "raw_response" BLOB NOT NULL,
            "expires_at"   TEXT NOT NULL,
            "created_at"   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            "updated_at"   TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );

        CREATE UNIQUE INDEX IF NOT EXISTS "IX_dns_cache_lookup" ON "dns_responses_cache" ("query_name", "query_type", "query_class");
        """;

    private static readonly Lazy<DbContextOptions<ApplicationDbContext>> Options = new(BuildOptions);
    private static readonly Lazy<bool> SqliteSchema = new(EnsureSqliteSchema);

    /// <summary>Absolute path of the local SQLite fallback database file.</summary>
    public static string SqlitePath => Path.Combine(AppContext.BaseDirectory, SqliteFileName);

    /// <summary>True when DOHPROXY_MYSQL_CONNECTION is set, i.e. the MySQL store will be used.</summary>
    public static bool IsMySql => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(MySqlConnectionEnvVar));

    public static ApplicationDbContext GetDatabaseContext()
    {
        if (!IsMySql)
        {
            // Creates the local SQLite file (and its schema) on first use.
            _ = SqliteSchema.Value;
        }

        return new ApplicationDbContext(Options.Value);
    }

    private static DbContextOptions<ApplicationDbContext> BuildOptions()
    {
        DbContextOptionsBuilder<ApplicationDbContext> builder = new();

        string? mySqlConnectionString = Environment.GetEnvironmentVariable(MySqlConnectionEnvVar);

        if (!string.IsNullOrWhiteSpace(mySqlConnectionString))
        {
            builder.UseMySQL(mySqlConnectionString);
            Console.WriteLine($"DNS store: MySQL ({MySqlConnectionEnvVar})");
        }
        else
        {
            builder.UseSqlite($"DataSource={SqlitePath};Cache=Shared");
            Console.WriteLine($"DNS store: SQLite ({SqlitePath}) — set {MySqlConnectionEnvVar} to use MySQL instead");
        }

        builder.EnableSensitiveDataLogging(); // Shows parameter values
        builder.EnableDetailedErrors(); // Shows which specific property failed

        return builder.Options;
    }

    private static bool EnsureSqliteSchema()
    {
        using ApplicationDbContext dbContext = new(Options.Value);
        dbContext.Database.ExecuteSqlRaw(SqliteSchemaSql);
        return true;
    }
}
