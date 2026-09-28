# DoHproxy

DNS to DNS-over-HTTPS proxy

## Data store

```bash
DOHPROXY_MYSQL_CONNECTION="Server=127.0.0.1; Port=3306; Database=fb7965sk; User=root; Password=..." dotnet run
```

When that variable is unset, the proxy falls back to a local SQLite database
(`dohproxy.db`, created next to the executable with the same schema), so it still resolves DNS
without any external database. The active store is printed once at startup.

## Running

`Config.ipAddr` / `Config.dnsPort` set the listen address (192.168.1.44:53), so the process needs
permission to bind a privileged port. Upstream resolvers and the rest of the settings live in
`Config.cs`.
