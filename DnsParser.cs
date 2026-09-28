using System.Text;
using System.Net;

namespace DoHproxy;

public static class DnsParser {
    public static List<string> ExtractIPs(byte[] packet)
    {
        List<string> ips = [];
        try
        {
            if (packet == null || packet.Length < 12) return ips;

            // Read counts from the 12-byte DNS Header
            ushort qdCount = (ushort)((packet[4] << 8) | packet[5]); // Questions
            ushort anCount = (ushort)((packet[6] << 8) | packet[7]); // Answers

            int index = 12; // Start past DNS Header

            // 1. Skip the Question Section
            for (int i = 0; i < qdCount; i++)
            {
                index = SkipName(packet, index);
                index += 4; // Skip QTYPE + QCLASS
            }

            // 2. Parse the Answer Section
            for (int i = 0; i < anCount; i++)
            {
                index = SkipName(packet, index); // Skip the record owner name (usually a pointer)

                ushort type = (ushort)((packet[index] << 8) | packet[index + 1]);
                index += 4; // Skip TYPE (2 bytes) + CLASS (2 bytes)
                index += 4; // Skip TTL (4 bytes)

                ushort dataLength = (ushort)((packet[index] << 8) | packet[index + 1]);
                index += 2; // Step past Data Length field

                // Type 1 is strictly an 'A' record (IPv4 Address)
                if (type == 1 && dataLength == 4)
                {
                    byte[] ipBytes = new byte[4];
                    Array.Copy(packet, index, ipBytes, 0, 4);
                    ips.Add(new IPAddress(ipBytes).ToString());
                }

                index += dataLength; // Advance past this record's resource data payload
            }
        }
        catch
        {
            // Suppress malformed packet edge cases or early stream terminations
        }
        return ips;
    }

    public static (string qname, ushort qtype, ushort qclass) ExtractQueryIdentity(byte[] packet)
    {
        try
        {
            int index = 12;
            List<string> labels = [];

            while (packet[index] != 0)
            {
                int len = packet[index++];
                labels.Add(Encoding.ASCII.GetString(packet, index, len));
                index += len;
            }

            index++; // Step past the terminating null byte (0)

            // Read QTYPE (2 bytes, Big-Endian)
            ushort qtype = (ushort)((packet[index] << 8) | packet[index + 1]);
            index += 2;

            // Read QCLASS (2 bytes, Big-Endian)
            ushort qclass = (ushort)((packet[index] << 8) | packet[index + 1]);

            return (string.Join(".", labels).ToLowerInvariant(), qtype, qclass);
        }
        catch
        {
            return ("<parse-error>", 0, 0);
        }
    }

    public static int ExtractTTL(byte[] packet)
    {
        try
        {
            if (packet == null || packet.Length < 12) return 60; // Safe default fallback

            // 1. Read the counts from the 12-byte DNS Header (Big-Endian)
            ushort qdCount = (ushort)((packet[4] << 8) | packet[5]); // Question Count
            ushort anCount = (ushort)((packet[6] << 8) | packet[7]); // Answer Count

            if (anCount == 0) return 60; // No answers (e.g., NXDOMAIN), cache briefly

            int index = 12; // Start past the DNS Header

            // 2. Skip all Questions in the Question Section
            for (int i = 0; i < qdCount; i++)
            {
                index = SkipName(packet, index);
                index += 4; // Skip QTYPE (2 bytes) + QCLASS (2 bytes)
            }

            // 3. Parse the First Answer Record to get its TTL
            // First, skip the record's NAME field (which is almost always a 2-byte pointer 0xC0xx)
            index = SkipName(packet, index);

            // Current position points to: TYPE (2 bytes) + CLASS (2 bytes) + TTL (4 bytes)
            index += 4; // Step past TYPE and CLASS

            // Read the 4-byte TTL integer (Big-Endian)
            uint ttl = (uint)((packet[index] << 24) |
                            (packet[index + 1] << 16) |
                            (packet[index + 2] << 8) |
                            packet[index + 3]);

            // Enforce safety limits: cap long TTLs to 1 day (86400s), ignore zero/negative corruption
            if (ttl == 0 || ttl > 86400) return 300;

            return (int)ttl;
        }
        catch
        {
            return 60; // Return a safe 1-minute fallback TTL on unexpected packet shapes
        }
    }

    /// <summary>
    /// Safely skips a DNS domain name variable field, handling standard labels and nested 0xC0 pointers.
    /// </summary>
    private static int SkipName(byte[] packet, int index)
    {
        while (index < packet.Length)
        {
            byte b = packet[index];

            if (b == 0) // Terminating null byte of an uncompressed string
            {
                return index + 1;
            }

            if ((b & 0xC0) == 0xC0) // Compression Pointer Flag detected!
            {
                return index + 2; // Pointers are strictly 2 bytes long; skip them entirely
            }

            // Standard label: skip the length byte + string segment length
            index += 1 + b;
        }
        return index;
    }

    public static byte[] GenerateLocalARecordResponse(byte[] requestPacket, string ipAddress)
    {
        // Parse the target IP string into a 4-byte array
        byte[] ipBytes = System.Net.IPAddress.Parse(ipAddress).GetAddressBytes();

        // Create a response buffer large enough to hold the original request + our answer block
        // A-record Answer Block size = 2 bytes (Name Pointer) + 2 (Type) + 2 (Class) + 4 (TTL) + 2 (DataLen) + 4 (IP) = 16 bytes
        byte[] response = new byte[requestPacket.Length + 16];
        Array.Copy(requestPacket, response, requestPacket.Length);

        // 1. Modify DNS Header Flags to mark this packet as a Response
        response[2] = 0x81; // QR=1 (Response), Opcode=0, AA=0, TC=0, RD=1
        response[3] = 0x80; // RA=1 (Recursion Available), Z=0, RCODE=0 (No Error)

        // 2. Set Answer Count (ANCOUNT) to 1 (Bytes 6 and 7 of the DNS Header)
        response[6] = 0x00;
        response[7] = 0x01;

        // 3. Construct the Answer Record trailing payload
        int index = requestPacket.Length;

        // Name Pointer: Point back to the domain name string located right after the 12-byte header
        response[index++] = 0xC0;
        response[index++] = 0x0C;

        // Type: A Record (0x0001)
        response[index++] = 0x00;
        response[index++] = 0x01;

        // Class: IN / Internet (0x0001)
        response[index++] = 0x00;
        response[index++] = 0x01;

        // TTL: Set a local static lease of 5 minutes / 300 seconds (0x0000012C)
        response[index++] = 0x00;
        response[index++] = 0x00;
        response[index++] = 0x01;
        response[index++] = 0x02; // 0x2C is 44, let's use a clear hex literal or byte mapping:

        // Let's refine the 4-byte TTL safely to 300 seconds (0x0000012C):
        response[index - 1] = 0x2C; // Sets TTL byte 4 cleanly

        // Data Length: 4 bytes long for an IPv4 address (0x0004)
        response[index++] = 0x00;
        response[index++] = 0x04;

        // Copy the 4 raw IP address bytes into the final slot
        Array.Copy(ipBytes, 0, response, index, 4);

        return response;
    }
}
