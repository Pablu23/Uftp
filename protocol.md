# Protocol

// Handshake or encryption setup here
1. Client sends request for file
2. Server answers with error or FileSize
3. Client ack
4. Server sends File Packets with Sync to keep track
5. Server sends Sync End Packet
// LOOP
6. If Packets were lost client sends request to resend specific Sync Packets
7. Server sends Packets 
// LOOP END
8. If Client has all packets, or retries has exceeded limit. Client sends Ack Packet for last Sync
9. Client and Server "close" / forget the connection

### Secure Header | Unencrypted
1 Byte RSA Flag | 24 Byte Nonce | 8 Byte Session ID | 4 Byte Encrypted Data Length

### Packet Header | Encrypted
1 Byte Header Type Flag | 4 Byte Sync

### Packet Structure
37 Byte Secure Header | 5 Byte Packet Header | <= 446 Byte Data | 16 Byte chacha20poly1305 overhead


### Data

Request Data = UTF-8 File Path / File Lookup

Packets to expect (PTE) = uint32 little endian Number of Packets to expect

Ack = uint32 little endian Sync number to Acknowledge

File = Raw file bytes

End = uint32 little endian Sync number of last File Packet

Resend = uint32 little endian Sync number to Resend
