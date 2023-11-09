# Simple UDP File Server

Probably has bugs
Not secure at all, for example: 
    - Path exploits
    - unencrypted Communication

Those two things are going to get fixed

Points that might or might not get looked at:

- No clue about Performance
- Should add PacketSize to PTE and or to request to allow for dynamic Packet size
- Need to add Resend Packet, if a Packet is lost right now, it wont get resend
- Needs timeouts, so server doesnt get bombed with trash data
- Needs to handle Errors correctly not just panic
- Tests would be nice but probably wont happen
- A Filelookup Packet would also be nice, to request what Files are available for download
- Maybe Upload Feature
- Simple Users auth so you can only get your Files
- If Users maybe groups so you can share Files with your Friends (very unlikly to happen)
- Better Go Project structure
- Comments