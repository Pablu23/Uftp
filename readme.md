# Simple UDP File transfer

A udp File transfer "Suite" with TCP Connection establishment

## Points that might or might not get looked at:
- Performance Improvements (right now on my PC ~400 Mbit/s Throughput allocated to all requesting clients, localhost / not Network bound)
- Timouts happen but only after all of the data is send, so pretty useless as of now
- Tests would be nice but probably wont happen
- A Filelookup Packet would also be nice, to request what Files are available for download
- Maybe Upload Feature
- Simple Users auth so you can only get your Files
- If Users maybe groups so you can share Files with your Friends (very unlikly to happen)
- Comments
- Better Cli support
- Better Readme

## Notes
- Udp max packet size is set with 504
