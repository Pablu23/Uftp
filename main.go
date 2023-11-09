package main

import (
	"os"
)

const PacketSize = 504

func main() {
	if os.Args[1] == "server" {
		server, err := New()
		if err != nil {
			panic(err)
		}
		server.Serve()
	} else {
		GetFile(os.Args[2])
	}
}
