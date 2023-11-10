package main

import (
	"client"
	"os"
	"server"
)

func main() {
	if os.Args[1] == "server" {
		server, err := server.New()
		if err != nil {
			panic(err)
		}
		server.Serve()
	} else {
		client.GetFile(os.Args[2])
	}
}
