package main

import (
	"os"

	"github.com/Pablu23/Uftp/internal/client"
	"github.com/Pablu23/Uftp/internal/server"
)

func main() {
	if os.Args[1] == "server" {
		server, err := server.New(func(o *server.Options) {
			o.SavePrivKey = false
			o.LoadPrivkey = true
			o.PrivKeyPath = "privkey.pem"
		})
		if err != nil {
			panic(err)
		}
		server.Serve()
	} else {
		client.GetFile(os.Args[2], os.Args[3])
	}
}
