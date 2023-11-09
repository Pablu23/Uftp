build:
	go build -o bin/helloGo main.go client.go packets.go server.go

server:
	go run main.go server.go client.go packets.go server 