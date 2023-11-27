build:
	go build -o bin/uftp main.go

server:
	go run main.go server 

test:
	go run main.go client testFiles/testFile