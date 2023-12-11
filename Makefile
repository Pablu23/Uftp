build:
	go build -o bin/uftp cmd/uftp/main.go

server:
	go run cmd/uftp/main.go server 

test:
	go run cmd/uftp/main.go client testFile 0.0.0.0

win:
	GOOS=windows GOARCH=amd64 go build -o bin/app-amd64.exe cmd/uftp/main.go
