build:
	go build -o bin/uftp main.go

server:
	go run main.go server 

test:
	go run main.go client testFiles/testFile 0.0.0.0:13374

win:
	GOOS=windows GOARCH=amd64 go build -o bin/app-amd64.exe main.go