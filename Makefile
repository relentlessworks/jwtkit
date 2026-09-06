.PHONY: build test vet clean run

build:
	go build -o jwtkit ./cmd/jwtkit

test:
	go test ./...

vet:
	go vet ./...

run: build
	./jwtkit

clean:
	rm -f jwtkit
