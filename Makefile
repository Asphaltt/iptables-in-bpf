
.DEFAULT_GOAL = build

.PHONY: build

build:
	go generate
	GOOS=linux go build -trimpath -v -o xdp_acl .
