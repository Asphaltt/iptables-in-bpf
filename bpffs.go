package main

import (
	"log"
	"os"

	"github.com/iovisor/gobpf/pkg/bpffs"
)

func checkBPFFS(fspath string) {
	mounted, err := bpffs.IsMountedAt(fspath)
	if err != nil {
		log.Fatalf("Failed to check mount -t bpf %s: %v", fspath, err)
	}

	if mounted {
		return
	}

	_ = os.MkdirAll(fspath, 0o700)
	err = bpffs.MountAt(fspath)
	if err != nil {
		log.Fatalf("Failed to mount -t bpf %s: %v", fspath, err)
	}
}
