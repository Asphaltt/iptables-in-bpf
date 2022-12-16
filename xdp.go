package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func loadXdpProg(pinPath string) (*xdpmainObjects, error) {
	spec, err := loadXdpmain()
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf spec: %w", err)
	}

	replacedMaps := make(map[string]*ebpf.Map, 1)

	progsMapSpec := spec.Maps["acl_progs"]
	progsMap, err := loadOrCreateMap(pinPath, progsMapSpec.Copy())
	if err != nil {
		return nil, fmt.Errorf("failed to create progs bpf map: %w", err)
	}
	replacedMaps["acl_progs"] = progsMap

	var obj xdpmainObjects
	err = spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
		MapReplacements: replacedMaps,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf obj: %w", err)
	}

	return &obj, nil
}

func attachXdpProg(obj *xdpmainObjects, flags link.XDPAttachFlags, pinPath string, devices []string) error {
	for _, device := range devices {
		devPinPath := filepath.Join(pinPath, device)
		if fileExists(devPinPath) {
			continue
		}

		ifi, err := net.InterfaceByName(device)
		if err != nil {
			return fmt.Errorf("failed to get interface info for %s: %w", device, err)
		}

		xdp, err := link.LoadPinnedLink(devPinPath, nil)
		if err == nil {
			_ = xdp.Unpin()
			_ = xdp.Close()
			_ = os.Remove(devPinPath)
		}

		xdp, err = link.AttachXDP(link.XDPOptions{
			Program:   obj.XdpAclFunc,
			Interface: ifi.Index,
			Flags:     flags,
		})
		if err != nil {
			return fmt.Errorf("failed to attach xdp_acl_func prog to %s: %w", device, err)
		}
		defer xdp.Close()

		err = xdp.Pin(devPinPath)
		if err != nil {
			return fmt.Errorf("failed to pin xdp_acl_func prog to %s: %w", devPinPath, err)
		}

		log.Printf("Pinned xdp_acl_func prog to %s\n", devPinPath)
	}

	return nil
}

func fileExists(fpath string) bool {
	_, err := os.Stat(fpath)
	return err == nil || os.IsExist(err)
}
