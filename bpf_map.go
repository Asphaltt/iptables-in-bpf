package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

func createMap(spec *ebpf.MapSpec, kvs []ebpf.MapKV) (*ebpf.Map, error) {
	spec.Pinning = ebpf.PinNone
	spec.Contents = kvs
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create map %s: %v", spec, err)
	}

	return m, nil
}

func loadOrCreateMap(pinPath string, spec *ebpf.MapSpec) (*ebpf.Map, error) {
	mapPinPath := filepath.Join(pinPath, spec.Name)
	m, err := ebpf.LoadPinnedMap(mapPinPath, nil)
	if err == nil {
		return m, nil
	}

	spec.Pinning = ebpf.PinByName
	m, err = ebpf.NewMapWithOptions(spec, ebpf.MapOptions{
		PinPath: pinPath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create map %s: %w", spec, err)
	}

	return m, nil
}

func loadOrRecreateMap(pinPath string, spec *ebpf.MapSpec, kvs []ebpf.MapKV) (*ebpf.Map, error) {
	mapPinPath := filepath.Join(pinPath, spec.Name)
	m, err := ebpf.LoadPinnedMap(mapPinPath, nil)
	if err == nil {
		_ = m.Unpin()
		_ = m.Close()
		_ = os.Remove(mapPinPath)
	}

	spec.Pinning = ebpf.PinNone
	spec.Contents = kvs
	m, err = ebpf.NewMapWithOptions(spec, ebpf.MapOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create map %s: %v", spec, err)
	}

	err = m.Pin(filepath.Join(pinPath, spec.Name))
	if err != nil {
		_ = m.Close()
		return nil, fmt.Errorf("failed to pin map %s to %s: %w", spec.Name, pinPath, err)
	}

	return m, nil
}
