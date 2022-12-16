package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/link"
	"github.com/iovisor/gobpf/pkg/bpffs"
	flags "github.com/spf13/pflag"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc=clang xdpacl ./ebpf/xdp_acl.c --  -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc=clang xdpmain ./ebpf/xdp_main.c --  -D__TARGET_ARCH_x86 -I./ebpf/headers -Wall

func main() {
	var flag struct {
		ruleFile string
		devices  []string

		xdpMode string
		pinPath string
	}

	flags.StringVar(&flag.ruleFile, "rule-file", "xdp_acl.json", "rule file in JSON format [Required]")
	flags.StringSliceVar(&flag.devices, "devices", nil, "devices to run XDP")
	flags.StringVar(&flag.xdpMode, "xdp-mode", "", "XDP mode to run XDP: generic, driver, offload or empty for default")
	flags.StringVar(&flag.pinPath, "pin-path", bpffs.BPFFSPath, "a path under bpffs directory [Required]")
	flags.Parse()

	checkBPFFS(flag.pinPath)
	rootPinPath := filepath.Join(flag.pinPath, "xdp_acl")
	_ = os.MkdirAll(rootPinPath, 0o700)

	rules, err := loadRules(flag.ruleFile)
	if err != nil {
		log.Fatalf("Failed to load rules from %s: %v", flag.ruleFile, err)
	}

	rules = sortRules(rules)
	if err := checkRules(rules); err != nil {
		log.Fatalf("Failed to check rules: %v", err)
	}

	obj, err := loadXdpProg(rootPinPath)
	if err != nil {
		log.Fatalf("Failed to load bpf obj: %v", err)
	}
	defer obj.Close()

	err = storeAclRules(rules, rootPinPath, obj)
	if err != nil {
		log.Fatalf("Failed to store rules to XDP: %v", err)
	}

	var xdpFlag link.XDPAttachFlags
	switch flag.xdpMode {
	case "generic":
		xdpFlag = link.XDPGenericMode
	case "driver":
		xdpFlag = link.XDPDriverMode
	case "offload":
		xdpFlag = link.XDPOffloadMode
	case "":
		// left xdpFlag as zero
	default:
		log.Fatalf("XDP mode %s is not support", flag.xdpMode)
	}

	err = attachXdpProg(obj, xdpFlag, rootPinPath, flag.devices)
	if err != nil {
		log.Fatalf("Failed to run XDP on devices %v: %v", flag.devices, err)
	}

	log.Printf("Stored %d rules to XDP\n", len(rules))

	if len(flag.devices) != 0 {
		log.Printf("XDP is ready to run on devices %v\n", flag.devices)
	}
}
