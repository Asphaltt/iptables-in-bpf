package main

import (
	"fmt"
	"net/netip"

	"github.com/cilium/ebpf"
	"github.com/samber/lo"
)

type lpmKey struct {
	Prefixlen uint32
	Data      [4]byte
}

func storeAclRules(rules []*aclRule, pinPath string, xdpObj *xdpmainObjects) error {
	saddrs := lo.Map(rules, func(rule *aclRule, _ int) []netip.Prefix {
		return rule.saddr
	})
	daddrs := lo.Map(rules, func(rule *aclRule, _ int) []netip.Prefix {
		return rule.daddr
	})
	sports := lo.Map(rules, func(rule *aclRule, index int) ebpf.MapKV {
		return ebpf.MapKV{
			Key:   uint32(index),
			Value: rule.sport,
		}
	})
	dports := lo.Map(rules, func(rule *aclRule, index int) ebpf.MapKV {
		return ebpf.MapKV{
			Key:   uint32(index),
			Value: rule.dport,
		}
	})
	protocols := lo.Map(rules, func(rule *aclRule, index int) ebpf.MapKV {
		return ebpf.MapKV{
			Key:   uint32(index),
			Value: rule.protocol,
		}
	})
	policies := lo.Map(rules, func(rule *aclRule, index int) ebpf.MapKV {
		return ebpf.MapKV{
			Key: uint32(index),
			Value: xdpaclRulePolicy{
				Priority: rule.priority,
				Action:   uint32(rule.action),
			},
		}
	})

	spec, err := loadXdpacl()
	if err != nil {
		return fmt.Errorf("failed to load bpf spec: %w", err)
	}

	replacedMaps := make(map[string]*ebpf.Map, 8)

	saddrInnerMaps := make([]ebpf.MapKV, 0, len(rules))

	mapSpecInner := spec.Maps["acl_addr_inner"]

	for i, saddr := range saddrs {
		kvs := lo.Map(saddr, func(addr netip.Prefix, _ int) ebpf.MapKV {
			return ebpf.MapKV{
				Key: lpmKey{
					Prefixlen: uint32(addr.Bits()),
					Data:      addr.Addr().As4(),
				},
				Value: uint16(1),
			}
		})

		mapSpec := mapSpecInner.Copy()
		// mapSpec.MaxEntries = uint32(len(kvs))

		m, err := createMap(mapSpec, kvs)
		if err != nil {
			return fmt.Errorf("failed to create inner addr bpf map: %w", err)
		}
		defer m.Close()

		saddrInnerMaps = append(saddrInnerMaps, ebpf.MapKV{
			Key:   uint32(i),
			Value: m,
		})
	}

	saddrMapSpec := spec.Maps["acl_saddr"]
	saddrMapSpec.InnerMap = mapSpecInner.Copy()
	saddrMap, err := loadOrRecreateMap(pinPath, saddrMapSpec, saddrInnerMaps)
	if err != nil {
		return fmt.Errorf("failed to create saddr bpf map: %w", err)
	}
	defer saddrMap.Close()
	replacedMaps["acl_saddr"] = saddrMap

	daddrInnerMaps := make([]ebpf.MapKV, 0, len(rules))

	for i, daddr := range daddrs {
		kvs := lo.Map(daddr, func(addr netip.Prefix, _ int) ebpf.MapKV {
			return ebpf.MapKV{
				Key: lpmKey{
					Prefixlen: uint32(addr.Bits()),
					Data:      addr.Addr().As4(),
				},
				Value: uint16(1),
			}
		})

		mapSpec := mapSpecInner.Copy()
		// mapSpec.MaxEntries = uint32(len(kvs))

		m, err := createMap(mapSpec, kvs)
		if err != nil {
			return fmt.Errorf("failed to create inner addr bpf map: %w", err)
		}
		defer m.Close()

		daddrInnerMaps = append(daddrInnerMaps, ebpf.MapKV{
			Key:   uint32(i),
			Value: m,
		})
	}

	daddrMapSpec := spec.Maps["acl_daddr"]
	daddrMapSpec.InnerMap = mapSpecInner.Copy()
	daddrMap, err := loadOrRecreateMap(pinPath, daddrMapSpec, daddrInnerMaps)
	if err != nil {
		return fmt.Errorf("failed to create daddr bpf map: %w", err)
	}
	defer daddrMap.Close()
	replacedMaps["acl_daddr"] = daddrMap

	sportMapSpec := spec.Maps["acl_sport"]
	sportMap, err := loadOrRecreateMap(pinPath, sportMapSpec.Copy(), sports)
	if err != nil {
		return fmt.Errorf("failed to create sport bpf map: %w", err)
	}
	defer sportMap.Close()
	replacedMaps["acl_sport"] = sportMap

	dportMapSpec := spec.Maps["acl_dport"]
	dportMap, err := loadOrRecreateMap(pinPath, dportMapSpec.Copy(), dports)
	if err != nil {
		return fmt.Errorf("failed to create dport bpf map: %w", err)
	}
	defer dportMap.Close()
	replacedMaps["acl_dport"] = dportMap

	protoMapSpec := spec.Maps["acl_protocol"]
	protoMap, err := loadOrRecreateMap(pinPath, protoMapSpec.Copy(), protocols)
	if err != nil {
		return fmt.Errorf("failed to create protocol bpf map: %w", err)
	}
	defer protoMap.Close()
	replacedMaps["acl_protocol"] = protoMap

	policyMapSpec := spec.Maps["acl_rule_policy"]
	policyMap, err := loadOrRecreateMap(pinPath, policyMapSpec.Copy(), policies)
	if err != nil {
		return fmt.Errorf("failed to create rule_policy bpf map: %w", err)
	}
	defer policyMap.Close()
	replacedMaps["acl_rule_policy"] = policyMap

	statMapSpec := spec.Maps["acl_stat"]
	statMap, err := loadOrCreateMap(pinPath, statMapSpec.Copy())
	if err != nil {
		return fmt.Errorf("failed to create stat bpf map: %w", err)
	}
	defer statMap.Close()
	replacedMaps["acl_stat"] = statMap

	err = spec.RewriteConstants(map[string]interface{}{
		"ACL_RULE_NUM": uint32(len(rules)),
		"XDPACL_DEBUG": uint32(1),
	})
	if err != nil {
		return fmt.Errorf("failed to rewrite constants: %w", err)
	}

	var obj xdpaclObjects
	err = spec.LoadAndAssign(&obj, &ebpf.CollectionOptions{
		MapReplacements: replacedMaps,
	})
	if err != nil {
		return fmt.Errorf("failed to load bpf obj: %w", err)
	}
	defer obj.Close()

	err = xdpObj.AclProgs.Put(uint32(0), obj.XdpAclFuncImm)
	if err != nil {
		return fmt.Errorf("failed to update acl prog to progs bpf map: %w", err)
	}

	return nil
}
