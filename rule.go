package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

type xdpAction uint16

const (
	xdpActionAborted xdpAction = iota
	xdpActionDrop
	xdpActionPass
	xdpActionTx
	xdpActionRedirect
)

func (x xdpAction) String() string {
	s := [...]string{"XDP_ABORTED", "XDP_DROP", "XDP_PASS", "XDP_TX", "XDP_REDIRECT"}
	if int(x) < len(s) {
		return s[x]
	}

	return "XDP_UNKNOWN"
}

type RulePortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

type Rule struct {
	Priority uint32 `json:"priority"`
	Action   string `json:"action"`

	SrcAddrs []string      `json:"saddr"`
	DstAddrs []string      `json:"daddr"`
	SrcPorts RulePortRange `json:"sport"`
	DstPorts RulePortRange `json:"dport"`
	Protocol []string      `json:"protocol"`
}

type aclRule struct {
	priority uint32
	action   xdpAction

	saddr    []netip.Prefix
	daddr    []netip.Prefix
	sport    xdpaclPortRange
	dport    xdpaclPortRange
	protocol uint64
}

func rule2aclRule(rule *Rule) (*aclRule, error) {
	var r aclRule
	r.priority = rule.Priority

	switch strings.ToLower(rule.Action) {
	case "drop":
		r.action = xdpActionDrop
	case "accept":
		r.action = xdpActionPass
	default:
		return nil, fmt.Errorf("unsupport action %s", rule.Action)
	}

	r.saddr = make([]netip.Prefix, 0, len(rule.SrcAddrs))
	for _, addr := range rule.SrcAddrs {
		cidr, err := netip.ParsePrefix(addr)
		if err == nil {
			r.saddr = append(r.saddr, cidr)
			continue
		}

		ip, err := netip.ParseAddr(addr)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("%s is no a valid CIDR nor IPv4 addr", addr)
		}

		r.saddr = append(r.saddr, netip.PrefixFrom(ip, 32))
	}

	r.daddr = make([]netip.Prefix, 0, len(rule.DstAddrs))
	for _, addr := range rule.DstAddrs {
		cidr, err := netip.ParsePrefix(addr)
		if err == nil {
			r.daddr = append(r.daddr, cidr)
			continue
		}

		ip, err := netip.ParseAddr(addr)
		if err != nil || !ip.Is4() {
			return nil, fmt.Errorf("%s is no a valid CIDR nor IPv4 addr", addr)
		}

		r.daddr = append(r.daddr, netip.PrefixFrom(ip, 32))
	}

	r.sport = xdpaclPortRange(rule.SrcPorts)
	r.dport = xdpaclPortRange(rule.DstPorts)

	if len(rule.Protocol) != 0 {
		for _, proto := range rule.Protocol {
			switch strings.ToLower(proto) {
			case "tcp":
				r.protocol |= 1 << 0
			case "udp":
				r.protocol |= 1 << 1
			case "icmp":
				r.protocol |= 1 << 2
			case "all":
				r.protocol |= 0b111
			}
		}
	} else {
		r.protocol |= 0b111
	}

	return &r, nil
}

func loadRules(fpath string) ([]*aclRule, error) {
	fd, err := os.Open(fpath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", fpath, err)
	}
	defer fd.Close()

	var rules []*Rule
	err = json.NewDecoder(fd).Decode(&rules)
	if err != nil {
		return nil, fmt.Errorf("failed to JSON decode %s: %w", fpath, err)
	}

	aRules := make([]*aclRule, len(rules))
	for i, rule := range rules {
		aRules[i], err = rule2aclRule(rule)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rule %+v: %w", rule, err)
		}
	}

	return aRules, nil
}

// sortRules sorts rules by priority DESC.
func sortRules(rules []*aclRule) []*aclRule {
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		return a.priority > b.priority
	})

	return rules
}

func checkRules(rules []*aclRule) error {
	priorities := make(map[uint32]struct{}, len(rules))
	for _, rule := range rules {
		if _, ok := priorities[rule.priority]; ok {
			return fmt.Errorf("priority %d can not duplicates", rule.priority)
		}

		priorities[rule.priority] = struct{}{}
	}

	return nil
}
