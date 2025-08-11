// SPDX-License-Identifier: APACHE-2.0

package networkpolicy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/armon/go-radix"
	nfqueue "github.com/florianl/go-nfqueue"
	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"

	"golang.org/x/net/dns/dnsmessage"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
)

// reference https://coredns.io/plugins/cache/
const (
	tableName = "kube-network-policies-dnscache"
	// same as LocalNodeDNS
	// https://github.com/kubernetes/dns/blob/c0fa2d1128d42c9b13e08a6a7e3ee8c635b9acd5/cmd/node-cache/Corefile#L3
	expireTimeout = 30 * time.Second
	maxTTL        = 300 * time.Second // expire entries that are older than 300 seconds independently of the TTL
	// It was 512 byRFC1035 for UDP until EDNS, but large packets can be fragmented ...
	// it seems bind uses 1232 as maximum size
	// https://kb.isc.org/docs/behavior-dig-versions-edns-bufsize
	maxDNSSize = 1232
)

func NewDomainCache(id int) *DomainCache {
	return &DomainCache{
		nfQueueID: id,
		cache: &domainMap{
			clock: clock.RealClock{},
			tree:  radix.New(),
		},
	}
}

type DomainCache struct {
	cache     *domainMap
	nfq       *nfqueue.Nfqueue
	nfQueueID int
}

func (n *DomainCache) Run(ctx context.Context) error {
	logger := klog.FromContext(ctx)

	// Set configuration options for nfqueue
	config := nfqueue.Config{
		NfQueue:      uint16(n.nfQueueID),
		Flags:        uint32(nfqueue.NfQaCfgFlagGSO + nfqueue.NfQaCfgFlagFailOpen),
		MaxPacketLen: maxDNSSize,
		MaxQueueLen:  1024,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 100 * time.Millisecond,
	}

	nf, err := nfqueue.Open(&config)
	if err != nil {
		logger.Info("could not open nfqueue socket", "error", err)
		return err
	}
	defer nf.Close()

	n.nfq = nf
	// hook that is called for every received packet by the nflog group
	fn := func(a nfqueue.Attribute) int {

		verdict := nfqueue.NfAccept
		startTime := time.Now()
		logger.V(2).Info("Processing sync for packet", "id", *a.PacketID)

		packet, err := parsePacket(*a.Payload)
		if err != nil {
			logger.Error(err, "Can not process packet")
			return 0
		}
		defer func() {
			logger.V(2).Info("Finished syncing packet", "id", *a.PacketID, "duration", time.Since(startTime))
		}()

		// Just print out the payload of the nflog packet
		logger.V(4).Info("Evaluating packet", "packet", packet)
		n.handleDNSPacket(ctx, packet)
		n.nfq.SetVerdict(*a.PacketID, verdict) //nolint:errcheck

		return 0
	}

	// Register your function to listen on nflog group 100
	err = nf.RegisterWithErrorFunc(ctx, fn, func(err error) int {
		if opError, ok := err.(*netlink.OpError); ok {
			if opError.Timeout() || opError.Temporary() {
				return 0
			}
		}
		logger.Info("Could not receive message", "error", err)
		return 0
	})
	if err != nil {
		logger.Info("could not open nfqueue socket", "error", err)
		return err
	}

	ticker := time.NewTicker(expireTimeout)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		err := n.syncRules()
		if err != nil {
			return err
		}
		// garbage collect ip cache entries
		n.cache.gc()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			continue
		}
	}
}

func (n *DomainCache) syncRules() error {
	klog.V(2).Info("Syncing kube-network-policies dnscache nftables rules")
	nft, err := nftables.New()
	if err != nil {
		return fmt.Errorf("fastpath failure, can not start nftables:%v", err)
	}

	// add + delete + add for flushing all the table
	table := &nftables.Table{
		Name:   tableName,
		Family: nftables.TableFamilyINet,
	}
	nft.AddTable(table)
	nft.DelTable(table)
	nft.AddTable(table)

	chain := nft.AddChain(&nftables.Chain{
		Name:     "postrouting",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityLast,
	})

	// Log UDP DNS answers
	// TODO(tcp)
	/*
	  [ meta load l4proto => reg 1 ]
	  [ cmp eq reg 1 0x00000011 ]
	  [ payload load 2b @ transport header + 0 => reg 1 ]
	  [ cmp eq reg 1 0x00003500 ]
	  [ log group 100 snaplen 0 qthreshold 0 ]
	*/
	nft.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, SourceRegister: false, Register: 0x1},
			&expr.Cmp{Op: 0x0, Register: 0x1, Data: []byte{syscall.IPPROTO_UDP}},
			&expr.Payload{DestRegister: 0x1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 0x1, Data: binaryutil.BigEndian.PutUint16(53)},
			&expr.Counter{},
			&expr.Queue{Num: uint16(n.nfQueueID), Flag: expr.QueueFlagBypass},
		},
	})
	err = nft.Flush()
	if err != nil {
		return fmt.Errorf("failed to create kube-network-policices table: %v", err)
	}
	return nil
}

func (n *DomainCache) cleanRules() {
	nft, err := nftables.New()
	if err != nil {
		klog.Infof("fastpath cleanup failure, can not start nftables:%v", err)
		return
	}
	// Add+Delete is idempotent and won't return an error if the table doesn't already
	// exist.
	table := nft.AddTable(&nftables.Table{
		Family: nftables.TableFamilyINet,
		Name:   tableName,
	})
	nft.DelTable(table)

	err = nft.Flush()
	if err != nil {
		klog.Infof("error deleting nftables rules %v", err)
	}
}

func (n *DomainCache) ContainsIP(domain string, ip net.IP) bool {
	return n.cache.containsIP(domain, ip)
}

func (n *DomainCache) handleDNSPacket(ctx context.Context, pkt Packet) {
	logger := klog.FromContext(ctx)
	// sanity check, the nftables rules should only queue UDP packets destined to port 53
	if pkt.proto != v1.ProtocolUDP || pkt.srcPort != 53 {
		logger.Info("SHOULD NOT HAPPEN expected udp src port 53", "protocol", pkt.proto, "src port", pkt.srcPort)
		return
	}

	if len(pkt.payload) > maxDNSSize {
		logger.Info("dns request size unsupported", "packet", pkt, "maxSize", maxDNSSize)
		return
	}

	logger.V(7).Info("starting parsing packet")
	var p dnsmessage.Parser
	hdr, err := p.Start(pkt.payload)
	if err != nil {
		logger.Error(err, "can not parse DNS message", "packet", pkt)
		return
	}
	questions, err := p.AllQuestions()
	if err != nil {
		logger.Error(err, "can not get DNS message questions", "packet", pkt)
		return
	}
	if len(questions) == 0 {
		logger.Error(err, "DNS message does not have any question", "packet", pkt, "header", hdr)
		return
	}
	// it is supported but not wildly implemented, at least not in golang stdlib
	if len(questions) > 1 {
		logger.Error(err, "DNS messages unsupported number of questions, only one supported", "packet", pkt, "header", hdr)
		return
	}
	q := questions[0]
	// data to build the response
	host := q.Name.String()
	var ips []net.IP

	// Only interested on IP addresses
	switch q.Type {
	case dnsmessage.TypeA:
	case dnsmessage.TypeAAAA:
	default:
		return
	}
	var ttl int
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			return

		}

		// we only have one question so we only expect one type
		switch h.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return
			}
			ips = append(ips, r.A[:])
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return
			}
			ips = append(ips, r.AAAA[:])
		default:
			if err := p.SkipAnswer(); err != nil && err != dnsmessage.ErrSectionDone {
				klog.ErrorS(err, "can not unmarshall DNS header")
			}
			continue
		}

		// take the minimum ttl value
		if ttl == 0 {
			ttl = int(h.TTL)
		} else {
			ttl = min(ttl, int(h.TTL))
		}
	}
	if len(ips) > 0 {
		// remove the trailing dot
		host = strings.TrimSuffix(host, ".")
		logger.V(4).Info("caching IP addresses", "host", host, "ips", ips)
		n.cache.add(host, ips, ttl)
	}
}
