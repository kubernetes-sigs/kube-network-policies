// SPDX-License-Identifier: APACHE-2.0

package network

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const skewTable = "skew"

// skewRuleset is the state another process or a previous version left in the
// kernel. Every rejection scenario sends a transaction that does not fit it.
var skewRuleset = fmt.Sprintf(`
flush ruleset
table inet %s {
	chain base { type filter hook postrouting priority srcnat - 5; policy accept; }
	chain regular { }
	chain target { }
	chain refs { type filter hook input priority filter; ip saddr @used accept; jump target; }
	set v4 { type ipv4_addr; }
	set iv4 { type ipv4_addr; flags interval; }
	set used { type ipv4_addr; }
	map m { type ipv4_addr : verdict; }
}
`, skewTable)

var inet = &nftables.Table{Name: skewTable, Family: nftables.TableFamilyINet}

func TestIsTransientNetlinkError_KernelRejections(t *testing.T) {
	if !unprivilegedUserns() {
		t.Skip("Test requires unprivileged user namespaces")
	}
	execInUserns(t, testIsTransientNetlinkError_KernelRejections, syscall.CLONE_NEWNET)
}

func testIsTransientNetlinkError_KernelRejections(t *testing.T) {
	tests := []struct {
		name string
		// setup adds to skewRuleset what the scenario needs.
		setup func(t *testing.T)
		// op appends the transaction to the connection.
		op func(t *testing.T, nft *nftables.Conn)
		// errnos the kernel is known to return, it depends on the version.
		errnos []syscall.Errno
	}{
		{
			name:   "create a table that exists",
			op:     func(_ *testing.T, nft *nftables.Conn) { nft.CreateTable(inet) },
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "base chain with another priority",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "base", Table: inet, Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityFilter})
			},
			errnos: []syscall.Errno{unix.EOPNOTSUPP, unix.EEXIST},
		},
		{
			name: "base chain with another hook",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "base", Table: inet, Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 5)})
			},
			errnos: []syscall.Errno{unix.EOPNOTSUPP, unix.EEXIST},
		},
		{
			name: "base chain with another type",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "base", Table: inet, Type: nftables.ChainTypeNAT,
					Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityRef(*nftables.ChainPriorityNATSource - 5)})
			},
			errnos: []syscall.Errno{unix.EEXIST, unix.EOPNOTSUPP},
		},
		{
			name: "base chain over a regular chain",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				nft.AddChain(&nftables.Chain{Name: "regular", Table: inet, Type: nftables.ChainTypeFilter,
					Hooknum: nftables.ChainHookPostrouting, Priority: nftables.ChainPriorityFilter})
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "set with another key type",
			op: func(t *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				addSet(t, nft, &nftables.Set{Name: "v4", Table: inet, KeyType: nftables.TypeIP6Addr})
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "set with other flags",
			op: func(t *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				addSet(t, nft, &nftables.Set{Name: "iv4", Table: inet, KeyType: nftables.TypeIPAddr})
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "set over a map",
			op: func(t *testing.T, nft *nftables.Conn) {
				nft.AddTable(inet)
				addSet(t, nft, &nftables.Set{Name: "m", Table: inet, KeyType: nftables.TypeIPAddr})
			},
			errnos: []syscall.Errno{unix.EEXIST},
		},
		{
			name: "rule in a chain that does not exist",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddRule(&nftables.Rule{Table: inet, Chain: &nftables.Chain{Name: "missing"},
					Exprs: []expr.Any{&expr.Verdict{Kind: expr.VerdictAccept}}})
			},
			errnos: []syscall.Errno{unix.ENOENT},
		},
		{
			name: "delete a table that does not exist",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.DelTable(&nftables.Table{Name: "missing", Family: nftables.TableFamilyINet})
			},
			errnos: []syscall.Errno{unix.ENOENT},
		},
		{
			name: "delete a set used by a rule",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.DelSet(&nftables.Set{Name: "used", Table: inet})
			},
			errnos: []syscall.Errno{unix.EBUSY},
		},
		{
			name: "delete a chain used by a jump",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.DelChain(&nftables.Chain{Name: "target", Table: inet})
			},
			errnos: []syscall.Errno{unix.EBUSY},
		},
		{
			name: "set element with another key length",
			op: func(t *testing.T, nft *nftables.Conn) {
				set := &nftables.Set{Name: "v4", Table: inet, KeyType: nftables.TypeIPAddr}
				if err := nft.SetAddElements(set, []nftables.SetElement{{Key: make([]byte, 16)}}); err != nil {
					t.Fatal(err)
				}
			},
			errnos: []syscall.Errno{unix.EINVAL},
		},
		{
			name: "rule reading the verdict register",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddRule(&nftables.Rule{Table: inet, Chain: &nftables.Chain{Name: "base"},
					Exprs: []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 0, Data: []byte{0}}}})
			},
			errnos: []syscall.Errno{unix.EINVAL},
		},
		{
			name: "queue range past the last queue number",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddRule(&nftables.Rule{Table: inet, Chain: &nftables.Chain{Name: "base"},
					Exprs: []expr.Any{&expr.Queue{Num: 65535, Total: 2}}})
			},
			errnos: []syscall.Errno{unix.ERANGE},
		},
		{
			name: "table name too long",
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(&nftables.Table{Name: strings.Repeat("a", 300), Family: nftables.TableFamilyINet})
			},
			errnos: []syscall.Errno{unix.ERANGE, unix.EINVAL},
		},
		{
			name:  "table owned by another process",
			setup: func(t *testing.T) { ownTable(t, "owned") },
			op: func(_ *testing.T, nft *nftables.Conn) {
				nft.AddTable(&nftables.Table{Name: "owned", Family: nftables.TableFamilyINet})
			},
			errnos: []syscall.Errno{unix.EPERM},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loadRuleset(t, skewRuleset)
			if tt.setup != nil {
				tt.setup(t)
			}
			before := listRuleset(t)

			nft, err := nftables.New()
			if err != nil {
				t.Fatal(err)
			}
			tt.op(t, nft)
			err = nft.Flush()
			if err == nil {
				t.Fatalf("the kernel accepted the transaction, ruleset:\n%s", listRuleset(t))
			}
			if !isAny(err, tt.errnos) {
				t.Errorf("error = %v, want one of %v", err, tt.errnos)
			}
			if IsTransientNetlinkError(err) {
				t.Errorf("IsTransientNetlinkError(%v) = true, the kernel rejected the transaction", err)
			}
			// A rejected batch applies nothing, the reason the caller can retry
			// it with a recreate.
			if after := listRuleset(t); after != before {
				t.Errorf("the rejected transaction changed the ruleset:\n--- before\n%s\n--- after\n%s", before, after)
			}
		})
	}
}

// TestIsTransientNetlinkError_SocketErrors reproduces the errors that come
// from the netlink socket after the kernel has committed the batch: the caller
// gets an error and the ruleset changed anyway, so a retry must not assume the
// kernel state is the one before the call.
func TestIsTransientNetlinkError_SocketErrors(t *testing.T) {
	if !unprivilegedUserns() {
		t.Skip("Test requires unprivileged user namespaces")
	}
	execInUserns(t, testIsTransientNetlinkError_SocketErrors, syscall.CLONE_NEWNET)
}

func testIsTransientNetlinkError_SocketErrors(t *testing.T) {
	t.Run("read deadline expired", func(t *testing.T) {
		loadRuleset(t, "flush ruleset")
		nft, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
			return c.SetReadDeadline(time.Now())
		}))
		if err != nil {
			t.Fatal(err)
		}
		nft.AddTable(inet)
		err = nft.Flush()
		if err == nil {
			t.Fatal("Flush() succeeded with an expired read deadline")
		}
		var opErr *netlink.OpError
		if !errors.As(err, &opErr) || !opErr.Timeout() {
			t.Errorf("error = %v, want a netlink timeout", err)
		}
		if !IsTransientNetlinkError(err) {
			t.Errorf("IsTransientNetlinkError(%v) = false, want true", err)
		}
		if out, err := exec.Command("nft", "list", "table", "inet", skewTable).CombinedOutput(); err != nil {
			t.Errorf("the table was not created although the send succeeded: %v: %s", err, out)
		}
	})

	t.Run("receive buffer overrun", func(t *testing.T) {
		loadRuleset(t, "flush ruleset")
		// The kernel clamps the buffer to its minimum, a few acknowledgements
		// fill it and the socket reports ENOBUFS on the next receive.
		nft, err := nftables.New(nftables.WithSockOptions(func(c *netlink.Conn) error {
			return c.SetReadBuffer(1)
		}))
		if err != nil {
			t.Fatal(err)
		}
		const rules = 2000
		nft.AddTable(inet)
		chain := nft.AddChain(&nftables.Chain{Name: "regular", Table: inet})
		for i := 0; i < rules; i++ {
			nft.AddRule(&nftables.Rule{Table: inet, Chain: chain, Exprs: []expr.Any{&expr.Counter{}}})
		}
		err = nft.Flush()
		if err == nil {
			t.Fatal("Flush() succeeded with a full receive buffer")
		}
		if !errors.Is(err, unix.ENOBUFS) {
			t.Errorf("error = %v, want ENOBUFS", err)
		}
		if !IsTransientNetlinkError(err) {
			t.Errorf("IsTransientNetlinkError(%v) = false, want true", err)
		}
		out, err := exec.Command("nft", "list", "chain", "inet", skewTable, "regular").CombinedOutput()
		if err != nil {
			t.Fatalf("nft list chain: %v: %s", err, out)
		}
		if got := strings.Count(string(out), "counter"); got != rules {
			t.Errorf("%d rules in the chain, want %d, the batch is committed before the acknowledgements are sent", got, rules)
		}
	})
}

func TestIsTransientNetlinkError_NotNetlink(t *testing.T) {
	for _, err := range []error{nil, errors.New("failed to add Set")} {
		if IsTransientNetlinkError(err) {
			t.Errorf("IsTransientNetlinkError(%v) = true, want false", err)
		}
	}
}

func addSet(t *testing.T, nft *nftables.Conn, set *nftables.Set) {
	t.Helper()
	if err := nft.AddSet(set, nil); err != nil {
		t.Fatal(err)
	}
}

func isAny(err error, errnos []syscall.Errno) bool {
	for _, errno := range errnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

func loadRuleset(t *testing.T, ruleset string) {
	t.Helper()
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v: %s\n%s", err, out, ruleset)
	}
}

func listRuleset(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list ruleset: %v: %s", err, out)
	}
	return string(out)
}

// ownTable creates a table with the owner flag from an nft process that stays
// alive until the test ends: the kernel returns EPERM to any other socket that
// touches the table.
func ownTable(t *testing.T, name string) {
	t.Helper()
	owner := exec.Command("nft", "-i")
	stdin, err := owner.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	owner.Stderr = os.Stderr
	if err := owner.Start(); err != nil {
		t.Fatalf("nft -i: %v", err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = owner.Wait()
	})
	if _, err := fmt.Fprintf(stdin, "add table inet %s { flags owner; }\n", name); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if exec.Command("nft", "list", "table", "inet", name).Run() == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the owner table %s was not created", name)
}

// execInUserns re-executes the test binary in a new user namespace, with the
// current user mapped to root, plus the namespaces in extraCloneflags, and runs
// f there as the "subprocess" subtest. Same helper as in pkg/dataplane.
func execInUserns(t *testing.T, f func(t *testing.T), extraCloneflags ...uintptr) {
	const subprocessEnvKey = `GO_SUBPROCESS_KEY`
	if v, ok := os.LookupEnv(subprocessEnvKey); ok && v == "1" {
		t.Run(`subprocess`, f)
		return
	}

	cmd := exec.Command(os.Args[0])
	cmd.Args = []string{os.Args[0], "-test.run=" + t.Name() + "$", "-test.v=true"}
	for _, arg := range os.Args {
		if strings.HasPrefix(arg, `-test.testlogfile=`) {
			cmd.Args = append(cmd.Args, arg)
		}
	}
	cmd.Env = append(os.Environ(), subprocessEnvKey+"=1")
	cmd.Env = append(cmd.Env, "PATH=/usr/local/sbin:/usr/sbin::/sbin:"+os.Getenv("PATH"))
	cmd.Stdin = os.Stdin

	cloneflags := uintptr(syscall.CLONE_NEWUSER)
	for _, f := range extraCloneflags {
		cloneflags |= f
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  cloneflags,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}

	out, err := cmd.CombinedOutput()
	t.Logf("%s", out)
	if err != nil {
		t.Fatal(err)
	}
}

func unprivilegedUserns() bool {
	cmd := exec.Command("sleep", "1")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
	}
	if err := cmd.Start(); err != nil {
		return false
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return true
}
