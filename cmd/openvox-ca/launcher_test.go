// Copyright (C) 2026 Trevor Vaughan
// Copyright (C) 2026 Vox Pupuli and contributors
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/ca"
	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
	"github.com/voxpupuli/openvox-ca/internal/signer"
)

// pskChildEnv selects child mode when the test binary re-execs itself: the
// fd-contract specs below spawn real child processes so the ExtraFiles
// slice position ↔ fd number contract (socketpair on fd 3, PSK pipe on
// fd 4) is exercised across a genuine exec boundary.
const pskChildEnv = "OPENVOX_CA_TEST_PSK_CHILD"

// memLimitOutEnv names the file the report-memlimit child writes its effective
// GOMEMLIMIT to. A file rather than stdout because spawnChild -- the production
// helper under test -- wires the child's stdout to the launcher's own, so the
// spec cannot capture it without changing the code it is meant to exercise.
const memLimitOutEnv = "OPENVOX_CA_TEST_MEMLIMIT_OUT"

func TestMain(m *testing.M) {
	if role := os.Getenv(pskChildEnv); role != "" {
		os.Exit(runPSKChild(role))
	}
	os.Exit(m.Run())
}

// runPSKChild is the child side of the fd-contract specs. It uses only the
// signer package's exported entry points — the same ones the production
// signer and frontend roles use — so fd recovery, PSK loading, and the
// mutual handshake all run exactly as they would under the real launcher.
func runPSKChild(role string) int {
	switch role {
	case "signer":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if err := signer.Serve(key); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "frontend":
		rs, err := signer.Dial(nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer rs.Close()
		digest := sha256.Sum256([]byte("fd-contract"))
		sig, err := rs.Sign(nil, digest[:], crypto.SHA256)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if len(sig) == 0 {
			fmt.Fprintln(os.Stderr, "empty signature")
			return 1
		}
		fmt.Println("SIGN-OK")
		return 0
	case "report-memlimit":
		// debug.SetMemoryLimit(-1) reports the limit without changing it, so
		// this is what the child's runtime ACTUALLY applied -- not the string it
		// was handed. A spec reading the variable back would pass on a value
		// that was delivered and never honoured.
		path := os.Getenv(memLimitOutEnv)
		if path == "" {
			fmt.Fprintln(os.Stderr, "report-memlimit child: "+memLimitOutEnv+" is unset")
			return 2
		}
		limit := strconv.FormatInt(debug.SetMemoryLimit(-1), 10)
		if err := os.WriteFile(path, []byte(limit), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		return 0
	case "sighup-ignored":
		// The signer's disposition, then a SIGHUP at this very process.
		// SIGHUP's default action is termination and kill(2) delivers to self
		// before it returns, so reaching the print at all is the assertion:
		// without the disposition this child dies inside the Kill call.
		ignoreReloadSignal()
		if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		fmt.Println("ALIVE")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown %s role %q\n", pskChildEnv, role)
		return 2
	}
}

// pskChildCmd builds a re-exec of the test binary in the given child role
// with the supplied inherited files, capturing combined output.
func pskChildCmd(ctx context.Context, role string, extraFiles []*os.File, out *bytes.Buffer) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0])
	cmd.Env = append(os.Environ(), pskChildEnv+"="+role)
	cmd.ExtraFiles = extraFiles
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd
}

var _ = Describe("launcher fd contract", func() {
	// verifies the full cross-process contract end to end: two real child
	// processes recover the socketpair from fd 3 and the PSK from the fd 4
	// pipe, complete the mutual handshake, and service a signing RPC.
	It("delivers the socketpair on fd 3 and the PSK pipe on fd 4", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		signerSock, frontendSock, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred(), "creating socketpair")

		signerPipe, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "creating signer PSK pipe")
		frontendPipe, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "creating frontend PSK pipe")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		var signerOut, frontendOut bytes.Buffer
		signerCmd := pskChildCmd(ctx, "signer", []*os.File{signerSock, signerPipe}, &signerOut)
		frontendCmd := pskChildCmd(ctx, "frontend", []*os.File{frontendSock, frontendPipe}, &frontendOut)

		// Mirror the launcher: drop the parent's copies of each child's files
		// immediately after that child starts, so only the children hold the
		// socketpair ends and pipe read ends.
		Expect(signerCmd.Start()).To(Succeed(), "starting signer child")
		// Registered before anything else can fail: a mid-spec failure aborts
		// the body by panic, so relying on the Wait calls below to reap these
		// leaves a child running whenever the spec fails -- which is exactly
		// when it matters. The sibling spec below already does this.
		DeferCleanup(func() { killAndReap(signerCmd) })
		signerSock.Close()
		signerPipe.Close()
		Expect(frontendCmd.Start()).To(Succeed(), "starting frontend child")
		DeferCleanup(func() { killAndReap(frontendCmd) })
		frontendSock.Close()
		frontendPipe.Close()

		Expect(frontendCmd.Wait()).To(Succeed(), "frontend child failed: %s", frontendOut.String())
		Expect(frontendOut.String()).To(ContainSubstring("SIGN-OK"),
			"frontend should obtain a signature over the socketpair")
		Expect(signerCmd.Wait()).To(Succeed(), "signer child failed: %s", signerOut.String())
	})

	// verifies the mandatory-handshake failure mode across the exec
	// boundary: a child whose fd 4 is not the launcher's PSK pipe must fail
	// closed rather than proceed unauthenticated.
	//
	// fd 4 is pinned to /dev/null rather than simply left out of ExtraFiles.
	// Omitting it does not guarantee the child sees fd 4 closed: exec only
	// rewrites fds 0-2 and the ExtraFiles range, so any descriptor this test
	// binary inherited without FD_CLOEXEC from its own parent stays open at
	// its original number in the child. Under a wrapper that leaks one at
	// fd 4 (lefthook's pre-push hook does, as do some CI runners) the child
	// would inherit a foreign pipe, satisfy loadPSK's S_IFIFO check, and then
	// block or fail with an unrelated read error instead of the fd-contract
	// message asserted here. A character device is never a FIFO, so this
	// drives the guard deterministically wherever the suite runs.
	It("fails closed when fd 4 is not the launcher's PSK pipe", func() {
		signerSock, frontendSock, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred(), "creating socketpair")
		// Both ends, registered before anything else can fail: the sibling spec
		// above makes exactly this argument about itself, and this one relied on
		// straight-line execution reaching its own Close for the other end.
		DeferCleanup(func() { _ = signerSock.Close(); _ = frontendSock.Close() })

		notAPipe, err := os.Open(os.DevNull)
		Expect(err).NotTo(HaveOccurred(), "opening %s", os.DevNull)
		DeferCleanup(func() { _ = notAPipe.Close() })

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		DeferCleanup(cancel)

		var out bytes.Buffer
		cmd := pskChildCmd(ctx, "frontend", []*os.File{frontendSock, notAPipe}, &out)
		err = cmd.Run()

		Expect(err).To(HaveOccurred(), "child without a PSK pipe on fd 4 should exit non-zero; output: %s", out.String())
		Expect(out.String()).To(ContainSubstring("not spawned by the launcher"),
			"child should report the missing PSK pipe")
		// Named, because that substring is shared by both fd 4 branches, both fd 3
		// branches and the read timeout -- so on its own it cannot say which guard
		// fired, which is the whole claim of the comment above.
		Expect(out.String()).To(ContainSubstring("fd 4 is not a pipe"))
	})
})

// capturePSKPipe replaces spawnChild's pipe constructor for the current spec and
// returns a handle on whatever it hands back, so a spec can assert the helper
// closed it. Restored by DeferCleanup.
//
// This replaced an fd-slot comparison. That could only ever say "the lowest free
// descriptor did not move up", which the socketpair close satisfies on its own --
// so it passed with the PSK pipe leaked, the single thing it was written to
// catch.
func capturePSKPipe() func() *os.File {
	GinkgoHelper()
	orig := pskPipeFn
	DeferCleanup(func() { pskPipeFn = orig })

	var captured *os.File
	pskPipeFn = func(pskHex string) (*os.File, error) {
		f, err := orig(pskHex)
		captured = f
		return f, err
	}
	// A getter, because the pipe does not exist until spawnChild runs.
	return func() *os.File { return captured }
}

var _ = DescribeTable("filterEnv strips exactly the named keys",
	// Two call sites now -- the launcher's children and the --daemon re-exec --
	// and no coverage at all. Swapping the key comparison for a prefix match
	// would strip every PUPPET_CA_* variable from all three children, silently:
	// the CA would come up with none of its configuration and the operator would
	// have nothing pointing at the cause.
	func(env []string, keys []string, want []string) {
		Expect(filterEnv(env, keys...)).To(Equal(want))
	},
	Entry("removes a named key and keeps the rest",
		[]string{"A=1", "PUPPET_CA_ROLE=signer", "B=2"},
		[]string{"PUPPET_CA_ROLE"},
		[]string{"A=1", "B=2"}),
	Entry("matches the whole key, not a prefix of it",
		[]string{"PUPPET_CA_ROLE=signer", "PUPPET_CA_ROLE_EXTRA=x"},
		[]string{"PUPPET_CA_ROLE"},
		[]string{"PUPPET_CA_ROLE_EXTRA=x"}),
	Entry("keeps a value containing an equals sign",
		[]string{"PUPPET_CA_AUTOSIGN=a=b", "PUPPET_CA_DAEMON=1"},
		[]string{"PUPPET_CA_DAEMON"},
		[]string{"PUPPET_CA_AUTOSIGN=a=b"}),
	Entry("is a no-op when nothing matches",
		[]string{"A=1"},
		[]string{"PUPPET_CA_ROLE"},
		[]string{"A=1"}),
	Entry("keeps a bare name with no equals sign",
		[]string{"WEIRD", "PUPPET_CA_ROLE=signer"},
		[]string{"PUPPET_CA_ROLE"},
		[]string{"WEIRD"}),
)

var _ = Describe("spawnChild and its cleanup", func() {
	// runLauncher itself has no test and cannot easily have one -- it re-execs
	// this binary twice and then blocks on signal forwarding -- so the two rules
	// its failure path depends on are pinned on the extracted helpers instead.
	It("reaps a child rather than only signalling it", func() {
		// The launcher kills the signer when the frontend fails to start. Kill
		// alone leaves a zombie for as long as the launcher lives, and the
		// launcher does not necessarily exit straight away.
		cmd := exec.Command("/bin/sh", "-c", "sleep 300")
		Expect(cmd.Start()).To(Succeed())
		pid := cmd.Process.Pid

		killAndReap(cmd)

		// Signal 0 probes for existence. A reaped child is gone; a zombie would
		// still be found, because a zombie is still a process table entry owned
		// by this process.
		Expect(syscall.Kill(pid, 0)).To(MatchError(syscall.ESRCH),
			"the child must be waited on, not merely signalled")
	})

	It("drops the parent's copies of both descriptors once the child holds them", func() {
		// The success path, which no spec reached: the end-to-end fd-contract spec
		// re-implements the spawn by hand and so satisfies this invariant itself,
		// leaving the helper's copy of it unguarded. Deleting the socketpair close
		// left the whole suite green while the launcher kept both endpoints alive
		// for its lifetime -- falsifying "only the two children hold endpoints"
		// and stopping the signer from ever seeing EOF when the frontend dies.
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		sock, otherEnd, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = otherEnd.Close(); _ = sock.Close() })

		// A child that exits immediately: this spec is about the parent's
		// descriptors, not about the handshake.
		exe, err := exec.LookPath("true")
		Expect(err).NotTo(HaveOccurred())

		// Capture the pipe the helper creates, so its close is asserted directly.
		// The fd-slot arithmetic this replaces could not tell a leaked pipe from a
		// closed socket -- the socket close alone satisfied it -- so it passed with
		// the pipe leaked, which is the one thing it was named for.
		pipe := capturePSKPipe()

		cmd, err := spawnChild(exe, os.Environ(), "signer", sock, hex.EncodeToString(psk), memoryBudget{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { killAndReap(cmd) })

		// The fd contract itself: position in ExtraFiles *is* the descriptor
		// number, and nothing asserted the slice the helper builds -- the
		// end-to-end spec hand-rolls its own. Swapping the two entries, or
		// dropping the pipe, left the whole suite green and produced a CA whose
		// children both refuse to start.
		Expect(cmd.ExtraFiles).To(HaveLen(2), "both descriptors must be handed over")
		Expect(cmd.ExtraFiles[signer.InheritedFD-3]).To(BeIdenticalTo(sock),
			"the socketpair end belongs on fd 3")
		Expect(cmd.ExtraFiles[signer.PSKFD-3]).To(BeIdenticalTo(pipe()),
			"the PSK pipe belongs on fd 4")

		// Two descriptors handed over, two closed. A second Close on an *os.File
		// returns ErrClosed rather than closing a recycled fd, so this is a safe
		// probe -- and it returns nil if the helper skipped the close.
		Expect(sock.Close()).To(MatchError(os.ErrClosed),
			"the socketpair end must already be closed by the helper")
		Expect(pipe().Close()).To(MatchError(os.ErrClosed),
			"and so must the PSK pipe's read end")

		// The role and daemon markers the children depend on. Dropping
		// PUPPET_CA_DAEMON=1 makes each child re-daemonise under --daemon (the
		// launcher strips the variable from baseEnv but forwards the operator's
		// own --daemon flag), print "started in background", and exit 0 -- so the
		// CA never starts, and no other spec notices.
		Expect(cmd.Env).To(ContainElement("PUPPET_CA_ROLE=signer"))
		Expect(cmd.Env).To(ContainElement("PUPPET_CA_DAEMON=1"))
	})

	It("does not let one child's role overwrite the other's", func() {
		// The anti-aliasing clip. filterEnv returns spare capacity whenever it
		// stripped anything, so two appends onto an unclipped slice share a
		// backing array and the second child's role lands in the first child's
		// env -- leaving this process tree with no signer, or two. Every other
		// spec passes os.Environ(), which has len == cap, so the clip is a no-op
		// there and could be deleted unnoticed.
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())
		exe, err := exec.LookPath("true")
		Expect(err).NotTo(HaveOccurred())

		// Room for exactly the two variables spawnChild appends: with less, the
		// append reallocates and the two children cannot share an array, so the
		// fixture would prove nothing.
		shared := filterEnv(
			[]string{"A=1", "B=2", "PUPPET_CA_ROLE=stale", "PUPPET_CA_DAEMON=stale"},
			"PUPPET_CA_ROLE", "PUPPET_CA_DAEMON")
		Expect(cap(shared)-len(shared)).To(Equal(2), "the fixture needs room for both appends")

		first, second, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { _ = first.Close(); _ = second.Close() })

		signerCmd, err := spawnChild(exe, shared, "signer", first, hex.EncodeToString(psk), memoryBudget{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { killAndReap(signerCmd) })
		frontendCmd, err := spawnChild(exe, shared, "frontend", second, hex.EncodeToString(psk), memoryBudget{})
		Expect(err).NotTo(HaveOccurred())
		DeferCleanup(func() { killAndReap(frontendCmd) })

		Expect(signerCmd.Env).To(ContainElement("PUPPET_CA_ROLE=signer"),
			"the second spawn must not have rewritten the first child's role")
		Expect(frontendCmd.Env).To(ContainElement("PUPPET_CA_ROLE=frontend"))
	})

	It("is safe on a child that was never started", func() {
		// The frontend-failure path calls this with whatever the signer spawn
		// returned, and a spawn that failed before Start returns a nil Cmd.
		killAndReap(nil)
		killAndReap(&exec.Cmd{})
	})

	It("does not leak a PSK pipe when the child cannot start", func() {
		// A pipe is created before the fork, so a Start that fails owns the only
		// remaining reference to it. Leaking one per attempt is a descriptor
		// leak in the one code path an operator hits repeatedly: a launcher
		// crash-looping because the binary cannot exec.
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred())

		sock, otherEnd, err := signer.Socketpair()
		Expect(err).NotTo(HaveOccurred())
		// Both ends: spawnChild closes sock on the failure path now, and a second
		// Close on an os.File is a no-op rather than a close of a reused fd.
		DeferCleanup(func() { _ = otherEnd.Close(); _ = sock.Close() })

		pipe := capturePSKPipe()
		cmd, err := spawnChild(filepath.Join(GinkgoT().TempDir(), "does-not-exist"),
			os.Environ(), "signer", sock, hex.EncodeToString(psk), memoryBudget{})
		Expect(err).To(HaveOccurred(), "a missing executable must not start")
		Expect(cmd).To(BeNil())
		Expect(pipe().Close()).To(MatchError(os.ErrClosed),
			"a pipe created for a child that never started must not be leaked")
		Expect(sock.Close()).To(MatchError(os.ErrClosed),
			"and the helper owns the socketpair end on this path too")
	})
})

var _ = Describe("pskPipe", func() {
	// verifies the returned read end yields exactly the hex PSK followed by
	// EOF, which is what a child's parsePSK relies on to drain the pipe.
	It("delivers the PSK followed by EOF", func() {
		psk := make([]byte, 32)
		_, err := rand.Read(psk)
		Expect(err).NotTo(HaveOccurred(), "generating PSK")
		pskHex := hex.EncodeToString(psk)

		r, err := pskPipe(pskHex)
		Expect(err).NotTo(HaveOccurred(), "pskPipe")
		DeferCleanup(func() { _ = r.Close() })

		// ReadAll only returns once the write end is closed, so this also
		// proves pskPipe closed it before returning.
		data, err := io.ReadAll(r)
		Expect(err).NotTo(HaveOccurred(), "reading PSK pipe")
		Expect(string(data)).To(Equal(pskHex), "pipe contents should be the hex PSK")
	})
})

// fakeChild records the signals the supervisor sends it, standing in for a
// spawned child so the supervisor loop can be driven without forking.
type fakeChild struct {
	mu      sync.Mutex
	signals []os.Signal
	kills   int
	err     error // returned from Signal, to exercise the failure path
}

func (f *fakeChild) Signal(sig os.Signal) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.signals = append(f.signals, sig)
	return f.err
}

func (f *fakeChild) Kill() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.kills++
	return nil
}

// syncBuffer is a log sink that is safe to read while another goroutine
// writes. bytes.Buffer is not, and the supervisor logs from its own goroutine.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// got returns the signals received so far.
func (f *fakeChild) got() []os.Signal {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]os.Signal(nil), f.signals...)
}

// killed reports how many times the child was hard-killed.
func (f *fakeChild) killed() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.kills
}

var _ = Describe("Launcher supervisor loop", func() {
	var (
		signer   *fakeChild
		frontend *fakeChild
		hupCh    chan os.Signal
		sigCh    chan os.Signal
		exitCh   chan childResult
		rec      *notifyRecorder
		sup      *supervisor
	)

	BeforeEach(func() {
		signer = &fakeChild{}
		frontend = &fakeChild{}
		hupCh = make(chan os.Signal, 1)
		sigCh = make(chan os.Signal, 1)
		exitCh = make(chan childResult, 2)

		rec = startNotifyRecorder(nil)
		notifier := sdnotify.New()
		DeferCleanup(func() { Expect(notifier.Close()).To(Succeed()) })

		sup = &supervisor{
			signer:   signer,
			frontend: frontend,
			notify:   notifier,
			hupCh:    hupCh,
			sigCh:    sigCh,
			exitCh:   exitCh,
			drain:    time.Minute,
			crash:    time.Minute,
		}
	})

	// run drives the loop on its own goroutine and returns a channel carrying
	// its result, so a spec can assert on behaviour before it returns.
	run := func() chan error {
		done := make(chan error, 1)
		go func() {
			defer GinkgoRecover()
			done <- sup.run()
		}()
		return done
	}

	// terminate drives the SIGTERM path to completion. The waits are
	// load-bearing: both arms of the loop's select become ready if exitCh is
	// fed before the signal has been taken, and Go picks between ready arms at
	// random, so a spec that skipped them would fail intermittently down the
	// crash path instead.
	terminate := func(done chan error) {
		GinkgoHelper()
		sigCh <- syscall.SIGTERM
		Eventually(signer.got).Should(ContainElement(syscall.SIGTERM))
		Eventually(frontend.got).Should(ContainElement(syscall.SIGTERM))
		exitCh <- childResult{"signer", nil}
		exitCh <- childResult{"frontend", nil}
		Eventually(done).Should(Receive(BeNil()))
	}

	Describe("reload forwarding", func() {
		It("forwards SIGHUP to the frontend and to nobody else", func() {
			// This hop is the entire delivery path for `systemctl reload` in
			// the default topology: systemd signals the launcher, and only
			// this forward reaches the process that owns the configuration.
			done := run()
			hupCh <- syscall.SIGHUP

			Eventually(frontend.got).Should(ConsistOf(syscall.SIGHUP))
			Consistently(signer.got).Should(BeEmpty(), "the signer holds nothing reloadable")

			Consistently(done).ShouldNot(Receive(), "a reload must not end the launcher")

			terminate(done)
		})

		It("keeps supervising after several reloads", func() {
			done := run()
			for i := 0; i < 3; i++ {
				hupCh <- syscall.SIGHUP
				Eventually(frontend.got).Should(HaveLen(i + 1))
			}

			terminate(done)
		})

		It("reports a signal it could not deliver", func() {
			// os.Process.Signal returns ErrProcessDone for a child that has
			// already exited. Dropping that silently would leave the operator
			// believing a rotated certificate was live.
			var buf syncBuffer
			orig := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
			defer slog.SetDefault(orig)

			frontend.err = errors.New("os: process already finished")
			done := run()
			hupCh <- syscall.SIGHUP
			Eventually(frontend.got).Should(HaveLen(1))
			Eventually(buf.String).Should(ContainSubstring("Failed to forward the reload signal"))

			terminate(done)
		})
	})

	Describe("the hard-kill fallback", func() {
		BeforeEach(func() {
			// Budgets short enough for the timer to fire inside a spec. In
			// production these are the drain budget and the shorter crash
			// budget; what matters is that a child which ignores SIGTERM is
			// eventually killed rather than left running — the signer holds
			// the CA private key.
			sup.drain = 10 * time.Millisecond
			sup.crash = 10 * time.Millisecond
		})

		It("kills both children when they do not exit within the drain budget", func() {
			done := run()
			sigCh <- syscall.SIGTERM

			// Withhold the exit reports: this is a child that has taken the
			// SIGTERM and not gone.
			Eventually(signer.killed).Should(BeNumerically(">", 0))
			Eventually(frontend.killed).Should(BeNumerically(">", 0))

			exitCh <- childResult{"signer", nil}
			exitCh <- childResult{"frontend", nil}
			Eventually(done).Should(Receive(BeNil()))
		})

		It("kills the survivor when one child has already crashed", func() {
			done := run()
			exitCh <- childResult{"signer", errors.New("boom")}

			Eventually(frontend.killed).Should(BeNumerically(">", 0))

			exitCh <- childResult{"frontend", nil}
			Eventually(done).Should(Receive(HaveOccurred()))
		})

		It("does not kill children that exit in time", func() {
			sup.drain = time.Minute
			done := run()
			terminate(done)

			Consistently(signer.killed).Should(BeZero())
			Consistently(frontend.killed).Should(BeZero())
		})
	})

	Describe("termination", func() {
		It("tells the service manager it is stopping, then stops both children", func() {
			done := run()
			sigCh <- syscall.SIGTERM

			Eventually(rec.msgs).Should(Receive(SatisfyAll(
				HavePrefix("STOPPING=1"),
				ContainSubstring("Shutting down on terminated"),
			)))
			Eventually(signer.got).Should(ConsistOf(syscall.SIGTERM))
			Eventually(frontend.got).Should(ConsistOf(syscall.SIGTERM))

			exitCh <- childResult{"signer", nil}
			exitCh <- childResult{"frontend", nil}
			Eventually(done).Should(Receive(BeNil()))
		})
	})

	Describe("an unexpected child exit", func() {
		It("names the failed process and returns its error", func() {
			done := run()
			exitCh <- childResult{"signer", errors.New("boom")}

			Eventually(rec.msgs).Should(Receive(ContainSubstring("The signer process exited unexpectedly")))
			Eventually(frontend.got).Should(ConsistOf(syscall.SIGTERM))

			exitCh <- childResult{"frontend", nil}

			var err error
			Eventually(done).Should(Receive(&err))
			Expect(err).To(MatchError(ContainSubstring("signer process exited unexpectedly")))
		})

		It("re-sends the cause so the surviving child's drain text does not bury it", func() {
			// The frontend publishes its own "draining connections" status on
			// the way out. Without the second send that generic line is the
			// last thing on the socket, and `systemctl status` shows it
			// instead of the named failure.
			done := run()
			exitCh <- childResult{"signer", errors.New("boom")}
			exitCh <- childResult{"frontend", nil}
			Eventually(done).Should(Receive())

			var seen []string
			for {
				select {
				case m := <-rec.msgs:
					seen = append(seen, m)
					continue
				default:
				}
				break
			}
			Expect(seen).NotTo(BeEmpty())
			Expect(seen[len(seen)-1]).To(ContainSubstring("The signer process exited unexpectedly"),
				"the cause must be the last status the service manager sees")
		})
	})
})

// SECURITY: the signer is the process holding the CA private key. A reload
// signal that reaches the process group rather than the launcher alone must not
// take it down -- the launcher would read the exit as a crash and tear the
// whole unit down with it.
var _ = Describe("the signer's SIGHUP disposition", func() {
	It("survives a SIGHUP delivered to itself", func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var out bytes.Buffer
		cmd := pskChildCmd(ctx, "sighup-ignored", nil, &out)

		Expect(cmd.Run()).To(Succeed(), "the child died on SIGHUP: %s", out.String())
		Expect(out.String()).To(ContainSubstring("ALIVE"))
	})
})

// SECURITY: what each child is and is not handed is a boundary, not a detail --
// the signer holds the CA private key. These drive the two functions the
// launcher and the --daemon re-exec actually call, so removing either strip
// fails a spec rather than passing silently.
var _ = Describe("the environments the launcher builds", func() {
	base := []string{
		"PATH=/usr/bin",
		"NOTIFY_SOCKET=/run/systemd/notify",
		"WATCHDOG_USEC=30000000",
		"PUPPET_CA_CADIR=/var/lib/puppet-ca",
	}

	It("withholds the notification socket from the signer, and nothing else", func() {
		Expect(signerEnv(base)).To(Equal([]string{
			"PATH=/usr/bin",
			"WATCHDOG_USEC=30000000",
			"PUPPET_CA_CADIR=/var/lib/puppet-ca",
		}))
	})

	It("withholds the socket and every internal variable from the daemon child", func() {
		// A stale role would make the child adopt a role it was not spawned
		// for; the socket would make it report readiness for a unit whose main
		// process has just exited.
		parent := append([]string{"PUPPET_CA_ROLE=signer", "PUPPET_CA_SIGNER_PSK=stale"}, base...)

		Expect(daemonEnv(parent)).To(Equal([]string{
			"PATH=/usr/bin",
			"WATCHDOG_USEC=30000000",
			"PUPPET_CA_CADIR=/var/lib/puppet-ca",
		}))
	})

	It("does not write through the shared internalEnvKeys slice", func() {
		// daemonEnv appends the socket to a copy; appending to internalEnvKeys
		// itself would corrupt the list every other caller reads.
		before := append([]string(nil), internalEnvKeys...)
		daemonEnv(base)

		Expect(internalEnvKeys).To(Equal(before))
	})
})

// The shipped unit encodes numbers derived from constants in this package.
// Nothing else notices when they drift apart, and the failure mode is systemd
// killing the CA part-way through a drain it was asked to wait for.
var _ = Describe("The shipped systemd unit", func() {
	var unit map[string]string

	BeforeEach(func() {
		raw, err := os.ReadFile("../../packaging/systemd/openvox-ca.service")
		Expect(err).NotTo(HaveOccurred(), "the unit staged into every release tarball must exist")

		unit = map[string]string{}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
				continue
			}
			if key, value, ok := strings.Cut(line, "="); ok {
				unit[key] = value
			}
		}
	})

	It("gives the drain more time than the launcher will take", func() {
		stop, err := time.ParseDuration(unit["TimeoutStopSec"])
		Expect(err).NotTo(HaveOccurred())
		Expect(stop).To(BeNumerically(">", defaultShutdownDrain+launcherShutdownHeadroom),
			"TimeoutStopSec must outlast the drain budget plus the supervisor's headroom")
	})

	It("asks for notifications from every process that sends them", func() {
		// READY=1 comes from the frontend child, not the unit's main PID, so
		// NotifyAccess=main would discard it and the start job would time out.
		Expect(unit["Type"]).To(Equal("notify"))
		Expect(unit["NotifyAccess"]).To(Equal("all"))
	})

	It("sets a watchdog the heartbeat can honour", func() {
		watchdog, err := time.ParseDuration(unit["WatchdogSec"])
		Expect(err).NotTo(HaveOccurred())

		// The binding constraint, and the reason the unit says 90s rather than
		// 60s: the status line the heartbeat sends takes the CA's read lock, so
		// a storage operation holding the write lock stalls the heartbeat for
		// up to the cluster-lock budget. A watchdog inside that budget has
		// systemd kill a healthy CA that is waiting on a slow backend.
		Expect(watchdog).To(BeNumerically(">", ca.LockTimeout),
			"WatchdogSec must outlast internal/ca's cluster-lock timeout")

		// Secondary, and far looser: below this the CA warns on every start.
		Expect(watchdog).To(BeNumerically(">=", 2*shortWatchdogWarnBelow))
	})

	It("does not pin --config, which would disable PUPPET_CA_CONFIG", func() {
		Expect(unit["ExecStart"]).NotTo(ContainSubstring("--config"))
	})

	It("keeps the CA key out of core dumps", func() {
		Expect(unit["LimitCORE"]).To(Equal("0"))
	})

	It("does not daemonise, which a notify unit cannot survive", func() {
		Expect(unit["ExecStart"]).NotTo(ContainSubstring("--daemon"))
	})

	It("keeps AF_UNIX, which both the notify socket and the signer socketpair need", func() {
		Expect(unit["RestrictAddressFamilies"]).To(ContainSubstring("AF_UNIX"))
	})

	It("declares a start timeout long enough to bootstrap a CA key", func() {
		start, err := time.ParseDuration(unit["TimeoutStartSec"])
		Expect(err).NotTo(HaveOccurred())

		// Two of internal/ca's lock budgets, not one. Init spends the first on
		// the inventory-HMAC step (EnsureHMACKey's `hmac-key` lock on a cold
		// start, plus verification) and the second on `bootstrap`; they are
		// separate context.WithTimeout calls in sequence, not one shared
		// budget. A contended cold start against a shared backend is also
		// exactly when a CA key has to be generated, so both terms land
		// together and the floor has to clear the pair.
		Expect(start).To(BeNumerically(">", 2*ca.LockTimeout),
			"TimeoutStartSec must outlast both of Init's sequential lock budgets with room for key generation")
	})
})
