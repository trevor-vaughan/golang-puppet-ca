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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/voxpupuli/openvox-ca/internal/sdnotify"
	"github.com/voxpupuli/openvox-ca/internal/signer"
)

const (
	// defaultShutdownDrain is the frontend's graceful HTTP-drain budget when the
	// operator has not set shutdown_timeout_sec / PUPPET_CA_SHUTDOWN_TIMEOUT_SEC.
	// 25s is chosen so the launcher's derived hard-kill deadline (drain +
	// launcherShutdownHeadroom = 28s) stays under Kubernetes' 30s default
	// terminationGracePeriodSeconds, leaving the platform headroom before it
	// SIGKILLs the pod.
	defaultShutdownDrain = 25 * time.Second
	// launcherShutdownHeadroom is added to the frontend's drain budget to form
	// the launcher's hard-kill deadline. Because the launcher's timer starts
	// when it forwards SIGTERM — strictly before the frontend begins its own
	// Shutdown — this headroom guarantees the launcher always outlasts the
	// frontend's drain so the supervisor can never truncate it.
	launcherShutdownHeadroom = 3 * time.Second
	// crashShutdownTimeout bounds teardown of the surviving child when the
	// other has already exited unexpectedly. This is a failure path, not a
	// graceful drain, so it uses a shorter budget.
	crashShutdownTimeout = 5 * time.Second
)

// runLauncher is the supervisor process that spawns the isolated signer and
// frontend children, monitors them, and propagates signals for clean shutdown.
//
// Process tree:
//
//	openvox-ca (launcher/supervisor)
//	├-- openvox-ca [signer]    holds CA key, no network, socketpair only
//	└-- openvox-ca [frontend]  HTTP server, connects to signer via socketpair
//
// SECURITY: The socketpair is created before either child is spawned and
// passed via inherited file descriptors (fd 3). There is no filesystem path
// for the socket; only the two child processes hold endpoints.
//
// cfg supplies the frontend's graceful HTTP-drain budget (see
// serverConfig.shutdownDrain) and the three memory-budget keys. The launcher
// waits that drain plus launcherShutdownHeadroom for both children to exit
// after forwarding SIGTERM before hard-killing them,
// so the frontend always gets its full drain even though the launcher's timer
// starts first.
//
// notify carries the launcher's own service-manager notifications: the status
// text while the children come up, and STOPPING=1 once teardown begins. READY=1
// deliberately comes from the frontend child instead, since only it knows when
// the listener is actually accepting — which is why units must set
// NotifyAccess=all (see docs/systemd.md).
//
// hupCh delivers reload requests, which the service manager sends to this
// process because it is the unit's main PID. It is registered by the caller
// before any startup work begins, so a reload arriving early is queued rather
// than fatal — SIGHUP's default disposition would otherwise kill the launcher.
// NIST 800-53: SC-3 (Security Function Isolation), SC-4 (Information in Shared System Resources)
func runLauncher(cfg *serverConfig, notify *sdnotify.Notifier, hupCh <-chan os.Signal) error {
	gracefulShutdownTimeout := cfg.shutdownDrain() + launcherShutdownHeadroom

	// Create the socketpair for signer ↔ frontend communication.
	signerSock, frontendSock, err := signer.Socketpair()
	if err != nil {
		return fmt.Errorf("creating signer socketpair: %w", err)
	}
	defer signerSock.Close()
	defer frontendSock.Close()

	// Generate a PSK for authenticating the socketpair endpoints.
	// Both children receive this via an inherited pipe (fd 4) and run a
	// mutual challenge-response handshake before the first RPC call: each
	// endpoint proves knowledge of the PSK to the other, so a rogue process
	// that somehow obtained a leaked fd could impersonate neither the
	// frontend nor the signer.
	//
	// SECURITY: the PSK travels over a pipe rather than an environment
	// variable because a child's exec-time environment stays visible in
	// /proc/<pid>/environ for its whole lifetime (os.Unsetenv only mutates
	// the process's own copy) and is captured verbatim by crash-dump and
	// support tooling such as systemd-coredump. A pipe is consumed once and
	// leaves no such residue.
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		return fmt.Errorf("generating socketpair PSK: %w", err)
	}
	pskHex := hex.EncodeToString(psk)

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	slog.Info("Starting isolated CA processes")
	notify.Status("Starting the isolated signer and frontend processes")

	// Build base environment: strip role/daemon vars to prevent inheritance
	// loops. PUPPET_CA_SIGNER_PSK is stripped defensively: the PSK travels
	// over a pipe, and a variable by that name must never reach a child.
	// spawnChild clips this before appending to it, so the two children cannot
	// share a backing array.
	baseEnv := filterEnv(os.Environ(), internalEnvKeys...)

	// Divide the tree's memory budget before either child starts. GOMEMLIMIT is
	// a per-process knob and all three processes would otherwise apply the
	// operator's whole value independently; see launcher_memlimit.go. A zero
	// share means "leave the runtime default alone", which is what every child
	// gets when no budget could be resolved.
	budget := applyMemoryBudget(cfg, os.Getenv, debug.SetMemoryLimit)

	// The frontend gets baseEnv untouched: it is the process that knows when
	// the listener is accepting, so it is the one that reports READY=1.
	signerCmd, err := spawnChild(exe, signerEnv(baseEnv), "signer", signerSock, pskHex, budget)
	if err != nil {
		return err
	}

	frontendCmd, err := spawnChild(exe, baseEnv, "frontend", frontendSock, pskHex, budget)
	if err != nil {
		// The signer is already running and nothing will ever connect to it, so
		// it has to go -- and be reaped, not merely signalled: Kill on its own
		// leaves a zombie for as long as this process lives, and the launcher
		// does not necessarily exit straight away.
		killAndReap(signerCmd)
		return err
	}

	slog.Info("CA processes started",
		"signer_pid", signerCmd.Process.Pid,
		"frontend_pid", frontendCmd.Process.Pid,
	)
	// The frontend takes it from here: it reports readiness once its listener
	// is up, and owns the status text from that point on.
	notify.Status("Waiting for the frontend process to become ready")

	// Forward termination signals to children. The buffer matches the
	// number of registered signals so a coincident SIGTERM+SIGINT (e.g.
	// terminal Ctrl-C racing with a supervisor SIGTERM) cannot drop a
	// notification and leave the launcher hung.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	// Wait for either child to exit.
	exitCh := make(chan childResult, 2)
	go func() { exitCh <- childResult{"signer", signerCmd.Wait()} }()
	go func() { exitCh <- childResult{"frontend", frontendCmd.Wait()} }()

	return (&supervisor{
		signer:   signerCmd.Process,
		frontend: frontendCmd.Process,
		notify:   notify,
		hupCh:    hupCh,
		sigCh:    sigCh,
		exitCh:   exitCh,
		drain:    gracefulShutdownTimeout,
		crash:    crashShutdownTimeout,
	}).run()
}

// applyMemoryBudget resolves the tree budget, applies the launcher's own share
// through setLimit, and reports the outcome at the level the documentation
// promises. It returns the budget so the caller can hand it to each child.
//
// Extracted from runLauncher, which has no test and cannot easily have one, so
// that its three decisions are pinned somewhere: that the launcher applies the
// LAUNCHER's share and not one of the children's, that the lookup starts at the
// cgroup mount root, and that each outcome reaches the level docs/configuration.md
// names. The first and third are asserted by specs; the second is now structural,
// since there is no mount-root argument to pass wrongly. All three were previously expressible only inside the untested function
// -- swapping shareFor("launcher") for shareFor("signer") changed nothing any
// spec could see.
//
// setLimit is a parameter rather than a direct debug.SetMemoryLimit call for the
// same reason: a spec cannot observe the process-global limit without changing
// it for every other spec in the suite. The mount root is deliberately NOT a
// parameter -- it comes from cgroupMountRootPath, which a spec stubs -- so this
// call site has no path argument to get wrong.
func applyMemoryBudget(cfg *serverConfig, getenv func(string) string, setLimit func(int64) int64) memoryBudget {
	budget, kind, reason := resolveMemoryBudget(cfg, getenv, cgroupMountRootPath)

	// Configured values that could not be used are reported whatever the
	// outcome: they are the operator's own input, and substituting a default in
	// silence is how a raised memory_reserve_signer went unnoticed.
	for _, note := range budget.notes {
		slog.Warn("Ignoring a memory-budget setting", "detail", note)
	}

	switch kind {
	case budgetApplied:
		slog.Info("Dividing the memory budget across the process tree",
			"source", budget.source,
			"ceiling_bytes", budget.ceiling,
			"total_bytes", budget.total,
			"launcher_bytes", budget.launcher,
			"signer_bytes", budget.signer,
			"frontend_bytes", budget.frontend,
		)
		setLimit(budget.shareFor("launcher"))
	case budgetTooSmall, budgetInvalid:
		// A ceiling was stated and the division did not happen, so the operator
		// asked for something and did not get it. Without this line the tree
		// silently keeps the triple-counted behaviour the limit was meant to
		// prevent -- and the documentation promises they are told.
		slog.Warn("Not dividing the memory budget across the process tree", "reason", reason)
	case budgetNoCeiling:
		// Nothing stated a ceiling anywhere, which is every host that is not
		// memory-limited. Unremarkable, so it does not warrant an operator's
		// attention.
		slog.Debug("No memory budget to divide across the process tree", "reason", reason)
	}
	return budget
}

// childResult reports which child exited and why.
type childResult struct {
	name string
	err  error
}

// childProcess is the slice of *os.Process the supervisor loop actually uses.
// Naming it lets the loop — which owns reload forwarding and every status
// notification the operator sees — be exercised without spawning children.
type childProcess interface {
	Signal(os.Signal) error
	Kill() error
}

// supervisor is runLauncher's steady state: forward reloads, propagate
// termination, and report whichever comes first to the service manager.
type supervisor struct {
	signer   childProcess
	frontend childProcess
	notify   *sdnotify.Notifier
	hupCh    <-chan os.Signal
	sigCh    <-chan os.Signal
	exitCh   <-chan childResult

	// drain is how long both children get to exit after a termination signal;
	// crash is the shorter budget for tearing down the survivor when one child
	// has already gone.
	drain time.Duration
	crash time.Duration
}

// run blocks until a termination signal arrives or a child exits, and returns
// the launcher's exit status.
func (s *supervisor) run() error {
	for {
		select {
		case <-s.hupCh:
			// The configuration a reload affects (the TLS keypair, the admin
			// allow list) belongs to the frontend, so the signal is forwarded
			// there rather than acted on here.
			slog.Info("Forwarding reload signal to the frontend process")
			if err := s.frontend.Signal(syscall.SIGHUP); err != nil {
				// Not teardown: the launcher keeps running, so a dropped
				// signal would otherwise leave the operator believing a
				// certificate or allow-list change had taken effect.
				slog.Error("Failed to forward the reload signal; the running configuration is unchanged",
					"error", err)
			}
			continue

		case sig := <-s.sigCh:
			slog.Info("Received signal, shutting down CA processes", "signal", sig)
			s.notify.Stopping(fmt.Sprintf("Shutting down on %s (up to %s for the children to exit)",
				sig, s.drain))
			timer := s.stopBoth(s.drain)
			<-s.exitCh
			<-s.exitCh
			timer.Stop()
			return nil

		case result := <-s.exitCh:
			slog.Error("CA child process exited unexpectedly", "process", result.name, "error", result.err)
			crashStatus := fmt.Sprintf("The %s process exited unexpectedly (%v); stopping", result.name, result.err)
			s.notify.Stopping(crashStatus)
			timer := s.stopBoth(s.crash)
			<-s.exitCh // wait for the other child
			timer.Stop()
			// Re-send the cause: the surviving child publishes its own drain
			// status on the way out, which would otherwise be the last thing
			// on the socket and would replace the named failure in
			// `systemctl status` at exactly the moment an operator looks.
			s.notify.Stopping(crashStatus)
			return fmt.Errorf("%s process exited unexpectedly: %w", result.name, result.err)
		}
	}
}

// stopBoth asks both children to exit and arms a hard kill after budget,
// returning the timer so the caller can stop it once both have gone.
func (s *supervisor) stopBoth(budget time.Duration) *time.Timer {
	// Best-effort teardown: a child that has already exited returns
	// os.ErrProcessDone, and the hard-kill timer below covers one that does
	// not go quietly. Unlike the reload forward, there is nothing an operator
	// could do with these errors — the launcher is on its way out either way.
	_ = s.frontend.Signal(syscall.SIGTERM)
	_ = s.signer.Signal(syscall.SIGTERM)
	return time.AfterFunc(budget, func() {
		_ = s.frontend.Kill()
		_ = s.signer.Kill()
	})
}

// daemonEnv is the environment the --daemon re-exec child is given: the
// parent's own, less the internal role/PSK variables and the notification
// socket.
//
// The role and PSK variables go because a stale value from a previous run
// would make the daemon child adopt a role it was not spawned for.
// $NOTIFY_SOCKET goes because the child would otherwise report readiness for a
// unit whose main process -- the parent, which returns as soon as it has
// forked -- has just exited. The parent's slice is copied rather than appended
// to in place, so the shared internalEnvKeys backing array is never written
// through.
//
// Named for the same reason as signerEnv: so a spec can drive it.
func daemonEnv(parent []string) []string {
	return filterEnv(parent, append(append([]string{}, internalEnvKeys...), "NOTIFY_SOCKET")...)
}

// signerEnv is the environment the signer child is given: the launcher's own,
// less the service-manager notification socket.
//
// SECURITY: the signer holds the CA key and talks to nothing but the frontend,
// so it has no state a service manager wants to hear about. Withholding
// $NOTIFY_SOCKET keeps the notification channel to exactly the two processes
// that use it (this launcher and the frontend) even under NotifyAccess=all.
//
// Named rather than inlined at the call site so the boundary has something a
// spec can drive. As one argument among five it was a one-token edit away from
// passing baseEnv straight through, and no assertion would have noticed.
//
// NIST 800-53: SC-3 (Security Function Isolation)
func signerEnv(baseEnv []string) []string {
	return filterEnv(baseEnv, "NOTIFY_SOCKET")
}

// internalEnvKeys are the variables the launcher and the --daemon re-exec strip
// before handing an environment to a child. One list, because the two call sites
// spelled it out separately and a fourth variable added to one and missed at the
// other would reach a child stale, with nothing to notice.
var internalEnvKeys = []string{"PUPPET_CA_ROLE", "PUPPET_CA_DAEMON", "PUPPET_CA_SIGNER_PSK"}

// pskPipeFn is the pipe constructor spawnChild uses. A variable so a spec can
// capture the descriptor the helper creates and assert directly that it was
// closed -- the fd-slot arithmetic that stood in for that could not distinguish a
// leaked pipe from a closed socket, so it passed either way.
var pskPipeFn = pskPipe

// spawnChild starts one isolated child in the given role, handing it the
// socketpair end on fd 3 and a freshly loaded PSK pipe on fd 4.
//
// Extracted so the two spawns cannot drift apart and so the failure ordering is
// testable: the parent's copies of both descriptors must be dropped as soon as
// the child holds them, and a PSK pipe created for a child that never starts
// must not be leaked. Both rules were open-coded twice.
//
// It takes the whole budget rather than one share, and picks the share by the
// role it was already given, so a share cannot reach the wrong process. Two
// positional int64 arguments at the call sites would let a transposition
// compile, run, and pass every spec that only checks the arithmetic.
func spawnChild(exe string, baseEnv []string, role string, sock *os.File, pskHex string, budget memoryBudget) (*exec.Cmd, error) {
	pskRead, err := pskPipeFn(pskHex)
	if err != nil {
		// Including here, the earliest exit: os.Pipe fails under descriptor
		// exhaustion, which is exactly the crash-looping launcher this helper's
		// other failure path reasons about. Leaving fd 3 to the caller's defer on
		// one exit and owning it on the other is the split the extraction removed.
		sock.Close()
		return nil, err
	}

	cmd := exec.Command(exe, os.Args[1:]...) //nolint:gosec // G204: re-execs this same binary (os.Executable) with the operator's own os.Args
	// Clipped to len==cap here, beside the append that depends on it: filterEnv
	// returns spare capacity whenever it stripped anything, so two spawns sharing
	// an unclipped slice would share a backing array and the second would rewrite
	// the first child's role -- leaving this process tree with no signer, or two.
	// The guard used to live in the caller, one function away from the append it
	// protects, which is how a third caller would have reintroduced it.
	baseEnv = baseEnv[:len(baseEnv):len(baseEnv)]
	cmd.Env = append(baseEnv,
		"PUPPET_CA_ROLE="+role,
		"PUPPET_CA_DAEMON=1",
	)
	if memLimit := budget.shareFor(role); memLimit > 0 {
		// Appended *after* baseEnv, which still carries the operator's
		// tree-wide GOMEMLIMIT when they set one: os/exec's dedupEnv keeps the
		// last occurrence of a key, so this child's share wins over the
		// inherited total. Stripping GOMEMLIMIT from baseEnv instead would be
		// wrong for the --daemon re-exec, which has to pass the operator's
		// value through so the re-executed launcher can divide it.
		cmd.Env = append(cmd.Env, goMemLimitEnv+"="+strconv.FormatInt(memLimit, 10))
	}
	cmd.ExtraFiles = []*os.File{sock, pskRead} // fd 3, fd 4
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		// Both, so the helper owns both descriptors unconditionally. Closing only
		// the pipe left fd 3 to the caller's defers, which runLauncher does have
		// -- but that is the split-ownership shape this extraction exists to
		// remove, and the second caller already got it wrong.
		pskRead.Close()
		sock.Close()
		return nil, fmt.Errorf("starting %s process: %w", role, err)
	}
	// Only the child should hold these now. The socketpair end is the
	// load-bearing one: while the launcher keeps a copy, both endpoints stay
	// alive, which falsifies the property this whole topology rests on -- that
	// only the two children hold endpoints -- and stops the signer seeing EOF
	// when the frontend dies. The PSK pipe's read end is closed for hygiene
	// rather than correctness: EOF for the child depends on the *write* end,
	// which pskPipe already closed before returning. An earlier comment here had
	// that backwards.
	sock.Close()
	pskRead.Close()
	return cmd, nil
}

// killAndReap signals a started child and waits for it, so a launcher that fails
// partway through leaves nothing behind. Errors are deliberately ignored: the
// caller is already returning a failure, and a child that has exited on its own
// is the outcome this wants anyway.
func killAndReap(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

// pskPipe returns the read end of a pipe pre-loaded with the hex-encoded
// PSK, ready to be inherited by a child via ExtraFiles. The write end is
// closed before returning, so the child reads the PSK followed immediately
// by EOF. The payload (64 bytes) is far below the kernel pipe buffer, so
// the write cannot block.
func pskPipe(pskHex string) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("creating PSK pipe: %w", err)
	}
	if _, err := w.WriteString(pskHex); err != nil {
		r.Close()
		w.Close()
		return nil, fmt.Errorf("writing PSK to pipe: %w", err)
	}
	if err := w.Close(); err != nil {
		r.Close()
		return nil, fmt.Errorf("closing PSK pipe write end: %w", err)
	}
	return r, nil
}

// filterEnv returns a copy of env with the named keys removed.
func filterEnv(env []string, keys ...string) []string {
	keySet := make(map[string]bool, len(keys))
	for _, k := range keys {
		keySet[k] = true
	}
	filtered := make([]string, 0, len(env))
	for _, e := range env {
		k, _, _ := strings.Cut(e, "=")
		if !keySet[k] {
			filtered = append(filtered, e)
		}
	}
	return filtered
}
