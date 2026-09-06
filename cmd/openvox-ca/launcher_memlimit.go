// Copyright (C) 2026 Chris Boot
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
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GOMEMLIMIT is a per-process knob, but the default deployment is a process
// tree: this launcher supervises an isolated signer and a frontend. Left to
// inherit it, all three apply the operator's value independently -- so
// GOMEMLIMIT set to just under the container limit, which is what the chart
// documentation used to recommend, yields three times that in aggregate soft
// limit. No runtime ever feels pressure and the cgroup wall arrives first: the
// advice given to convert an OOMKill into GC pressure removes the GC pressure
// it was meant to create.
//
// The launcher is the only process that can divide the budget, because it is
// the only one that knows the tree exists.
//
// GOMAXPROCS is deliberately left alone. Since Go 1.25 the runtime derives it
// from the cgroup CPU limit when it is unset (the containermaxprocs and
// updatemaxprocs GODEBUGs), and there is no memory equivalent anywhere in the
// runtime. The asymmetry is principled: CPU is time-sliced, so three runtimes
// sizing to the same quota costs parked threads and GC workers, whereas memory
// is a hard ceiling and triple-counting it is fatal. An operator who sets
// GOMAXPROCS explicitly does still have it inherited by all three, which is the
// same shape at far lower stakes.
const goMemLimitEnv = "GOMEMLIMIT"

// cgroupMountRoot is where the unified hierarchy is conventionally mounted, and
// cgroupSelfPath names this process's own cgroup within it.
//
// Both are needed. Inside a container with a cgroup namespace the container's
// own cgroup *is* the root, so memory.max sits directly at the mount point.
// Under systemd on a host it does not: the service lives at
// system.slice/<unit>, the v2 root carries no memory.max at all (the root
// cgroup is exempt from resource control), and reading only the mount point
// finds nothing. Resolving /proc/self/cgroup first makes a unit's MemoryMax=
// work; falling back to the mount point keeps the container case working when
// /proc is unavailable.
//
// cgroup v1's memory.limit_in_bytes is deliberately not consulted. It reports a
// near-int64-max sentinel rather than a word when unlimited, so a v1 reader that
// forgot the sentinel would derive an absurd budget and silently divide it --
// worse than deriving nothing. An operator on v1 can still set GOMEMLIMIT
// explicitly, which takes precedence anyway.
// cgroupMountRootPath is where the lookup starts. A variable rather than a
// parameter of applyMemoryBudget so runLauncher's one call site has no argument
// to transpose: cgroupMountRoot and cgroupSelfPath are declared together and
// swapping them disabled the derived path on every host with no spec noticing.
var cgroupMountRootPath = cgroupMountRoot

const (
	cgroupMountRoot = "/sys/fs/cgroup"
	cgroupSelfPath  = "/proc/self/cgroup"
	cgroupMemoryMax = "memory.max"
)

// The launcher's and signer's shares are absolute reservations rather than
// percentages, and the frontend takes whatever is left. Only the frontend's
// footprint grows with the fleet in steady state, so it should absorb growth; a
// percentage split scales the two processes whose cost is roughly constant and
// starves them exactly where the total is tightest. At the chart's default 64Mi
// limit a 10% signer share would be 6.4MiB, which is below a bare Go runtime's
// own footprint.
const (
	// defaultLauncherReservation covers the supervisor, which holds two
	// os.Process handles and blocks on channels. Its live heap is a few hundred
	// KiB, but GOMEMLIMIT governs the runtime's whole mapped-and-unreleased
	// footprint (MemStats.Sys - MemStats.HeapReleased), not live heap: arenas,
	// stacks and GC metadata are inside it, and that baseline is a few MiB for
	// any process built from this binary. The margin over live heap is
	// therefore the point, not slack -- Go's own documentation warns that a
	// limit below the runtime's own usage makes the collector run nearly
	// continuously.
	defaultLauncherReservation = 8 << 20

	// defaultSignerReservation must cover the signer's *peak*, which falls
	// during ca.Init and is fleet-proportional at roughly 420 bytes per
	// certificate: buildSerialIndex plus the []CertRecord that rebuildCertIndex
	// materialises. The share must also carry the runtime's own mapped
	// footprint -- the same few MiB minProcessReservation exists to protect --
	// so the usable headroom in 24MiB is nearer 16MiB, covering on the order of
	// 40,000 certificates rather than the 60,000 the raw division suggests.
	//
	// This share does NOT scale with the tree total, so raising the container
	// limit does not reach the signer. Above roughly that fleet size, raise
	// PUPPET_CA_MEMORY_RESERVE_SIGNER. Exceeding the share is not fatal --
	// GOMEMLIMIT is a soft limit, so the signer collects harder during startup
	// and Init takes longer.
	defaultSignerReservation = 24 << 20

	// minProcessReservation is the floor for a CONFIGURED reservation. GOMEMLIMIT
	// governs the runtime's whole mapped footprint, not live heap, and a limit
	// below that baseline makes the collector run nearly continuously -- silently,
	// since the process still makes progress. memory_reserve_signer names the
	// share of the process holding the CA key, so a value of "1" is accepted
	// arithmetic and a starved signer; below this floor the built-in default is
	// used instead.
	minProcessReservation = 8 << 20

	// minFrontendMemoryShare is the floor below which dividing the budget is
	// worse than leaving it undivided: the frontend is the process actually
	// serving traffic, and squeezing it into a share near its live heap trades
	// an OOMKill for a GC death spiral that reports nothing.
	minFrontendMemoryShare = 24 << 20

	// defaultMemoryBudgetPercent is how much of a cgroup ceiling the tree may
	// claim when memory_budget_percent is unset.
	// GOMEMLIMIT bounds Go runtime memory only: the binary's resident text,
	// kernel memory charged to the cgroup, and -- for this chart specifically --
	// the cadir tmpfs when persistence is disabled all sit outside it and count
	// against the same cgroup. Handing the runtimes 100% of the ceiling would
	// make them collect harder only once the cgroup was already at the wall,
	// which is the OOMKill this whole mechanism exists to convert into GC
	// pressure. An explicit GOMEMLIMIT is taken at face value instead, because
	// the operator naming a number has already chosen their own headroom.
	defaultMemoryBudgetPercent = 90
)

// budgetKind says why a budget was or was not applied, so the caller can log
// the cases an operator must act on differently from the ones they need not.
type budgetKind int

const (
	// budgetApplied: the tree budget was resolved and divided.
	budgetApplied budgetKind = iota
	// budgetNoCeiling: nothing stated a ceiling. Unremarkable -- it is every
	// host that is not memory-limited -- so it does not warrant an operator's
	// attention.
	budgetNoCeiling
	// budgetTooSmall: a ceiling was found and rejected as too small to divide.
	// The operator asked for a limit and did not get the division, so this one
	// has to be visible.
	budgetTooSmall
	// budgetInvalid: GOMEMLIMIT was set to something unparseable.
	budgetInvalid
)

// memoryBudget is the tree's total allowance and its division between the three
// processes.
type memoryBudget struct {
	total    int64
	launcher int64
	signer   int64
	frontend int64
	// ceiling is the raw figure the budget was derived from before headroom was
	// withheld, and equals total when the operator stated it outright.
	ceiling int64
	// source names where the ceiling came from, for the operator-facing log.
	source string
	// notes carries operator-facing complaints about configured values that
	// could not be used. Non-fatal by design -- a tuning knob should not stop
	// the CA starting -- but never silent, which is what they used to be.
	notes []string
}

// shareFor returns the limit for one role in the tree.
//
// The mapping lives here rather than at the call sites so that a share cannot
// reach the wrong process: spawnChild is handed the whole budget and the role it
// is already spawning, so there is no argument left to transpose. Passing
// budget.signer and budget.frontend positionally is exactly the shape where a
// swap compiles, runs, and is invisible to every spec that checks arithmetic.
//
// An unknown role, and every role when no budget was resolved, returns 0 --
// which spawnChild reads as "leave the runtime default alone". Zero must never
// be handed to debug.SetMemoryLimit as a limit.
func (b memoryBudget) shareFor(role string) int64 {
	switch role {
	case "launcher":
		return b.launcher
	case "signer":
		return b.signer
	case "frontend":
		return b.frontend
	default:
		return 0
	}
}

// resolveMemoryBudget determines the tree-wide budget and divides it.
//
// An explicit GOMEMLIMIT wins: the operator asked for a specific number and it
// is taken to name the budget for the whole tree, which is what the
// documentation says it means. Only when it is unset is the cgroup consulted,
// so deriving can never override a deliberate setting.
//
// The returned kind says how the caller should report the outcome, and reason
// is the operator-facing explanation (empty when a budget was applied). getenv
// and cgroupPath are parameters rather than package-level references so a spec
// can drive every branch without mutating the process environment or writing
// under /sys; cfg supplies the three tuning keys (memory_reserve_launcher,
// memory_reserve_signer, memory_budget_percent).
func resolveMemoryBudget(cfg *serverConfig, getenv func(string) string, cgroupPath string) (budget memoryBudget, kind budgetKind, reason string) {
	// The configured keys are resolved BEFORE the ceiling lookup, so a value
	// that could not be used is reported whatever the lookup does. Resolving
	// them afterwards meant the notes were built only on the path that
	// divided: a mistyped memory_reserve_signer went unreported on every host
	// with no ceiling -- the shipped systemd unit, every cgroup v1 host, any
	// container without a memory limit -- and, worse, on the too-small path,
	// where the warning went on to quote the substituted defaults back at the
	// operator as though they were what had been configured.
	percent, percentNote := cfg.memoryBudgetPercent()
	launcher, launcherNote := cfg.memoryReserveLauncher()
	signer, signerNote := cfg.memoryReserveSigner()
	notes := make([]string, 0, 3)
	for _, n := range []string{percentNote, launcherNote, signerNote} {
		if n != "" {
			notes = append(notes, n)
		}
	}

	ceiling, source, kind, reason := treeMemoryCeiling(getenv, cgroupPath)
	if kind != budgetApplied {
		return memoryBudget{notes: notes}, kind, reason
	}

	total := ceiling
	if source != goMemLimitEnv {
		// Withhold headroom only from a figure we derived. See
		// serverConfig.MemoryBudgetPercent.
		total = scalePercent(ceiling, percent)
	}

	// Ordered so neither subtraction can wrap. A reservation is bounded only by
	// ParseInt on the bare-decimal path, so two MaxInt64 reservations would make
	// total-launcher-signer wrap positive and pass the floor check below --
	// admitting a division whose shares sum far above the budget, which is the
	// state this whole mechanism exists to prevent.
	frontend := int64(0)
	if launcher < total && signer < total-launcher {
		frontend = total - launcher - signer
	}
	if frontend < minFrontendMemoryShare {
		return memoryBudget{notes: notes}, budgetTooSmall, fmt.Sprintf(
			"%s gives a tree budget of %d bytes, which leaves the frontend %d after reserving "+
				"%d for the launcher and %d for the signer; it needs at least %d. %s Raise the "+
				"limit, or lower memory_reserve_launcher / memory_reserve_signer",
			source, total, frontend, launcher, signer, int64(minFrontendMemoryShare),
			undividedState(source))
	}

	return memoryBudget{
		total:    total,
		launcher: launcher,
		signer:   signer,
		frontend: frontend,
		ceiling:  ceiling,
		source:   source,
		notes:    notes,
	}, budgetApplied, ""
}

// scalePercent returns percent% of n, multiplying before dividing so the result
// is exact for every plausible ceiling. Dividing first truncates n to a
// multiple of 100 and loses up to 99 bytes per percentage point, which is
// harmless operationally but makes the arithmetic awkward to state and to
// assert.
//
// The guard covers an implausibly large ceiling, where the multiply would
// overflow; there the imprecise order is used instead, because a wrong sign is
// worse than a lost byte. That ceiling comes from parseCgroupMemoryMax's
// ParseInt, not from parseGoByteCount: scalePercent runs only on the derived
// path, and an explicit GOMEMLIMIT is taken at face value without it.
func scalePercent(n int64, percent int) int64 {
	if n > math.MaxInt64/100 {
		return n / 100 * int64(percent)
	}
	return n * int64(percent) / 100
}

// undividedState says what memory limits are in force when the division is
// declined, which differs by where the ceiling came from and is the half an
// operator cannot infer from the refusal.
//
// Saying only what was refused is not enough, and that is not hypothetical: an
// operator read "Not dividing the memory budget across the process tree",
// concluded that no process had a limit, and carried that into a merge request
// and two other sessions before anyone checked the spawn path. The opposite was
// true -- their GOMEMLIMIT was still in force on all three processes, because
// it is not stripped from the children's environment and no share is appended
// to override it when the budget is the zero value.
func undividedState(source string) string {
	if source == goMemLimitEnv {
		return "Nothing is overridden, so all three processes continue to apply " +
			"GOMEMLIMIT independently -- the whole value each, not a third of it."
	}
	return "No process is given a memory limit at all."
}

// treeMemoryCeiling returns the ceiling the tree budget is drawn from and where
// it came from.
func treeMemoryCeiling(getenv func(string) string, cgroupPath string) (int64, string, budgetKind, string) {
	raw := strings.TrimSpace(getenv(goMemLimitEnv))
	switch raw {
	case "":
		// Fall through to the cgroup.
	case "off":
		// The Go runtime special-cases "off" to mean unlimited, ahead of its own
		// byte-count parser (runtime.readGOMEMLIMIT). An operator who wrote it
		// disabled the limit deliberately, so this is neither an error nor a
		// budget -- and it must not fall through to the cgroup, which would
		// reinstate the limit they just turned off.
		return 0, "", budgetNoCeiling, "GOMEMLIMIT is off, so no budget is divided"
	default:
		n, valid := parseGoByteCount(raw)
		if !valid {
			return 0, "", budgetInvalid, fmt.Sprintf(
				"GOMEMLIMIT is set to %s, which is not a byte count the Go runtime accepts", strconv.Quote(raw))
		}
		return n, goMemLimitEnv, budgetApplied, ""
	}

	n, path, found := readCgroupMemoryMax(cgroupPath)
	if !found {
		return 0, "", budgetNoCeiling, "GOMEMLIMIT is unset and no cgroup memory ceiling was found"
	}
	return n, "cgroup " + path, budgetApplied, ""
}

// readCgroupMemoryMax reads a cgroup v2 memory ceiling, preferring this
// process's own cgroup over the mount root, and returns the path it read.
//
// mountRoot is a parameter so a spec can point the whole lookup at a temporary
// directory. It is a mount root in specs exactly as it is in production: an
// earlier version short-circuited when handed a file, which let every spec
// bypass the two filepath.Join constructions that are the only thing production
// ever runs.
func readCgroupMemoryMax(mountRoot string) (int64, string, bool) {
	for _, candidate := range cgroupMemoryMaxCandidates(mountRoot) {
		if n, ok := parseCgroupMemoryMax(candidate); ok {
			return n, candidate, true
		}
	}
	return 0, "", false
}

// cgroupMemoryMaxCandidates lists the files that may hold this process's memory
// ceiling, most specific first.
func cgroupMemoryMaxCandidates(mountRoot string) []string {
	candidates := make([]string, 0, 2)
	if rel := selfCgroupPath(); rel != "" {
		// Containment, not because a traversal is reachable -- /proc/self/cgroup
		// is kernel-generated and a cgroup directory cannot be named ".." -- but
		// because this is a path built from file content and joined onto a
		// system root. filepath.Join cleans, so a rel of "/../.." would escape
		// silently; dropping the candidate leaves the mount-root fallback, so
		// no supported deployment loses its ceiling.
		if p := filepath.Join(mountRoot, rel, cgroupMemoryMax); withinRoot(mountRoot, p) {
			candidates = append(candidates, p)
		}
	}
	return append(candidates, filepath.Join(mountRoot, cgroupMemoryMax))
}

// withinRoot reports whether path stays beneath root, both cleaned first.
//
// Cleaning path is the load-bearing half and it used to be missing: the comment
// claimed it and the code compared the argument raw, so a path containing ".."
// was reported as contained even though it escaped. The only caller passes a
// filepath.Join result, which is already clean, so production was never
// exposed -- but a containment helper that does not honour its own contract is
// the wrong thing to leave in the tree, and the obvious spec written against
// the old behaviour would have pinned the escape as correct.
func withinRoot(root, path string) bool {
	cleanRoot := filepath.Clean(root)
	return strings.HasPrefix(filepath.Clean(path), cleanRoot+string(os.PathSeparator))
}

// selfCgroupPath returns this process's cgroup v2 path relative to the mount
// root, or "" when it cannot be determined.
// cgroupSelfPathFile is the file selfCgroupPath reads. A variable for the same
// reason mountRoot is a parameter: the read had no spec of its own, so pointing
// it at a nonexistent path left every spec green because the mount-root
// candidate answers either way. It is the only seam on this path -- an earlier
// version also wrapped the resolver, which let every ordering spec bypass
// parseSelfCgroup entirely.
var cgroupSelfPathFile = cgroupSelfPath

func selfCgroupPath() string {
	data, err := os.ReadFile(cgroupSelfPathFile)
	if err != nil {
		return ""
	}
	return parseSelfCgroup(string(data))
}

// parseSelfCgroup extracts the unified-hierarchy path from /proc/self/cgroup
// content: the line with an empty controller list, written "0::<path>".
//
// Split from the file read so it can be driven directly. Behind a stub point,
// the resolver itself had no coverage at all -- changing the "0::" prefix, or
// returning the whole line instead of the path, would have broken the one thing
// the systemd documentation promises (that a unit's MemoryMax= is honoured) with
// every spec still green, because the mount-root candidate answers either way.
func parseSelfCgroup(content string) string {
	for _, line := range strings.Split(content, "\n") {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "0::")
		if !ok {
			continue
		}
		// "/" is the root, which the mount-root candidate already covers, and
		// joining it would produce that same path twice.
		if rest == "" || rest == "/" {
			return ""
		}
		return rest
	}
	return ""
}

// parseCgroupMemoryMax reads one memory.max file. A missing file, an unreadable
// one, the literal "max", or anything that does not parse all yield false --
// every one of them means "no ceiling stated here", and none is worth failing
// startup over.
func parseCgroupMemoryMax(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	raw := strings.TrimSpace(string(data))
	if raw == "" || raw == "max" {
		return 0, false
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// parseConfiguredByteCount parses a byte count written in a configuration file.
// It accepts everything parseGoByteCount does, plus the IEC form without the
// trailing "B" -- "24Mi" as well as "24MiB".
//
// The two grammars differ deliberately. GOMEMLIMIT has to match the runtime
// exactly, because a value this accepted and the runtime did not would be
// divided here and then abort the child at startup. A configured reservation
// never reaches a child as a string -- spawnChild formats the resolved number
// with strconv.FormatInt -- so nothing is lost by accepting the spelling this
// project uses everywhere else: resources.limits.memory is "64Mi", MemoryMax= is
// "512M", and the shares are described in prose as "8Mi" and "24Mi". Rejecting
// the form the surrounding documentation writes, and silently substituting a
// default, was a trap rather than a strictness.
func parseConfiguredByteCount(s string) (int64, bool) {
	if n, ok := parseGoByteCount(s); ok {
		return n, true
	}
	// Retry the IEC form with the "B" the operator omitted. Only that: a bare
	// "24M" stays invalid, since SI and IEC differ by 5% and guessing which was
	// meant is worse than refusing.
	for _, prefix := range []string{"Ki", "Mi", "Gi", "Ti"} {
		if strings.HasSuffix(s, prefix) {
			return parseGoByteCount(s + "B")
		}
	}
	return 0, false
}

// parseGoByteCount mirrors the grammar the Go runtime accepts for GOMEMLIMIT,
// ^[0-9]+(([KMGT]i)?B)?$ -- an integer with an optional IEC suffix. It is
// reimplemented rather than approximated with a general size parser because the
// value has to round-trip: anything this accepts but the runtime rejects would
// be divided here and then refused by the child, and anything the runtime
// accepts but this rejects would be reported as budgetInvalid and nothing
// divided, leaving all three processes to inherit the operator's value and
// apply the whole of it each -- the defect this file exists to remove.
//
// The runtime's "off" is handled by the caller rather than here, because it is
// not a byte count: it names the absence of a limit.
func parseGoByteCount(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	digits := s
	shift := 0

	switch {
	case strings.HasSuffix(s, "B"):
		digits = s[:len(s)-1]
		for i, prefix := range []string{"K", "M", "G", "T"} {
			if strings.HasSuffix(digits, prefix+"i") {
				digits = digits[:len(digits)-2]
				shift = 10 * (i + 1)
				break
			}
		}
		// A remaining "i" means a suffix like "XiB" with an unknown prefix.
		if strings.HasSuffix(digits, "i") {
			return 0, false
		}
	case s[len(s)-1] >= '0' && s[len(s)-1] <= '9':
		// Bare byte count.
	default:
		return 0, false
	}

	if digits == "" {
		return 0, false
	}
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	// Reject an overflowing shift rather than wrapping to a negative budget.
	// The bound is the runtime's own -- math.MaxInt64 after scaling, as
	// runtime.parseByteCount computes it -- not 1<<62, which this used to use.
	// That was narrower than the runtime by a factor of two at the top of the
	// range, so a suffixed count between 2^62 and 2^63 was accepted by the
	// runtime and refused here, with the operator told it was "not a byte count
	// the Go runtime accepts". Nothing is divided on that path, so all three
	// processes would then inherit and apply the whole value each.
	if shift > 0 && uint64(n) > uint64(math.MaxInt64)>>shift {
		return 0, false
	}
	return n << shift, true
}
