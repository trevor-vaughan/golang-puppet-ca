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
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/voxpupuli/openvox-ca/internal/signer"
)

// noEnv is a getenv that reports every variable as unset.
func noEnv(string) string { return "" }

// memLimitEnv returns a getenv serving GOMEMLIMIT and nothing else.
func memLimitEnv(v string) func(string) string {
	return func(k string) string {
		if k == goMemLimitEnv {
			return v
		}
		return ""
	}
}

// captureLogs runs fn with the default logger redirected to a buffer at the
// given level, so the debug and warning branches are both observable.
//
// syncBuffer, not bytes.Buffer: this replaces the PROCESS-GLOBAL default
// logger, so any goroutine in the suite that logs during the window writes into
// it, and launcher_test.go already records that bytes.Buffer is not safe to
// read while another goroutine writes.
func captureLogs(level slog.Level, fn func()) string {
	var buf syncBuffer
	orig := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: level})))
	defer slog.SetDefault(orig)
	fn()
	return buf.String()
}

// defaultCfg is the configuration with none of the three memory keys set, so
// the built-in defaults apply.
func defaultCfg() *serverConfig { return &serverConfig{} }

// writeCgroupFile writes a memory.max fixture and returns the mount ROOT holding
// it, which is the shape production passes. Returning the file itself let an
// earlier shortcut in cgroupMemoryMaxCandidates answer directly, so the two
// filepath.Join constructions that are the only thing production runs were never
// exercised by any spec.
func writeCgroupFile(contents string) string {
	root := GinkgoT().TempDir()
	Expect(os.WriteFile(filepath.Join(root, "memory.max"), []byte(contents), 0o600)).To(Succeed())
	return root
}

// stubMountRoot points the production lookup at a temporary root for the
// current spec, since applyMemoryBudget no longer takes one as an argument.
func stubMountRoot(root string) {
	GinkgoHelper()
	previous := cgroupMountRootPath
	cgroupMountRootPath = root
	DeferCleanup(func() { cgroupMountRootPath = previous })
}

// stubSelfCgroup points the real resolver at a fixture stating rel, so the
// candidate ordering can be driven on a host whose own /proc/self/cgroup says
// nothing useful (macOS) as well as one where it does.
//
// It writes a file rather than replacing the resolver: a second seam above the
// read let every ordering spec bypass parseSelfCgroup entirely, so the two
// could disagree with nothing noticing. One seam, at the file.
func stubSelfCgroup(rel string) {
	GinkgoHelper()
	f := filepath.Join(GinkgoT().TempDir(), "cgroup")
	Expect(os.WriteFile(f, []byte("0::"+rel+"\n"), 0o600)).To(Succeed())
	previous := cgroupSelfPathFile
	cgroupSelfPathFile = f
	DeferCleanup(func() { cgroupSelfPathFile = previous })
}

// missingPath names a file that does not exist, standing in for a host with no
// unified cgroup hierarchy.
func missingPath() string {
	return filepath.Join(GinkgoT().TempDir(), "no-such-file")
}

// The smallest tree budget that can be divided under the default reservations.
// Written as the sum rather than as a literal so it tracks the constants: a spec
// that hard-codes 56MiB stops testing the boundary the moment one moves.
const (
	smallestDivisibleBudget = defaultLauncherReservation + defaultSignerReservation + minFrontendMemoryShare
)

var _ = Describe("dividing the memory budget across the process tree", func() {
	Describe("where the total comes from", func() {
		It("takes an explicit GOMEMLIMIT as the budget for the whole tree", func() {
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.source).To(Equal(goMemLimitEnv))
			Expect(budget.total).To(Equal(int64(256 << 20)))
		})

		It("prefers an explicit GOMEMLIMIT over the cgroup ceiling", func() {
			// The ruling this pins: deriving must never override a deliberate
			// setting. With both present the operator's value has to win, and
			// the cgroup number must not appear anywhere in the result.
			cgroup := writeCgroupFile("1073741824\n") // 1GiB
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), cgroup)

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.total).To(Equal(int64(256<<20)),
				"the operator's value must win over the cgroup ceiling")
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
			Expect(budget.source).To(Equal(goMemLimitEnv))
		})

		It("derives the budget from the cgroup when GOMEMLIMIT is unset", func() {
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("268435456\n"))

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.source).To(ContainSubstring("cgroup"))
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
		})

		It("treats GOMEMLIMIT=off as no budget rather than as a malformed one", func() {
			// The Go runtime special-cases "off" ahead of its own byte-count
			// parser, so an operator who wrote it disabled the limit
			// deliberately. Reporting it as malformed would tell them their
			// value is wrong when it is not -- and falling through to the cgroup
			// would reinstate the limit they just turned off.
			cgroup := writeCgroupFile("268435456\n")
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("off"), cgroup)

			Expect(kind).To(Equal(budgetNoCeiling), "off is not an error")
			Expect(reason).To(ContainSubstring("off"))
			Expect(budget.total).To(BeZero(), "the cgroup must not be consulted once off is set")
		})

		It("reports a malformed GOMEMLIMIT rather than falling through to the cgroup", func() {
			// Falling through would silently replace the operator's intent with
			// a derived number.
			_, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("240 MiB"), writeCgroupFile("268435456\n"))

			Expect(kind).To(Equal(budgetInvalid))
			Expect(reason).To(ContainSubstring("GOMEMLIMIT"))
			Expect(reason).To(ContainSubstring("240 MiB"))
		})

		It("distinguishes no ceiling anywhere from a ceiling too small to divide", func() {
			// These two reach different log levels: one is every unlimited host
			// and unremarkable, the other is an operator who set a limit and did
			// not get the division. Collapsing them is what made the
			// too-small case invisible at the default verbosity.
			_, absent, _ := resolveMemoryBudget(defaultCfg(), noEnv, missingPath())
			Expect(absent).To(Equal(budgetNoCeiling))

			_, small, _ := resolveMemoryBudget(defaultCfg(), memLimitEnv("32MiB"), missingPath())
			Expect(small).To(Equal(budgetTooSmall))
		})

		DescribeTable("cgroup ceilings that state nothing usable",
			func(contents string) {
				_, kind, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile(contents))
				Expect(kind).To(Equal(budgetNoCeiling))
			},
			Entry("the literal max", "max\n"),
			Entry("an empty file", ""),
			Entry("whitespace only", "  \n"),
			Entry("a non-numeric value", "not-a-number\n"),
			Entry("zero", "0\n"),
			Entry("a negative count", "-1\n"),
		)

		It("reads memory.max from under the mount root it is given", func() {
			// The production shape: cgroupMountRoot is a directory, and the
			// candidate paths are built by joining onto it. Renaming
			// cgroupMemoryMax or dropping either join fails here.
			root := writeCgroupFile("268435456\n")
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, root)

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
			Expect(budget.source).To(ContainSubstring(filepath.Join(root, "memory.max")),
				"the source must name the file actually read")
		})

		It("prefers this process's own cgroup over the mount root", func() {
			// What makes a systemd unit's MemoryMax= work: the service's cgroup
			// is system.slice/<unit>, not the root. Reversing the candidate
			// order fails here.
			root := GinkgoT().TempDir()
			Expect(os.WriteFile(filepath.Join(root, "memory.max"), []byte("1073741824\n"), 0o600)).To(Succeed())
			own := filepath.Join(root, "system.slice", "openvox-ca.service")
			Expect(os.MkdirAll(own, 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(own, "memory.max"), []byte("268435456\n"), 0o600)).To(Succeed())
			stubSelfCgroup("/system.slice/openvox-ca.service")

			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, root)

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.ceiling).To(Equal(int64(256<<20)),
				"the unit's own ceiling must win over the mount root's")
		})

		It("falls back to the mount root when the process's own cgroup states nothing", func() {
			root := writeCgroupFile("268435456\n")
			stubSelfCgroup("/system.slice/openvox-ca.service") // no memory.max written there

			budget, kind, _ := resolveMemoryBudget(defaultCfg(), noEnv, root)
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
		})

		It("accepts a ceiling written without a trailing newline", func() {
			// Gives the "max" case above a sibling it is checked against: without
			// an accepted fixture, deleting the max clause would send it to
			// ParseInt, fail identically, and no assertion could tell.
			budget, kind, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("268435456"))
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.ceiling).To(Equal(int64(256 << 20)))
		})
	})

	Describe("headroom on a derived ceiling", func() {
		It("claims only the configured percentage of a cgroup ceiling", func() {
			// GOMEMLIMIT bounds Go memory only; the binary's text, kernel memory
			// and a memory-backed cadir all count against the same cgroup from
			// outside it. Claiming the whole ceiling would apply GC pressure
			// only once the cgroup was already at the wall.
			const ceiling = int64(1) << 30
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("1073741824\n"))

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.ceiling).To(Equal(ceiling))
			// 1GiB at the default 90 percent: 1073741824 * 90 / 100.
			Expect(budget.total).To(Equal(int64(966367641)))
			Expect(budget.total).To(BeNumerically("<", ceiling), "headroom must be withheld")
		})

		It("takes an explicit GOMEMLIMIT at face value, withholding nothing", func() {
			budget, kind, _ := resolveMemoryBudget(defaultCfg(), memLimitEnv("1GiB"), missingPath())
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.total).To(Equal(budget.ceiling),
				"the operator naming a number has already chosen their headroom")
		})

		It("honours memory_budget_percent", func() {
			cfg := &serverConfig{MemoryBudgetPercent: 50}
			budget, kind, _ := resolveMemoryBudget(cfg, noEnv, writeCgroupFile("1073741824\n"))
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.total).To(Equal(int64(1) << 29))
		})

		It("does not wrap on a ceiling large enough to overflow the multiply", func() {
			// scalePercent multiplies before dividing, so above MaxInt64/100 the
			// product would wrap negative and the budget would be refused as too
			// small. Deleting the guard fails here.
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv,
				writeCgroupFile("9223372036854775807\n"))

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.total).To(BeNumerically(">", int64(0)), "a wrapped total goes negative")
			Expect(budget.total).To(Equal(int64(9223372036854775807) / 100 * defaultMemoryBudgetPercent))
		})

		It("takes the exact path just below the overflow threshold", func() {
			// The other arm of the guard: at or below MaxInt64/100 the multiply
			// is used, which is exact.
			const ceiling = int64(92233720368547758) // math.MaxInt64 / 100
			budget, kind, _ := resolveMemoryBudget(defaultCfg(), noEnv,
				writeCgroupFile("92233720368547758\n"))
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.total).To(Equal(ceiling * defaultMemoryBudgetPercent / 100))
		})

		DescribeTable("a percentage outside 1-100 falls back to the default",
			func(percent int) {
				cfg := &serverConfig{MemoryBudgetPercent: percent}
				budget, kind, _ := resolveMemoryBudget(cfg, noEnv, writeCgroupFile("1073741824\n"))
				Expect(kind).To(Equal(budgetApplied))
				Expect(budget.total).To(Equal(int64(966367641)), "must fall back to the default percentage")
			},
			Entry("zero", 0),
			Entry("negative", -10),
			Entry("above 100", 101),
		)

		DescribeTable("both endpoints of the accepted range are honoured",
			func(percent int, want int64) {
				cfg := &serverConfig{MemoryBudgetPercent: percent}
				// 8GiB, so even 1% clears the divisibility floor and the
				// endpoint is exercised rather than refused for being small.
				budget, kind, reason := resolveMemoryBudget(cfg, noEnv, writeCgroupFile("8589934592\n"))
				Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
				Expect(budget.total).To(Equal(want))
			},
			// Without these, >= 1 could become > 1 and <= 100 become < 100 with
			// the suite still green, silently giving an operator the default.
			Entry("the lowest accepted percentage", 1, int64(85899345)),
			Entry("the whole ceiling", 100, int64(8589934592)),
		)
	})

	Describe("how the total is divided", func() {
		It("gives the launcher and signer fixed reservations and the frontend the rest", func() {
			const total = 256 << 20
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			// Absolute, not the constants that produce them: asserting a value
			// against its own constant cannot fail when the constant moves, and
			// launcher 16MiB / signer 16MiB would otherwise pass every spec
			// while halving the signer's documented startup-peak share.
			Expect(budget.launcher).To(Equal(int64(8 << 20)))
			Expect(budget.signer).To(Equal(int64(24 << 20)))
			Expect(budget.frontend).To(Equal(int64(total - defaultLauncherReservation - defaultSignerReservation)))
		})

		It("never hands out more in total than the tree was given", func() {
			// The whole point of #304: three shares that sum above the ceiling
			// are what the inherited-GOMEMLIMIT bug produced. Asserted across a
			// range so a reservation change cannot quietly break the invariant
			// at one size while passing at another.
			for _, total := range []string{"64MiB", "128MiB", "256MiB", "1GiB", "4GiB"} {
				budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv(total), missingPath())

				Expect(kind).To(Equal(budgetApplied), "%s: %s", total, reason)
				Expect(budget.launcher+budget.signer+budget.frontend).
					To(Equal(budget.total), "shares must sum to the budget at %s", total)
			}
		})

		It("divides a budget of exactly the smallest divisible size", func() {
			// The accept side of the floor. Without it the refusal spec below is
			// satisfied by a frontend share of zero, so the floor's VALUE is
			// pinned by nothing and the constant could drop to a single byte
			// with every spec still green.
			budget, kind, reason := resolveMemoryBudget(defaultCfg(),
				memLimitEnv(strconv.FormatInt(smallestDivisibleBudget, 10)), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.frontend).To(Equal(int64(minFrontendMemoryShare)),
				"the frontend must land exactly on its floor")
		})

		It("refuses a budget one byte below the smallest divisible size", func() {
			// The reject side. Together with the spec above this pins both the
			// floor's value and the strictness of the comparison: a < to <= flip
			// fails one of the pair.
			_, kind, reason := resolveMemoryBudget(defaultCfg(),
				memLimitEnv(strconv.FormatInt(smallestDivisibleBudget-1, 10)), missingPath())

			Expect(kind).To(Equal(budgetTooSmall))
			Expect(reason).To(ContainSubstring(strconv.FormatInt(minFrontendMemoryShare, 10)),
				"the reason must name the floor the operator has to clear")
		})

		// The two specs above pin the STRICTNESS of the floor comparison but not
		// its value: their totals are derived from the same constants, so the
		// boundary moves with a mutation and both stay green with the floor set
		// to a single byte (verified by mutation). These bracket it with
		// absolute totals instead.
		It("refuses 48MiB, which clears both reservations but leaves the frontend under its floor", func() {
			// 48 - 8 launcher - 24 signer leaves 16MiB. This fails if the floor
			// drops to 16MiB or below.
			_, kind, _ := resolveMemoryBudget(defaultCfg(), memLimitEnv("48MiB"), missingPath())
			Expect(kind).To(Equal(budgetTooSmall))
		})

		It("divides an explicit 64MiB, leaving the frontend 32MiB", func() {
			// Fails if the floor rises above 32MiB. With the spec above, the
			// floor is bracketed to (16MiB, 32MiB] on the face-value path.
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("64MiB"), missingPath())
			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.frontend).To(Equal(int64(32 << 20)))
		})

		// The specs above drive an explicit GOMEMLIMIT, which is taken at face
		// value. The chart sets no GOMEMLIMIT: its limits.memory arrives as a
		// cgroup ceiling and is scaled to 90% first, so those specs say nothing
		// about the shipped configuration. These pin it, and the figures the
		// chart and helm-chart.md publish.
		It("divides the chart's shipped 128Mi limit on the cgroup path", func() {
			// 128Mi is what charts/openvox-ca/values.yaml ships. These are the
			// exact figures values.yaml, the chart README row and the Sizing
			// section all publish by value, so a change to the reservations or
			// the percentage that nobody carried into the documents fails here.
			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("134217728\n"))

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.total).To(Equal(int64(120795955)), "the documented 115.2Mi tree budget")
			Expect(budget.frontend).To(Equal(int64(87241523)), "the documented 83.2Mi frontend share")
			Expect(budget.launcher).To(Equal(int64(8 << 20)))
			Expect(budget.signer).To(Equal(int64(24 << 20)))
		})

		It("divides at the documented 63Mi threshold and refuses just below it", func() {
			// The published figure. 62Mi does NOT divide -- the smallest ceiling
			// that does is 65244729 bytes, 62.22Mi -- which is why the docs say
			// 63Mi. A spec at 62Mi would have caught the original wrong figure.
			_, tooSmall, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("65244728\n"))
			Expect(tooSmall).To(Equal(budgetTooSmall), "one byte below the threshold must be refused")

			_, exact, reason := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("65244729\n"))
			Expect(exact).To(Equal(budgetApplied), "reason: %s", reason)

			_, at62, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("65011712\n"))
			Expect(at62).To(Equal(budgetTooSmall), "62Mi must not divide; the docs say 63Mi")

			_, at63, _ := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("66060288\n"))
			Expect(at63).To(Equal(budgetApplied), "63Mi is the first whole MiB that divides")
		})

		It("names the source in the too-small reason, so the advice is actionable", func() {
			// The reason once told an operator on the derived path to "unset
			// GOMEMLIMIT" -- a variable that path only reaches because it is
			// already unset.
			_, kind, viaCgroup := resolveMemoryBudget(defaultCfg(), noEnv, writeCgroupFile("33554432\n"))
			Expect(kind).To(Equal(budgetTooSmall))
			Expect(viaCgroup).To(ContainSubstring("cgroup"))
			Expect(viaCgroup).NotTo(ContainSubstring("unset GOMEMLIMIT"))

			_, kind, viaEnv := resolveMemoryBudget(defaultCfg(), memLimitEnv("32MiB"), missingPath())
			Expect(kind).To(Equal(budgetTooSmall))
			Expect(viaEnv).To(ContainSubstring(goMemLimitEnv))
		})

		It("honours configured reservations, which is how a large fleet reaches the signer", func() {
			// The signer's share does not scale with the tree total, so this key
			// is the only way an operator past ~40,000 certificates can give it
			// more. If this stops working the documented remedy has no effect.
			cfg := &serverConfig{MemoryReserveSigner: "64MiB", MemoryReserveLauncher: "16MiB"}
			budget, kind, reason := resolveMemoryBudget(cfg, memLimitEnv("512MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.signer).To(Equal(int64(64 << 20)))
			Expect(budget.launcher).To(Equal(int64(16 << 20)))
			Expect(budget.frontend).To(Equal(int64(512<<20 - 64<<20 - 16<<20)))
		})

		DescribeTable("an unusable reservation falls back to its default rather than failing",
			func(value string) {
				cfg := &serverConfig{MemoryReserveSigner: value}
				budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())
				Expect(kind).To(Equal(budgetApplied))
				Expect(budget.signer).To(Equal(int64(24 << 20)))
			},
			Entry("not a byte count", "enormous"),
			Entry("zero", "0"),
			Entry("negative", "-1"),
			Entry("a decimal", "1.5GiB"),
			// Below the floor is arithmetically valid and operationally a
			// process that collects continuously. This is the share of the
			// process holding the CA key, so "1" must not be taken at its word.
			Entry("one byte", "1"),
			Entry("well under the runtime's own footprint", "2MiB"),
			Entry("one byte below the floor", "8388607"),
		)

		It("reports a reservation it could not use rather than substituting in silence", func() {
			// memory_reserve_signer is the documented remedy for a fleet whose
			// signer outgrows its share, so a value quietly ignored leaves the
			// operator with the problem they had just tried to fix.
			cfg := &serverConfig{MemoryReserveSigner: "64MB", MemoryBudgetPercent: 250}
			budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.notes).To(HaveLen(2), "both rejected settings must be reported")
			joined := strings.Join(budget.notes, "\n")
			Expect(joined).To(ContainSubstring("memory_reserve_signer"))
			Expect(joined).To(ContainSubstring("memory_budget_percent"))
			// The value too, not only the key: the documentation promises the
			// warning names "the key and the value it ignored", and dropping
			// the value from either format string left every assertion green
			// while removing the half that lets an operator find their typo.
			Expect(joined).To(ContainSubstring(`"64MB"`), "the rejected byte count")
			Expect(joined).To(ContainSubstring("250"), "the rejected percentage")
		})

		DescribeTable("reports an ignored setting whatever the ceiling lookup did",
			func(getenv func(string) string, wantKind budgetKind) {
				// The notes used to be built after the ceiling lookup and
				// attached only to a divided budget, so a mistyped reservation
				// went unreported on every host with no ceiling -- the shipped
				// systemd unit, cgroup v1, any container without a limit -- and
				// on the too-small path, where the warning then quoted the
				// substituted defaults back as though they were configured.
				cfg := &serverConfig{MemoryReserveSigner: "64MB"}
				budget, kind, _ := resolveMemoryBudget(cfg, getenv, missingPath())

				Expect(kind).To(Equal(wantKind))
				Expect(strings.Join(budget.notes, "\n")).To(ContainSubstring("memory_reserve_signer"),
					"the rejected key must be named on every path")
			},
			Entry("no ceiling anywhere", noEnv, budgetNoCeiling),
			Entry("a budget too small to divide", memLimitEnv("32MiB"), budgetTooSmall),
			Entry("GOMEMLIMIT off", memLimitEnv("off"), budgetNoCeiling),
		)

		DescribeTable("an unusable launcher reservation falls back to its own default",
			func(value string) {
				// The signer's equivalent asserted the resulting VALUE; the
				// launcher's asserted only that a note mentioned the right key.
				// A note naming the correct key while the share fell back to the
				// wrong number would have passed -- the observation was scoped
				// wider than the property it was named for.
				cfg := &serverConfig{MemoryReserveLauncher: value}
				budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())

				Expect(kind).To(Equal(budgetApplied))
				Expect(budget.launcher).To(Equal(int64(8<<20)),
					"the launcher's own default, not the signer's")
				Expect(budget.signer).To(Equal(int64(24<<20)), "and the signer's is untouched")
			},
			Entry("not a byte count", "64MB"),
			Entry("zero", "0"),
			Entry("negative", "-1"),
			Entry("below the floor", "1MiB"),
			Entry("one byte below the floor", "8388607"),
		)

		It("names the launcher's own key in its note, not the signer's", func() {
			// byteCountOrDefault takes the key name as a string, and only the
			// signer's was ever asserted: a copy-paste making both resolvers
			// pass "memory_reserve_signer" would warn about the wrong key.
			cfg := &serverConfig{MemoryReserveLauncher: "64MB"}
			budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied))
			joined := strings.Join(budget.notes, "\n")
			Expect(joined).To(ContainSubstring("memory_reserve_launcher"))
			Expect(joined).To(ContainSubstring(`"64MB"`), "and the value it ignored")
			Expect(joined).NotTo(ContainSubstring("memory_reserve_signer"))
		})

		It("names the key when a reservation is below the floor, not only when it is malformed", func() {
			// Both note-producing arms of byteCountOrDefault: the unparseable
			// one is covered above, this is the below-floor one. Returning an
			// empty note here would restore silent substitution on the key that
			// names the process holding the CA key.
			cfg := &serverConfig{MemoryReserveSigner: "1MiB"}
			budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())

			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.signer).To(Equal(int64(24 << 20)))
			Expect(strings.Join(budget.notes, "\n")).To(ContainSubstring("memory_reserve_signer"))
			Expect(strings.Join(budget.notes, "\n")).To(ContainSubstring("minimum"))
		})

		It("keeps the strict runtime grammar for GOMEMLIMIT itself", func() {
			// The two grammars differ deliberately: a configured key accepts
			// "24Mi", GOMEMLIMIT must not, because it has to mirror what the Go
			// runtime accepts. Swapping the parser at that call site would
			// otherwise pass every spec.
			_, kind, reason := resolveMemoryBudget(defaultCfg(), memLimitEnv("24Mi"), missingPath())
			Expect(kind).To(Equal(budgetInvalid))
			Expect(reason).To(ContainSubstring("24Mi"))
		})

		It("says nothing when every setting was usable", func() {
			cfg := &serverConfig{MemoryReserveSigner: "64Mi"}
			budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.notes).To(BeEmpty())
			Expect(budget.signer).To(Equal(int64(64<<20)), "the Kubernetes spelling must be accepted")
		})

		It("accepts a reservation exactly on the floor", func() {
			// The other side of it, so the floor's value is pinned rather than
			// merely its direction.
			cfg := &serverConfig{MemoryReserveSigner: "8MiB"}
			budget, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())
			Expect(kind).To(Equal(budgetApplied))
			Expect(budget.signer).To(Equal(int64(8 << 20)))
		})

		It("refuses reservations large enough to wrap the remainder", func() {
			// Two MaxInt64 reservations made total-launcher-signer wrap positive
			// and pass the frontend floor, admitting a division whose shares sum
			// far above the budget.
			cfg := &serverConfig{
				MemoryReserveLauncher: "9223372036854775807",
				MemoryReserveSigner:   "9223372036854775807",
			}
			_, kind, _ := resolveMemoryBudget(cfg, memLimitEnv("256MiB"), missingPath())
			Expect(kind).To(Equal(budgetTooSmall))
		})
	})

	Describe("which share reaches which process", func() {
		// spawnChild picks the share by the role it is already spawning, so a
		// transposition cannot be expressed. These pin the mapping itself.
		budget := memoryBudget{launcher: 1, signer: 2, frontend: 3}

		DescribeTable("shareFor maps a role to its own share",
			func(role string, want int64) {
				Expect(budget.shareFor(role)).To(Equal(want))
			},
			Entry("launcher", "launcher", int64(1)),
			Entry("signer", "signer", int64(2)),
			Entry("frontend", "frontend", int64(3)),
		)

		It("returns no limit for an unknown role", func() {
			Expect(budget.shareFor("bootstrap")).To(BeZero())
		})

		It("returns no limit for every role when no budget was resolved", func() {
			// Zero means "leave the runtime default alone". It must never be
			// handed to debug.SetMemoryLimit as a limit, which would collapse
			// the process into permanent GC.
			var none memoryBudget
			for _, role := range []string{"launcher", "signer", "frontend"} {
				Expect(none.shareFor(role)).To(BeZero(), "role %s", role)
			}
		})
	})

	DescribeTable("parsing the byte counts the Go runtime accepts",
		func(in string, want int64, valid bool) {
			got, ok := parseGoByteCount(in)
			Expect(ok).To(Equal(valid), "validity of %q", in)
			if valid {
				Expect(got).To(Equal(want), "value of %q", in)
			}
		},
		// The runtime's grammar is ^[0-9]+(([KMGT]i)?B)?$ -- anything this
		// accepts that the runtime rejects would be divided here and then
		// refused by the child, and anything it rejects that the runtime accepts
		// would silently fall through to the cgroup and override the operator.
		Entry("a bare byte count", "1024", int64(1024), true),
		Entry("an explicit B suffix", "1024B", int64(1024), true),
		Entry("KiB", "1KiB", int64(1024), true),
		Entry("MiB, as the chart documents", "240MiB", int64(240<<20), true),
		Entry("GiB", "2GiB", int64(2<<30), true),
		Entry("TiB", "1TiB", int64(1<<40), true),
		Entry("zero", "0", int64(0), true),
		Entry("the empty string", "", int64(0), false),
		Entry("a decimal, which the runtime does not accept", "1.5GiB", int64(0), false),
		Entry("lowercase units", "1kib", int64(0), false),
		Entry("a lowercase B", "1Mb", int64(0), false),
		Entry("SI rather than IEC", "1MB", int64(0), false),
		Entry("a suffix with no digits", "MiB", int64(0), false),
		Entry("an unknown IEC prefix", "1XiB", int64(0), false),
		Entry("a bare i before B", "1iB", int64(0), false),
		Entry("an embedded space", "240 MiB", int64(0), false),
		Entry("a negative count", "-1", int64(0), false),
		Entry("hexadecimal", "0x10", int64(0), false),
		// The shift-overflow guard. Without these the guard could be deleted
		// with every other entry still green: the largest value above is 1TiB,
		// which is nowhere near the threshold.
		// The boundary is the runtime's own: the largest n whose scaled value
		// still fits int64. It moved when the guard stopped rejecting at 1<<62,
		// which was narrower than the runtime by a factor of two.
		Entry("a large TiB count well inside the bound", "4194303TiB", int64(4194303)<<40, true),
		Entry("the largest TiB count that does not overflow", "8388607TiB", int64(8388607)<<40, true),
		Entry("one TiB past the overflow threshold", "8388608TiB", int64(0), false),
		Entry("a count that overflows the shift wildly", "16777216TiB", int64(0), false),
		Entry("digits that overflow ParseInt itself", "99999999999999999999", int64(0), false),
		Entry("the old, wrongly narrow 1<<62 bound is no longer a boundary", "4194304TiB", int64(1)<<62, true),
	)

	DescribeTable("parsing the byte counts a configuration file may use",
		func(in string, want int64, valid bool) {
			got, ok := parseConfiguredByteCount(in)
			Expect(ok).To(Equal(valid), "validity of %q", in)
			if valid {
				Expect(got).To(Equal(want), "value of %q", in)
			}
		},
		// Everything GOMEMLIMIT accepts, plus the trailing-B-less IEC spelling
		// this project writes everywhere else: resources.limits.memory is
		// "128Mi", and the shares are described in prose as "8Mi" and "24Mi".
		// Rejecting that form and silently substituting a default was a trap.
		Entry("the GOMEMLIMIT spelling", "24MiB", int64(24<<20), true),
		Entry("the Kubernetes spelling", "24Mi", int64(24<<20), true),
		Entry("a bare byte count", "25165824", int64(25165824), true),
		Entry("KiB without the B", "1Ki", int64(1024), true),
		Entry("GiB without the B", "2Gi", int64(2<<30), true),
		Entry("TiB without the B", "1Ti", int64(1<<40), true),
		// SI is still refused: it differs from IEC by 5% and guessing is worse
		// than refusing.
		Entry("SI megabytes", "64M", int64(0), false),
		Entry("SI with a B", "64MB", int64(0), false),
		Entry("a decimal", "1.5GiB", int64(0), false),
		Entry("an embedded space", "24 MiB", int64(0), false),
		Entry("lowercase", "24mi", int64(0), false),
		Entry("the empty string", "", int64(0), false),
	)

	Describe("the production defaults of the cgroup seams", func() {
		// The seams exist because a path constant could be passed wrongly with
		// no spec noticing. Nothing asserted their defaults, so the same
		// transposition simply moved into the var declaration: pointing
		// cgroupMountRootPath at cgroupSelfPath disabled the derived budget on
		// every host with the whole suite green. These are the assertions that
		// were missing.
		It("starts the lookup at the cgroup mount root", func() {
			Expect(cgroupMountRootPath).To(Equal("/sys/fs/cgroup"))
		})

		It("reads this process's cgroup from /proc/self/cgroup", func() {
			Expect(cgroupSelfPathFile).To(Equal("/proc/self/cgroup"))
		})

		It("always has somewhere to report a failed close", func() {
			// Non-nil, not identity with os.Stderr. Asserting identity passed
			// locally and failed on CI: logCloseErrOut captures os.Stderr when
			// the package initialises, and a test runner may replace os.Stderr
			// afterwards, so the two being the same object is a property of the
			// runner rather than of this code. What matters here is that the
			// fallback path for a failed close can never write to nil.
			Expect(logCloseErrOut).NotTo(BeNil())
		})

		It("resolves a unit's own cgroup through the real chain, unstubbed", func() {
			// End to end with nothing replaced but the file itself: the
			// candidate list, selfCgroupPath and parseSelfCgroup all run. A
			// resolver rebound to return "" would fall back to the mount root
			// and pass every other spec in this file.
			root := GinkgoT().TempDir()
			own := filepath.Join(root, "system.slice", "openvox-ca.service")
			Expect(os.MkdirAll(own, 0o700)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(own, "memory.max"), []byte("268435456\n"), 0o600)).To(Succeed())
			Expect(os.WriteFile(filepath.Join(root, "memory.max"), []byte("1073741824\n"), 0o600)).To(Succeed())
			stubSelfCgroup("/system.slice/openvox-ca.service")

			budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, root)

			Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
			Expect(budget.ceiling).To(Equal(int64(256<<20)),
				"the unit's own ceiling must win, through the unstubbed resolver")
		})
	})

	DescribeTable("containing the cgroup candidate path beneath the mount root",
		func(root, path string, want bool) {
			Expect(withinRoot(root, path)).To(Equal(want))
		},
		// New production code, so it needs its own coverage rather than
		// borrowing the behavioural spec below.
		Entry("a path directly beneath", "/sys/fs/cgroup", "/sys/fs/cgroup/memory.max", true),
		Entry("a path nested beneath", "/sys/fs/cgroup", "/sys/fs/cgroup/system.slice/x/memory.max", true),
		Entry("the root itself is not beneath it", "/sys/fs/cgroup", "/sys/fs/cgroup", false),
		Entry("an escape", "/sys/fs/cgroup", "/etc/memory.max", false),
		Entry("a sibling sharing a prefix", "/sys/fs/cgroup", "/sys/fs/cgroupX/memory.max", false),
		Entry("an unclean root still contains", "/sys/fs/cgroup/", "/sys/fs/cgroup/memory.max", true),
		// Asserted FALSE deliberately. Against the previous implementation this
		// returned true -- a path that escapes reported as contained -- so an
		// entry written to match the old behaviour would have pinned the bug as
		// correct. The helper cleans the path now.
		Entry("a traversing path escapes", "/sys/fs/cgroup", "/sys/fs/cgroup/../etc/memory.max", false),
		Entry("a traversal that stays inside is contained", "/sys/fs/cgroup", "/sys/fs/cgroup/x/../memory.max", true),
	)

	It("drops a cgroup candidate whose relative path escapes the mount root", func() {
		// The behaviour, not just the helper: a traversing rel must not produce
		// a candidate, and the mount-root fallback must still answer so no
		// deployment loses its ceiling.
		root := writeCgroupFile("268435456\n")
		stubSelfCgroup("/../../../etc")

		budget, kind, reason := resolveMemoryBudget(defaultCfg(), noEnv, root)

		Expect(kind).To(Equal(budgetApplied), "reason: %s", reason)
		Expect(budget.source).To(ContainSubstring(root),
			"the fallback under the mount root must be what answered")
		Expect(budget.ceiling).To(Equal(int64(256 << 20)))
	})

	Describe("reading this process's cgroup path", func() {
		// The parsing is table-driven below, but the read above it had no spec:
		// pointing the constant at a nonexistent file left every spec green,
		// because the mount-root candidate answers either way.
		It("returns the unified path from the file it is pointed at", func() {
			f := filepath.Join(GinkgoT().TempDir(), "cgroup")
			Expect(os.WriteFile(f, []byte("12:pids:/system.slice/x.service\n0::/system.slice/openvox-ca.service\n"), 0o600)).To(Succeed())
			previous := cgroupSelfPathFile
			cgroupSelfPathFile = f
			DeferCleanup(func() { cgroupSelfPathFile = previous })

			Expect(selfCgroupPath()).To(Equal("/system.slice/openvox-ca.service"))
		})

		It("reports nothing when the file cannot be read", func() {
			previous := cgroupSelfPathFile
			cgroupSelfPathFile = filepath.Join(GinkgoT().TempDir(), "absent")
			DeferCleanup(func() { cgroupSelfPathFile = previous })

			Expect(selfCgroupPath()).To(BeEmpty())
		})
	})

	DescribeTable("extracting this process's cgroup path from /proc/self/cgroup",
		func(content, want string) {
			Expect(parseSelfCgroup(content)).To(Equal(want))
		},
		// Behind the stub point this resolver had no coverage at all: changing
		// the "0::" prefix, or returning the whole line, would have broken the
		// systemd MemoryMax= promise with every spec still green, because the
		// mount-root candidate answers either way.
		Entry("a systemd host, unified line last",
			"12:pids:/system.slice/x.service\n0::/system.slice/openvox-ca.service\n",
			"/system.slice/openvox-ca.service"),
		Entry("a container with its own namespace, which the mount root covers", "0::/\n", ""),
		Entry("no trailing newline", "0::/system.slice/x.service", "/system.slice/x.service"),
		Entry("a v1-only file with no unified line", "12:pids:/system.slice/x.service\n", ""),
		Entry("an empty unified path", "0::\n", ""),
		Entry("empty content", "", ""),
		// A near-miss prefix must not match: "0:" alone is a v1 controller line.
		Entry("a v1 line whose prefix is a substring", "0:cpuset:/some/path\n", ""),
	)

	Describe("what the launcher applies to itself", func() {
		// applyMemoryBudget reads cgroupMountRootPath rather than taking a root,
		// so every spec here pins it at a path that states nothing. Without this
		// the outcome would depend on whether the host running the suite is
		// itself in a memory-limited cgroup.
		BeforeEach(func() { stubMountRoot(missingPath()) })

		// runLauncher has no test and cannot easily have one, so its three
		// decisions live in applyMemoryBudget where a spec can reach them.
		It("applies the launcher's own share, not a child's", func() {
			// The transposition shareFor exists to prevent, at the one call site
			// where the role is not already an argument. Distinct fixture values
			// so signer and frontend cannot stand in for it.
			var applied []int64
			budget := applyMemoryBudget(defaultCfg(), memLimitEnv("256MiB"),
				func(n int64) int64 { applied = append(applied, n); return 0 })

			Expect(applied).To(HaveLen(1), "the limit must be applied exactly once")
			Expect(applied[0]).To(Equal(budget.launcher))
			Expect(applied[0]).NotTo(Equal(budget.signer))
			Expect(applied[0]).NotTo(Equal(budget.frontend))
		})

		It("applies nothing when no budget was resolved", func() {
			// Zero must never reach SetMemoryLimit: it would collapse the
			// supervisor into permanent GC.
			var applied []int64
			applyMemoryBudget(defaultCfg(), noEnv,
				func(n int64) int64 { applied = append(applied, n); return 0 })
			Expect(applied).To(BeEmpty())
		})

		It("logs the division with every share the operator needs", func() {
			applied := captureLogs(slog.LevelDebug, func() {
				applyMemoryBudget(defaultCfg(), memLimitEnv("256MiB"), func(int64) int64 { return 0 })
			})
			Expect(applied).To(ContainSubstring("level=INFO"))
			// Values, not key names: a dropped attribute, or one bound to the
			// wrong share, still contains the key.
			Expect(applied).To(ContainSubstring("launcher_bytes=8388608"))
			Expect(applied).To(ContainSubstring("signer_bytes=25165824"))
			Expect(applied).To(ContainSubstring("frontend_bytes=234881024"))
			Expect(applied).To(ContainSubstring("total_bytes=268435456"))

			// A ceiling was stated and not divided: the operator asked for
			// something and did not get it, so this one has to be visible at
			// the default level.
			tooSmall := captureLogs(slog.LevelDebug, func() {
				applyMemoryBudget(defaultCfg(), memLimitEnv("32MiB"), func(int64) int64 { return 0 })
			})
			Expect(tooSmall).To(ContainSubstring("level=WARN"))

		})

		DescribeTable("reports each outcome at the level the documentation promises",
			func(getenv func(string) string, wantLevel, notLevel string) {
				out := captureLogs(slog.LevelDebug, func() {
					applyMemoryBudget(defaultCfg(), getenv, func(int64) int64 { return 0 })
				})
				Expect(out).To(ContainSubstring(wantLevel))
				if notLevel != "" {
					Expect(out).NotTo(ContainSubstring(notLevel))
				}
			},
			// A ceiling stated and not divided: the operator asked for something
			// and did not get it, so it must be visible at the default level.
			Entry("a budget too small to divide warns", memLimitEnv("32MiB"), "level=WARN", ""),
			// No ceiling anywhere is every unlimited host: unremarkable.
			Entry("no ceiling anywhere stays at debug", noEnv, "level=DEBUG", "level=WARN"),
			// The fourth kind. Grouped with too-small in one WARN arm, and
			// reached by nothing until now: removing it from the case list
			// dropped the outcome to silence with the suite green. It is
			// unreachable in production, because the Go runtime rejects a
			// malformed GOMEMLIMIT before any of this runs, so it is a backstop
			// against the two grammars diverging rather than a live path.
			Entry("a malformed GOMEMLIMIT warns", memLimitEnv("240 MiB"), "level=WARN", ""),
		)

		It("applies nothing when the budget was too small to divide", func() {
			// Zero must not reach setLimit on this path either, not only on the
			// no-ceiling one: the budget is the zero value here too.
			var applied []int64
			captureLogs(slog.LevelDebug, func() {
				applyMemoryBudget(defaultCfg(), memLimitEnv("32MiB"),
					func(n int64) int64 { applied = append(applied, n); return 0 })
			})
			Expect(applied).To(BeEmpty())
		})

		It("warns about an ignored setting even when nothing was divided", func() {
			cfg := &serverConfig{MemoryReserveSigner: "64MB"}
			out := captureLogs(slog.LevelDebug, func() {
				applyMemoryBudget(cfg, noEnv, func(int64) int64 { return 0 })
			})
			Expect(out).To(ContainSubstring("level=WARN"))
			Expect(out).To(ContainSubstring("memory_reserve_signer"))
		})

		It("emits one warning per ignored setting, not just the first", func() {
			// Driven with two rejected keys because one proves only that the
			// loop runs, not that it accumulates: emitting the first element,
			// or overwriting instead of appending, passes a single-note spec
			// unchanged. resolveMemoryBudget's own notes-length assertion
			// covers the slice; this covers the loop that reaches the operator.
			cfg := &serverConfig{MemoryReserveSigner: "64MB", MemoryBudgetPercent: 250}
			out := captureLogs(slog.LevelDebug, func() {
				applyMemoryBudget(cfg, noEnv, func(int64) int64 { return 0 })
			})

			Expect(strings.Count(out, "Ignoring a memory-budget setting")).To(Equal(2),
				"one warning line per rejected key")
			Expect(out).To(ContainSubstring("memory_reserve_signer"))
			Expect(out).To(ContainSubstring("memory_budget_percent"))
		})

		It("returns the budget it resolved, for the children to draw shares from", func() {
			budget := applyMemoryBudget(defaultCfg(), memLimitEnv("256MiB"),
				func(int64) int64 { return 0 })
			Expect(budget.shareFor("signer")).To(Equal(int64(24 << 20)))
			Expect(budget.shareFor("frontend")).To(Equal(int64(256<<20 - 8<<20 - 24<<20)))
		})
	})

	Describe("what the child process actually receives", func() {
		// These spawn a real child through the production spawnChild and read
		// back debug.SetMemoryLimit(-1) from inside it. Asserting cmd.Env would
		// only show the string the launcher built; this shows the limit the
		// child's runtime applied, so a value that is delivered but never
		// honoured cannot pass.
		spawnReporting := func(baseEnv []string, budget memoryBudget, role string) int64 {
			GinkgoHelper()
			out := filepath.Join(GinkgoT().TempDir(), "limit")
			sock, otherEnd, err := signer.Socketpair()
			Expect(err).NotTo(HaveOccurred())
			DeferCleanup(func() { _ = otherEnd.Close() })

			psk := make([]byte, 32)
			_, err = rand.Read(psk)
			Expect(err).NotTo(HaveOccurred())

			env := append([]string{}, baseEnv...)
			env = append(env, pskChildEnv+"=report-memlimit", memLimitOutEnv+"="+out)

			cmd, err := spawnChild(os.Args[0], env, role, sock, hex.EncodeToString(psk), budget)
			Expect(err).NotTo(HaveOccurred())
			Expect(cmd.Wait()).To(Succeed(), "the reporting child must exit cleanly")

			raw, err := os.ReadFile(out)
			Expect(err).NotTo(HaveOccurred(), "the child must have reported a limit")
			limit, err := strconv.ParseInt(string(raw), 10, 64)
			Expect(err).NotTo(HaveOccurred())
			return limit
		}

		DescribeTable("applies the share belonging to the role it spawned",
			func(role string, want int64) {
				// Both roles, with distinct values, so the two cannot coincide.
				// Driving only "signer" left spawnChild free to pass a literal
				// role to shareFor: the frontend would then come up on the
				// signer's reservation, which under the defaults is exactly the
				// floor the code refuses to divide below.
				budget := memoryBudget{launcher: 8 << 20, signer: 64 << 20, frontend: 128 << 20}
				Expect(spawnReporting(envWithoutMemLimit(), budget, role)).To(Equal(want))
			},
			Entry("the signer gets the signer's share", "signer", int64(64<<20)),
			Entry("the frontend gets the frontend's share", "frontend", int64(128<<20)),
		)

		It("overrides a tree-wide GOMEMLIMIT the child would otherwise inherit", func() {
			// The defect itself. The child's environment carries the operator's
			// whole-tree value, exactly as it does in production; the share is
			// appended after it and must win. This is the spec that goes red if
			// spawnChild stops appending, because the child would then come up
			// on the inherited total.
			const share = 64 << 20
			inherited := append(envWithoutMemLimit(), goMemLimitEnv+"=256MiB")

			Expect(spawnReporting(inherited, memoryBudget{signer: share}, "signer")).To(Equal(int64(share)),
				"the child's share must win over the inherited tree-wide total")
		})

		It("leaves the runtime default alone when there is no budget", func() {
			// Zero means "no budget was resolved", which must not be mistaken for
			// a limit of zero -- that would collapse the child into permanent GC.
			Expect(spawnReporting(envWithoutMemLimit(), memoryBudget{}, "signer")).
				To(BeNumerically(">", int64(1)<<40),
					"an unlimited runtime reports a very large limit, not zero")
		})
	})
})

// envWithoutMemLimit is the test process's environment with GOMEMLIMIT removed,
// so a value set on the runner cannot decide the outcome of a spec about
// GOMEMLIMIT.
func envWithoutMemLimit() []string {
	return filterEnv(os.Environ(), goMemLimitEnv)
}
