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
	"log/slog"
	"os"
	"path/filepath"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// The launcher's logger setup arrived with the memory-budget change and had no
// coverage. It is the wiring that makes every line applyMemoryBudget emits
// reach the configured destination, so a mis-wiring would take the whole
// memory-budget diagnostic with it -- silently, and for exactly the logfile
// deployment the change exists to fix.
var _ = Describe("installing a role's logger", func() {
	// Each spec replaces the process-global default logger, so it is restored.
	restoreLogger := func() {
		GinkgoHelper()
		orig := slog.Default()
		DeferCleanup(func() { slog.SetDefault(orig) })
	}

	It("sends a warning to the configured logfile rather than the default handler", func() {
		// The failure this catches: before the launcher called this, it ran on
		// Go's built-in handler and its warnings bypassed logfile entirely.
		restoreLogger()
		path := filepath.Join(GinkgoT().TempDir(), "ca.log")
		closeLog, err := openRoleLog(&serverConfig{LogFile: path})
		Expect(err).NotTo(HaveOccurred())

		slog.Warn("Ignoring a memory-budget setting", "detail", "memory_reserve_signer is bad")
		closeLog()

		written, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(written)).To(ContainSubstring("memory_reserve_signer is bad"),
			"the warning must land in the logfile, not on the default handler")
	})

	It("honours the configured verbosity, so the debug line can appear at all", func() {
		// The other half of the same defect: verbosity was pinned at info
		// whatever the operator set, so the line explaining why no budget was
		// divided could never be emitted.
		restoreLogger()
		path := filepath.Join(GinkgoT().TempDir(), "ca.log")
		closeLog, err := openRoleLog(&serverConfig{LogFile: path, Verbosity: 1})
		Expect(err).NotTo(HaveOccurred())

		slog.Debug("No memory budget to divide across the process tree", "reason", "no ceiling")
		closeLog()

		written, err := os.ReadFile(path)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(written)).To(ContainSubstring("No memory budget to divide"))
	})

	It("returns a usable closer when no logfile is configured", func() {
		// The closer is always non-nil so callers can defer it unconditionally;
		// returning nil here would panic the launcher on every default install.
		restoreLogger()
		closeLog, err := openRoleLog(&serverConfig{})
		Expect(err).NotTo(HaveOccurred())
		Expect(closeLog).NotTo(BeNil())
		Expect(closeLog).NotTo(Panic())
	})

	It("reports a failed close on stderr rather than into the file being closed", func() {
		// Reporting through slog would write to the very file whose close just
		// failed. Driven by closing the handle first, so the deferred Close
		// returns ErrClosed.
		restoreLogger()
		path := filepath.Join(GinkgoT().TempDir(), "ca.log")
		closeLog, err := openRoleLog(&serverConfig{LogFile: path})
		Expect(err).NotTo(HaveOccurred())

		var out syncBuffer
		previous := logCloseErrOut
		logCloseErrOut = &out
		DeferCleanup(func() { logCloseErrOut = previous })

		closeLog() // succeeds
		closeLog() // the same handle again: now ErrClosed

		Expect(out.String()).To(ContainSubstring("failed to close log file"))
	})

	It("surfaces an unopenable logfile as an error", func() {
		restoreLogger()
		// A directory where a file is wanted.
		dir := GinkgoT().TempDir()
		_, err := openRoleLog(&serverConfig{LogFile: dir})
		Expect(err).To(HaveOccurred())
	})
})
