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
	"context"
	"fmt"
	"io"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/voxpupuli/openvox-ca/internal/storage"
)

// newRebuildInventoryHMACCmd builds the "rebuild-inventory-hmac" subcommand,
// which re-asserts the inventory integrity value over the inventory as it
// currently stands.
//
// It lives on the server binary rather than openvox-ca-ctl for the reason csr
// and import-ca-cert do: it must reach the *configured* backend. The failure
// this repairs is most likely on etcd, Redis and the filesystem backend, and
// openvox-ca-ctl can address only a local filesystem directory through a
// different configuration schema, so a ctl version could not repair the
// deployments that most need it.
func newRebuildInventoryHMACCmd() *cobra.Command {
	return newRebuildInventoryHMACCmdWith(func(ctx context.Context, cfg *serverConfig) (*caRuntime, error) {
		// withKeyProvider is false: rebuilding reads the inventory and the
		// inventory HMAC key, both of which live in storage. The CA signing key
		// is not involved, so this command never opens an authenticated session
		// to the key backend -- which matters because it is run by hand, on a
		// degraded CA, quite possibly by someone who is not the person trusted
		// with the signing key.
		return resolveRuntime(ctx, cfg, false)
	})
}

// newRebuildInventoryHMACCmdWith is newRebuildInventoryHMACCmd with runtime
// resolution injected, so a spec can drive backends a temp directory cannot be.
func newRebuildInventoryHMACCmdWith(resolve runtimeResolver) *cobra.Command {
	var (
		configFile      string
		caDir           string
		confirm         bool
		replicasStopped bool
	)

	cmd := &cobra.Command{
		Use:   "rebuild-inventory-hmac",
		Short: "Re-assert the inventory integrity value over the inventory as it stands",
		Long: `Recompute and store the certificate inventory's integrity value from the
inventory as it currently stands.

This is a repair of last resort for a CA that will not start, whose logs carry
"integrity check failed". While the stored value does not verify, every read
path is fail-closed: revocation fails for every subject, so credentials cannot
even be retired while the cause is investigated.

This does not verify or repair the inventory. It re-asserts integrity over
whatever the inventory now contains, so any tampering present is signed over and
becomes valid. Establish why verification failed before running it.

With no --yes-re-bless it reports the current state and changes nothing, which
is the safe way to inspect a CA that will not start.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()

			resolvedCfgFile := resolveConfigFile(configFile, "PUPPET_CA_CONFIG", "/etc/puppet-ca/config.yaml")
			cfg, err := loadServerConfig(resolvedCfgFile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("cadir") {
				cfg.CADir = caDir
			}

			// Before resolveRuntime, for the reason import-ca-cert states: every
			// failure in there is a symptom of a misresolved configuration and
			// none of those messages names the file that was read.
			//
			// To `out`, not to stderr as csr, import-ca-cert and generate do.
			// Those three reserve stdout for an artefact -- generate's
			// certificate, csr's request PEM -- so their human output has to go
			// elsewhere. This command produces no artefact: the report IS its
			// output, and an operator diagnosing a CA that will not start
			// captures it with `> report.txt` to attach to a ticket. Splitting
			// the resolved-config header onto stderr would drop from that
			// capture exactly the two lines operator-cli.md tells them to check.
			reportResolvedConfig(out, resolvedCfgFile, cfg)

			// Point slog at the server's own logfile before anything acts, so
			// the record below lands where the CA's other integrity messages do
			// rather than only in this terminal. Degrades to stderr rather than
			// failing, and never creates the file.
			closeLog := applySubcommandLogging(cfg, out, "this rebuild")
			defer closeLog()

			rt, err := resolve(ctx, cfg)
			if err != nil {
				return err
			}
			defer func() { _ = rt.Close() }()

			distributed, capabilityKnown := reportRebuildCapabilities(ctx, out, rt.Store)

			// Report before acting, and before any gate refuses: an operator
			// whose CA is down needs to see the state whatever they then decide,
			// and this is the only path that will show it to them -- every
			// ordinary read returns ErrInventoryTampered instead.
			rep, err := rt.Store.InventoryIntegrityReport(ctx)
			if err != nil {
				return fmt.Errorf("reading the inventory integrity state: %w", err)
			}
			reportInventoryIntegrity(out, rep)

			if rep.LegacyUndecomposed {
				// Refuse rather than report: this store's entries have not been
				// decomposed yet, so the report above describes an inventory
				// that is not the one in use, and rebuilding would write an
				// empty chain head over the whole-blob MAC that is the only
				// thing able to validate the real inventory. The server
				// decomposes on start; this command deliberately does not,
				// because reporting must not write.
				// Deliberately not "start the server and re-run": decomposition
				// verifies the legacy blob against its own stored MAC before it
				// commits, and returns ErrInventoryTampered on a mismatch. So
				// starting the server fixes the benign case (upgraded, never
				// restarted) and fails the very case an operator with a failing
				// integrity check is in. Saying otherwise sends them in a
				// circle. The server's own refusal names the remedy for the
				// other sub-case, so point at it rather than restating it.
				return fmt.Errorf("this store still holds an undecomposed legacy inventory, so the entry " +
					"count above describes the decomposed rows rather than the inventory in use. Rebuilding " +
					"now would replace the only value that can validate the legacy blob, and this command " +
					"cannot repair a pre-decomposition inventory. Start the server: if the legacy blob still " +
					"verifies it decomposes and starts, after which this command applies normally. If it does " +
					"not, the server refuses with an integrity error naming the stored legacy value to remove " +
					"in order to acknowledge a lost baseline")
			}

			if rep.KeyState == storage.HMACKeyAbsent {
				// RebuildInventoryHMAC is a no-op with no key, so a "success"
				// here would be a lie: nothing would be written and the CA would
				// fail in exactly the same way on the next start.
				// Which advice is right depends on whether a value is still
				// stored. With none, this really is a CA that never initialised
				// integrity and starting it establishes a baseline. With one,
				// saying that sends the operator into a loop: the next start
				// mints a key, computes under it, disagrees with the retained
				// head, and refuses with a tampering error for something the CA
				// itself just did.
				if rep.StoredHead != nil {
					return fmt.Errorf("no inventory HMAC key is stored, but an integrity value is. " +
						"No key can reproduce that value, so it cannot be verified or rebuilt, and starting " +
						"the server would mint a key and then refuse with an integrity error. Acknowledge the " +
						"lost baseline by removing the stored integrity value, then start the server, which " +
						"will establish a new one")
				}
				return fmt.Errorf("no inventory HMAC key is stored, so there is no integrity value to rebuild. " +
					"This CA has never initialised inventory integrity; starting the server will establish a baseline")
			}

			if rep.Verifies {
				_, _ = fmt.Fprintln(out, "\nThe stored integrity value verifies. Nothing to do.")
				return nil
			}

			if rep.StoredHead == nil {
				// No baseline was ever written. That is not a mismatch and not
				// tampering: verifyInventoryHMACLocked treats a missing value as
				// first run, logs "initializing integrity baseline" and writes
				// one, so the server starts normally. Deleting the stored value
				// is a documented operator gesture for acknowledging a lost
				// baseline (docs/development/inventory-store.md), so an operator
				// who has just done it, or who restored a store without the
				// blob, arrives here on a healthy CA. Routing them into the
				// re-bless refusal would answer that with a warning about
				// tampering being signed over, which is alarming and false.
				// Say what that baseline will be, and record it. The next start
				// takes verifyInventoryHMACLocked's fs.ErrNotExist path and
				// writes a head over the inventory exactly as it stands, without
				// verifying it -- the same act --yes-re-bless gates behind an
				// explicit acknowledgement, arrived at by a different route. An
				// operator reaching this during an integrity investigation
				// should be told that, and it should be as findable afterwards
				// as the re-blessing is.
				_, _ = fmt.Fprintln(out, "\nNo integrity value is stored, so there is nothing to rebuild.\n"+
					"The next start will establish a baseline over the inventory as it now stands,\n"+
					"without verifying it. If you are investigating an integrity failure, inspect the\n"+
					"inventory itself before starting the server -- the report above summarises it\n"+
					"but does not list it, and reads are not fail-closed while no value is stored.")
				slog.Warn("No inventory integrity value is stored; the next start will baseline the inventory as it stands",
					"scheme", rep.Scheme,
					"entries", rep.Entries,
					"key_state", rep.KeyState.String(),
					"computed", fullHead(rep.ComputedHead))
				return nil
			}

			if !confirm {
				return fmt.Errorf("refusing to rebuild without --yes-re-bless: this re-asserts integrity over the " +
					"inventory above rather than verifying it, so any tampering it contains would be signed over " +
					"and become valid. Establish why verification failed first, then re-run with --yes-re-bless")
			}

			// The single-instance rule is enforced by an flock the instance lock
			// takes, and AcquireInstanceLock deliberately does not enforce it on
			// backends that coordinate across hosts -- those support many
			// replicas, so there is nothing to refuse. That leaves this command
			// with no way to tell whether a replica is appending right now,
			// which is precisely the state in which a rebuild writes a fresh
			// incorrect value: the head is computed from a snapshot, and an
			// append landing between the read and the write is not detected.
			//
			// So on those backends the precondition cannot be enforced and is
			// required as an assertion instead. An undetermined capability takes
			// the same path: if the probe could not answer, the instance lock
			// will not enforce either, and the honest reading is that this
			// command does not know the store is quiet.
			if (distributed || !capabilityKnown) && !replicasStopped {
				why := "this backend coordinates locks across hosts, so the single-instance check does not apply to it"
				if !capabilityKnown {
					why = "whether this backend coordinates locks across hosts could not be determined, " +
						"so the single-instance check will not be enforced"
				}
				return fmt.Errorf("refusing to rebuild: %s. A replica appending during the rebuild would leave a "+
					"fresh incorrect value, and this command cannot detect one. Stop every replica, then re-run "+
					"with --replicas-stopped to confirm you have", why)
			}

			// Real enforcement where it exists: on filesystem and SQLite this
			// takes an flock and refuses while a server holds the store, naming
			// the holder. Reuse the capability answer the report above paid for,
			// omitting it when undetermined so that case keeps its one policy.
			var lockOpts []storage.InstanceLockOption
			if capabilityKnown {
				lockOpts = append(lockOpts, storage.WithKnownDistributedLocking(distributed))
			}
			enforced, err := holdInstanceLock(ctx, rt, lockOpts...)
			if err != nil {
				return err
			}
			if !enforced && !replicasStopped {
				// The lock was taken and excludes nobody. AcquireInstanceLock
				// does that whenever it has nothing to enforce -- no
				// InstanceLocker at all, or a lock set that is unavailable (an
				// in-memory SQLite store, a platform without flock(2), a
				// read-only mount) -- and says so only through slog, which
				// applySubcommandLogging has by now pointed at the server's
				// logfile rather than at this terminal. Without this the
				// operator is told the command refuses beside a live server and
				// then it silently does not, on the one command whose
				// correctness depends on nothing appending underneath it.
				return fmt.Errorf("refusing to rebuild: this store offers no lock that would exclude a second " +
					"instance, so it cannot be shown to be quiet. Stop every process writing to it, then " +
					"re-run with --replicas-stopped to confirm you have")
			}

			// Captured before the write, because after it the old value is gone
			// from the store and this is the only place it survives.
			previous := fullHead(rep.StoredHead)

			if err := rt.Store.RebuildInventoryHMAC(ctx); err != nil {
				// RebuildInventoryHMAC is two writes in the wrong-length-key
				// state: EnsureHMACKey persists a fresh key, then the head is
				// written. A failure between them leaves a new key beside the
				// old head, so this return is a mutating path too and needs the
				// same record the successful one gets.
				slog.Warn("Inventory integrity rebuild failed; the store may already have been changed",
					"scheme", rep.Scheme,
					"entries", rep.Entries,
					"key_state", rep.KeyState.String(),
					"previous", previous,
					"error", err.Error())
				if rep.KeyState == storage.HMACKeyWrongLength {
					return fmt.Errorf("rebuilding the inventory integrity value: %w\n\n"+
						"A new inventory HMAC key may already have been minted before this failed. "+
						"Re-running with --yes-re-bless completes the repair", err)
				}
				return fmt.Errorf("rebuilding the inventory integrity value: %w", err)
			}

			// Logged here rather than after the verification below, because the
			// store has already been mutated at this point and the paths that
			// return between here and there are exactly the ones an auditor most
			// needs to find: the re-read failing, the rebuilt value not
			// verifying ("something is writing to this store"), or the process
			// being killed. A record emitted only on success is not an audit
			// trail of a change, it is a record of the happy path.
			slog.Warn("Inventory integrity re-asserted by rebuild-inventory-hmac; "+
				"the inventory as it stood is now treated as authentic",
				"scheme", rep.Scheme,
				"entries", rep.Entries,
				"key_state", rep.KeyState.String(),
				"previous", previous,
				"replicas_stopped_asserted", replicasStopped)

			// Re-read rather than assuming. The rebuild is the whole point of
			// the command, and reporting a computed expectation as though it
			// were the stored result would hide exactly the failure an operator
			// is here to resolve.
			after, err := rt.Store.InventoryIntegrityReport(ctx)
			if err != nil {
				return fmt.Errorf("re-reading the inventory integrity state after the rebuild: %w", err)
			}
			if !after.Verifies {
				return fmt.Errorf("the integrity value still does not verify after rebuilding: stored %s, computed %s. "+
					"Something is writing to this store, or the backend did not persist the new value",
					headFingerprint(after.StoredHead, "(none stored)"),
					headFingerprint(after.ComputedHead, "(not computed)"))
			}

			// A durable record, because this is the one command that can make
			// tampered inventory content authentic. Warn rather than Info: an
			// operator asking after the fact whether a CA's integrity baseline
			// was ever reset needs to find this without knowing to look, and
			// afterwards nothing else distinguishes a re-blessed store from a
			// healthy one. It carries both heads so the answer to "what was
			// signed over" survives the terminal that ran it.
			// The outcome, separately from the mutation above. Full hex rather
			// than the terminal's fingerprint: a log line has no width to save,
			// and eight of thirty-two bytes is not the answer to "what was
			// signed over".
			slog.Warn("Inventory integrity rebuild verified",
				"scheme", after.Scheme,
				"entries", after.Entries,
				"key_state", after.KeyState.String(),
				"previous", previous,
				"new", fullHead(after.StoredHead))

			_, _ = fmt.Fprintf(out, "\nRebuilt. The integrity value now covers %d %s: %s\n",
				after.Entries, pluralEntries(after.Entries), headFingerprint(after.StoredHead, "(none stored)"))
			_, _ = fmt.Fprintln(out, "Integrity has been re-asserted, not verified. The server should now start.")
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&configFile, "config", "c", "", "Path to the server configuration file")
	f.StringVar(&caDir, "cadir", "", "CA directory (overrides the configured cadir)")
	f.BoolVar(&confirm, "yes-re-bless", false,
		"Confirm that integrity should be re-asserted over the inventory as it stands, tampering included")
	f.BoolVar(&replicasStopped, "replicas-stopped", false,
		"Assert that every replica writing to this store has been stopped (required where that cannot be checked)")

	return cmd
}

// reportInventoryIntegrity prints the integrity state an operator needs in
// order to decide whether re-asserting is the right response.
//
// It reports the scheme because a mismatch also fires when a store is served
// under a different scheme than the value was written with, which is a
// different problem with a different fix; the entry count and both head values
// because they are what the new value would cover; and it stops there. It does
// not claim to say which entry diverged: only one head is persisted, so nothing
// records what any prefix should have hashed to.
func reportInventoryIntegrity(w io.Writer, rep storage.InventoryIntegrityReport) {
	_, _ = fmt.Fprintf(w, "\nInventory integrity\n")
	_, _ = fmt.Fprintf(w, "  scheme:        %s\n", rep.Scheme)
	_, _ = fmt.Fprintf(w, "  entries:       %d\n", rep.Entries)
	if rep.UnparseableLines > 0 {
		// The blob scheme MACs the whole blob, so these are covered by the value
		// a rebuild would re-assert while being absent from the count above. An
		// operator being asked to bless a blob has to be told it holds content
		// the count does not describe.
		_, _ = fmt.Fprintf(w, "  unparseable:   %d line(s) the entry count does not describe,\n"+
			"                 but which the integrity value covers\n", rep.UnparseableLines)
	}
	_, _ = fmt.Fprintf(w, "  HMAC key:      %s\n", rep.KeyState)
	_, _ = fmt.Fprintf(w, "  stored value:  %s\n", storedFingerprint(rep.StoredHead))
	_, _ = fmt.Fprintf(w, "  computed:      %s\n", headFingerprint(rep.ComputedHead, "(not computed)"))

	switch {
	case rep.KeyState == storage.HMACKeyAbsent:
		_, _ = fmt.Fprintf(w, "  verifies:      no key stored, so nothing can be computed\n")
	case rep.KeyState == storage.HMACKeyWrongLength:
		_, _ = fmt.Fprintf(w, "  verifies:      no -- the stored key is not usable\n")
		_, _ = fmt.Fprintf(w, "\nThe stored HMAC key is the wrong length, so every existing value was computed\n"+
			"under a key that no longer exists and none of them can be reproduced. Rebuilding\n"+
			"will mint a new key as well as a new value.\n")
	case rep.Verifies:
		_, _ = fmt.Fprintf(w, "  verifies:      yes\n")
	case rep.StoredHead == nil:
		// Ahead of the default, because a bare "NO" reads as a mismatch and
		// this is not one: nothing has been stored to disagree with.
		_, _ = fmt.Fprintf(w, "  verifies:      no baseline stored yet, which is not a mismatch\n")
	default:
		_, _ = fmt.Fprintf(w, "  verifies:      NO\n")
		// The caveat belongs beside the verdict, not only in the documentation:
		// this report takes no store-wide lock and reads the inventory and the
		// stored value separately, so a NO read against a running CA can be a
		// torn read rather than a real mismatch.
		_, _ = fmt.Fprintf(w, "                 (if the server is running, re-check with it stopped:\n"+
			"                 this report is two reads and takes no store-wide lock)\n")
	}
}

// storedFingerprint renders the stored column, which has three states where the
// computed column has two: absent, present-but-empty, and a real value. A
// zero-length blob comes back from Get with a nil error, so it is stored — and
// rendering it as "(none stored)" put "no value is stored" directly above
// "verifies: NO", which is a contradiction in exactly the torn-write state this
// command exists to repair.
func storedFingerprint(head []byte) string {
	if head != nil && len(head) == 0 {
		return "(stored, but empty)"
	}
	return headFingerprint(head, "(none stored)")
}

// headFingerprint renders an integrity value for an operator to compare by eye.
// Truncated because the comparison it supports is "did this change", and a full
// 32-byte hex string is harder to compare at a glance, not easier.
//
// absent names what a nil value means for this column, because the two columns
// do not mean the same thing by it: no value has been stored, versus none could
// be computed (which is every unusable-key case, since InventoryIntegrityReport
// computes only under a usable key). Rendering both as "(none stored)" told an
// operator in the wrong-length-key state -- a headline case for this command --
// that a value they never asked storage for was missing from it.
func headFingerprint(head []byte, absent string) string {
	switch {
	case len(head) == 0:
		// nil and empty are one case on purpose. computeInventoryHMAC folds a
		// chain from `var head []byte` and returns it unchanged over an empty
		// structured inventory, so "computed but empty" arrives here as nil and
		// cannot be told from "not computed" by inspecting the slice.
		return absent
	case len(head) <= 8:
		return fmt.Sprintf("%x", head)
	default:
		return fmt.Sprintf("%x…", head[:8])
	}
}

// reportRebuildCapabilities states what this backend coordinates and what a
// missing capability costs *this* command.
//
// It exists rather than reusing reportBackendCapabilities because that
// function's wording is generate's: its green branch says "safe to run
// alongside a live server" and its warning branch names a duplicate
// certificate. Both are about minting. On a distributed backend this command
// goes on to refuse unless --replicas-stopped is given, so the shared green
// line would have reassured the operator, six lines above that refusal, that
// the state they are being asked to assert away is fine -- talking them past
// the one guard rail standing in for a precondition nothing can enforce.
func reportRebuildCapabilities(ctx context.Context, w io.Writer,
	store *storage.StorageService,
) (distributed, known bool) {
	locking, atomicInventory, lockErr := probeBackendCapabilities(ctx, store)

	if lockErr != nil {
		_, _ = fmt.Fprintf(w, "Warning: could not determine whether this backend coordinates locks "+
			"across processes: %v\n"+
			"  Treating that as \"not known to be quiet\": the single-instance check will not be\n"+
			"  enforced either, so --replicas-stopped is required.\n", lockErr)
		return locking, false
	}

	if locking {
		// Deliberately not a green light. Coordination across hosts is exactly
		// why the single-instance rule does not apply here, which is exactly why
		// this command cannot tell whether a replica is writing.
		_, _ = fmt.Fprintf(w, "Backend coordinates locks across hosts, so it supports many replicas.\n"+
			"  This command cannot detect one. An append landing during the rebuild would leave\n"+
			"  a fresh incorrect integrity value, so every replica must be stopped first.\n")
		return locking, true
	}

	// Deliberately not "refuses to run beside a live server". Two ways that
	// would be false. Reporting never takes the instance lock at all -- which is
	// the point of report-only mode, and what the documentation offers as the
	// safe way to inspect a running CA. And even on the acting path the refusal
	// is conditional: AcquireInstanceLock returns a no-op with a nil error when
	// the backend offers no store-wide lock, or when one is unavailable
	// (in-memory SQLite, a platform without flock(2), a read-only mount), and it
	// says so only through slog, which by then points at the server's logfile
	// rather than at the operator's terminal.
	_, _ = fmt.Fprintf(w, "Backend does not coordinate locks across hosts "+
		"(atomic inventory append: %t), so exactly one\n"+
		"  instance is supported. Rebuilding refuses while a server holds the store, where the\n"+
		"  store offers a lock to hold; reporting never takes it.\n",
		atomicInventory)
	return locking, true
}

// fullHead renders an integrity value for a log record, where there is no width
// to save and a truncated value cannot answer the question the record is kept
// to answer. Distinguishes absent from present without borrowing the terminal
// report's "(none stored)" wording, which would also swallow the empty-chain
// case.
func fullHead(head []byte) string {
	if len(head) == 0 {
		return "none"
	}
	return fmt.Sprintf("%x", head)
}

// pluralEntries keeps the summary line readable for a one-entry inventory.
func pluralEntries(n int) string {
	if n == 1 {
		return "entry"
	}
	return "entries"
}
