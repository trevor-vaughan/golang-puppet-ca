# Development documentation

Documentation for people working **on** OpenVox CA, as opposed to deploying it.
If you are deploying OpenVox CA, start with the [README](../../README.md) and the
user-facing [docs](../).

Start here: [`CONTRIBUTING.md`](../../CONTRIBUTING.md) for how to build, test, and
submit changes, and [`AGENTS.md`](../../AGENTS.md) for the authoritative
repository conventions (testing framework, compatibility contracts, commit
style).

## Contents

| Document | What it covers |
| --- | --- |
| [Testing](testing.md) | Unit, integration, compose, and load test suites and how to run them |
| [Storage internals](storage-internals.md) | Backend key layouts, cross-node coordination, SQL schema, and how to add a backend |
| [Locking and concurrency](locking.md) | The three locking tiers, lock names and ordering, read-path policy, and rules for new code |
| [Inventory store](inventory-store.md) | Internal design of the structured (`InventoryStore`) inventory capability, and the inventory integrity threat model |
| [Publishing container images](publishing-images.md) | The GHCR publishing workflow and one-time repository setup |
| [Cutting a release](releasing.md) | Tagging a release, what the automation publishes, release notes, and rehearsing on a fork |
