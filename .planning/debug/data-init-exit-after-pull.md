---
status: resolved
trigger: "After pulling origin/main from 19bacc7 to da42834 on Raspberry Pi, docker compose up -d --build builds beacon:2.0.1 but data-init exits 1."
created: 2026-08-14
updated: 2026-08-14
---

# Debug Session: data-init exits after latest pull

## Symptoms

**Expected:** `docker compose up -d --build` completes data initialization and starts Beacon after the fast-forward pull.

**Actual:** The image builds successfully, containers are recreated, and Compose stops with `service "data-init" didn't complete successfully: exit 1` on two consecutive attempts.

**Errors:** Pi follow-up confirms `chown: cannot read directory '/data/backups': Permission denied`. The stopped container exited 1, was not OOM-killed, and reports no Docker runtime error. The transcript also reports non-fatal kernel/cgroup memory-limit warnings for recovery, worker, and web.

**Timeline:** Began immediately after fast-forwarding Raspberry Pi checkout from commit `19bacc7` to `da42834`.

**Reproduction:** On Raspberry Pi, run `git pull`, then `docker compose up -d --build` against the existing named data volume/database.

**Evidence source:** `/Users/william/.codex/attachments/e7d5673c-e233-4707-8a77-e1415f6a9552/pasted-text.txt`

## Current Focus

bug_class: bohrbug
hypothesis: confirmed: verified-backup creation and data initialization have incompatible directory-access policies. The former creates `/data/backups` as uid 10001/mode 0700; the latter is uid 0 with only CAP_CHOWN, which cannot bypass directory read/search checks, so recursive GNU chown cannot enumerate the backup catalog.
test: completed a constrained reproduction on a fresh disposable volume: create `/data/backups` as 10001:10001 mode 0700, then run the precise data-init capability set and command.
expecting: exact stderr `chown: cannot read directory '/data/backups': Permission denied` and exit 1; a successful run would falsify the lifecycle-permission hypothesis.
next_action: diagnosis complete; run the preservation-first Pi inspection and apply the directory-only mode or ACL repair only if its results match the confirmed ordinary 10001:10001/0700 catalog state.
reasoning_checkpoint:
  hypothesis: a uid-10001/mode-0700 migration backup directory causes a CAP_CHOWN-only uid-0 process to fail recursive traversal because CAP_CHOWN grants ownership changes but not DAC read/search bypass.
  confirming_evidence:
    - `create_verified_backup` has created `backups` with `mkdir(mode=0o700)` since 85fa893c (2026-07-31), while worker services run as uid 10001.
    - `data-init` has used uid 0, `cap_drop: [ALL]`, `cap_add: [CHOWN]`, and `chown -R 10001:10001 /data` since 1e9161c3 (2026-07-17).
    - a disposable volume seeded exactly as uid 10001/mode 0700 failed with the Pi's exact error and exit status under the identical restrictions.
  falsification_test: the same constrained command succeeds against a uid-10001/mode-0700 backup directory, or Pi inspection shows no restrictive mode/ACL/attribute on `/data/backups`.
  fix_rationale: grant the initializer read/search access only to the backup directory (mode 0755 or an equivalent ACL), so its already-intended recursive chown can enumerate the directory without touching backup database contents.
  blind_spots: Pi-side `stat`, ACL, and immutable-attribute results have not yet been captured; an unusual ACL or filesystem attribute could be the immediate representation of the same traversal denial.
  candidate_causes:
    - code: `create_verified_backup` deliberately creates a uid-10001-only mode-0700 catalog.
    - config: data-init deliberately drops DAC_READ_SEARCH/DAC_OVERRIDE while relying on recursive directory enumeration.
    - data: the persisted volume contains the backup directory, whereas an empty/ordinary volume does not trigger the failure.
  and_gate: yes — this occurs only when both a restrictive persisted backup catalog exists and the initializer is restricted to CAP_CHOWN without DAC read/search; neither condition alone produces the observed failure.
tdd_checkpoint:

## Evidence

- timestamp: 2026-08-14; source: session-manager checkpoint; observation: investigation began in diagnosis-only mode; action: no product code changes authorized
- timestamp: 2026-08-14; source: supplied Compose transcript; observation: image build completes, then only data-init exits 1 twice; action: treat recovery/worker/web cgroup memory-limit warnings as non-fatal and unrelated
- timestamp: 2026-08-14; source: docker-compose.yml plus resolved Compose config; observation: data-init is root, network-isolated, read-only, has only CAP_CHOWN, mounts dashboard-data at /data, and runs only chown -R 10001:10001 /data; action: locate fault in ownership normalization or the mounted volume, not in Python startup
- timestamp: 2026-08-14; source: Git comparison 19bacc7..da42834; observation: docker-compose.yml, dashboard/Dockerfile, and dashboard/runtime_smoke.py are byte-identical (matching Git object IDs); action: reject the pull as a code-level cause of data-init behavior
- timestamp: 2026-08-14; source: disposable Docker-volume reproduction; observation: the exact constrained command exited 0 on both an empty volume and a volume containing root-owned dashboard.db, WAL, SHM, maintenance lock, and backup placeholder files, all corrected to 10001:10001; action: reject a general CAP_CHOWN/no-new-privileges/read-only incompatibility
- timestamp: 2026-08-14; source: tests; observation: complete migration suite passed (23 passed, 6 subtests) and focused Compose initializer contract passed (1 passed); action: reject packaged support-floor/migration-8 regression on supported fixtures
- timestamp: 2026-08-14; source: Pi follow-up commands; observation: data-init stderr is `chown: cannot read directory '/data/backups': Permission denied`; container exited 1, was not OOM-killed, and has no Docker runtime error; action: isolate directory traversal permissions/ACLs on the persisted backup directory and preserve all backup contents
- timestamp: 2026-08-14; source: Phase-0 recall; observation: MemPalace CLI is unavailable and `.planning/debug/knowledge-base.md` does not exist; action: no prior-resolution hypothesis candidate exists, so continue from direct evidence.
- timestamp: 2026-08-14; source: `dashboard/beacon/migrations.py:create_verified_backup`; observation: the worker-owned migration path creates `data_dir/backups` with `mkdir(mode=0o700, parents=True, exist_ok=True)` before creating verified SQLite backups; action: test this explicit mode/uid combination against data-init's CAP_CHOWN-only sandbox.
- timestamp: 2026-08-14; source: Git history; observation: the CAP_CHOWN-only recursive data initializer predates verified-backup creation (1e9161c3 on 2026-07-17 versus 85fa893c on 2026-07-31); action: classify this as a deterministic lifecycle-permission incompatibility, not a `da42834` regression.
- timestamp: 2026-08-14; source: constrained disposable Docker volume; observation: `/data/backups` seeded as `10001:10001` mode `0700` made `docker run --user 0:0 --read-only --cap-drop ALL --cap-add CHOWN --security-opt no-new-privileges:true --network none ... chown -R 10001:10001 /data` exit 1 with the exact Pi stderr `chown: cannot read directory '/data/backups': Permission denied`; action: confirm the root cause and preserve backups while restoring initializer traversal.

## Eliminated

- The non-fatal cgroup/memory-limit warnings emitted for recovery, worker, and web.
- The pulled migration-8/support-floor change: migrations execute only from worker preparation after data-init completes.
- runtime_smoke or image-build code: neither is invoked by data-init, and both its Dockerfile and smoke script are unchanged across the pull.
- A general inability of the configured data-init capability set to chown ordinary persisted SQLite-related files.

## Resolution

root_cause: confirmed AND-gate: (1) Beacon migration code creates its persistent backup catalog as uid 10001 with mode 0700, and (2) data-init runs a recursive chown as uid 0 after dropping every capability except CAP_CHOWN. CAP_CHOWN permits ownership changes but does not provide DAC directory read/search bypass, so root cannot enumerate the uid-10001-only catalog. The exact setup reproduces the Pi's `/data/backups` error; the pull merely caused data-init to be rerun against the pre-existing directory.
fix: not applied (diagnosis-only). First inspect the persisted directory read-only. If it is the expected `10001:10001 0700` directory with ordinary backup files, change only `/data/backups` to mode 0755 (or add a uid-0 `r-x` ACL) and rerun the normal CAP_CHOWN-only initializer; do not remove, replace, or restore any database/backup files.
verification: pre/post-pull initializer artifacts match exactly; ordinary data succeeds under the declared restrictions; exact uid-10001/mode-0700 backup catalog fails under the identical restrictions with the Pi's exact stderr and exit 1; migration suite 23 passed plus 6 subtests and Compose initializer contract 1 passed.
files_changed: .planning/debug/data-init-exit-after-pull.md only; the disposable Docker volume beacon-debug-data-init-20260814 was removed after verification.
