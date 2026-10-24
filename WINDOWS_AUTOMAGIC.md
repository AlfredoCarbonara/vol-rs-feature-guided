# Windows Automagic (Research Scope)

## Supported scope

- Windows 10/11 x64.
- QEMU-produced ELF64 memory cores, including the five BCCC files named `.vmem`.
- VMware native `.vmem` with matching `.vmss` or `.vmsn` CPU metadata.
- Local Volatility kernel, service, and callback ISF repositories.
- Optional first-use exact ISF provisioning with `--download-symbols`.
- Manual `--dtb`, `--kernel-base`, `--symbols`, and `--service-symbols` overrides remain supported.

Raw captures without QEMU/VMware CPU metadata still require manual DTB/kernel-base overrides in this phase.

## Detection pipeline

1. Detect the input by ELF64 signature and construct the physical PT_LOAD layer.
2. Select a CPU-state adapter:
   - parse PT_NOTE records named `QEMU`; or
   - parse VMware `cpu` group tags `CR64` and `IDTR`.
3. Extract x86_64 CR3 and IDTR from each available vCPU state.
4. Build a candidate Windows Intel32e virtual layer with the active CR3.
5. Decode IDT gates to obtain kernel interrupt-handler addresses.
6. Search backwards on 2 MiB boundaries for an `MZ`/PE32+ AMD64 image.
7. Read the PE debug directory and extract CodeView `RSDS` database, GUID, and age.
8. Resolve the exact local ISF path from `<database>/<GUID>-<age>.json.xz`.
9. Validate the candidate with the selected ISF:
   - `NtBuildNumber` must be plausible;
   - `PsActiveProcessHead.Flink/Blink` must be canonical kernel addresses.
10. Select the service-layout ISF from the validated Windows build number and
    the architecture-specific `callbacks-x64.json` auxiliary ISF when needed.
11. Store the resolved parameters in the shared `Context` for every Windows plugin.

## VMware CPU-state layout

For VMware metadata version 2, variable-length tags contain one disk-size
field, one repeated memory-size field, two reserved bytes, and the payload.
`CR64` is an array of nine little-endian `u64` values; CR3 is element 3 and is
page-aligned by clearing its lower 12 bits. `IDTR` is decoded as a `u16` limit
followed by a `u64` base.

The current VMware reference sample resolves to:

```text
DTB/CR3    : 0x1ad000
Kernel base: 0xfffff8071c000000
PDB        : ntkrnlmp.pdb
Identifier : 89284D0CA6ACC8274B9A44BD5AF9290B-1
```

Plugin execution for this sample requires the matching ISF to be placed under
the local Windows symbol root. Rust extracts the exact PDB identity; the
optional provisioning path invokes Volatility's official `pdbconv` module to
download the matching Microsoft PDB and convert it into ISF. This one-time
network/conversion phase is excluded from Rust plugin runtime benchmarks.

The reference sample now has the validated ISF:

```text
ntkrnlmp.pdb/89284D0CA6ACC8274B9A44BD5AF9290B-1.json.xz
```

## Simple commands

```powershell
vol3.exe --file 7512_1.vmem --os windows --show-automagic --output pretty ps-list
vol3.exe --file 7512_1.vmem --os windows --show-automagic --output pretty handles
vol3.exe --file 7512_1.vmem --os windows --show-automagic --output pretty svc-scan
vol3.exe --file 7512_1.vmem --os windows --show-automagic --output pretty callbacks
```

`--show-automagic` prints DTB/CR3, kernel base, Windows build, kernel ISF, and service ISF to stderr without corrupting JSON/CSV stdout.

## Symbol resolver

The default workspace layout is:

```text
.venv-volatility/Lib/site-packages/volatility3/
├── symbols/windows/**/*.json.xz
├── framework/symbols/windows/services/*.json
└── framework/symbols/windows/callbacks-x64.json
```

Alternative repositories can be supplied with:

```text
--symbol-root <directory>
--service-symbol-root <directory>
```

Explicit file overrides retain the old behavior:

```text
--symbols <kernel-isf>
--dtb <physical-cr3>
--kernel-base <virtual-base>
svc-scan --service-symbols <service-isf>
callbacks --callback-symbols <callbacks-x64-isf>
```

If an exact kernel ISF is absent, provision it once and continue the requested
plugin automatically:

```powershell
vol3.exe --file <dump.vmem> --os windows --download-symbols ps-list
```

Subsequent executions use the cached ISF and return to the normal command:

```powershell
vol3.exe --file <dump.vmem> --os windows ps-list
```

`--pdbconv-python <python.exe>` overrides the bundled Volatility virtual
environment when another installation must perform the conversion.

## Validation result

`benchmark/automagic_equivalence.py` compares automagic mode with the previous fully-resolved manual mode. On `7512_1` through `7512_5`, all 15 plugin/dump comparisons were exact for PsList, Handles, and SvcScan.

The Rust callbacks implementation covers the same five collection sources as
Volatility 3 (notify arrays, bugcheck, bugcheck-reason, registry, and callback
pool allocations). Validation on the thesis corpus (25 BCCC dumps plus one
Windows 10 VMware dump) produced exact `Type + Callback` identities and exact
`callbacks_ncallbacks` counts on all 26 dumps. This is feature-level and
artifact-identity equivalence.

The October 2026 audit added a shared `PsLoadedModuleList` resolver and exact
per-module symbol lookup.  Against the same 26-dump corpus, normalized
`Module`, `Symbol`, and `Detail` values now also match the Python reference for
all 6,756 callback rows.  Handles now resolves File device names and Registry
Key paths; all five compared fields match across 1,279,083 rows.  SvcScan keeps
service-record `Offset` as an explicitly audited provenance field: semantic
fields match at 0.999959 mean equivalence, with five unresolved `Binary` values
and expected address differences caused by physical-pool versus VAD discovery.
The reproducible report is stored in
`benchmark/results/audit_fix_validation_final_20261012/AUDIT_RESULTS.md`.
