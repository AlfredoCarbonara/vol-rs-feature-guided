# vol3-plugins-windows

Initial Windows 10 x64 support for the Rust Volatility migration.

## Implemented milestone

`windows.pslist.PsList` enumerates `_EPROCESS` objects through:

```text
PsActiveProcessHead
  -> _LIST_ENTRY.Flink
  -> _EPROCESS.ActiveProcessLinks
  -> next process
```

Offsets are resolved from the Windows kernel ISF for `_EPROCESS` and
`_HANDLE_TABLE`. The implementation currently extracts:

- PID and parent PID;
- image file name;
- `_EPROCESS` virtual offset;
- active thread and handle counts;
- session ID and WOW64 status;
- creation and exit time.

`PsList::list_processes` is public because the future `handles` extractor will
reuse the same `_EPROCESS` enumeration.

## Context contract

The plugin currently expects the caller to prepare:

- `primary`: a Windows kernel virtual layer;
- `nt_symbols`: the name of a loaded Windows kernel ISF table;
- `kernel_virtual_offset`: the kernel virtual offset added to relative symbols;
- optionally `plugins.windows.pslist.pid`: a PID filter.

## CLI status and current boundary

The CLI can now run this plugin against real Windows ELF64 core dumps when the
matching ISF, DTB, and kernel base are supplied explicitly. It also detects an
ELF core by signature before applying extension-based VMware handling.

Windows automagic for discovering the DTB, kernel base, and matching PDB/ISF
remains the next bootstrap milestone. Until it exists, use Volatility
`windows.info.Info` to resolve those three inputs before invoking the Rust CLI.

For the tested `7512_1.vmem`, see `../../benchmark/README.md` from the workspace
root for the exact command, equivalence gate, and benchmark procedure.

Run the synthetic tests with:

```powershell
cargo test -p vol3-plugins-windows
```
