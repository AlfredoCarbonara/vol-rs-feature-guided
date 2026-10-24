# Windows Malfind (Rust)

The Windows `malfind` command reads active processes from PsList, each process's
`VadRoot` tree from the matching kernel ISF, the process page tables, and
`MmProtectToValue`. It applies Volatility 3's executable and writable or
executable and dirty page conditions, private memory and tag checks, and the
nonempty region check. `CommitCharge` is read from the ISF-defined VAD flags
bitfield. The command reports one row per suspicious VAD. The comparison script
also reports the sum of `CommitCharge` across emitted rows. The CIC-MalMem paper
describes its `commitCharge` feature as a total, but the exact dataset creation
script should still be checked before asserting feature identity.

Build:

```powershell
cd 'C:\Users\ASUS\Documents\T Gua\RUSTVOL3'
cargo build --release -p vol3-cli
```

Run on a VMware image with metadata sidecar in the same directory:

```powershell
.\target\release\vol3.exe --file 'D:\Memory Dump Thesis\Windows 10 x64-0fabb307.vmem' --os windows --output json malfind
```

Add `--pid 5192` after `malfind` to select one process. `--output csv` is also
supported. The installed Python reference is:

```powershell
cd 'C:\Users\ASUS\Documents\T Gua'
.\.venv-volatility\Scripts\vol.exe --cache-path '.\benchmark\volatility-cache' -q -f 'D:\Memory Dump Thesis\Windows 10 x64-0fabb307.vmem' -r json windows.malware.malfind
```

Run the artifact comparison:

```powershell
python benchmark\verify_malfind.py 'D:\Memory Dump Thesis\Windows 10 x64-0fabb307.vmem'
```

Matching kernel ISF remains required. An image whose PDB identity has no local
ISF cannot be interpreted accurately; automatic detection alone cannot supply
the structure offsets.

Current verification covers one Windows 10 VMware dump (build 19045): three
Python rows and three Rust rows matched on all twelve reported fields after
normalizing hexadecimal addresses. The PID 5192 subset matched on two rows.
Windows 11 and the BCCC dumps need separate validation. The `Disasm` JSON
column currently mirrors the installed Python renderer's quoted byte-string
fallback; it is not an instruction-by-instruction disassembler.
