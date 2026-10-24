//! Volatility3 Rust CLI

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use log::info;

use vol3_core::error::Vol3Result;
use vol3_framework::context::Context;
use vol3_framework::module::{Column, Module, ModuleRegistry};
use vol3_framework::windows_automagic::{
    discover_kernel_pe, discover_windows_kernel, extract_pdb_identity, qemu_cpu_states,
    PdbIdentity, WindowsCpuState,
};
use vol3_layers::intel::Intel32e;
use vol3_layers::physical::{FileLayer, StreamingFileLayer};
use vol3_layers::traits::DataLayer;
use vol3_layers::vmware::VmwareMetadata;
use vol3_layers::{Elf64Layer, VmwareLayer};
use vol3_plugins_linux::register_linux_plugins;
use vol3_plugins_windows::register_windows_plugins; //windows plugins
use vol3_renderers::{CsvRenderer, JsonRenderer};
use vol3_symbols::IntermediateSymbolTable;

/// Output format
#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Csv,
    Json,
    Jsonl,
    Pretty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum TargetOs {
    Linux,
    Windows,
}

fn parse_address(value: &str) -> Result<u64, String> {
    let value = value.trim();
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).map_err(|error| error.to_string())
    } else {
        value.parse::<u64>().map_err(|error| error.to_string())
    }
}

fn canonicalize_x64_address(value: u64) -> u64 {
    const LOW_48_MASK: u64 = 0x0000_ffff_ffff_ffff;
    const SIGN_BIT_48: u64 = 1 << 47;
    if value <= LOW_48_MASK && value & SIGN_BIT_48 != 0 {
        value | !LOW_48_MASK
    } else {
        value
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum RecoverFsCompressionFormat {
    Gz,
    Bz2,
    Xz,
}

impl RecoverFsCompressionFormat {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gz => "gz",
            Self::Bz2 => "bz2",
            Self::Xz => "xz",
        }
    }
}

/// Volatility3 Rust - Memory forensics framework
#[derive(Parser)]
#[command(name = "vol3")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Memory dump file
    #[arg(short, long)]
    file: PathBuf,

    /// Target operating system
    #[arg(long, value_enum, default_value_t = TargetOs::Linux)]
    os: TargetOs,

    /// Windows page-table base (DTB/CR3), in decimal or 0x-prefixed hex
    #[arg(long, value_parser = parse_address)]
    dtb: Option<u64>,

    /// Windows kernel virtual base, in decimal or 0x-prefixed hex
    #[arg(long, value_parser = parse_address)]
    kernel_base: Option<u64>,

    /// Symbol file (ISF JSON/XZ)
    #[arg(short, long)]
    symbols: Option<PathBuf>,

    /// Root directory searched recursively for Windows kernel ISF files
    #[arg(long)]
    symbol_root: Option<PathBuf>,

    /// Root directory containing Volatility Windows service ISF files
    #[arg(long)]
    service_symbol_root: Option<PathBuf>,

    /// Output format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Csv)]
    output: OutputFormat,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Directory for plugin artifacts (e.g. recoverfs tar output)
    #[arg(long)]
    output_dir: Option<PathBuf>,

    /// Directory used for Vol3 Rust caches (e.g. decompressed ISF cache)
    #[arg(long)]
    cache_path: Option<PathBuf>,

    /// Clear Vol3 Rust cache entries before loading symbols
    #[arg(long)]
    clear_cache: bool,

    /// Print the resolved Windows automagic parameters to stderr
    #[arg(long)]
    show_automagic: bool,

    /// Plugin to run
    #[command(subcommand)]
    plugin: PluginCommand,
}

#[derive(Subcommand)]
enum PluginCommand {
    // === Core process plugins ===
    /// List all processes
    PsList {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// List process handles (Windows)
    Handles {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
        /// Filter by object type (for example Event)
        #[arg(long = "type")]
        object_type: Option<String>,
    },
    /// Scan Windows service records
    SvcScan {
        /// Volatility services ISF matching the Windows build
        #[arg(long)]
        service_symbols: Option<PathBuf>,
    },
    /// List Windows kernel callbacks
    Callbacks {
        /// Volatility callbacks-x64 ISF (normally resolved automatically)
        #[arg(long)]
        callback_symbols: Option<PathBuf>,
    },
    /// Scan for processes
    PsScan,
    /// Show process tree
    PsTree,
    /// List processes with command line arguments
    PsAux {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// List kernel threads
    Kthreads,
    /// Show call stacks for processes
    PsCallstack {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// List processes from PID hash table
    PidHashTable,
    /// List processes being ptraced
    Ptrace,

    // === Module plugins ===
    /// List kernel modules
    Lsmod,
    /// Find hidden kernel modules
    HiddenModules,
    /// Compare module list to sysfs
    CheckModules,
    /// Cross-view module analysis
    Modxview,
    /// Extract a kernel module
    ModuleExtract {
        /// Module name to extract
        #[arg(long)]
        module: Option<String>,
        /// Output directory
        #[arg(long)]
        dump_dir: Option<String>,
    },

    // === File system plugins ===
    /// List mount points
    MountInfo,
    /// List files from page cache
    #[command(name = "pagecache-files")]
    PageCacheFiles {
        /// Filter by file type (REG, DIR, LNK, etc.)
        #[arg(long, name = "type")]
        file_type: Option<String>,
        /// Find specific file path
        #[arg(long)]
        find: Option<String>,
    },
    /// Recover cached filesystem data
    #[command(name = "recoverfs")]
    RecoverFs {
        /// Extract only files from tmpfs file systems
        #[arg(long)]
        tmpfs_only: bool,
        /// Compression format for recovered tar archive
        #[arg(long, value_enum, default_value_t = RecoverFsCompressionFormat::Gz)]
        compression_format: RecoverFsCompressionFormat,
    },
    /// List open files
    Lsof {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// List ELF files mapped in process memory
    Elfs {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// List libraries loaded by processes
    LibraryList {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },

    // === Memory plugins ===
    /// List memory maps (proc/maps)
    Maps {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Show /proc information
    Proc {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Find potentially injected code (Linux or Windows)
    Malfind {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Scan VMAs with regex
    VmaRegexScan {
        /// Regex pattern
        #[arg(long)]
        pattern: Option<String>,
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Scan VMAs with YARA rules
    VmaYaraScan {
        /// YARA rules file
        #[arg(long)]
        yara_file: Option<String>,
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },

    // === Network plugins ===
    /// List socket statistics
    Sockstat {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// Scan for sockets
    Sockscan,
    /// List netfilter hooks
    Netfilter,
    /// List IP addresses
    #[command(name = "ip-addr")]
    IpAddr,
    /// List network links
    #[command(name = "ip-link")]
    IpLink,
    /// Check for AF info hooks
    CheckAfinfo,

    // === Process info plugins ===
    /// List environment variables
    Envars {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },
    /// List process capabilities
    Capabilities {
        /// Filter by PID
        #[arg(long)]
        pids: Option<Vec<u32>>,
    },
    /// List bash history
    Bash {
        /// Filter by PID
        #[arg(long)]
        pid: Option<u32>,
    },

    // === System info plugins ===
    /// List I/O memory regions
    Iomem,
    /// Show system boot time
    Boottime,
    /// Read kernel log buffer
    Kmsg,
    /// List kernel symbols (kallsyms)
    Kallsyms,
    /// Show VMCOREINFO
    Vmcoreinfo,

    // === Security/malware plugins ===
    /// Check shared credentials
    CheckCreds,
    /// Check IDT for hooks
    CheckIdt,
    /// Check syscall table
    CheckSyscall,
    /// List keyboard notifiers
    KeyboardNotifiers,
    /// Check TTY for hooks
    TtyCheck,
    /// List eBPF programs
    Ebpf,

    /// List plugins
    #[command(name = "list")]
    ListPlugins,
}

fn main() -> Vol3Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    if cli.verbose {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    } else {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    }

    // Register plugins
    let mut registry = ModuleRegistry::new();
    register_linux_plugins(&mut registry);
    register_windows_plugins(&mut registry);

    // Handle list plugins
    if matches!(cli.plugin, PluginCommand::ListPlugins) {
        println!("Available plugins:");
        for module in registry.modules() {
            println!("  {} - {}", module.name(), module.description());
        }
        return Ok(());
    }

    // Create context
    let context = setup_context(&cli)?;
    if cli.show_automagic && cli.os == TargetOs::Windows {
        let dtb = context.config_get_int("automagic.windows.dtb").unwrap_or(0) as u64;
        let kernel_base = context
            .config_get_int("automagic.windows.kernel_base")
            .unwrap_or(0) as u64;
        let build = context.config_get_int("windows.build_number").unwrap_or(0);
        let symbols = context
            .config_get_string("automagic.windows.kernel_symbols")
            .unwrap_or_else(|| "<unknown>".to_string());
        eprintln!("Windows automagic:");
        eprintln!("  DTB/CR3       : {dtb:#x}");
        eprintln!("  Kernel base   : {kernel_base:#x}");
        eprintln!("  Windows build : {build}");
        eprintln!("  Kernel ISF    : {symbols}");
        if let Some(pdb) = context.config_get_string("automagic.windows.pdb_identity") {
            eprintln!("  Kernel PDB    : {pdb}");
        }
        if let Some(service_symbols) =
            context.config_get_string("automagic.windows.service_symbols")
        {
            eprintln!("  Service ISF   : {service_symbols}");
        }
        if let Some(callback_symbols) =
            context.config_get_string("automagic.windows.callback_symbols")
        {
            eprintln!("  Callback ISF  : {callback_symbols}");
        }
    }

    // Get and run plugin
    let plugin_name = match &cli.plugin {
        // Core process
        PluginCommand::PsList { .. } if cli.os == TargetOs::Windows => "windows.pslist.PsList",
        PluginCommand::PsList { .. } => "linux.pslist.PsList",
        PluginCommand::Handles { .. } => "windows.handles.Handles",
        PluginCommand::SvcScan { .. } => "windows.svcscan.SvcScan",
        PluginCommand::Callbacks { .. } => "windows.callbacks.Callbacks",
        PluginCommand::PsScan => "linux.psscan.PsScan",
        PluginCommand::PsTree => "linux.pstree.PsTree",
        PluginCommand::PsAux { .. } => "linux.psaux.PsAux",
        PluginCommand::Kthreads => "linux.kthreads.Kthreads",
        PluginCommand::PsCallstack { .. } => "linux.pscallstack.PsCallStack",
        PluginCommand::PidHashTable => "linux.pidhashtable.PidHashTable",
        PluginCommand::Ptrace => "linux.ptrace.Ptrace",

        // Module
        PluginCommand::Lsmod => "linux.lsmod.Lsmod",
        PluginCommand::HiddenModules => "linux.hidden_modules.HiddenModules",
        PluginCommand::CheckModules => "linux.check_modules.CheckModules",
        PluginCommand::Modxview => "linux.modxview.Modxview",
        PluginCommand::ModuleExtract { .. } => "linux.module_extract.ModuleExtract",

        // File system
        PluginCommand::MountInfo => "linux.mountinfo.MountInfo",
        PluginCommand::PageCacheFiles { .. } => "linux.pagecache.Files",
        PluginCommand::RecoverFs { .. } => "linux.pagecache.RecoverFs",
        PluginCommand::Lsof { .. } => "linux.lsof.Lsof",
        PluginCommand::Elfs { .. } => "linux.elfs.Elfs",
        PluginCommand::LibraryList { .. } => "linux.library_list.LibraryList",

        // Memory
        PluginCommand::Maps { .. } => "linux.proc.Maps",
        PluginCommand::Proc { .. } => "linux.proc.Proc",
        PluginCommand::Malfind { .. } if cli.os == TargetOs::Windows => "windows.malware.malfind.Malfind",
        PluginCommand::Malfind { .. } => "linux.malfind.Malfind",
        PluginCommand::VmaRegexScan { .. } => "linux.vmaregexscan.VmaRegexScan",
        PluginCommand::VmaYaraScan { .. } => "linux.vmayarascan.VmaYaraScan",

        // Network
        PluginCommand::Sockstat { .. } => "linux.sockstat.Sockstat",
        PluginCommand::Sockscan => "linux.sockscan.Sockscan",
        PluginCommand::Netfilter => "linux.netfilter.Netfilter",
        PluginCommand::IpAddr => "linux.ip.IpAddr",
        PluginCommand::IpLink => "linux.ip.IpLink",
        PluginCommand::CheckAfinfo => "linux.check_afinfo.CheckAfinfo",

        // Process info
        PluginCommand::Envars { .. } => "linux.envars.Envars",
        PluginCommand::Capabilities { .. } => "linux.capabilities.Capabilities",
        PluginCommand::Bash { .. } => "linux.bash.Bash",

        // System info
        PluginCommand::Iomem => "linux.iomem.Iomem",
        PluginCommand::Boottime => "linux.boottime.Boottime",
        PluginCommand::Kmsg => "linux.kmsg.Kmsg",
        PluginCommand::Kallsyms => "linux.kallsyms.Kallsyms",
        PluginCommand::Vmcoreinfo => "linux.vmcoreinfo.VmcoreInfo",

        // Security/malware
        PluginCommand::CheckCreds => "linux.check_creds.CheckCreds",
        PluginCommand::CheckIdt => "linux.check_idt.Check_idt",
        PluginCommand::CheckSyscall => "linux.check_syscall.CheckSyscall",
        PluginCommand::KeyboardNotifiers => "linux.keyboard_notifiers.KeyboardNotifiers",
        PluginCommand::TtyCheck => "linux.tty_check.TtyCheck",
        PluginCommand::Ebpf => "linux.ebpf.Ebpf",

        PluginCommand::ListPlugins => unreachable!(),
    };

    let module = registry.get(plugin_name).ok_or_else(|| {
        vol3_core::error::Vol3Error::Plugin(vol3_core::error::PluginError::NotFound(
            plugin_name.to_string(),
        ))
    })?;

    // Set plugin-specific config
    if let PluginCommand::PsList { pid } = &cli.plugin {
        if let Some(pid) = pid {
            let key = if cli.os == TargetOs::Windows {
                "plugins.windows.pslist.pid"
            } else {
                "plugins.pslist.pid"
            };
            context.config_set(key, *pid as i64);
        }
    }
    if let PluginCommand::Handles { pid, object_type } = &cli.plugin {
        if let Some(pid) = pid {
            context.config_set("plugins.windows.handles.pid", *pid as i64);
        }
        if let Some(object_type) = object_type {
            context.config_set("plugins.windows.handles.type", object_type.clone());
        }
    }
    if let PluginCommand::Malfind { pid } = &cli.plugin {
        if let Some(pid) = pid {
            let key = if cli.os == TargetOs::Windows {
                "plugins.windows.malfind.pid"
            } else {
                "plugins.malfind.pid"
            };
            context.config_set(key, *pid as i64);
        }
    }
    if let PluginCommand::SvcScan { service_symbols } = &cli.plugin {
        if let Some(service_symbols) = service_symbols {
            context.config_set(
                "plugins.windows.svcscan.service_symbols",
                service_symbols.to_string_lossy().to_string(),
            );
        }
    }
    if let PluginCommand::Callbacks { callback_symbols } = &cli.plugin {
        if let Some(callback_symbols) = callback_symbols {
            context.config_set(
                "plugins.windows.callbacks.callback_symbols",
                callback_symbols.to_string_lossy().to_string(),
            );
        }
    }
    if let PluginCommand::PsAux { pid } = &cli.plugin {
        if let Some(pid) = pid {
            context.config_set("plugins.psaux.pid", *pid as i64);
        }
    }
    if let PluginCommand::PageCacheFiles { file_type, find } = &cli.plugin {
        if let Some(t) = file_type {
            context.config_set("plugins.pagecache.type", t.clone());
        }
        if let Some(p) = find {
            context.config_set("plugins.pagecache.find", p.clone());
        }
    }
    if let PluginCommand::RecoverFs {
        tmpfs_only,
        compression_format,
    } = &cli.plugin
    {
        context.config_set("plugins.recoverfs.tmpfs_only", *tmpfs_only);
        context.config_set(
            "plugins.recoverfs.compression_format",
            compression_format.as_str().to_string(),
        );
    }
    if let PluginCommand::VmaRegexScan { pattern, pid } = &cli.plugin {
        if let Some(p) = pattern {
            context.config_set("plugins.vmaregexscan.pattern", p.clone());
        }
        if let Some(pid) = pid {
            context.config_set("plugins.vmaregexscan.pid", *pid as i64);
        }
    }
    if let PluginCommand::LibraryList { pid } = &cli.plugin {
        if let Some(pid) = pid {
            context.config_set("plugins.library_list.pid", *pid as i64);
        }
    }

    // Run the plugin
    info!("Running plugin: {}", plugin_name);
    let output = module.run(Arc::new(context))?;

    // Render output
    render_output(&cli.output, &module.columns(), output)?;

    Ok(())
}

/// VMCOREINFO magic bytes (aligned to 4 bytes)
const VMCOREINFO_MAGIC: &[u8] = b"VMCOREINFO\x00\x00";

/// Parse VMCOREINFO data into a key-value map
fn parse_vmcoreinfo(data: &[u8]) -> Option<std::collections::HashMap<String, String>> {
    // Check it's printable ASCII
    if !data
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b == b'=')
    {
        return None;
    }

    let text = std::str::from_utf8(data).ok()?;
    let mut map = std::collections::HashMap::new();

    for line in text.lines() {
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once('=') {
            map.insert(key.to_string(), value.to_string());
        }
    }

    // Must have OSRELEASE to be valid
    if map.contains_key("OSRELEASE") {
        Some(map)
    } else {
        None
    }
}

/// Extract KASLR and DTB info from VMCOREINFO
fn extract_vmcoreinfo_shifts(
    vmcoreinfo: &std::collections::HashMap<String, String>,
) -> Option<(u64, u64, u64)> {
    // According to Python vol3 linux.py:
    // aslr_shift = KERNELOFFSET
    // kaslr_shift = phys_base + aslr_shift
    // dtb_paddr = virtual_to_physical(dtb_vaddr) - aslr_shift + kaslr_shift

    // Get aslr_shift from KERNELOFFSET (this is the virtual address randomization)
    let aslr_shift = vmcoreinfo
        .get("KERNELOFFSET")
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok())?;

    // Get phys_base (physical address base where kernel starts in physical memory)
    let phys_base = vmcoreinfo
        .get("NUMBER(phys_base)")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);

    // kaslr_shift is the physical address randomization
    let kaslr_shift = phys_base.wrapping_add(aslr_shift);

    // Get swapper_pg_dir virtual address from VMCOREINFO
    let dtb_symbol_value = vmcoreinfo
        .get("SYMBOL(swapper_pg_dir)")
        .or_else(|| vmcoreinfo.get("SYMBOL(init_top_pgt)"))
        .or_else(|| vmcoreinfo.get("SYMBOL(init_level4_pgt)"))
        .and_then(|v| u64::from_str_radix(v.trim_start_matches("0x"), 16).ok());

    if let Some(dtb_virt) = dtb_symbol_value {
        // virtual_to_physical = addr - 0xffffffff80000000 (for 64-bit)
        let dtb_phys_base = if dtb_virt > 0xffff_ffff_8000_0000 {
            dtb_virt.wrapping_sub(0xffff_ffff_8000_0000)
        } else {
            dtb_virt.wrapping_sub(0xc000_0000)
        };

        // Calculate actual DTB: dtb_paddr = virtual_to_physical(dtb_vaddr) - aslr_shift + kaslr_shift
        let dtb_phys = dtb_phys_base
            .wrapping_sub(aslr_shift)
            .wrapping_add(kaslr_shift);

        log::debug!(
            "VMCOREINFO: phys_base={:#x}, aslr_shift={:#x}, kaslr_shift={:#x}, dtb_virt={:#x}, dtb_phys={:#x}",
            phys_base, aslr_shift, kaslr_shift, dtb_virt, dtb_phys
        );

        return Some((kaslr_shift, aslr_shift, dtb_phys));
    }

    None
}

fn collect_isf_files(root: &Path, output: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_isf_files(&path, output);
        } else if path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(".json") || name.ends_with(".json.xz"))
        {
            output.push(path);
        }
    }
}

fn default_volatility_root() -> Option<PathBuf> {
    let mut starts = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        starts.push(cwd);
    }
    if let Ok(executable) = std::env::current_exe() {
        if let Some(parent) = executable.parent() {
            starts.push(parent.to_path_buf());
        }
    }
    for start in starts {
        for ancestor in start.ancestors() {
            let candidate = ancestor.join(".venv-volatility/Lib/site-packages/volatility3");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }
    None
}

fn kernel_symbol_candidates(cli: &Cli) -> Vec<PathBuf> {
    if let Some(path) = &cli.symbols {
        return vec![path.clone()];
    }
    let root = cli
        .symbol_root
        .clone()
        .or_else(|| default_volatility_root().map(|root| root.join("symbols/windows")));
    let mut paths = Vec::new();
    if let Some(root) = root {
        collect_isf_files(&root, &mut paths);
    }
    paths.sort();
    paths
}

fn isf_matches_pdb(path: &Path, identity: &PdbIdentity) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    normalized.contains(&identity.database.to_ascii_lowercase())
        && normalized.contains(&identity.identifier().to_ascii_lowercase())
}

fn service_symbol_for_build(cli: &Cli, build: u32) -> Option<PathBuf> {
    let root = cli.service_symbol_root.clone().or_else(|| {
        default_volatility_root().map(|root| root.join("framework/symbols/windows/services"))
    })?;
    let stem = if build >= 25_398 {
        "services-win10-25398-x64"
    } else if build >= 19_041 {
        "services-win10-19041-x64"
    } else if build >= 18_362 {
        "services-win10-18362-x64"
    } else if build >= 16_299 {
        "services-win10-16299-x64"
    } else if build >= 15_063 {
        "services-win10-15063-x64"
    } else {
        "services-win8-x64"
    };
    [
        root.join(format!("{stem}.json")),
        root.join(format!("{stem}.json.xz")),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn callback_symbol_path(cli: &Cli) -> Option<PathBuf> {
    if let PluginCommand::Callbacks {
        callback_symbols: Some(path),
    } = &cli.plugin
    {
        return Some(path.clone());
    }
    let root = default_volatility_root()?.join("framework/symbols/windows");
    [
        root.join("callbacks-x64.json"),
        root.join("callbacks-x64.json.xz"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn setup_context(cli: &Cli) -> Vol3Result<Context> {
    use byteorder::{ByteOrder, LittleEndian};
    use vol3_symbols::SymbolTableInterface;

    let context = Context::new();
    if let Some(output_dir) = &cli.output_dir {
        context.config_set(
            "plugins.output_dir",
            output_dir.to_string_lossy().to_string(),
        );
    }

    // Load memory file.  Signature detection must precede extension-based
    // VMware handling because some acquisition tools emit ELF cores named .vmem.
    let file_path = cli.file.to_string_lossy().to_string();
    info!("Loading memory file: {}", file_path);

    // SvcScan reads the whole image sequentially. A buffered reader avoids
    // pulling a multi-gigabyte mmap into its working set, while other plugins
    // retain mmap-backed random access.
    let file_layer: Arc<dyn DataLayer> = if matches!(
        &cli.plugin,
        PluginCommand::SvcScan { .. } | PluginCommand::Callbacks { .. }
    ) {
        Arc::new(StreamingFileLayer::new("file_layer", &file_path)?)
    } else {
        Arc::new(FileLayer::new("file_layer", &file_path)?)
    };
    let physical_layer: Arc<dyn DataLayer> = if Elf64Layer::is_elf64_core(file_layer.as_ref()) {
        let elf = Elf64Layer::from_base("elf64_layer", file_layer.clone())?;
        info!(
            "Detected ELF64 core with {} PT_LOAD segments",
            elf.segment_count()
        );
        Arc::new(elf)
    } else if VmwareLayer::is_vmware_vmem(&cli.file) {
        info!("Detected VMware memory format");
        let metadata_path = VmwareLayer::metadata_for_vmem(&cli.file).ok_or_else(|| {
            vol3_core::error::Vol3Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("No VMware metadata found for {}", cli.file.display()),
            ))
        })?;
        Arc::new(VmwareLayer::from_files_with_base(
            &cli.file,
            &metadata_path,
            file_layer.clone(),
        )?)
    } else {
        file_layer.clone()
    };

    context.add_layer(physical_layer.clone());
    context.config_set("physical", physical_layer.name().to_string());

    // Linux keeps its explicit-symbol path. Windows resolves its ISF below so
    // each candidate can participate in kernel-base validation.
    let symbol_table = if cli.os != TargetOs::Windows {
        let Some(symbols_path) = &cli.symbols else {
            return Err(vol3_core::error::Vol3Error::Plugin(
                vol3_core::error::PluginError::MissingRequirement(
                    "--symbols is required for Linux analysis".to_string(),
                ),
            ));
        };
        info!("Loading symbols: {}", symbols_path.display());
        let table_name = "vmlinux";
        let table = IntermediateSymbolTable::from_path_with_cache(
            symbols_path,
            table_name,
            cli.cache_path.as_deref(),
            cli.clear_cache,
        )?;
        let table = Arc::new(table);
        context.add_symbol_table(table.clone());
        context.config_set(table_name, table_name.to_string());
        Some(table)
    } else {
        None
    };

    if cli.os == TargetOs::Windows {
        let needs_cpu_state =
            cli.dtb.is_none() || cli.kernel_base.is_none() || cli.symbols.is_none();
        let (cpu_states, acquisition) = if needs_cpu_state {
            match qemu_cpu_states(file_layer.as_ref()) {
                Ok(states) => (Some(states), "QEMU ELF CPU notes".to_string()),
                Err(qemu_error) => {
                    let metadata_path = VmwareLayer::metadata_for_vmem(&cli.file).ok_or_else(|| {
                        vol3_core::error::Vol3Error::Plugin(
                            vol3_core::error::PluginError::ExecutionFailed(format!(
                                "no supported CPU-state source: QEMU={qemu_error}; VMware sidecar not found"
                            )),
                        )
                    })?;
                    let metadata = VmwareMetadata::parse(&metadata_path)?;
                    let states: Vec<WindowsCpuState> = metadata
                        .cpu_states()
                        .into_iter()
                        .map(|state| WindowsCpuState {
                            cr3: state.cr3,
                            idtr_base: state.idtr_base,
                        })
                        .collect();
                    if states.is_empty() {
                        return Err(vol3_core::error::Vol3Error::Plugin(
                            vol3_core::error::PluginError::ExecutionFailed(format!(
                                "VMware metadata {} contains no usable CR64/IDTR CPU state",
                                metadata_path.display()
                            )),
                        ));
                    }
                    (
                        Some(states),
                        format!("VMware CPU tags from {}", metadata_path.display()),
                    )
                }
            }
        } else {
            (None, "manual CPU parameters".to_string())
        };
        let pe_discovery = if let Some(states) = &cpu_states {
            Some(discover_kernel_pe(physical_layer.clone(), states)?)
        } else {
            None
        };
        let detected_dtb = cli
            .dtb
            .or(pe_discovery.as_ref().map(|value| value.dtb))
            .unwrap();
        let detected_kernel_base = canonicalize_x64_address(
            cli.kernel_base
                .or(pe_discovery.as_ref().map(|value| value.kernel_base))
                .unwrap(),
        );
        let pdb_identity =
            extract_pdb_identity(physical_layer.clone(), detected_dtb, detected_kernel_base)?;
        let mut candidates = kernel_symbol_candidates(cli);
        if cli.symbols.is_none() {
            candidates.retain(|path| isf_matches_pdb(path, &pdb_identity));
        }
        if candidates.is_empty() {
            return Err(vol3_core::error::Vol3Error::Plugin(
                vol3_core::error::PluginError::MissingRequirement(format!(
                    "kernel detected but matching ISF is absent: database={}, identifier={}; expected path contains {}/{}.json.xz; DTB={:#x}, kernel_base={:#x}, source={}",
                    pdb_identity.database,
                    pdb_identity.identifier(),
                    pdb_identity.database,
                    pdb_identity.identifier(),
                    detected_dtb,
                    detected_kernel_base,
                    acquisition
                )),
            ));
        }
        let mut selected = None;
        let mut last_error = None;
        for symbols_path in candidates {
            let table = match IntermediateSymbolTable::from_path_with_cache(
                &symbols_path,
                "nt_symbols",
                cli.cache_path.as_deref(),
                cli.clear_cache,
            ) {
                Ok(table) => Arc::new(table),
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            let discovery = if let Some(states) = &cpu_states {
                match discover_windows_kernel(physical_layer.clone(), states, table.as_ref()) {
                    Ok(value) => Some(value),
                    Err(error) => {
                        last_error = Some(format!("{}: {error}", symbols_path.display()));
                        continue;
                    }
                }
            } else {
                None
            };
            let dtb = detected_dtb;
            let kernel_base = detected_kernel_base;
            let probe = Intel32e::new_windows(
                "windows_parameter_validation",
                physical_layer.clone(),
                dtb,
                0,
            );
            let build_rva = match table.get_symbol("NtBuildNumber") {
                Ok(symbol) => symbol.address,
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            let build = match probe.read(kernel_base + build_rva, 4, false) {
                Ok(bytes) => LittleEndian::read_u32(&bytes) & 0xffff,
                Err(error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
            };
            if !(10_000..=40_000).contains(&build) {
                last_error = Some(format!("implausible Windows build {build}"));
                continue;
            }
            selected = Some((symbols_path, table, dtb, kernel_base, build, discovery));
            break;
        }
        let Some((symbols_path, table, dtb, kernel_base, build, discovery)) = selected else {
            return Err(vol3_core::error::Vol3Error::Plugin(
                vol3_core::error::PluginError::ExecutionFailed(format!(
                    "Windows automagic could not validate any kernel ISF{}",
                    last_error
                        .map(|value| format!(": {value}"))
                        .unwrap_or_default()
                )),
            ));
        };
        context.add_symbol_table(table);
        let kernel_layer = Intel32e::new_windows("kernel_layer", physical_layer, dtb, 0);
        context.add_layer(Arc::new(kernel_layer));
        context.config_set("primary", "kernel_layer".to_string());
        context.config_set("nt_symbols", "nt_symbols".to_string());
        context.config_set("kernel_virtual_offset", kernel_base as i64);
        context.config_set("windows.build_number", build as i64);
        context.config_set("automagic.windows.dtb", dtb as i64);
        context.config_set("automagic.windows.kernel_base", kernel_base as i64);
        context.config_set(
            "automagic.windows.kernel_symbols",
            symbols_path.to_string_lossy().to_string(),
        );
        context.config_set(
            "automagic.windows.pdb_identity",
            format!("{} {}", pdb_identity.database, pdb_identity.identifier()),
        );
        let evidence = discovery
            .map(|value| format!("{}; {}; PDB RSDS validation", acquisition, value.evidence))
            .unwrap_or_else(|| "manual DTB/kernel-base override with ISF validation".to_string());
        info!(
            "Windows context: DTB={:#x}, kernel_base={:#x}, build={}, symbols={}, evidence={}",
            dtb,
            kernel_base,
            build,
            symbols_path.display(),
            evidence
        );
        if matches!(
            &cli.plugin,
            PluginCommand::SvcScan {
                service_symbols: None
            }
        ) {
            let service_symbols = service_symbol_for_build(cli, build).ok_or_else(|| {
                vol3_core::error::Vol3Error::Plugin(
                    vol3_core::error::PluginError::MissingRequirement(format!(
                        "no x64 service ISF found for Windows build {build}; use --service-symbols"
                    )),
                )
            })?;
            info!("Resolved service symbols: {}", service_symbols.display());
            context.config_set(
                "plugins.windows.svcscan.service_symbols",
                service_symbols.to_string_lossy().to_string(),
            );
            context.config_set(
                "automagic.windows.service_symbols",
                service_symbols.to_string_lossy().to_string(),
            );
        }
        if matches!(&cli.plugin, PluginCommand::Callbacks { .. }) {
            let callback_symbols = callback_symbol_path(cli).ok_or_else(|| {
                vol3_core::error::Vol3Error::Plugin(
                    vol3_core::error::PluginError::MissingRequirement(
                        "callbacks-x64.json was not found; use callbacks --callback-symbols <path>"
                            .to_string(),
                    ),
                )
            })?;
            info!("Resolved callback symbols: {}", callback_symbols.display());
            context.config_set(
                "plugins.windows.callbacks.callback_symbols",
                callback_symbols.to_string_lossy().to_string(),
            );
            context.config_set(
                "automagic.windows.callback_symbols",
                callback_symbols.to_string_lossy().to_string(),
            );
        }
        return Ok(context);
    }

    // Try VMCOREINFO-based KASLR detection first
    let mut kaslr_result: Option<(u64, u64, u64, String, u64)> = None;
    let max_scan = physical_layer.maximum_address();
    let chunk_size = 0x100_0000usize; // 16MB chunks

    info!("Scanning for VMCOREINFO...");
    'vmcoreinfo_scan: for offset in (0..max_scan).step_by(chunk_size) {
        let read_size = std::cmp::min(chunk_size + 4096, (max_scan - offset) as usize);
        if let Ok(data) = physical_layer.read(offset, read_size, false) {
            for (i, window) in data.windows(VMCOREINFO_MAGIC.len()).enumerate() {
                if window == VMCOREINFO_MAGIC {
                    let vmcoreinfo_offset = offset + i as u64;
                    info!("Found VMCOREINFO magic at {:#x}", vmcoreinfo_offset);

                    // Read ELF note header (before the magic)
                    let elf_note_offset = vmcoreinfo_offset.saturating_sub(12);
                    if let Ok(note_header) = physical_layer.read(elf_note_offset, 12, false) {
                        let n_namesz = LittleEndian::read_u32(&note_header[0..4]);
                        let n_descsz = LittleEndian::read_u32(&note_header[4..8]);
                        let n_type = LittleEndian::read_u32(&note_header[8..12]);

                        // Verify ELF note structure
                        if n_namesz == 11 && n_type == 0 && n_descsz > 0 && n_descsz < 65536 {
                            let data_offset = vmcoreinfo_offset + VMCOREINFO_MAGIC.len() as u64;
                            if let Ok(vmcoreinfo_data) =
                                physical_layer.read(data_offset, n_descsz as usize, false)
                            {
                                if vmcoreinfo_data.starts_with(b"OSRELEASE=") {
                                    // Store raw bytes for plugin use (preserves order)
                                    let vmcoreinfo_raw =
                                        String::from_utf8_lossy(&vmcoreinfo_data).to_string();

                                    if let Some(vmcoreinfo) = parse_vmcoreinfo(&vmcoreinfo_data) {
                                        info!(
                                            "Parsed VMCOREINFO: OSRELEASE={}",
                                            vmcoreinfo.get("OSRELEASE").unwrap_or(&"?".to_string())
                                        );

                                        if let Some((kaslr, aslr, dtb)) =
                                            extract_vmcoreinfo_shifts(&vmcoreinfo)
                                        {
                                            info!(
                                                "VMCOREINFO: kaslr={:#x}, aslr={:#x}, dtb={:#x}",
                                                kaslr, aslr, dtb
                                            );
                                            // Store physical offset for later conversion to virtual
                                            kaslr_result = Some((
                                                kaslr,
                                                aslr,
                                                dtb,
                                                vmcoreinfo_raw,
                                                elf_note_offset,
                                            ));
                                            break 'vmcoreinfo_scan;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // If VMCOREINFO worked, use it
    if let Some((kaslr_shift, aslr_shift, dtb_phys, vmcoreinfo_raw, vmcoreinfo_phys_offset)) =
        kaslr_result
    {
        if symbol_table.is_some() {
            info!(
                "Using VMCOREINFO: kaslr={:#x}, aslr={:#x}, dtb={:#x}",
                kaslr_shift, aslr_shift, dtb_phys
            );

            let kernel_layer = Intel32e::new("kernel_layer", physical_layer.clone(), dtb_phys, 0);
            context.add_layer(Arc::new(kernel_layer));

            context.config_set("kaslr_shift", kaslr_shift as i64);
            context.config_set("aslr_shift", aslr_shift as i64);
            context.config_set("primary", "kernel_layer".to_string());

            // Store VMCOREINFO for plugin use
            // Store physical ELF note offset (same as Python yields)
            // Store raw VMCOREINFO text to preserve key order
            context.config_set("vmcoreinfo_offset", vmcoreinfo_phys_offset as i64);
            context.config_set("vmcoreinfo_raw", vmcoreinfo_raw);

            return Ok(context);
        }
    }

    // Fallback: swapper-based detection
    if let Some(ref symbols) = symbol_table {
        info!("Trying swapper-based KASLR detection...");

        if let Ok(task_struct) = symbols.get_type("task_struct") {
            if let vol3_symbols::TypeTemplate::Struct(s) = task_struct.as_ref() {
                if let Some(comm_field) = s.get_field("comm") {
                    let comm_offset = comm_field.offset;
                    info!("comm offset in task_struct: {:#x}", comm_offset);

                    if let Ok(init_task_sym) = symbols.get_symbol("init_task") {
                        let init_task_virt = init_task_sym.address;
                        let init_task_phys_base =
                            init_task_virt.wrapping_sub(0xffff_ffff_8000_0000);
                        info!(
                            "init_task virtual: {:#x}, physical base: {:#x}",
                            init_task_virt, init_task_phys_base
                        );

                        let swapper_pattern = b"swapper";
                        info!("Scanning for 'swapper' (init_task.comm)...");

                        'outer: for offset in (0..max_scan).step_by(chunk_size) {
                            let read_size =
                                std::cmp::min(chunk_size + 64, (max_scan - offset) as usize);
                            if let Ok(data) = physical_layer.read(offset, read_size, false) {
                                for (i, window) in data.windows(swapper_pattern.len()).enumerate() {
                                    if window == swapper_pattern {
                                        let comm_phys = offset + i as u64;
                                        let potential_init_task =
                                            comm_phys.saturating_sub(comm_offset as u64);

                                        if let Ok(pid_field) =
                                            symbols.get_type("task_struct").and_then(|t| {
                                                if let vol3_symbols::TypeTemplate::Struct(st) =
                                                    t.as_ref()
                                                {
                                                    st.get_field("pid")
                                                        .map(|f| f.offset)
                                                        .ok_or_else(|| {
                                                            vol3_core::error::SymbolError::NotFound(
                                                                "pid".to_string(),
                                                            )
                                                        })
                                                } else {
                                                    Err(vol3_core::error::SymbolError::NotFound(
                                                        "pid".to_string(),
                                                    ))
                                                }
                                            })
                                        {
                                            if let Ok(pid_bytes) = physical_layer.read(
                                                potential_init_task + pid_field as u64,
                                                4,
                                                false,
                                            ) {
                                                let pid = LittleEndian::read_i32(&pid_bytes);
                                                if pid == 0 {
                                                    info!(
                                                        "Found init_task at physical {:#x} (pid=0)",
                                                        potential_init_task
                                                    );

                                                    let kaslr_shift = potential_init_task
                                                        .wrapping_sub(init_task_phys_base);
                                                    info!("KASLR shift: {:#x}", kaslr_shift);

                                                    let dtb_symbol = symbols
                                                        .get_symbol("init_top_pgt")
                                                        .or_else(|_| {
                                                            symbols.get_symbol("init_level4_pgt")
                                                        })
                                                        .or_else(|_| {
                                                            symbols.get_symbol("level4_kernel_pgt")
                                                        })
                                                        .or_else(|_| {
                                                            symbols.get_symbol("swapper_pg_dir")
                                                        })
                                                        .ok();

                                                    if let Some(dtb_sym) = dtb_symbol {
                                                        let dtb_virt = dtb_sym.address;
                                                        let dtb_phys = dtb_virt
                                                            .wrapping_sub(0xffff_ffff_8000_0000)
                                                            .wrapping_add(kaslr_shift);
                                                        info!(
                                                            "DTB virtual: {:#x}, physical: {:#x}",
                                                            dtb_virt, dtb_phys
                                                        );

                                                        let kernel_layer = Intel32e::new(
                                                            "kernel_layer",
                                                            physical_layer.clone(),
                                                            dtb_phys,
                                                            0,
                                                        );
                                                        context.add_layer(Arc::new(kernel_layer));
                                                        context.config_set(
                                                            "kaslr_shift",
                                                            kaslr_shift as i64,
                                                        );
                                                        context.config_set(
                                                            "primary",
                                                            "kernel_layer".to_string(),
                                                        );
                                                        return Ok(context);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Fallback: use physical layer directly
    info!("Using physical layer directly (no translation)");
    context.config_set("primary", physical_layer.name().to_string());

    Ok(context)
}

fn render_output(
    format: &OutputFormat,
    columns: &[Column],
    output: Box<dyn Iterator<Item = Vol3Result<Vec<vol3_core::types::CellValue>>> + Send>,
) -> Vol3Result<()> {
    let stdout = io::stdout();
    let mut writer = stdout.lock();

    match format {
        OutputFormat::Csv => {
            let renderer = CsvRenderer::new();
            renderer.render_header(&mut writer, columns)?;
            for row in output {
                let row = row?;
                renderer.render_row(&mut writer, &row)?;
            }
        }
        OutputFormat::Json => {
            let renderer = JsonRenderer::new().pretty();
            let rows: Vec<_> = output.collect::<Result<Vec<_>, _>>()?;
            renderer.render(&mut writer, columns, rows.into_iter())?;
        }
        OutputFormat::Jsonl => {
            let renderer = JsonRenderer::new();
            for row in output {
                let row = row?;
                renderer.render_row(&mut writer, columns, &row)?;
            }
        }
        OutputFormat::Pretty => {
            // Simple pretty format
            // Header
            for (i, col) in columns.iter().enumerate() {
                if i > 0 {
                    write!(writer, "\t")?;
                }
                write!(writer, "{}", col.name)?;
            }
            writeln!(writer)?;
            writeln!(writer, "{}", "-".repeat(80))?;

            // Rows
            for row in output {
                let row = row?;
                for (i, val) in row.iter().enumerate() {
                    if i > 0 {
                        write!(writer, "\t")?;
                    }
                    write!(
                        writer,
                        "{}",
                        vol3_renderers::treegrid::format_cell_value(val)
                    )?;
                }
                writeln!(writer)?;
            }
        }
    }

    Ok(())
}
