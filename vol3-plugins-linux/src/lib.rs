//! # vol3-plugins-linux
//!
//! Linux plugins for the Volatility3 Rust framework.
//!
//! This crate provides all Linux-specific plugins from volatility3.

pub mod extensions;
pub mod helpers;
pub mod process_layer;

// Core process plugins
pub mod pidhashtable;
pub mod psaux;
pub mod pscallstack;
pub mod pslist;
pub mod psscan;
pub mod pstree;
pub mod ptrace;

// Module plugins
pub mod check_modules;
pub mod hidden_modules;
pub mod lsmod;
pub mod module_extract;
pub mod modxview;

// File system plugins
pub mod elfs;
pub mod library_list;
pub mod lsof;
pub mod mountinfo;
pub mod pagecache;
pub mod recoverfs;

// Memory plugins
pub mod malfind;
pub mod proc;
pub mod proc_maps;
pub mod vmaregexscan;
pub mod vmayarascan;

// Network plugins
pub mod check_afinfo;
pub mod ip;
pub mod netfilter;
pub mod sockscan;
pub mod sockstat;

// Process info plugins
pub mod bash;
pub mod capabilities;
pub mod envars;
pub mod kthreads;

// System info plugins
pub mod boottime;
pub mod iomem;
pub mod kallsyms;
pub mod kmsg;
pub mod vmcoreinfo;

// Security/malware plugins
pub mod check_creds;
pub mod check_idt;
pub mod check_syscall;
pub mod ebpf;
pub mod keyboard_notifiers;
pub mod tty_check;

use std::sync::Arc;

use vol3_framework::module::ModuleRegistry;

// Re-exports
pub use pidhashtable::PidHashTable;
pub use psaux::PsAux;
pub use pscallstack::PsCallStack;
pub use pslist::PsList;
pub use psscan::PsScan;
pub use pstree::PsTree;
pub use ptrace::Ptrace;

pub use check_modules::CheckModules;
pub use hidden_modules::HiddenModules;
pub use lsmod::Lsmod;
pub use module_extract::ModuleExtract;
pub use modxview::Modxview;

pub use elfs::Elfs;
pub use library_list::LibraryList;
pub use lsof::Lsof;
pub use mountinfo::MountInfo;
pub use pagecache::PageCacheFiles;
pub use recoverfs::RecoverFs;

pub use malfind::Malfind;
pub use proc::Proc;
pub use proc_maps::Maps;
pub use vmaregexscan::VmaRegexScan;
pub use vmayarascan::VmaYaraScan;

pub use check_afinfo::CheckAfinfo;
pub use ip::{IpAddr, IpLink};
pub use netfilter::Netfilter;
pub use sockscan::Sockscan;
pub use sockstat::Sockstat;

pub use bash::Bash;
pub use capabilities::Capabilities;
pub use envars::Envars;
pub use kthreads::Kthreads;

pub use boottime::Boottime;
pub use iomem::Iomem;
pub use kallsyms::Kallsyms;
pub use kmsg::Kmsg;
pub use vmcoreinfo::VmcoreInfo;

pub use check_creds::CheckCreds;
pub use check_idt::CheckIdt;
pub use check_syscall::CheckSyscall;
pub use ebpf::Ebpf;
pub use keyboard_notifiers::KeyboardNotifiers;
pub use tty_check::TtyCheck;

/// Register all Linux plugins
pub fn register_linux_plugins(registry: &mut ModuleRegistry) {
    // Core process plugins
    registry.register(Arc::new(PsList::new()));
    registry.register(Arc::new(PsScan::new()));
    registry.register(Arc::new(PsTree::new()));
    registry.register(Arc::new(PsAux::new()));
    registry.register(Arc::new(PsCallStack::new()));
    registry.register(Arc::new(PidHashTable::new()));
    registry.register(Arc::new(Ptrace::new()));

    // Module plugins
    registry.register(Arc::new(Lsmod::new()));
    registry.register(Arc::new(HiddenModules::new()));
    registry.register(Arc::new(CheckModules::new()));
    registry.register(Arc::new(Modxview::new()));
    registry.register(Arc::new(ModuleExtract::new()));

    // File system plugins
    registry.register(Arc::new(MountInfo::new()));
    registry.register(Arc::new(PageCacheFiles::new()));
    registry.register(Arc::new(RecoverFs::new()));
    registry.register(Arc::new(Lsof::new()));
    registry.register(Arc::new(Elfs::new()));
    registry.register(Arc::new(LibraryList::new()));

    // Memory plugins
    registry.register(Arc::new(Maps::new()));
    registry.register(Arc::new(Proc::new()));
    registry.register(Arc::new(Malfind::new()));
    registry.register(Arc::new(VmaRegexScan::new()));
    registry.register(Arc::new(VmaYaraScan::new()));

    // Network plugins
    registry.register(Arc::new(Sockstat::new()));
    registry.register(Arc::new(Sockscan::new()));
    registry.register(Arc::new(Netfilter::new()));
    registry.register(Arc::new(IpAddr::new()));
    registry.register(Arc::new(IpLink::new()));
    registry.register(Arc::new(CheckAfinfo::new()));

    // Process info plugins
    registry.register(Arc::new(Envars::new()));
    registry.register(Arc::new(Capabilities::new()));
    registry.register(Arc::new(Kthreads::new()));
    registry.register(Arc::new(Bash::new()));

    // System info plugins
    registry.register(Arc::new(Iomem::new()));
    registry.register(Arc::new(Boottime::new()));
    registry.register(Arc::new(Kmsg::new()));
    registry.register(Arc::new(Kallsyms::new()));
    registry.register(Arc::new(VmcoreInfo::new()));

    // Security/malware plugins
    registry.register(Arc::new(CheckCreds::new()));
    registry.register(Arc::new(CheckIdt::new()));
    registry.register(Arc::new(CheckSyscall::new()));
    registry.register(Arc::new(KeyboardNotifiers::new()));
    registry.register(Arc::new(TtyCheck::new()));
    registry.register(Arc::new(Ebpf::new()));
}
