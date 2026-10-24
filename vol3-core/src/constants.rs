//! Constants used throughout the Volatility3 framework.

/// Symbol table name separator (used in qualified names like "table!symbol")
pub const BANG: &str = "!";

/// Minimum supported ISF version
pub const ISF_MINIMUM_SUPPORTED: (u32, u32, u32) = (4, 0, 0);

/// Minimum deprecated ISF version (still works but warns)
pub const ISF_MINIMUM_DEPRECATED: (u32, u32, u32) = (6, 0, 0);

/// Default chunk size for scanning operations (16MB)
pub const DEFAULT_SCAN_CHUNK_SIZE: usize = 0x1000000;

/// Default overlap for scanning operations (4KB)
pub const DEFAULT_SCAN_OVERLAP: usize = 0x1000;

/// Log level for verbose output
pub const LOGLEVEL_V: u8 = 1;
pub const LOGLEVEL_VV: u8 = 2;
pub const LOGLEVEL_VVV: u8 = 3;

/// Linux-specific constants
pub mod linux {
    /// Process flag: kernel thread
    pub const PF_KTHREAD: u64 = 0x00200000;

    /// Process flag: exiting
    pub const PF_EXITING: u64 = 0x00000004;

    /// Maximum core text size for module validation
    pub const MODULE_MAXIMUM_CORE_TEXT_SIZE: u64 = 100 * 1024 * 1024; // 100MB

    /// Maximum core size for module validation
    pub const MODULE_MAXIMUM_CORE_SIZE: u64 = 100 * 1024 * 1024; // 100MB

    /// Minimum module size for validation
    pub const MODULE_MINIMUM_SIZE: u64 = 4096;

    /// Task states
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(u64)]
    pub enum TaskState {
        Running = 0x0000,
        Interruptible = 0x0001,
        Uninterruptible = 0x0002,
        Stopped = 0x0004,
        Traced = 0x0008,
        ExitDead = 0x0010,
        ExitZombie = 0x0020,
        Parked = 0x0040,
        Dead = 0x0080,
        WakeKill = 0x0100,
        Waking = 0x0200,
        NoLoad = 0x0400,
        New = 0x0800,
    }

    /// Ptrace flags
    pub mod ptrace_flags {
        pub const PT_PTRACED: u64 = 0x00000001;
        pub const PT_DTRACE: u64 = 0x00000002;
        pub const PT_PTRACE_CAP: u64 = 0x00000004;
        pub const PT_SEIZED: u64 = 0x00010000;
    }

    /// VMA flags
    pub mod vma_flags {
        pub const VM_READ: u64 = 0x00000001;
        pub const VM_WRITE: u64 = 0x00000002;
        pub const VM_EXEC: u64 = 0x00000004;
        pub const VM_SHARED: u64 = 0x00000008;
        pub const VM_MAYREAD: u64 = 0x00000010;
        pub const VM_MAYWRITE: u64 = 0x00000020;
        pub const VM_MAYEXEC: u64 = 0x00000040;
        pub const VM_MAYSHARE: u64 = 0x00000080;
    }

    /// File descriptor flags
    pub mod fd_flags {
        pub const O_RDONLY: u64 = 0x0000;
        pub const O_WRONLY: u64 = 0x0001;
        pub const O_RDWR: u64 = 0x0002;
        pub const O_CREAT: u64 = 0x0040;
        pub const O_EXCL: u64 = 0x0080;
        pub const O_NOCTTY: u64 = 0x0100;
        pub const O_TRUNC: u64 = 0x0200;
        pub const O_APPEND: u64 = 0x0400;
        pub const O_NONBLOCK: u64 = 0x0800;
    }

    /// Socket families
    pub mod socket_families {
        pub const AF_UNIX: u16 = 1;
        pub const AF_INET: u16 = 2;
        pub const AF_INET6: u16 = 10;
        pub const AF_NETLINK: u16 = 16;
        pub const AF_PACKET: u16 = 17;
    }

    /// Socket types
    pub mod socket_types {
        pub const SOCK_STREAM: u16 = 1;
        pub const SOCK_DGRAM: u16 = 2;
        pub const SOCK_RAW: u16 = 3;
        pub const SOCK_SEQPACKET: u16 = 5;
    }
}

/// Windows-specific constants
pub mod windows {
    /// Page size
    pub const PAGE_SIZE: usize = 0x1000;

    /// Pool tags
    pub mod pool_tags {
        pub const EPROCESS_TAG: &[u8] = b"Proc";
        pub const FILE_TAG: &[u8] = b"File";
    }
}

/// Architecture constants
pub mod arch {
    /// Intel page sizes
    pub const PAGE_SIZE_4K: usize = 0x1000;
    pub const PAGE_SIZE_2M: usize = 0x200000;
    pub const PAGE_SIZE_1G: usize = 0x40000000;

    /// Intel paging structure sizes
    pub const PTE_SIZE: usize = 8;
    pub const PDE_SIZE: usize = 8;

    /// Address masks
    pub const CANONICAL_MASK_48: u64 = 0x0000_FFFF_FFFF_FFFF;
    pub const CANONICAL_MASK_57: u64 = 0x01FF_FFFF_FFFF_FFFF;
}
