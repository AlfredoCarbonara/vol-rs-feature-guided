//! Windows plugins for the Volatility3 Rust framework.
//!
//! The first milestone implements `windows.pslist.PsList` for Windows 10 x64.
//! Field offsets are resolved from a Windows kernel ISF symbol table rather
//! than hard-coded for one kernel build.

pub mod callback_layout;
pub mod callbacks;
pub mod handle_layout;
pub mod handles;
pub mod layout;
pub mod malfind;
mod module_resolver;
pub mod pslist;
pub mod reader;
pub mod service_layout;
pub mod svcscan;
pub mod vad_layout;

use std::sync::Arc;

use vol3_framework::module::ModuleRegistry;

pub use callbacks::{CallbackInfo, Callbacks};
pub use handles::{HandleInfo, Handles};
pub use malfind::{Malfind, MalfindInfo};
pub use pslist::{ProcessInfo, PsList};
pub use svcscan::{ServiceInfo, SvcScan};

/// Register the Windows plugins currently implemented by this crate.
pub fn register_windows_plugins(registry: &mut ModuleRegistry) {
    registry.register(Arc::new(PsList::new()));
    registry.register(Arc::new(Handles::new()));
    registry.register(Arc::new(SvcScan::new()));
    registry.register(Arc::new(Callbacks::new()));
    registry.register(Arc::new(Malfind::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registers_windows_pslist() {
        let mut registry = ModuleRegistry::new();
        register_windows_plugins(&mut registry);

        let module = registry
            .get("windows.pslist.PsList")
            .expect("Windows PsList should be registered");
        assert_eq!(module.supported_os(), vec!["windows"]);
        assert!(registry.get("windows.handles.Handles").is_some());
        assert!(registry.get("windows.svcscan.SvcScan").is_some());
        assert!(registry.get("windows.callbacks.Callbacks").is_some());
        assert!(registry.get("windows.malware.malfind.Malfind").is_some());
    }
}
