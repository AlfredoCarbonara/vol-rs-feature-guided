//! Linux PsTree plugin.
//!
//! Lists processes in a tree based on their parent process ID.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use log::debug;

use vol3_core::error::{Vol3Error, Vol3Result};
use vol3_core::types::{Address, CellValue};
use vol3_framework::context::Context;
use vol3_framework::module::{Column, ColumnType, Module, ModuleOutput, ModuleRequirements, Row};
use vol3_framework::requirements::RequirementsBuilder;

use crate::extensions::{TaskStruct, TaskStructExt};
use crate::helpers;
use crate::pslist::PsList;

/// Process info with hierarchy level
#[derive(Debug, Clone)]
struct ProcessNode {
    offset: Address,
    pid: i32,
    tid: i32,
    ppid: i32,
    comm: String,
    level: usize,
}

/// PsTree plugin
pub struct PsTree;

impl PsTree {
    pub fn new() -> Self {
        Self
    }

    /// Build process tree from flat list
    fn build_tree(context: &Context) -> Vol3Result<Vec<ProcessNode>> {
        use vol3_core::error::{ConfigError, LayerError};

        let layer_name = context
            .config_get_string("primary")
            .ok_or_else(|| Vol3Error::Config(ConfigError::KeyNotFound("primary".to_string())))?;

        let layer = context
            .get_layer(&layer_name)
            .ok_or_else(|| Vol3Error::Layer(LayerError::NotFound(layer_name.clone())))?;

        let symbol_table = context
            .config_get_string("vmlinux")
            .unwrap_or_else(|| "vmlinux".to_string());

        let init_task_addr = helpers::get_init_task(context, &symbol_table)?;
        let template = helpers::get_task_struct_template(context, &symbol_table)?;
        let tasks = helpers::collect_processes(layer.as_ref(), init_task_addr, &template)?;

        // Address mask for 48-bit virtual addresses (like Python volatility3)
        let address_mask: u64 = 0x0000_FFFF_FFFF_FFFF;

        // Build maps: pid -> task info, pid -> children
        let mut task_map: HashMap<i32, (Address, i32, String)> = HashMap::new();
        let mut parent_map: HashMap<i32, i32> = HashMap::new();
        let mut children_map: HashMap<i32, HashSet<i32>> = HashMap::new();

        for task in &tasks {
            let pid = task.pid(layer.as_ref()).unwrap_or(-1);
            let tgid = task.tgid(layer.as_ref()).unwrap_or(pid);
            let comm = task
                .comm(layer.as_ref())
                .unwrap_or_else(|_| "<unknown>".to_string());

            // Use parent for hierarchy (not real_parent)
            let ppid = task
                .parent_addr(layer.as_ref())
                .ok()
                .and_then(|parent_addr| {
                    if helpers::is_valid_kernel_address(parent_addr) {
                        TaskStruct::new(parent_addr, template.clone())
                            .ok()
                            .and_then(|parent| parent.pid(layer.as_ref()).ok())
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            // Mask the task address for output
            let masked_offset = task.address() & address_mask;
            let masked_offset = task.address() & address_mask;

            task_map.insert(pid, (masked_offset, tgid, comm));
            parent_map.insert(pid, ppid);

            children_map
                .entry(ppid)
                .or_insert_with(HashSet::new)
                .insert(pid);
        }

        // Calculate levels for each process
        // Level is how many ancestors a process has until swapper (pid 0)
        // PID 1 and 2 have level 1 (direct children of swapper)
        let mut levels: HashMap<i32, usize> = HashMap::new();

        for &pid in task_map.keys() {
            if pid == 0 {
                continue;
            }

            let mut level = 1; // Start at 1 (count self as having at least depth of 1 from root)
            let mut current = pid;
            let mut seen = HashSet::new();

            while let Some(&parent_pid) = parent_map.get(&current) {
                // Stop at swapper or on cycle
                if parent_pid == 0 || seen.contains(&parent_pid) {
                    break;
                }
                seen.insert(current);
                current = parent_pid;
                level += 1;
            }

            levels.insert(pid, level);
        }

        // Build output in tree order using DFS
        let mut result = Vec::new();
        let mut visited = HashSet::new();

        fn visit_tree(
            pid: i32,
            task_map: &HashMap<i32, (Address, i32, String)>,
            parent_map: &HashMap<i32, i32>,
            children_map: &HashMap<i32, HashSet<i32>>,
            levels: &HashMap<i32, usize>,
            visited: &mut HashSet<i32>,
            result: &mut Vec<ProcessNode>,
        ) {
            if visited.contains(&pid) || pid == 0 {
                return;
            }
            visited.insert(pid);

            if let Some(&(offset, tgid, ref comm)) = task_map.get(&pid) {
                let ppid = *parent_map.get(&pid).unwrap_or(&0);
                let level = *levels.get(&pid).unwrap_or(&0);

                result.push(ProcessNode {
                    offset,
                    pid: tgid, // PID (user-space)
                    tid: pid,  // TID
                    ppid,
                    comm: comm.clone(),
                    level,
                });
            }

            // Visit children in sorted order
            if let Some(children) = children_map.get(&pid) {
                let mut sorted_children: Vec<_> = children.iter().copied().collect();
                sorted_children.sort();
                for child_pid in sorted_children {
                    visit_tree(
                        child_pid,
                        task_map,
                        parent_map,
                        children_map,
                        levels,
                        visited,
                        result,
                    );
                }
            }
        }

        // Start from root processes (those with level 1)
        let mut root_pids: Vec<_> = levels
            .iter()
            .filter(|&(_, &level)| level == 1)
            .map(|(&pid, _)| pid)
            .collect();
        root_pids.sort();

        for pid in root_pids {
            visit_tree(
                pid,
                &task_map,
                &parent_map,
                &children_map,
                &levels,
                &mut visited,
                &mut result,
            );
        }

        Ok(result)
    }
}

impl Default for PsTree {
    fn default() -> Self {
        Self::new()
    }
}

impl Module for PsTree {
    fn name(&self) -> &str {
        "linux.pstree.PsTree"
    }

    fn description(&self) -> &str {
        "Plugin for listing processes in a tree based on their parent process ID"
    }

    fn requirements(&self) -> ModuleRequirements {
        let requirements = RequirementsBuilder::new()
            .layer("primary", "Memory layer for the kernel")
            .symbol_table("vmlinux", "Linux kernel symbol table")
            .int_optional("pid", "Filter by process ID")
            .int_optional("threads", "Include user threads")
            .int_optional("decorate_comm", "Show threads in brackets")
            .build();

        ModuleRequirements {
            name: self.name().to_string(),
            description: self.description().to_string(),
            requirements,
        }
    }

    fn columns(&self) -> Vec<Column> {
        vec![
            Column::new("OFFSET (V)", ColumnType::Hex),
            Column::new("PID", ColumnType::Int),
            Column::new("TID", ColumnType::Int),
            Column::new("PPID", ColumnType::Int),
            Column::new("COMM", ColumnType::String),
        ]
    }

    fn run(&self, context: Arc<Context>) -> Vol3Result<ModuleOutput> {
        let tree = Self::build_tree(&context)?;

        let rows: Vec<Vol3Result<Row>> = tree
            .into_iter()
            .map(|node| {
                // TreeDepth is level - 1 (level 1 = depth 0)
                let tree_depth = if node.level > 0 { node.level - 1 } else { 0 };
                Ok(vec![
                    CellValue::TreeDepth(tree_depth as i64),
                    CellValue::Hex(node.offset),
                    CellValue::Int(node.pid as i64),
                    CellValue::Int(node.tid as i64),
                    CellValue::Int(node.ppid as i64),
                    CellValue::String(node.comm),
                ])
            })
            .collect();

        Ok(Box::new(rows.into_iter()))
    }

    fn supported_os(&self) -> Vec<&str> {
        vec!["linux"]
    }
}
