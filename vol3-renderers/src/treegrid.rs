//! TreeGrid for hierarchical output.
//!
//! A TreeGrid represents tabular data that can have a tree structure.

use std::io::Write;

use vol3_core::types::CellValue;
use vol3_framework::module::Column;

/// A node in the tree
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Values for this row
    pub values: Vec<CellValue>,
    /// Child nodes
    pub children: Vec<TreeNode>,
    /// Depth in tree (0 = root level)
    pub depth: usize,
}

impl TreeNode {
    /// Create a new tree node
    pub fn new(values: Vec<CellValue>) -> Self {
        Self {
            values,
            children: Vec::new(),
            depth: 0,
        }
    }

    /// Create a child node
    pub fn child(values: Vec<CellValue>, depth: usize) -> Self {
        Self {
            values,
            children: Vec::new(),
            depth,
        }
    }

    /// Add a child
    pub fn add_child(&mut self, mut child: TreeNode) {
        child.depth = self.depth + 1;
        self.children.push(child);
    }

    /// Check if this is a leaf node
    pub fn is_leaf(&self) -> bool {
        self.children.is_empty()
    }

    /// Get all nodes (including children) in depth-first order
    pub fn flatten(&self) -> Vec<&TreeNode> {
        let mut result = vec![self];
        for child in &self.children {
            result.extend(child.flatten());
        }
        result
    }
}

/// A grid of data with optional tree structure
pub struct TreeGrid {
    /// Column definitions
    columns: Vec<Column>,
    /// Root nodes
    nodes: Vec<TreeNode>,
}

impl TreeGrid {
    /// Create a new empty TreeGrid
    pub fn new(columns: Vec<Column>) -> Self {
        Self {
            columns,
            nodes: Vec::new(),
        }
    }

    /// Add a root-level row
    pub fn add_row(&mut self, values: Vec<CellValue>) {
        self.nodes.push(TreeNode::new(values));
    }

    /// Add a tree node
    pub fn add_node(&mut self, node: TreeNode) {
        self.nodes.push(node);
    }

    /// Get the columns
    pub fn columns(&self) -> &[Column] {
        &self.columns
    }

    /// Get the root nodes
    pub fn nodes(&self) -> &[TreeNode] {
        &self.nodes
    }

    /// Get all rows flattened
    pub fn rows(&self) -> impl Iterator<Item = &[CellValue]> {
        self.nodes
            .iter()
            .flat_map(|n| n.flatten())
            .map(|n| n.values.as_slice())
    }

    /// Get number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get total row count (including nested)
    pub fn row_count(&self) -> usize {
        self.nodes.iter().map(|n| n.flatten().len()).sum()
    }

    /// Render to a writer using a simple text format
    pub fn render_text<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // Header
        for (i, col) in self.columns.iter().enumerate() {
            if i > 0 {
                write!(writer, "\t")?;
            }
            write!(writer, "{}", col.name)?;
        }
        writeln!(writer)?;

        // Rows
        for node in &self.nodes {
            self.render_node_text(writer, node)?;
        }

        Ok(())
    }

    fn render_node_text<W: Write>(&self, writer: &mut W, node: &TreeNode) -> std::io::Result<()> {
        // Indent based on depth
        let indent = "  ".repeat(node.depth);

        for (i, value) in node.values.iter().enumerate() {
            if i > 0 {
                write!(writer, "\t")?;
            }
            if i == 0 {
                write!(writer, "{}", indent)?;
            }
            write!(writer, "{}", format_cell_value(value))?;
        }
        writeln!(writer)?;

        // Children
        for child in &node.children {
            self.render_node_text(writer, child)?;
        }

        Ok(())
    }
}

/// Format a cell value as a string
pub fn format_cell_value(value: &CellValue) -> String {
    match value {
        CellValue::String(s) => s.clone(),
        CellValue::Int(n) => n.to_string(),
        CellValue::UInt(n) => n.to_string(),
        CellValue::Hex(n) => format!("{:#x}", n),
        CellValue::Float(f) => f.to_string(),
        CellValue::Bool(b) => b.to_string(),
        CellValue::Bytes(b) => {
            let hex: Vec<String> = b.iter().map(|byte| format!("{:02x}", byte)).collect();
            hex.join(" ")
        }
        CellValue::DateTime(dt) => dt.to_rfc3339(),
        CellValue::Absent(reason) => format!("N/A ({})", reason),
        CellValue::Error(msg) => format!("Error: {}", msg),
        CellValue::TreeDepth(d) => d.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_framework::module::ColumnType;

    #[test]
    fn test_tree_grid() {
        let columns = vec![
            Column::new("PID", ColumnType::Int),
            Column::new("Name", ColumnType::String),
        ];

        let mut grid = TreeGrid::new(columns);
        grid.add_row(vec![
            CellValue::Int(1),
            CellValue::String("init".to_string()),
        ]);

        let mut parent = TreeNode::new(vec![
            CellValue::Int(2),
            CellValue::String("parent".to_string()),
        ]);
        parent.add_child(TreeNode::new(vec![
            CellValue::Int(3),
            CellValue::String("child".to_string()),
        ]));
        grid.add_node(parent);

        assert_eq!(grid.column_count(), 2);
        assert_eq!(grid.row_count(), 3); // init, parent, child
    }

    #[test]
    fn test_format_cell_value() {
        assert_eq!(format_cell_value(&CellValue::Int(42)), "42");
        assert_eq!(format_cell_value(&CellValue::Hex(255)), "0xff");
        assert_eq!(format_cell_value(&CellValue::Bool(true)), "true");
    }
}
