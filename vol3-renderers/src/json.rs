//! JSON renderer.

use std::io::Write;

use serde_json::{json, Map, Value};

use vol3_core::types::CellValue;
use vol3_framework::module::Column;

/// JSON renderer
pub struct JsonRenderer {
    /// Pretty print
    pretty: bool,
}

impl Default for JsonRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl JsonRenderer {
    /// Create a new JSON renderer
    pub fn new() -> Self {
        Self { pretty: false }
    }

    /// Enable pretty printing
    pub fn pretty(mut self) -> Self {
        self.pretty = true;
        self
    }

    /// Convert a cell value to JSON
    fn cell_to_json(value: &CellValue) -> Value {
        match value {
            CellValue::String(s) => Value::String(s.clone()),
            CellValue::Int(n) => json!(n),
            CellValue::UInt(n) => json!(n),
            CellValue::Hex(n) => Value::String(format!("{:#x}", n)),
            CellValue::Float(f) => json!(f),
            CellValue::Bool(b) => Value::Bool(*b),
            CellValue::Bytes(b) => {
                let hex: Vec<String> = b.iter().map(|byte| format!("{:02x}", byte)).collect();
                Value::String(hex.join(""))
            }
            CellValue::DateTime(dt) => Value::String(dt.to_rfc3339()),
            CellValue::Absent(_reason) => Value::Null,
            CellValue::Error(msg) => json!({"error": msg}),
            CellValue::TreeDepth(d) => json!(d),
        }
    }

    /// Render a single row as JSON object
    pub fn row_to_json(&self, columns: &[Column], values: &[CellValue]) -> Value {
        let mut obj = Map::new();
        for (col, val) in columns.iter().zip(values.iter()) {
            obj.insert(col.name.clone(), Self::cell_to_json(val));
        }
        Value::Object(obj)
    }

    /// Render rows as JSON array
    pub fn render<W: Write>(
        &self,
        writer: &mut W,
        columns: &[Column],
        rows: impl Iterator<Item = Vec<CellValue>>,
    ) -> std::io::Result<()> {
        let array: Vec<Value> = rows.map(|row| self.row_to_json(columns, &row)).collect();
        let json = Value::Array(array);

        if self.pretty {
            serde_json::to_writer_pretty(&mut *writer, &json)?;
        } else {
            serde_json::to_writer(&mut *writer, &json)?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Render a single row
    pub fn render_row<W: Write>(
        &self,
        writer: &mut W,
        columns: &[Column],
        values: &[CellValue],
    ) -> std::io::Result<()> {
        let json = self.row_to_json(columns, values);
        if self.pretty {
            serde_json::to_writer_pretty(&mut *writer, &json)?;
        } else {
            serde_json::to_writer(&mut *writer, &json)?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Render in JSON Lines format (one JSON object per line)
    pub fn render_jsonl<W: Write>(
        &self,
        writer: &mut W,
        columns: &[Column],
        rows: impl Iterator<Item = Vec<CellValue>>,
    ) -> std::io::Result<()> {
        for row in rows {
            let json = self.row_to_json(columns, &row);
            serde_json::to_writer(&mut *writer, &json)?;
            writeln!(writer)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_framework::module::ColumnType;

    #[test]
    fn test_json_render() {
        let renderer = JsonRenderer::new();
        let columns = vec![
            Column::new("name", ColumnType::String),
            Column::new("value", ColumnType::Int),
        ];

        let rows = vec![
            vec![CellValue::String("a".to_string()), CellValue::Int(1)],
            vec![CellValue::String("b".to_string()), CellValue::Int(2)],
        ];

        let mut output = Vec::new();
        renderer
            .render(&mut output, &columns, rows.into_iter())
            .unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("\"name\":\"a\""));
        assert!(result.contains("\"value\":2"));
    }

    #[test]
    fn test_cell_to_json() {
        assert_eq!(JsonRenderer::cell_to_json(&CellValue::Int(42)), json!(42));
        assert_eq!(
            JsonRenderer::cell_to_json(&CellValue::Bool(true)),
            json!(true)
        );
        assert_eq!(
            JsonRenderer::cell_to_json(&CellValue::Hex(255)),
            json!("0xff")
        );
    }
}
