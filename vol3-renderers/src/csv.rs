//! CSV renderer.

use std::io::Write;

use vol3_core::types::CellValue;
use vol3_framework::module::Column;

use crate::treegrid::format_cell_value;

/// CSV renderer
pub struct CsvRenderer {
    /// Delimiter (default: comma)
    delimiter: char,
    /// Quote character
    quote: char,
    /// Escape character (default: backslash, like Python csv with escapechar="\\")
    escape: char,
}

impl Default for CsvRenderer {
    fn default() -> Self {
        Self::new()
    }
}

impl CsvRenderer {
    /// Create a new CSV renderer
    pub fn new() -> Self {
        Self {
            delimiter: ',',
            quote: '"',
            escape: '\\',
        }
    }

    /// Set the delimiter
    pub fn with_delimiter(mut self, delimiter: char) -> Self {
        self.delimiter = delimiter;
        self
    }

    /// Set the quote character
    pub fn with_quote(mut self, quote: char) -> Self {
        self.quote = quote;
        self
    }

    /// Render header with TreeDepth as first column (like Python vol3)
    pub fn render_header<W: Write>(
        &self,
        writer: &mut W,
        columns: &[Column],
    ) -> std::io::Result<()> {
        // Python vol3 CSV renderer adds TreeDepth as the first column
        write!(writer, "TreeDepth")?;
        for col in columns.iter() {
            write!(writer, "{}", self.delimiter)?;
            self.write_field(writer, &col.name)?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Render a single row with TreeDepth prepended (like Python vol3)
    /// If the first value is CellValue::TreeDepth, extract and use it
    pub fn render_row<W: Write>(
        &self,
        writer: &mut W,
        values: &[CellValue],
    ) -> std::io::Result<()> {
        // Check if first value is TreeDepth
        if let Some(CellValue::TreeDepth(depth)) = values.first() {
            // Use the depth from the row, render remaining values
            write!(writer, "{}", depth)?;
            for value in values.iter().skip(1) {
                write!(writer, "{}", self.delimiter)?;
                let formatted = format_cell_value(value);
                self.write_field(writer, &formatted)?;
            }
            writeln!(writer)?;
            Ok(())
        } else {
            // No tree depth in row, use default 0
            self.render_row_with_depth(writer, values, 0)
        }
    }

    /// Render a row with specified tree depth
    pub fn render_row_with_depth<W: Write>(
        &self,
        writer: &mut W,
        values: &[CellValue],
        depth: usize,
    ) -> std::io::Result<()> {
        // Python vol3 CSV renderer prepends TreeDepth to each row
        write!(writer, "{}", depth)?;
        for value in values.iter() {
            write!(writer, "{}", self.delimiter)?;
            let formatted = format_cell_value(value);
            self.write_field(writer, &formatted)?;
        }
        writeln!(writer)?;
        Ok(())
    }

    /// Write a field, quoting if necessary and escaping backslashes
    fn write_field<W: Write>(&self, writer: &mut W, value: &str) -> std::io::Result<()> {
        let needs_quote = value.contains(self.delimiter)
            || value.contains(self.quote)
            || value.contains('\n')
            || value.contains('\r');

        if needs_quote {
            write!(writer, "{}", self.quote)?;
            for ch in value.chars() {
                if ch == self.quote {
                    write!(writer, "{}{}", self.quote, self.quote)?;
                } else if ch == self.escape {
                    // Escape backslashes like Python's csv module with escapechar="\\"
                    write!(writer, "{}{}", self.escape, self.escape)?;
                } else {
                    write!(writer, "{}", ch)?;
                }
            }
            write!(writer, "{}", self.quote)?;
        } else {
            // Even outside quotes, escape backslashes to match Python behavior
            for ch in value.chars() {
                if ch == self.escape {
                    write!(writer, "{}{}", self.escape, self.escape)?;
                } else {
                    write!(writer, "{}", ch)?;
                }
            }
        }
        Ok(())
    }

    /// Render complete output
    pub fn render<W: Write>(
        &self,
        writer: &mut W,
        columns: &[Column],
        rows: impl Iterator<Item = Vec<CellValue>>,
    ) -> std::io::Result<()> {
        self.render_header(writer, columns)?;
        for row in rows {
            self.render_row(writer, &row)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vol3_framework::module::ColumnType;

    #[test]
    fn test_csv_simple() {
        let renderer = CsvRenderer::new();
        let columns = vec![
            Column::new("A", ColumnType::String),
            Column::new("B", ColumnType::Int),
        ];

        let mut output = Vec::new();
        renderer.render_header(&mut output, &columns).unwrap();
        renderer
            .render_row(
                &mut output,
                &[CellValue::String("hello".to_string()), CellValue::Int(42)],
            )
            .unwrap();

        let result = String::from_utf8(output).unwrap();
        // TreeDepth is prepended to header and rows
        assert_eq!(result, "TreeDepth,A,B\n0,hello,42\n");
    }

    #[test]
    fn test_csv_quoting() {
        let renderer = CsvRenderer::new();
        let mut output = Vec::new();

        renderer
            .render_row(
                &mut output,
                &[
                    CellValue::String("hello, world".to_string()),
                    CellValue::String("has \"quotes\"".to_string()),
                ],
            )
            .unwrap();

        let result = String::from_utf8(output).unwrap();
        // TreeDepth 0 is prepended
        assert_eq!(result, "0,\"hello, world\",\"has \"\"quotes\"\"\"\n");
    }
}
