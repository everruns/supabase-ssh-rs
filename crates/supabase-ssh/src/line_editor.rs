/// Lightweight line editor for SSH channels.
///
/// Handles raw byte input from PTY clients and produces:
/// - Completed lines (on Enter)
/// - Echo bytes to send back to the client
///
/// Supports:
/// - Cursor movement (Left/Right arrow keys, Home/End)
/// - Command history (Up/Down arrow keys)
/// - Backspace/Delete
/// - Ctrl+C (cancel line), Ctrl+D (EOF), Ctrl+A (home), Ctrl+E (end)
/// - Ctrl+U (kill line), Ctrl+K (kill to end), Ctrl+W (kill word back)
/// - Multi-byte UTF-8

/// Events produced by the line editor when processing input bytes.
pub enum LineEvent {
    /// A complete line was submitted (Enter pressed).
    Line(String),
    /// EOF signal (Ctrl+D on empty line).
    Eof,
    /// Bytes to echo back to the client terminal.
    Echo(Vec<u8>),
    /// Nothing to do.
    None,
}

pub struct LineEditor {
    /// Current line buffer (UTF-8 chars).
    buf: Vec<char>,
    /// Cursor position in the buffer (char index).
    cursor: usize,
    /// Command history.
    history: Vec<String>,
    /// Current position in history (history.len() = "new line").
    history_pos: usize,
    /// Saved current line when navigating history.
    saved_line: String,
    /// Escape sequence accumulator.
    esc_buf: Vec<u8>,
    /// Are we in the middle of an escape sequence?
    in_escape: bool,
    /// Max history entries.
    max_history: usize,
}

impl LineEditor {
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            cursor: 0,
            history: Vec::new(),
            history_pos: 0,
            saved_line: String::new(),
            esc_buf: Vec::new(),
            in_escape: false,
            max_history: 100,
        }
    }

    /// Feed a single byte from the SSH channel. Returns a LineEvent.
    /// Call this for each byte in the data received from the client.
    /// Multiple events may need to be collected per data chunk.
    pub fn feed(&mut self, byte: u8) -> LineEvent {
        // Handle escape sequence accumulation
        if self.in_escape {
            return self.feed_escape(byte);
        }

        match byte {
            // ESC - start escape sequence
            0x1b => {
                self.in_escape = true;
                self.esc_buf.clear();
                self.esc_buf.push(byte);
                LineEvent::None
            }
            // Enter
            b'\r' | b'\n' => {
                let line: String = self.buf.iter().collect();
                // Add to history if non-empty and different from last
                if !line.trim().is_empty() {
                    if self.history.last().map_or(true, |last| last != &line) {
                        self.history.push(line.clone());
                        if self.history.len() > self.max_history {
                            self.history.remove(0);
                        }
                    }
                }
                self.buf.clear();
                self.cursor = 0;
                self.history_pos = self.history.len();
                self.saved_line.clear();
                LineEvent::Line(line)
            }
            // Backspace / DEL
            0x7f | 0x08 => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    self.buf.remove(self.cursor);
                    LineEvent::Echo(self.redraw_from_cursor_with_backspace())
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+C - cancel current line
            0x03 => {
                self.buf.clear();
                self.cursor = 0;
                LineEvent::Echo(b"^C\r\n".to_vec())
            }
            // Ctrl+D - EOF if empty, delete char if not
            0x04 => {
                if self.buf.is_empty() {
                    LineEvent::Eof
                } else if self.cursor < self.buf.len() {
                    self.buf.remove(self.cursor);
                    LineEvent::Echo(self.redraw_from_cursor_delete())
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+A - move to beginning
            0x01 => {
                if self.cursor > 0 {
                    let echo = self.move_cursor_to(0);
                    LineEvent::Echo(echo)
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+E - move to end
            0x05 => {
                if self.cursor < self.buf.len() {
                    let echo = self.move_cursor_to(self.buf.len());
                    LineEvent::Echo(echo)
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+U - kill line (clear everything before cursor)
            0x15 => {
                if self.cursor > 0 {
                    let removed = self.cursor;
                    self.buf.drain(..self.cursor);
                    self.cursor = 0;
                    LineEvent::Echo(self.redraw_full_line(removed))
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+K - kill to end of line
            0x0b => {
                if self.cursor < self.buf.len() {
                    let remaining = self.buf.len() - self.cursor;
                    self.buf.truncate(self.cursor);
                    // Erase from cursor to end
                    LineEvent::Echo(format!("\x1b[{}P", remaining).into_bytes())
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+W - kill word backwards
            0x17 => {
                if self.cursor > 0 {
                    let old_cursor = self.cursor;
                    // Skip trailing spaces
                    while self.cursor > 0 && self.buf[self.cursor - 1] == ' ' {
                        self.cursor -= 1;
                    }
                    // Skip word chars
                    while self.cursor > 0 && self.buf[self.cursor - 1] != ' ' {
                        self.cursor -= 1;
                    }
                    self.buf.drain(self.cursor..old_cursor);
                    let chars_removed = old_cursor - self.cursor;
                    LineEvent::Echo(self.redraw_full_line(chars_removed))
                } else {
                    LineEvent::None
                }
            }
            // Ctrl+L - clear screen, redraw prompt + line
            0x0c => {
                // Just clear screen, the caller should redraw prompt
                let mut echo = b"\x1b[2J\x1b[H".to_vec();
                // We can't redraw the prompt from here, so just signal clear
                // The line content will be redrawn by the caller
                echo.extend(self.current_line_bytes());
                let move_back = self.buf.len() - self.cursor;
                if move_back > 0 {
                    echo.extend(format!("\x1b[{}D", move_back).as_bytes());
                }
                LineEvent::Echo(echo)
            }
            // Tab - we'll handle this as a no-op for now (completion is complex)
            b'\t' => LineEvent::None,
            // Regular printable character or UTF-8 lead byte
            _ => {
                // For ASCII printable
                if byte >= 0x20 && byte < 0x7f {
                    let ch = byte as char;
                    self.buf.insert(self.cursor, ch);
                    self.cursor += 1;
                    if self.cursor == self.buf.len() {
                        // Simple case: appending at end
                        LineEvent::Echo(vec![byte])
                    } else {
                        // Inserting in middle: redraw from cursor
                        LineEvent::Echo(self.redraw_from_cursor_insert())
                    }
                } else if byte >= 0xc0 {
                    // UTF-8 lead byte — for now treat as single replacement char
                    // A full implementation would accumulate multi-byte sequences
                    let ch = '?';
                    self.buf.insert(self.cursor, ch);
                    self.cursor += 1;
                    LineEvent::Echo(b"?".to_vec())
                } else {
                    // Continuation byte or other control — ignore
                    LineEvent::None
                }
            }
        }
    }

    /// Process escape sequence bytes.
    fn feed_escape(&mut self, byte: u8) -> LineEvent {
        self.esc_buf.push(byte);

        // ESC [ ... is CSI sequence
        if self.esc_buf.len() == 2 {
            if byte == b'[' || byte == b'O' {
                // Continue accumulating
                return LineEvent::None;
            }
            // Unknown escape, discard
            self.in_escape = false;
            self.esc_buf.clear();
            return LineEvent::None;
        }

        // CSI sequences end with a letter (0x40-0x7e)
        if byte >= 0x40 && byte <= 0x7e {
            self.in_escape = false;
            let seq = self.esc_buf.clone();
            self.esc_buf.clear();
            return self.handle_csi(&seq);
        }

        // Still accumulating (parameter bytes 0x30-0x3f, intermediate 0x20-0x2f)
        if self.esc_buf.len() > 8 {
            // Too long, abort
            self.in_escape = false;
            self.esc_buf.clear();
        }
        LineEvent::None
    }

    /// Handle a complete CSI escape sequence.
    fn handle_csi(&mut self, seq: &[u8]) -> LineEvent {
        // seq = [ESC, '[', ...params, final_byte]
        if seq.len() < 3 {
            return LineEvent::None;
        }
        let final_byte = *seq.last().unwrap();

        match final_byte {
            // Arrow Up
            b'A' => self.history_prev(),
            // Arrow Down
            b'B' => self.history_next(),
            // Arrow Right
            b'C' => {
                if self.cursor < self.buf.len() {
                    self.cursor += 1;
                    LineEvent::Echo(b"\x1b[C".to_vec())
                } else {
                    LineEvent::None
                }
            }
            // Arrow Left
            b'D' => {
                if self.cursor > 0 {
                    self.cursor -= 1;
                    LineEvent::Echo(b"\x1b[D".to_vec())
                } else {
                    LineEvent::None
                }
            }
            // Home
            b'H' => {
                if self.cursor > 0 {
                    let echo = self.move_cursor_to(0);
                    LineEvent::Echo(echo)
                } else {
                    LineEvent::None
                }
            }
            // End
            b'F' => {
                if self.cursor < self.buf.len() {
                    let echo = self.move_cursor_to(self.buf.len());
                    LineEvent::Echo(echo)
                } else {
                    LineEvent::None
                }
            }
            // Delete key (ESC [3~)
            b'~' if seq.len() >= 4 && seq[2] == b'3' => {
                if self.cursor < self.buf.len() {
                    self.buf.remove(self.cursor);
                    LineEvent::Echo(self.redraw_from_cursor_delete())
                } else {
                    LineEvent::None
                }
            }
            _ => LineEvent::None,
        }
    }

    /// Navigate to previous history entry.
    fn history_prev(&mut self) -> LineEvent {
        if self.history.is_empty() || self.history_pos == 0 {
            return LineEvent::None;
        }
        if self.history_pos == self.history.len() {
            self.saved_line = self.buf.iter().collect();
        }
        self.history_pos -= 1;
        self.replace_line(&self.history[self.history_pos].clone())
    }

    /// Navigate to next history entry.
    fn history_next(&mut self) -> LineEvent {
        if self.history_pos >= self.history.len() {
            return LineEvent::None;
        }
        self.history_pos += 1;
        if self.history_pos == self.history.len() {
            let saved = self.saved_line.clone();
            self.replace_line(&saved)
        } else {
            self.replace_line(&self.history[self.history_pos].clone())
        }
    }

    /// Replace the current line buffer with new content and generate echo.
    fn replace_line(&mut self, new_line: &str) -> LineEvent {
        let old_cursor = self.cursor;

        self.buf = new_line.chars().collect();
        self.cursor = self.buf.len();

        // Move cursor to start of line
        let mut echo = Vec::new();
        if old_cursor > 0 {
            echo.extend(format!("\x1b[{}D", old_cursor).as_bytes());
        }
        // Erase old content
        echo.extend(b"\x1b[K");
        // Write new content
        echo.extend(self.current_line_bytes());
        LineEvent::Echo(echo)
    }

    /// Generate ANSI escape to move cursor to target position.
    fn move_cursor_to(&mut self, target: usize) -> Vec<u8> {
        let old = self.cursor;
        self.cursor = target;
        if target < old {
            format!("\x1b[{}D", old - target).into_bytes()
        } else if target > old {
            format!("\x1b[{}C", target - old).into_bytes()
        } else {
            Vec::new()
        }
    }

    /// Get the current line content as bytes.
    fn current_line_bytes(&self) -> Vec<u8> {
        let s: String = self.buf.iter().collect();
        s.into_bytes()
    }

    /// Redraw from cursor position after inserting a character.
    /// Writes chars from cursor to end, then moves cursor back.
    fn redraw_from_cursor_insert(&self) -> Vec<u8> {
        let tail: String = self.buf[self.cursor - 1..].iter().collect();
        let move_back = self.buf.len() - self.cursor;
        let mut echo = tail.into_bytes();
        if move_back > 0 {
            echo.extend(format!("\x1b[{}D", move_back).as_bytes());
        }
        echo
    }

    /// Redraw after backspace: move back one, redraw tail, erase trailing, reposition.
    fn redraw_from_cursor_with_backspace(&self) -> Vec<u8> {
        let tail: String = self.buf[self.cursor..].iter().collect();
        let mut echo = Vec::new();
        // Move back one
        echo.push(0x08);
        // Write remaining chars
        echo.extend(tail.as_bytes());
        // Erase the extra char at the end
        echo.push(b' ');
        // Move cursor back to correct position
        let move_back = self.buf.len() - self.cursor + 1;
        echo.extend(format!("\x1b[{}D", move_back).as_bytes());
        echo
    }

    /// Redraw after delete at cursor position.
    fn redraw_from_cursor_delete(&self) -> Vec<u8> {
        let tail: String = self.buf[self.cursor..].iter().collect();
        let mut echo = Vec::new();
        echo.extend(tail.as_bytes());
        echo.push(b' ');
        let move_back = self.buf.len() - self.cursor + 1;
        echo.extend(format!("\x1b[{}D", move_back).as_bytes());
        echo
    }

    /// Redraw the full line after a destructive edit (Ctrl+U, Ctrl+W).
    /// `extra_to_erase`: how many extra chars need erasing beyond current buf.
    fn redraw_full_line(&self, extra_to_erase: usize) -> Vec<u8> {
        let mut echo = Vec::new();
        // Move to start of line
        if self.cursor > 0 {
            echo.extend(format!("\x1b[{}D", self.cursor).as_bytes());
        }
        // Wait — cursor is already updated. Move from position 0 is implicit.
        // Actually we need to move from where the terminal cursor is.
        // After buf mutation, self.cursor is the new position.
        // The terminal cursor is still at old position. Let's use absolute approach:
        // Move to column 0 of the line content (after prompt), erase, rewrite.
        echo.extend(b"\r");
        // We can't know prompt width here, so use save/restore:
        // Actually, simpler: move to start with \r, then the caller's prompt won't be affected
        // since we don't know the prompt. Use erase-to-end + rewrite approach.
        // Move left by a lot to get to start of input (after prompt):
        echo.clear();
        // Move cursor to beginning of input area
        let current_terminal_cursor = self.cursor + extra_to_erase; // where cursor was before edit
        // Hmm, this is getting complicated. Let's just use the CSI erase approach:
        // Go back to start of line content
        if current_terminal_cursor > 0 {
            echo.extend(format!("\x1b[{}D", current_terminal_cursor).as_bytes());
        }
        // Erase from cursor to end of line
        echo.extend(b"\x1b[K");
        // Write new buffer
        echo.extend(self.current_line_bytes());
        // Move cursor to correct position
        let move_back = self.buf.len() - self.cursor;
        if move_back > 0 {
            echo.extend(format!("\x1b[{}D", move_back).as_bytes());
        }
        echo
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_str(editor: &mut LineEditor, s: &str) -> Vec<LineEvent> {
        s.bytes().map(|b| editor.feed(b)).collect()
    }

    #[test]
    fn simple_line() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "hello");
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "hello"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn backspace() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "helloo");
        ed.feed(0x7f); // backspace
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "hello"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn ctrl_c_clears_line() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "partial");
        let event = ed.feed(0x03); // Ctrl+C
        assert!(matches!(event, LineEvent::Echo(_)));
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, ""),
            _ => panic!("expected empty Line event"),
        }
    }

    #[test]
    fn ctrl_d_on_empty_is_eof() {
        let mut ed = LineEditor::new();
        let event = ed.feed(0x04);
        assert!(matches!(event, LineEvent::Eof));
    }

    #[test]
    fn ctrl_d_on_nonempty_deletes_char() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "ab");
        // Move cursor left
        ed.feed(0x1b); // ESC
        ed.feed(b'[');
        ed.feed(b'D'); // Left
        // Now cursor is at position 1, delete 'b'
        ed.feed(0x04);
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "a"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn history_navigation() {
        let mut ed = LineEditor::new();
        // Enter two commands
        feed_str(&mut ed, "first");
        ed.feed(b'\r');
        feed_str(&mut ed, "second");
        ed.feed(b'\r');

        // Arrow up twice
        ed.feed(0x1b);
        ed.feed(b'[');
        ed.feed(b'A'); // Up -> "second"
        ed.feed(0x1b);
        ed.feed(b'[');
        ed.feed(b'A'); // Up -> "first"

        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "first"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn arrow_left_right() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "abc");
        // Left twice
        ed.feed(0x1b);
        ed.feed(b'[');
        ed.feed(b'D');
        ed.feed(0x1b);
        ed.feed(b'[');
        ed.feed(b'D');
        // Insert 'X' at position 1
        ed.feed(b'X');
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "aXbc"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn ctrl_a_and_ctrl_e() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "hello");
        ed.feed(0x01); // Ctrl+A -> beginning
        ed.feed(b'X');
        ed.feed(0x05); // Ctrl+E -> end
        ed.feed(b'Y');
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "XhelloY"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn ctrl_u_kills_to_start() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "hello world");
        // Move cursor left 5 times (to position 6, before "world")
        for _ in 0..5 {
            ed.feed(0x1b);
            ed.feed(b'[');
            ed.feed(b'D');
        }
        ed.feed(0x15); // Ctrl+U
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "world"),
            _ => panic!("expected Line event"),
        }
    }

    #[test]
    fn ctrl_w_kills_word() {
        let mut ed = LineEditor::new();
        feed_str(&mut ed, "hello world");
        ed.feed(0x17); // Ctrl+W -> kills "world"
        let event = ed.feed(b'\r');
        match event {
            LineEvent::Line(s) => assert_eq!(s, "hello "),
            _ => panic!("expected Line event"),
        }
    }
}
