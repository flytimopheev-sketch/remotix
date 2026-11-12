//! Мини-эмулятор экрана для резервного терминала.
//!
//! В EL9 / РЕД ОС нет `libvte-2.91-gtk4`, поэтому вместо VTE используется
//! `GtkTextView`. Обычный вывод команд в нём работает, но полноэкранные
//! приложения (`mc`, `vim`, `top`) рисуют экран через CSI-последовательности
//! (позиционирование курсора, очистка, альтернативный экран). Этот модуль
//! реализует сетку такого экрана; рисует её `DrawingArea` в `terminal.rs`.
//!
//! Модуль намеренно не зависит от GTK: парсер и сетку можно тестировать
//! обычными unit-тестами.

use super::TerminalModes;

/// Цвет ячейки: по умолчанию, из 16/256-цветной палитры или true color.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Color {
    #[default]
    Default,
    Indexed(u8),
    Rgb(u8, u8, u8),
}

/// Оформление одной ячейки.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Style {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub underline: bool,
    pub reverse: bool,
}

/// Ячейка экрана. `ch == '\0'` — продолжение широкого символа.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Cell {
    pub ch: char,
    pub style: Style,
}

impl Cell {
    fn blank() -> Self {
        Self {
            ch: ' ',
            style: Style::default(),
        }
    }
}

#[derive(Debug)]
enum Parser {
    Ground,
    Escape,
    /// CSI: накопленные параметры/промежуточные байты до финального 0x40..=0x7e.
    Csi(Vec<u8>),
    /// OSC/DCS/APC/PM: пропускаем строку до BEL или ST.
    String,
    /// Внутри строки встретился ESC; ждём `\`.
    StringEscape,
    /// После ESC ( / ) / * / + идёт один байт выбора набора символов.
    Charset,
}

/// Экран полноэкранного приложения.
pub(super) struct Screen {
    cols: usize,
    rows: usize,
    cells: Vec<Cell>,
    cx: usize,
    cy: usize,
    saved_cursor: (usize, usize),
    style: Style,
    scroll_top: usize,
    scroll_bottom: usize,
    autowrap: bool,
    insert: bool,
    cursor_visible: bool,
    wrap_pending: bool,
    parser: Parser,
    utf8: Vec<u8>,
    /// Ответы приложению (DSR/DA), которые нужно отправить в SSH.
    responses: Vec<u8>,
}

impl Screen {
    pub(super) fn new(cols: usize, rows: usize) -> Self {
        let cols = cols.max(2);
        let rows = rows.max(2);
        let mut screen = Self {
            cols,
            rows,
            cells: vec![Cell::blank(); cols * rows],
            cx: 0,
            cy: 0,
            saved_cursor: (0, 0),
            style: Style::default(),
            scroll_top: 0,
            scroll_bottom: rows - 1,
            autowrap: true,
            insert: false,
            cursor_visible: true,
            wrap_pending: false,
            parser: Parser::Ground,
            utf8: Vec::new(),
            responses: Vec::new(),
        };
        screen.reset();
        screen
    }

    /// Полная очистка перед входом в альтернативный экран.
    pub(super) fn reset(&mut self) {
        self.cells.fill(Cell::blank());
        self.cx = 0;
        self.cy = 0;
        self.saved_cursor = (0, 0);
        self.style = Style::default();
        self.scroll_top = 0;
        self.scroll_bottom = self.rows.saturating_sub(1);
        self.autowrap = true;
        self.insert = false;
        self.cursor_visible = true;
        self.wrap_pending = false;
        self.parser = Parser::Ground;
        self.utf8.clear();
        self.responses.clear();
    }

    /// Меняет размер сетки, сохраняя верхний левый угол (полноэкранное
    /// приложение всё равно перерисуется по SIGWINCH).
    pub(super) fn resize(&mut self, cols: usize, rows: usize) {
        let cols = cols.max(2);
        let rows = rows.max(2);
        if cols == self.cols && rows == self.rows {
            return;
        }
        let mut cells = vec![Cell::blank(); cols * rows];
        let copy_cols = cols.min(self.cols);
        let copy_rows = rows.min(self.rows);
        for y in 0..copy_rows {
            for x in 0..copy_cols {
                cells[y * cols + x] = self.cells[y * self.cols + x];
            }
        }
        self.cells = cells;
        self.cols = cols;
        self.rows = rows;
        self.cx = self.cx.min(cols - 1);
        self.cy = self.cy.min(rows - 1);
        self.scroll_top = 0;
        self.scroll_bottom = rows - 1;
        self.wrap_pending = false;
    }

    pub(super) fn cols(&self) -> usize {
        self.cols
    }

    pub(super) fn rows(&self) -> usize {
        self.rows
    }

    pub(super) fn cell(&self, x: usize, y: usize) -> Cell {
        self.cells[y * self.cols + x]
    }

    pub(super) fn cursor(&self) -> (usize, usize) {
        (self.cx, self.cy)
    }

    pub(super) fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    /// Текст видимого экрана (для копирования в буфер обмена).
    pub(super) fn text(&self) -> String {
        let mut out = String::new();
        for y in 0..self.rows {
            let mut line = String::with_capacity(self.cols);
            for x in 0..self.cols {
                let ch = self.cells[y * self.cols + x].ch;
                if ch != '\0' {
                    line.push(ch);
                }
            }
            out.push_str(line.trim_end());
            if y + 1 < self.rows {
                out.push('\n');
            }
        }
        out
    }

    pub(super) fn take_responses(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.responses)
    }

    pub(super) fn feed(&mut self, data: &[u8]) {
        for &byte in data {
            self.feed_byte(byte);
        }
    }

    fn feed_byte(&mut self, byte: u8) {
        let parser = std::mem::replace(&mut self.parser, Parser::Ground);
        match parser {
            Parser::Ground => self.ground(byte),
            Parser::Escape => self.escape(byte),
            // Набор символов после ESC ( / ) и т.п. — просто пропускаем байт.
            Parser::Charset => {}
            Parser::Csi(mut params) => {
                // Финальный байт CSI.
                if (0x40..=0x7e).contains(&byte) {
                    self.csi(&params, byte);
                } else if params.len() < 64 {
                    params.push(byte);
                    self.parser = Parser::Csi(params);
                }
            }
            Parser::String => match byte {
                0x07 => {}
                0x1b => self.parser = Parser::StringEscape,
                _ => self.parser = Parser::String,
            },
            Parser::StringEscape => {
                if byte != b'\\' && byte != 0x07 {
                    self.parser = Parser::String;
                }
            }
        }
    }

    fn ground(&mut self, byte: u8) {
        match byte {
            0x00..=0x1f => match byte {
                0x07 => {}
                0x08 => {
                    self.wrap_pending = false;
                    self.cx = self.cx.saturating_sub(1);
                }
                0x09 => {
                    self.wrap_pending = false;
                    self.cx = ((self.cx / 8 + 1) * 8).min(self.cols.saturating_sub(1));
                }
                0x0a..=0x0c => self.linefeed(),
                0x0d => {
                    self.cx = 0;
                    self.wrap_pending = false;
                }
                0x1b => self.parser = Parser::Escape,
                _ => {}
            },
            0x20..=0x7e => self.put_char(char::from(byte)),
            _ => {
                // UTF-8 может прийти разрезанным между chunks.
                self.utf8.push(byte);
                match std::str::from_utf8(&self.utf8) {
                    Ok(text) => {
                        let text = text.to_owned();
                        self.utf8.clear();
                        for ch in text.chars() {
                            self.put_char(ch);
                        }
                    }
                    Err(e) if e.error_len().is_none() => {}
                    Err(_) => self.utf8.clear(),
                }
            }
        }
    }

    fn escape(&mut self, byte: u8) {
        self.parser = Parser::Ground;
        match byte {
            b'[' => self.parser = Parser::Csi(Vec::new()),
            b']' | b'P' | b'^' | b'_' => self.parser = Parser::String,
            b'(' | b')' | b'*' | b'+' | b'-' | b'.' | b'/' => self.parser = Parser::Charset,
            b'7' => self.saved_cursor = (self.cx, self.cy),
            b'8' => {
                self.cx = self.saved_cursor.0.min(self.cols - 1);
                self.cy = self.saved_cursor.1.min(self.rows - 1);
            }
            b'D' => self.linefeed(),
            b'E' => {
                self.cx = 0;
                self.linefeed();
            }
            b'M' => self.reverse_linefeed(),
            b'c' => self.reset(),
            _ => {}
        }
    }

    fn csi(&mut self, params: &[u8], final_byte: u8) {
        // Любая escape-последовательность отменяет отложенный перенос строки.
        self.wrap_pending = false;
        let text = String::from_utf8_lossy(params);
        let (private, body) = match text.strip_prefix('?') {
            Some(rest) => (Some('?'), rest),
            None => match text.strip_prefix('>') {
                Some(rest) => (Some('>'), rest),
                None => (None, text.as_ref()),
            },
        };
        let values: Vec<usize> = body
            .split(';')
            .map(|part| {
                part.split(':')
                    .next()
                    .unwrap_or_default()
                    .parse()
                    .unwrap_or(0)
            })
            .collect();
        let first = || values.first().copied().filter(|&n| n != 0).unwrap_or(1);
        let second = || values.get(1).copied().unwrap_or(1);

        match final_byte {
            b'A' => self.cy = self.cy.saturating_sub(first()),
            b'B' => self.cy = (self.cy + first()).min(self.rows - 1),
            b'C' => self.cx = (self.cx + first()).min(self.cols - 1),
            b'D' => self.cx = self.cx.saturating_sub(first()),
            b'E' => {
                self.cx = 0;
                self.cy = (self.cy + first()).min(self.rows - 1);
            }
            b'F' => {
                self.cx = 0;
                self.cy = self.cy.saturating_sub(first());
            }
            b'G' => self.cx = first().saturating_sub(1).min(self.cols - 1),
            b'd' => self.cy = first().saturating_sub(1).min(self.rows - 1),
            b'H' | b'f' => {
                self.cy = first().saturating_sub(1).min(self.rows - 1);
                self.cx = second().saturating_sub(1).min(self.cols - 1);
            }
            b'J' => self.erase_display(values.first().copied().unwrap_or(0)),
            b'K' => self.erase_line(values.first().copied().unwrap_or(0)),
            b'X' => self.erase_chars(first()),
            b'@' => self.insert_chars(first()),
            b'P' => self.delete_chars(first()),
            b'L' => self.insert_lines(first()),
            b'M' => self.delete_lines(first()),
            b'S' => self.scroll_up(first()),
            b'T' => self.scroll_down(first()),
            b'm' => self.apply_sgr(&values),
            b'r' => {
                let top = first().saturating_sub(1);
                let bottom = second().saturating_sub(1).min(self.rows - 1);
                if top < bottom {
                    self.scroll_top = top;
                    self.scroll_bottom = bottom;
                    self.cx = 0;
                    self.cy = 0;
                }
            }
            b's' => self.saved_cursor = (self.cx, self.cy),
            b'u' => {
                self.cx = self.saved_cursor.0.min(self.cols - 1);
                self.cy = self.saved_cursor.1.min(self.rows - 1);
            }
            b'h' | b'l' => {
                let set = final_byte == b'h';
                for value in values {
                    self.set_mode(private, value, set);
                }
            }
            b'n' if values.first() == Some(&6) => {
                // CPR: приложение спрашивает позицию курсора.
                self.responses
                    .extend_from_slice(format!("\x1b[{};{}R", self.cy + 1, self.cx + 1).as_bytes());
            }
            b'n' if values.first() == Some(&5) => self.responses.extend_from_slice(b"\x1b[0n"),
            b'c' => self.responses.extend_from_slice(b"\x1b[?1;2c"),
            _ => {}
        }
    }

    fn set_mode(&mut self, private: Option<char>, value: usize, set: bool) {
        match (private, value) {
            (None, 4) => self.insert = set,
            (Some('?'), 7) => self.autowrap = set,
            (Some('?'), 25) => self.cursor_visible = set,
            _ => {}
        }
    }

    fn apply_sgr(&mut self, values: &[usize]) {
        let mut i = 0;
        while i < values.len() {
            match values[i] {
                0 => self.style = Style::default(),
                1 => self.style.bold = true,
                4 => self.style.underline = true,
                7 => self.style.reverse = true,
                22 => self.style.bold = false,
                24 => self.style.underline = false,
                27 => self.style.reverse = false,
                30..=37 => self.style.fg = Color::Indexed((values[i] - 30) as u8),
                39 => self.style.fg = Color::Default,
                40..=47 => self.style.bg = Color::Indexed((values[i] - 40) as u8),
                49 => self.style.bg = Color::Default,
                90..=97 => self.style.fg = Color::Indexed((values[i] - 90 + 8) as u8),
                100..=107 => self.style.bg = Color::Indexed((values[i] - 100 + 8) as u8),
                38 | 48 => {
                    let is_fg = values[i] == 38;
                    let color = match (values.get(i + 1), values.get(i + 2)) {
                        (Some(5), Some(index)) => {
                            i += 2;
                            Color::Indexed((*index).min(255) as u8)
                        }
                        (Some(2), Some(r)) => {
                            let g = values.get(i + 3).copied().unwrap_or(0).min(255);
                            let b = values.get(i + 4).copied().unwrap_or(0).min(255);
                            i += 4;
                            Color::Rgb((*r).min(255) as u8, g as u8, b as u8)
                        }
                        _ => Color::Default,
                    };
                    if is_fg {
                        self.style.fg = color;
                    } else {
                        self.style.bg = color;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    fn char_width(ch: char) -> usize {
        let code = ch as u32;
        if matches!(code, 0x0300..=0x036f | 0x1ab0..=0x1aff | 0x1dc0..=0x1dff
            | 0x20d0..=0x20ff | 0xfe20..=0xfe2f)
        {
            return 0;
        }
        if matches!(code,
            0x1100..=0x115f | 0x2e80..=0xa4cf | 0xac00..=0xd7a3
            | 0xf900..=0xfaff | 0xfe30..=0xfe4f | 0xff00..=0xff60
            | 0xffe0..=0xffe6 | 0x1f300..=0x1f64f | 0x1f900..=0x1f9ff
            | 0x20000..=0x3fffd)
        {
            2
        } else {
            1
        }
    }

    fn put_char(&mut self, ch: char) {
        let width = Self::char_width(ch);
        if width == 0 {
            return;
        }
        if self.wrap_pending && self.autowrap {
            self.cx = 0;
            self.linefeed();
            self.wrap_pending = false;
        }
        if width == 2 && self.cx + 1 >= self.cols {
            if self.autowrap {
                self.cx = 0;
                self.linefeed();
            } else {
                self.cx = self.cols.saturating_sub(2);
            }
        } else if self.cx >= self.cols {
            if self.autowrap {
                self.cx = 0;
                self.linefeed();
            } else {
                self.cx = self.cols - 1;
            }
        }

        if self.insert {
            let start = self.cy * self.cols;
            for x in (self.cx + width..self.cols).rev() {
                self.cells[start + x] = self.cells[start + x - width];
            }
            for x in self.cx..self.cx + width {
                self.cells[start + x] = Cell::blank();
            }
        }

        let index = self.cy * self.cols + self.cx;
        self.cells[index] = Cell {
            ch,
            style: self.style,
        };
        if width == 2 && self.cx + 1 < self.cols {
            self.cells[index + 1] = Cell {
                ch: '\0',
                style: self.style,
            };
        }
        self.cx += width;
        if self.cx >= self.cols {
            self.cx = self.cols.saturating_sub(1);
            self.wrap_pending = self.autowrap;
        }
    }

    fn linefeed(&mut self) {
        self.wrap_pending = false;
        if self.cy >= self.scroll_bottom {
            self.scroll_up(1);
        } else if self.cy + 1 < self.rows {
            self.cy += 1;
        }
    }

    fn reverse_linefeed(&mut self) {
        self.wrap_pending = false;
        if self.cy <= self.scroll_top {
            self.scroll_down(1);
        } else {
            self.cy = self.cy.saturating_sub(1);
        }
    }

    fn scroll_up(&mut self, n: usize) {
        let n = n.min(self.scroll_bottom - self.scroll_top + 1);
        for _ in 0..n {
            for y in self.scroll_top..self.scroll_bottom {
                let src = (y + 1) * self.cols;
                let dst = y * self.cols;
                let row = self.cells[src..src + self.cols].to_vec();
                self.cells[dst..dst + self.cols].copy_from_slice(&row);
            }
            let start = self.scroll_bottom * self.cols;
            self.cells[start..start + self.cols].fill(Cell::blank());
        }
    }

    fn scroll_down(&mut self, n: usize) {
        let n = n.min(self.scroll_bottom - self.scroll_top + 1);
        for _ in 0..n {
            for y in (self.scroll_top + 1..=self.scroll_bottom).rev() {
                let src = (y - 1) * self.cols;
                let dst = y * self.cols;
                let row = self.cells[src..src + self.cols].to_vec();
                self.cells[dst..dst + self.cols].copy_from_slice(&row);
            }
            let start = self.scroll_top * self.cols;
            self.cells[start..start + self.cols].fill(Cell::blank());
        }
    }

    fn erase_display(&mut self, mode: usize) {
        match mode {
            1 => {
                for y in 0..=self.cy {
                    let end = if y == self.cy { self.cx } else { self.cols - 1 };
                    self.erase_row(y, 0, end);
                }
            }
            2 | 3 => self.cells.fill(Cell::blank()),
            _ => {
                for y in self.cy..self.rows {
                    let start = if y == self.cy { self.cx } else { 0 };
                    self.erase_row(y, start, self.cols - 1);
                }
            }
        }
    }

    fn erase_line(&mut self, mode: usize) {
        match mode {
            1 => self.erase_row(self.cy, 0, self.cx),
            2 => self.erase_row(self.cy, 0, self.cols - 1),
            _ => self.erase_row(self.cy, self.cx, self.cols - 1),
        }
    }

    fn erase_row(&mut self, y: usize, from: usize, to: usize) {
        if from > to || y >= self.rows || from >= self.cols {
            return;
        }
        let end = to.min(self.cols - 1);
        let start = y * self.cols + from;
        let stop = y * self.cols + end + 1;
        self.cells[start..stop].fill(Cell::blank());
    }

    fn erase_chars(&mut self, n: usize) {
        let end = (self.cx + n - 1).min(self.cols - 1);
        self.erase_row(self.cy, self.cx, end);
    }

    fn insert_chars(&mut self, n: usize) {
        let n = n.min(self.cols - self.cx);
        let start = self.cy * self.cols + self.cx;
        let end = self.cy * self.cols + self.cols;
        let row = self.cells[start..end].to_vec();
        for i in 0..row.len() {
            self.cells[start + i] = if i < n { Cell::blank() } else { row[i - n] };
        }
    }

    fn delete_chars(&mut self, n: usize) {
        let n = n.min(self.cols - self.cx);
        let start = self.cy * self.cols + self.cx;
        let end = self.cy * self.cols + self.cols;
        let row = self.cells[start..end].to_vec();
        for i in 0..row.len() {
            self.cells[start + i] = row.get(i + n).copied().unwrap_or_else(Cell::blank);
        }
    }

    fn insert_lines(&mut self, n: usize) {
        if self.cy < self.scroll_top || self.cy > self.scroll_bottom {
            return;
        }
        let n = n.min(self.scroll_bottom - self.cy + 1);
        for _ in 0..n {
            for y in (self.cy + 1..=self.scroll_bottom).rev() {
                let src = (y - 1) * self.cols;
                let dst = y * self.cols;
                let row = self.cells[src..src + self.cols].to_vec();
                self.cells[dst..dst + self.cols].copy_from_slice(&row);
            }
            let start = self.cy * self.cols;
            self.cells[start..start + self.cols].fill(Cell::blank());
        }
    }

    fn delete_lines(&mut self, n: usize) {
        if self.cy < self.scroll_top || self.cy > self.scroll_bottom {
            return;
        }
        let n = n.min(self.scroll_bottom - self.cy + 1);
        for _ in 0..n {
            for y in self.cy..self.scroll_bottom {
                let src = (y + 1) * self.cols;
                let dst = y * self.cols;
                let row = self.cells[src..src + self.cols].to_vec();
                self.cells[dst..dst + self.cols].copy_from_slice(&row);
            }
            let start = self.scroll_bottom * self.cols;
            self.cells[start..start + self.cols].fill(Cell::blank());
        }
    }
}

/// Кусок вывода и то, куда его направить.
pub(super) struct RoutedChunk {
    pub alt: bool,
    pub data: Vec<u8>,
}

/// Разбирает поток вывода: определяет альтернативный экран и запоминает
/// режимы терминала, нужные для кодирования клавиатуры и мыши.
pub(super) struct OutputRouter {
    alt: bool,
    /// Альтернативный экран включён из-за `ESC[?25l` (не `?1049`).
    /// Такие программы (например, `top`) не просят отдельный экран, но
    /// рисуют его позиционированием курсора.
    cursor_alt: bool,
    pending: Vec<u8>,
    modes: TerminalModes,
}

impl OutputRouter {
    pub(super) fn new() -> Self {
        Self {
            alt: false,
            cursor_alt: false,
            pending: Vec::new(),
            modes: TerminalModes::default(),
        }
    }

    pub(super) fn modes(&self) -> TerminalModes {
        self.modes
    }

    pub(super) fn alt(&self) -> bool {
        self.alt
    }

    /// Режет данные на обычные и альтернативно-экранные части.
    ///
    /// Неполная escape-последовательность в конце chunks сохраняется до
    /// следующего вызова (в том числе `ESC[?1049h`, разрезанный на две части).
    pub(super) fn route(&mut self, data: &[u8]) -> Vec<RoutedChunk> {
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut seg_start = 0;
        let mut i = 0;

        while i < buf.len() {
            if buf[i] != 0x1b {
                i += 1;
                continue;
            }
            if i + 1 >= buf.len() {
                break;
            }
            let next = buf[i + 1];
            let end = match next {
                b'[' => {
                    let mut end = None;
                    for (offset, &b) in buf[i + 2..].iter().enumerate() {
                        if (0x40..=0x7e).contains(&b) {
                            end = Some(i + 2 + offset);
                            break;
                        }
                    }
                    match end {
                        Some(end) => end,
                        None => break,
                    }
                }
                b']' | b'P' | b'^' | b'_' => {
                    // Строка OSC/DCS: ищем BEL или ST.
                    let mut end = None;
                    let mut j = i + 2;
                    while j < buf.len() {
                        if buf[j] == 0x07 {
                            end = Some(j);
                            break;
                        }
                        if buf[j] == 0x1b && buf.get(j + 1) == Some(&b'\\') {
                            end = Some(j + 1);
                            break;
                        }
                        j += 1;
                    }
                    match end {
                        Some(end) => end,
                        None => break,
                    }
                }
                _ => i + 1,
            };

            let mut toggle = None;
            if next == b'[' {
                toggle = self.apply_csi(&buf[i + 2..end], buf[end]);
            }
            i = end + 1;

            // Команда переключения альтернативного экрана относится к
            // старому режиму, а всё после неё — уже к новому.
            if let Some(alt) = toggle {
                if alt != self.alt {
                    if end + 1 > seg_start {
                        out.push(RoutedChunk {
                            alt: self.alt,
                            data: buf[seg_start..end + 1].to_vec(),
                        });
                    }
                    self.alt = alt;
                    seg_start = end + 1;
                }
            }
        }

        if i < buf.len() {
            // Хвост — незавершённая escape-последовательность.
            if i > seg_start {
                out.push(RoutedChunk {
                    alt: self.alt,
                    data: buf[seg_start..i].to_vec(),
                });
            }
            // Ограничение на случай «мусорного» ESC без завершения.
            if buf.len() - i <= 4096 {
                self.pending = buf[i..].to_vec();
            } else if i < buf.len() {
                out.push(RoutedChunk {
                    alt: self.alt,
                    data: buf[i..].to_vec(),
                });
            }
        } else if seg_start < buf.len() {
            out.push(RoutedChunk {
                alt: self.alt,
                data: buf[seg_start..].to_vec(),
            });
        }

        out
    }

    /// Обновляет режимы терминала, если пришла CSI-команда `h`/`l`.
    ///
    /// Возвращает новое состояние альтернативного экрана, если команда
    /// переключает его (`?47`, `?1047`, `?1049`).
    fn apply_csi(&mut self, params: &[u8], final_byte: u8) -> Option<bool> {
        if final_byte != b'h' && final_byte != b'l' {
            return None;
        }
        let text = std::str::from_utf8(params).ok()?;
        let body = text.strip_prefix('?')?;
        let set = final_byte == b'h';
        let mut alt = None;

        for part in body.split(';') {
            let Ok(value) = part.parse::<u16>() else {
                continue;
            };
            match value {
                1 => self.modes.app_cursor = set,
                9 => {
                    self.modes.mouse = if set {
                        super::MouseMode::X10
                    } else {
                        super::MouseMode::Off
                    }
                }
                // `top` и подобные программы не переключают ?1049, а просто
                // прячут курсор и рисуют полноэкранный вывод позиционированием.
                // Считаем скрытый курсор признаком такого экрана; показ
                // курсора возвращает обычный TextView.
                25 if !set && !self.alt => {
                    alt = Some(true);
                    self.cursor_alt = true;
                }
                25 if set && self.cursor_alt => {
                    alt = Some(false);
                    self.cursor_alt = false;
                }
                47 | 1047 | 1049 => {
                    alt = Some(set);
                    self.cursor_alt = false;
                }
                1000 => {
                    self.modes.mouse = if set {
                        super::MouseMode::Normal
                    } else {
                        super::MouseMode::Off
                    }
                }
                1002 => {
                    self.modes.mouse = if set {
                        super::MouseMode::Button
                    } else {
                        super::MouseMode::Off
                    }
                }
                1003 => {
                    self.modes.mouse = if set {
                        super::MouseMode::Any
                    } else {
                        super::MouseMode::Off
                    }
                }
                1006 => self.modes.sgr_mouse = set,
                2004 => self.modes.bracketed_paste = set,
                _ => {}
            }
        }

        alt
    }
}
