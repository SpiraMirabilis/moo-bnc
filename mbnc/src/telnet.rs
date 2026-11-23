//! Minimal streaming telnet parser / encoder.

pub const IAC: u8 = 255;
pub const DONT: u8 = 254;
pub const DO: u8 = 253;
pub const WONT: u8 = 252;
pub const WILL: u8 = 251;
pub const SB: u8 = 250;
pub const GA: u8 = 249;
pub const NOP: u8 = 241;
pub const SE: u8 = 240;
pub const EOR: u8 = 239;

pub mod opt {
    pub const ECHO: u8 = 1;
    pub const SGA: u8 = 3;
    pub const TTYPE: u8 = 24;
    pub const EOR: u8 = 25;
    pub const NAWS: u8 = 31;
    pub const CHARSET: u8 = 42;
    pub const MSDP: u8 = 69;
    pub const MSSP: u8 = 70;
    pub const COMPRESS2: u8 = 86;
    pub const COMPRESS3: u8 = 87;
    pub const MSP: u8 = 90;
    pub const MXP: u8 = 91;
    pub const ATCP: u8 = 200;
    pub const GMCP: u8 = 201;
}

/// TTYPE subnegotiation codes.
pub const TTYPE_IS: u8 = 0;
pub const TTYPE_SEND: u8 = 1;

/// Subnegotiations longer than this are truncated (protects memory).
const MAX_SB_LEN: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Plain data, IAC IAC already unescaped.
    Data(Vec<u8>),
    /// IAC <cmd> for single-byte commands (GA, EOR, NOP, AYT, ...).
    Command(u8),
    /// IAC WILL/WONT/DO/DONT <option>.
    Negotiate(u8, u8),
    /// IAC SB <option> <payload> IAC SE, payload unescaped.
    Sub(u8, Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Normal,
    Iac,
    Verb(u8),
    SbOpt,
    Sb,
    SbIac,
}

#[derive(Debug)]
pub struct Parser {
    state: State,
    data: Vec<u8>,
    sb_opt: u8,
    sb_buf: Vec<u8>,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub fn new() -> Self {
        Parser { state: State::Normal, data: Vec::new(), sb_opt: 0, sb_buf: Vec::new() }
    }

    fn flush(&mut self, out: &mut Vec<Event>) {
        if !self.data.is_empty() {
            out.push(Event::Data(std::mem::take(&mut self.data)));
        }
    }

    /// Feed bytes; complete events are appended to `out`. Pending plain data is
    /// flushed at the end of each call; partial commands are kept for the next call.
    pub fn feed(&mut self, input: &[u8], out: &mut Vec<Event>) {
        for &b in input {
            self.byte(b, out);
        }
        self.flush(out);
    }

    fn byte(&mut self, b: u8, out: &mut Vec<Event>) {
        match self.state {
            State::Normal => {
                if b == IAC {
                    self.state = State::Iac;
                } else {
                    self.data.push(b);
                }
            }
            State::Iac => self.after_iac(b, out),
            State::Verb(v) => {
                out.push(Event::Negotiate(v, b));
                self.state = State::Normal;
            }
            State::SbOpt => {
                self.sb_opt = b;
                self.sb_buf.clear();
                self.state = State::Sb;
            }
            State::Sb => {
                if b == IAC {
                    self.state = State::SbIac;
                } else if self.sb_buf.len() < MAX_SB_LEN {
                    self.sb_buf.push(b);
                }
            }
            State::SbIac => match b {
                IAC => {
                    if self.sb_buf.len() < MAX_SB_LEN {
                        self.sb_buf.push(IAC);
                    }
                    self.state = State::Sb;
                }
                SE => {
                    out.push(Event::Sub(self.sb_opt, std::mem::take(&mut self.sb_buf)));
                    self.state = State::Normal;
                }
                _ => {
                    // Malformed: IAC <x> inside a subnegotiation. Terminate the
                    // subnegotiation and treat <x> as following a bare IAC.
                    out.push(Event::Sub(self.sb_opt, std::mem::take(&mut self.sb_buf)));
                    self.after_iac(b, out);
                }
            },
        }
    }

    fn after_iac(&mut self, b: u8, out: &mut Vec<Event>) {
        match b {
            IAC => {
                self.data.push(IAC);
                self.state = State::Normal;
            }
            WILL | WONT | DO | DONT => {
                self.flush(out);
                self.state = State::Verb(b);
            }
            SB => {
                self.flush(out);
                self.state = State::SbOpt;
            }
            _ => {
                self.flush(out);
                out.push(Event::Command(b));
                self.state = State::Normal;
            }
        }
    }
}

/// Append `data` to `out`, doubling any IAC bytes.
pub fn escape_into(data: &[u8], out: &mut Vec<u8>) {
    for &b in data {
        if b == IAC {
            out.push(IAC);
        }
        out.push(b);
    }
}

pub fn encode(ev: &Event, out: &mut Vec<u8>) {
    match ev {
        Event::Data(d) => escape_into(d, out),
        Event::Command(c) => out.extend_from_slice(&[IAC, *c]),
        Event::Negotiate(v, o) => out.extend_from_slice(&[IAC, *v, *o]),
        Event::Sub(o, p) => encode_sub(*o, p, out),
    }
}

pub fn encode_sub(opt: u8, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&[IAC, SB, opt]);
    escape_into(payload, out);
    out.extend_from_slice(&[IAC, SE]);
}

/// Strip telnet sequences from a byte stream (convenience for tests / simple tools).
pub fn strip(parser: &mut Parser, input: &[u8]) -> Vec<u8> {
    let mut evs = Vec::new();
    parser.feed(input, &mut evs);
    let mut out = Vec::new();
    for e in evs {
        if let Event::Data(d) = e {
            out.extend_from_slice(&d);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_all(chunks: &[&[u8]]) -> Vec<Event> {
        let mut p = Parser::new();
        let mut out = Vec::new();
        for c in chunks {
            p.feed(c, &mut out);
        }
        out
    }

    #[test]
    fn mixed_stream() {
        let ev = parse_all(&[b"hi\xff\xff!\xff\xfb\x01abc\xff\xfa\xc9Core.Hello {}\xff\xf0\xff\xf9"]);
        assert_eq!(
            ev,
            vec![
                Event::Data(b"hi\xff!".to_vec()),
                Event::Negotiate(WILL, 1),
                Event::Data(b"abc".to_vec()),
                Event::Sub(201, b"Core.Hello {}".to_vec()),
                Event::Command(GA),
            ]
        );
    }

    #[test]
    fn split_across_feeds() {
        let ev = parse_all(&[b"a\xff", b"\xfb", b"\x18b\xff\xfa\x18\x01\xff", b"\xf0"]);
        assert_eq!(
            ev,
            vec![
                Event::Data(b"a".to_vec()),
                Event::Negotiate(WILL, 24),
                Event::Data(b"b".to_vec()),
                Event::Sub(24, vec![1]),
            ]
        );
    }

    #[test]
    fn roundtrip() {
        let src = b"x\xff\xff\xff\xfd\x1f\xff\xfa\xc9a\xff\xffb\xff\xf0\xff\xefy";
        let ev = parse_all(&[src]);
        let mut out = Vec::new();
        for e in &ev {
            encode(e, &mut out);
        }
        assert_eq!(&out[..], &src[..]);
    }

    #[test]
    fn malformed_sb() {
        let ev = parse_all(&[b"\xff\xfa\xc9abc\xff\xf9z"]);
        assert_eq!(
            ev,
            vec![Event::Sub(201, b"abc".to_vec()), Event::Command(GA), Event::Data(b"z".to_vec())]
        );
    }
}
