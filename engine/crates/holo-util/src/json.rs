//! A minimal JSON value model with parser + serializer (RFC 8259).
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Value>),
    Obj(BTreeMap<String, Value>),
}

impl Value {
    pub fn obj(pairs: Vec<(&str, Value)>) -> Value {
        Value::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
    pub fn s(v: impl Into<String>) -> Value {
        Value::Str(v.into())
    }
    pub fn n(v: f64) -> Value {
        Value::Num(v)
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self { Value::Obj(m) => m.get(key), _ => None }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self { Value::Str(s) => Some(s), _ => None }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self { Value::Num(n) => Some(*n), _ => None }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self { Value::Num(n) if n.fract() == 0.0 && n.abs() < 9e18 => Some(*n as i64), _ => None }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self { Value::Bool(b) => Some(*b), _ => None }
    }
    pub fn as_arr(&self) -> Option<&[Value]> {
        match self { Value::Arr(a) => Some(a), _ => None }
    }
    pub fn str_or<'a>(&'a self, key: &str, def: &'a str) -> &'a str {
        self.get(key).and_then(|v| v.as_str()).unwrap_or(def)
    }

    pub fn parse(input: &str) -> Result<Value, String> {
        let mut p = Parser { b: input.as_bytes(), i: 0 };
        p.skip_ws();
        let v = p.value()?;
        p.skip_ws();
        if p.i != p.b.len() {
            return Err(format!("json: trailing data at byte {}", p.i));
        }
        Ok(v)
    }

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(true) => out.push_str("true"),
            Value::Bool(false) => out.push_str("false"),
            Value::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 9.0e15 {
                    out.push_str(&format!("{}", *n as i64));
                } else {
                    out.push_str(&format!("{}", n));
                }
            }
            Value::Str(s) => write_escaped(s, out),
            Value::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 { out.push(','); }
                    v.write(out);
                }
                out.push(']');
            }
            Value::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 { out.push(','); }
                    write_escaped(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> { b: &'a [u8], i: usize }

impl<'a> Parser<'a> {
    fn skip_ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> { self.b.get(self.i).copied() }
    fn eat(&mut self, lit: &str) -> Result<(), String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(())
        } else {
            Err(format!("json: expected {:?} at byte {}", lit, self.i))
        }
    }
    fn value(&mut self) -> Result<Value, String> {
        self.skip_ws();
        match self.peek() {
            Some(b'n') => { self.eat("null")?; Ok(Value::Null) }
            Some(b't') => { self.eat("true")?; Ok(Value::Bool(true)) }
            Some(b'f') => { self.eat("false")?; Ok(Value::Bool(false)) }
            Some(b'"') => Ok(Value::Str(self.string()?)),
            Some(b'[') => {
                self.i += 1;
                let mut arr = Vec::new();
                self.skip_ws();
                if self.peek() == Some(b']') { self.i += 1; return Ok(Value::Arr(arr)); }
                loop {
                    arr.push(self.value()?);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => { self.i += 1; return Ok(Value::Arr(arr)); }
                        _ => return Err(format!("json: expected , or ] at byte {}", self.i)),
                    }
                }
            }
            Some(b'{') => {
                self.i += 1;
                let mut m = BTreeMap::new();
                self.skip_ws();
                if self.peek() == Some(b'}') { self.i += 1; return Ok(Value::Obj(m)); }
                loop {
                    self.skip_ws();
                    let key = self.string()?;
                    self.skip_ws();
                    if self.peek() != Some(b':') {
                        return Err(format!("json: expected ':' at byte {}", self.i));
                    }
                    self.i += 1;
                    let v = self.value()?;
                    m.insert(key, v);
                    self.skip_ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => { self.i += 1; return Ok(Value::Obj(m)); }
                        _ => return Err(format!("json: expected , or }} at byte {}", self.i)),
                    }
                }
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(format!("json: unexpected byte at {}", self.i)),
        }
    }
    fn number(&mut self) -> Result<Value, String> {
        let start = self.i;
        if self.peek() == Some(b'-') { self.i += 1; }
        while self.peek().map(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-')).unwrap_or(false) {
            self.i += 1;
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        s.parse::<f64>().map(Value::Num).map_err(|_| format!("json: bad number {:?}", s))
    }
    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err(format!("json: expected string at byte {}", self.i));
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            match self.peek() {
                None => return Err("json: unterminated string".into()),
                Some(b'"') => { self.i += 1; return Ok(out); }
                Some(b'\\') => {
                    self.i += 1;
                    match self.peek() {
                        Some(b'"') => { out.push('"'); self.i += 1; }
                        Some(b'\\') => { out.push('\\'); self.i += 1; }
                        Some(b'/') => { out.push('/'); self.i += 1; }
                        Some(b'b') => { out.push('\x08'); self.i += 1; }
                        Some(b'f') => { out.push('\x0c'); self.i += 1; }
                        Some(b'n') => { out.push('\n'); self.i += 1; }
                        Some(b'r') => { out.push('\r'); self.i += 1; }
                        Some(b't') => { out.push('\t'); self.i += 1; }
                        Some(b'u') => {
                            self.i += 1;
                            let cp = self.hex4()?;
                            let ch = if (0xd800..0xdc00).contains(&cp) {
                                if self.b[self.i..].starts_with(b"\\u") {
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    char::from_u32(0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00)).unwrap_or('\u{fffd}')
                                } else { '\u{fffd}' }
                            } else {
                                char::from_u32(cp).unwrap_or('\u{fffd}')
                            };
                            out.push(ch);
                        }
                        _ => return Err("json: bad escape".into()),
                    }
                }
                Some(_) => {
                    let rest = std::str::from_utf8(&self.b[self.i..]).map_err(|_| "json: invalid utf-8".to_string())?;
                    let c = rest.chars().next().unwrap();
                    out.push(c);
                    self.i += c.len_utf8();
                }
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        if self.i + 4 > self.b.len() { return Err("json: truncated \\u escape".into()); }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4]).unwrap();
        let v = u32::from_str_radix(s, 16).map_err(|_| "json: bad \\u escape".to_string())?;
        self.i += 4;
        Ok(v)
    }
}

pub fn parse(text: &str) -> Result<Value, String> {
    Value::parse(text)
}

pub fn to_string(v: &Value) -> String {
    v.to_json()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip() {
        let src = r#"{"a":1,"b":[true,false,null,"x\ny"],"c":{"d":-2.5,"e":1e2}}"#;
        let v = parse(src).unwrap();
        assert_eq!(v.get("a").and_then(|v| v.as_i64()), Some(1));
        assert_eq!(v.get("b").unwrap().as_arr().unwrap()[3].as_str(), Some("x\ny"));
        let re = parse(&v.to_json()).unwrap();
        assert_eq!(v, re);
    }
    #[test]
    fn errors() {
        assert!(parse("{").is_err());
        assert!(parse("[1,]").is_err());
        assert!(parse("\"abc").is_err());
        assert!(parse("{} extra").is_err());
    }
}
