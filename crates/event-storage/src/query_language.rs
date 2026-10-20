//! Bounded recursive-descent parser. Only static columns and bound values reach SQL.
use rusqlite::types::Value;

#[derive(Debug, thiserror::Error)]
#[error("query syntax at byte {offset}: {message}")]
pub struct QueryError {
    offset: usize,
    message: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Word(String),
    Text(String),
    Number(i64),
    Null,
    And,
    Or,
    Contains,
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Open,
    Close,
    End,
}
struct Parser<'a> {
    input: &'a str,
    offset: usize,
    token: Token,
    terms: usize,
    values: &'a mut Vec<Value>,
}

pub fn compile(input: &str, values: &mut Vec<Value>) -> Result<String, QueryError> {
    if input.len() > 4096 {
        return Err(QueryError {
            offset: 0,
            message: "maximum query size is 4096 bytes",
        });
    }
    let mut parser = Parser {
        input,
        offset: 0,
        token: Token::End,
        terms: 0,
        values,
    };
    parser.advance()?;
    let result = parser.or(0)?;
    if parser.token != Token::End {
        return Err(parser.error("expected AND, OR or end of query"));
    }
    Ok(result)
}
impl Parser<'_> {
    fn error(&self, message: &'static str) -> QueryError {
        QueryError {
            offset: self.offset,
            message,
        }
    }
    fn advance(&mut self) -> Result<(), QueryError> {
        let bytes = self.input.as_bytes();
        while self.offset < bytes.len() && bytes[self.offset].is_ascii_whitespace() {
            self.offset += 1;
        }
        if self.offset == bytes.len() {
            self.token = Token::End;
            return Ok(());
        }
        let start = self.offset;
        self.offset += 1;
        self.token = match bytes[start] {
            b'(' => Token::Open,
            b')' => Token::Close,
            b'=' => Token::Eq,
            b'!' | b'>' | b'<' => {
                let equal = bytes.get(self.offset) == Some(&b'=');
                if equal {
                    self.offset += 1;
                }
                match (bytes[start], equal) {
                    (b'!', true) => Token::Ne,
                    (b'>', true) => Token::Ge,
                    (b'<', true) => Token::Le,
                    (b'>', false) => Token::Gt,
                    (b'<', false) => Token::Lt,
                    _ => return Err(self.error("expected !=")),
                }
            }
            b'"' => {
                let mut escaped = false;
                let mut closed = false;
                while self.offset < bytes.len() {
                    let c = bytes[self.offset];
                    self.offset += 1;
                    if !escaped && c == b'"' {
                        closed = true;
                        break;
                    }
                    escaped = !escaped && c == b'\\';
                }
                if !closed {
                    return Err(self.error("unterminated quoted string"));
                }
                let value: String = serde_json::from_str(&self.input[start..self.offset])
                    .map_err(|_| self.error("invalid JSON string escape"))?;
                if value.len() > 1024 {
                    return Err(self.error("maximum string size is 1024 bytes"));
                }
                Token::Text(value)
            }
            b'0'..=b'9' => {
                while bytes.get(self.offset).is_some_and(u8::is_ascii_digit) {
                    self.offset += 1;
                }
                Token::Number(
                    self.input[start..self.offset]
                        .parse()
                        .map_err(|_| self.error("integer out of range"))?,
                )
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                while bytes
                    .get(self.offset)
                    .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_'))
                {
                    self.offset += 1;
                }
                let word = &self.input[start..self.offset];
                match word.to_ascii_uppercase().as_str() {
                    "AND" => Token::And,
                    "OR" => Token::Or,
                    "NULL" => Token::Null,
                    "CONTAINS" => Token::Contains,
                    _ => Token::Word(word.into()),
                }
            }
            _ => return Err(self.error("unexpected character; quote text values")),
        };
        Ok(())
    }
    fn or(&mut self, depth: usize) -> Result<String, QueryError> {
        let mut result = self.and(depth)?;
        while self.token == Token::Or {
            self.advance()?;
            result = format!("({result} OR {})", self.and(depth)?);
        }
        Ok(result)
    }
    fn and(&mut self, depth: usize) -> Result<String, QueryError> {
        let mut result = self.term(depth)?;
        while self.token == Token::And {
            self.advance()?;
            result = format!("({result} AND {})", self.term(depth)?);
        }
        Ok(result)
    }
    fn term(&mut self, depth: usize) -> Result<String, QueryError> {
        if self.token == Token::Open {
            if depth >= 8 {
                return Err(self.error("maximum parenthesis depth is 8"));
            }
            self.advance()?;
            let result = self.or(depth + 1)?;
            if self.token != Token::Close {
                return Err(self.error("expected closing parenthesis"));
            }
            self.advance()?;
            return Ok(format!("({result})"));
        }
        self.terms += 1;
        if self.terms > 32 {
            return Err(self.error("maximum comparison count is 32"));
        }
        let Token::Word(field) = &self.token else {
            return Err(self.error("expected a supported event field"));
        };
        let (column, numeric) = field_column(field)
            .ok_or_else(|| self.error("unsupported field; use the documented normalized fields"))?;
        self.advance()?;
        let operator = self.token.clone();
        if !matches!(
            operator,
            Token::Eq | Token::Ne | Token::Contains | Token::Gt | Token::Ge | Token::Lt | Token::Le
        ) {
            return Err(self.error("expected =, !=, CONTAINS, >, >=, < or <="));
        }
        self.advance()?;
        if self.token == Token::Null {
            let sql = match operator {
                Token::Eq => format!("{column} IS NULL"),
                Token::Ne => format!("{column} IS NOT NULL"),
                _ => return Err(self.error("NULL supports only = or !=")),
            };
            self.advance()?;
            return Ok(sql);
        }
        let value = match (&self.token, numeric) {
            (Token::Number(value), true) if operator != Token::Contains => Value::Integer(*value),
            (Token::Text(value), false)
                if matches!(operator, Token::Eq | Token::Ne | Token::Contains) =>
            {
                Value::Text(value.clone())
            }
            _ => return Err(self.error("wrong value type or operator for field")),
        };
        self.values.push(value);
        let param = self.values.len();
        self.advance()?;
        if operator == Token::Contains {
            return Ok(format!(
                "COALESCE(instr(lower({column}),lower(?{param}))>0,0)"
            ));
        }
        let op = match operator {
            Token::Eq => "=",
            Token::Ne => "!=",
            Token::Gt => ">",
            Token::Ge => ">=",
            Token::Lt => "<",
            Token::Le => "<=",
            _ => return Err(self.error("unsupported comparison")),
        };
        // Missing data cannot satisfy a negative comparison.
        Ok(format!("COALESCE({column} {op} ?{param},0)"))
    }
}
fn field_column(field: &str) -> Option<(&'static str, bool)> {
    Some(match field {
        "event.id" => ("event_id", false),
        "event.type" => ("event_type", false),
        "event.severity" => ("severity", false),
        "event.time" => ("wall_time", true),
        "host.id" => ("host_id", false),
        "sensor.id" => ("sensor_id", false),
        "process.name" => (
            "json_extract(CAST(payload AS TEXT),'$.process.name')",
            false,
        ),
        "process.path" => (
            "json_extract(CAST(payload AS TEXT),'$.process.executable_path')",
            false,
        ),
        "process.instance" => (
            "json_extract(CAST(payload AS TEXT),'$.process.instance_id')",
            false,
        ),
        "process.pid" => ("json_extract(CAST(payload AS TEXT),'$.process.pid')", true),
        "user.sid" => (
            "json_extract(CAST(payload AS TEXT),'$.actor_identity.sid')",
            false,
        ),
        "event.category" => (
            "json_extract(CAST(payload AS TEXT),'$.event_category')",
            false,
        ),
        "event.operation" => ("json_extract(CAST(payload AS TEXT),'$.operation')", false),
        "event.result" => ("json_extract(CAST(payload AS TEXT),'$.result')", false),
        "target.identifier" => (
            "json_extract(CAST(payload AS TEXT),'$.target.identifier')",
            false,
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn values_never_become_sql_and_precedence_is_explicit() -> Result<(), QueryError> {
        let mut values = vec![];
        let sql = compile(
            r#"process.name = "x' OR 1=1 --" OR process.pid = 12 AND user.sid != null"#,
            &mut values,
        )?;
        assert!(!sql.contains("1=1"));
        assert!(sql.contains(" OR ("));
        assert_eq!(
            values,
            vec![Value::Text("x' OR 1=1 --".into()), Value::Integer(12)]
        );
        assert!(sql.contains("IS NOT NULL"));
        Ok(())
    }
    #[test]
    fn bounded_parser_rejects_types_unknown_capabilities_and_programs() {
        for input in [
            "",
            "process.pid = \"42\"",
            "process.name > \"abc\"",
            "process.pid CONTAINS 1",
            "event.time = -1",
            "process.name = true",
            "network.destination.first_seen = true",
            "RELATED_TO incident:1",
            "event.type = \"a\"; DROP TABLE events",
            "process.name = \"unterminated",
            "process.name = \"x\" OR",
            "(process.pid = 1",
        ] {
            assert!(compile(input, &mut vec![]).is_err(), "accepted: {input}");
        }
        assert!(compile(
            &format!("{}process.pid = 1{}", "(".repeat(9), ")".repeat(9)),
            &mut vec![]
        )
        .is_err());
        assert!(compile(&vec!["process.pid = 1"; 33].join(" AND "), &mut vec![]).is_err());
        assert!(compile(&" ".repeat(4097), &mut vec![]).is_err());
    }
    #[test]
    fn unicode_escapes_quotes_and_windows_paths_are_bound() -> Result<(), QueryError> {
        let mut values = vec![];
        compile(
            r#"process.path CONTAINS "C:\\Utenti\\città\\\"file\"""#,
            &mut values,
        )?;
        assert_eq!(
            values,
            vec![Value::Text("C:\\Utenti\\città\\\"file\"".into())]
        );
        Ok(())
    }
}
