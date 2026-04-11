//! Pipeline parser.
//!
//! Grammar (intentionally tiny):
//!
//!   line     := pipeline
//!   pipeline := stage ('|' stage)*
//!   stage    := word (WS word)*
//!   word     := bareword | dquoted
//!   bareword := [A-Za-z0-9_./:=@%+,-]+
//!   dquoted  := '"' ( [^"\\] | '\\"' | '\\\\' )* '"'
//!
//! Explicitly REJECTED (parse error, before any dispatch):
//!   - Any of: ; & && || > >> < << ` $ ( ) { } [ ] * ? ~ ! #
//!   - Unbalanced quotes
//!   - Empty stages (e.g. `| foo` or `foo |`)
//!   - Lines exceeding `max_line_len`
//!   - Pipelines exceeding `max_pipeline_stages`
//!
//! Rejecting at the parse layer means no builtin or external will ever
//! see an argv containing a shell metachar.

use anyhow::{bail, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub stages: Vec<Stage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    pub argv: Vec<String>,
}

pub fn parse(input: &str, max_line_len: usize, max_stages: usize) -> Result<Pipeline> {
    if input.len() > max_line_len {
        bail!("input exceeds max_line_len ({} bytes)", max_line_len);
    }
    if !input.is_ascii() {
        // Keep v1 strictly ASCII at the parse layer. Arguments that need
        // UTF-8 can still be read from files; command lines cannot.
        for ch in input.chars() {
            if !ch.is_ascii() {
                bail!("non-ASCII character in command line: {:?}", ch);
            }
        }
    }

    let mut stages = Vec::new();
    let mut cur = Vec::<String>::new();
    let mut awaiting_stage = false;
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b' ' | b'\t' | b'\r' | b'\n' => {
                i += 1;
            }
            b'|' => {
                if cur.is_empty() {
                    bail!("empty pipeline stage before '|'");
                }
                stages.push(Stage {
                    argv: std::mem::take(&mut cur),
                });
                if stages.len() >= max_stages {
                    bail!("pipeline exceeds max_pipeline_stages ({})", max_stages);
                }
                awaiting_stage = true;
                i += 1;
            }
            b'"' => {
                let (word, next) = read_dquoted(bytes, i)?;
                cur.push(word);
                awaiting_stage = false;
                i = next;
            }
            b';' | b'&' | b'<' | b'>' | b'`' | b'$' | b'(' | b')' | b'{' | b'}' | b'[' | b']'
            | b'*' | b'?' | b'~' | b'!' | b'#' | b'\\' | b'\'' => {
                bail!("forbidden metacharacter: {:?}", c as char);
            }
            _ => {
                let (word, next) = read_bareword(bytes, i)?;
                cur.push(word);
                awaiting_stage = false;
                i = next;
            }
        }
    }

    if awaiting_stage && cur.is_empty() {
        bail!("empty pipeline stage after '|'");
    }
    if !cur.is_empty() {
        stages.push(Stage { argv: cur });
    }
    if stages.is_empty() {
        return Ok(Pipeline { stages: vec![] });
    }
    for s in &stages {
        if s.argv.is_empty() {
            bail!("empty pipeline stage");
        }
    }
    Ok(Pipeline { stages })
}

fn read_bareword(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if is_bareword_byte(c) {
            i += 1;
        } else {
            break;
        }
    }
    if i == start {
        bail!("unexpected character {:?}", bytes[start] as char);
    }
    // Safe: bareword bytes are ASCII.
    Ok((
        std::str::from_utf8(&bytes[start..i]).unwrap().to_string(),
        i,
    ))
}

fn is_bareword_byte(c: u8) -> bool {
    matches!(c,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
        | b'_' | b'.' | b'/' | b':' | b'=' | b'@' | b'%' | b'+' | b',' | b'-'
    )
}

fn read_dquoted(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    debug_assert_eq!(bytes[start], b'"');
    let mut i = start + 1;
    let mut out = String::new();
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'"' => return Ok((out, i + 1)),
            b'\\' => {
                if i + 1 >= bytes.len() {
                    bail!("dangling backslash in quoted string");
                }
                let n = bytes[i + 1];
                match n {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    _ => bail!("invalid escape \\{:?} in quoted string", n as char),
                }
                i += 2;
            }
            // Forbid control chars and $/backtick inside quotes too.
            b'$' | b'`' => bail!("forbidden {:?} inside quoted string", c as char),
            0..=0x1f | 0x7f => bail!("control byte {:#x} inside quoted string", c),
            _ => {
                out.push(c as char);
                i += 1;
            }
        }
    }
    bail!("unterminated quoted string")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Pipeline> {
        parse(s, 4096, 8)
    }

    #[test]
    fn empty_input() {
        assert_eq!(p("").unwrap().stages.len(), 0);
        assert_eq!(p("   \t\n").unwrap().stages.len(), 0);
    }

    #[test]
    fn simple_command() {
        let pl = p("ls").unwrap();
        assert_eq!(pl.stages.len(), 1);
        assert_eq!(pl.stages[0].argv, vec!["ls"]);
    }

    #[test]
    fn command_with_args() {
        let pl = p("ls -la /var/log").unwrap();
        assert_eq!(pl.stages[0].argv, vec!["ls", "-la", "/var/log"]);
    }

    #[test]
    fn simple_pipeline() {
        let pl = p("ls /var/log | grep err | head -20").unwrap();
        assert_eq!(pl.stages.len(), 3);
        assert_eq!(pl.stages[2].argv, vec!["head", "-20"]);
    }

    #[test]
    fn dquoted_arg() {
        let pl = p(r#"grep "hello world" file.log"#).unwrap();
        assert_eq!(pl.stages[0].argv, vec!["grep", "hello world", "file.log"]);
    }

    #[test]
    fn dquoted_escapes() {
        let pl = p(r#"echo "a\"b\\c""#).unwrap();
        assert_eq!(pl.stages[0].argv[1], r#"a"b\c"#);
    }

    #[test]
    fn forbids_semicolon() {
        assert!(p("ls; id").is_err());
    }

    #[test]
    fn forbids_background() {
        assert!(p("ls &").is_err());
        assert!(p("ls && id").is_err());
        assert!(p("ls || id").is_err());
    }

    #[test]
    fn forbids_redirect() {
        assert!(p("ls > /tmp/x").is_err());
        assert!(p("ls >> /tmp/x").is_err());
        assert!(p("cat < /etc/passwd").is_err());
    }

    #[test]
    fn forbids_command_substitution() {
        assert!(p("echo $(id)").is_err());
        assert!(p("echo `id`").is_err());
        assert!(p("echo $HOME").is_err());
    }

    #[test]
    fn forbids_glob() {
        assert!(p("ls *.log").is_err());
        assert!(p("ls ?.log").is_err());
        assert!(p("ls [abc].log").is_err());
    }

    #[test]
    fn forbids_brace_expansion() {
        assert!(p("ls {a,b}").is_err());
    }

    #[test]
    fn forbids_tilde_home() {
        assert!(p("ls ~/logs").is_err());
    }

    #[test]
    fn forbids_bang() {
        assert!(p("!ls").is_err());
    }

    #[test]
    fn forbids_comment() {
        assert!(p("ls # comment").is_err());
    }

    #[test]
    fn forbids_unterminated_quote() {
        assert!(p(r#"echo "hi"#).is_err());
    }

    #[test]
    fn forbids_empty_stage() {
        assert!(p("| ls").is_err());
        assert!(p("ls |").is_err());
        assert!(p("ls || grep x").is_err());
    }

    #[test]
    fn forbids_dollar_in_quotes() {
        assert!(p(r#"echo "$HOME""#).is_err());
    }

    #[test]
    fn forbids_backtick_in_quotes() {
        assert!(p(r#"echo "`id`""#).is_err());
    }

    #[test]
    fn forbids_single_quote() {
        // Single quotes are a whole other parsing mode; v1 only supports ".
        assert!(p("echo 'hi'").is_err());
    }

    #[test]
    fn enforces_line_length() {
        let long = "a".repeat(5000);
        assert!(parse(&long, 4096, 8).is_err());
    }

    #[test]
    fn enforces_max_stages() {
        let many = "a | b | c | d | e | f | g | h | i";
        assert!(parse(many, 4096, 4).is_err());
    }

    #[test]
    fn rejects_non_ascii() {
        assert!(p("echo café").is_err());
    }
}
