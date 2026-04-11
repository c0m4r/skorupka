//! Integration tests: every known shell-escape vector must be rejected
//! by the parser before any builtin ever sees it.

use skorupka::parser::parse;

fn p(s: &str) -> bool {
    parse(s, 4096, 8).is_ok()
}

#[test]
fn all_metachars_rejected() {
    let bad = [
        "ls; id",
        "ls && id",
        "ls || id",
        "ls | id", // <-- this one is actually OK, leave as sanity
        "ls & ",
        "cat > /tmp/x",
        "cat >> /tmp/x",
        "cat < /etc/passwd",
        "echo $(id)",
        "echo `id`",
        "echo $HOME",
        "ls *",
        "ls ?",
        "ls [a-z]",
        "ls {a,b}",
        "ls ~root",
        "!ls",
        "# comment",
        r#"echo "$(id)""#,
        r#"echo "`id`""#,
        "echo 'hi'",
        "find / -exec sh {} ;", // semicolon is itself rejected
    ];
    for b in bad {
        if b == "ls | id" {
            // sanity: a plain pipe is allowed
            assert!(p(b), "pipe should be allowed: {}", b);
        } else {
            assert!(!p(b), "should reject: {}", b);
        }
    }
}

#[test]
fn whitelist_allows_real_log_queries() {
    let good = [
        "ls",
        "ls -la /var/log",
        "cat /var/log/syslog",
        "grep ERROR /var/log/app.log",
        "grep -i warn /var/log/syslog | head -20",
        "tail -n 100 /var/log/auth.log",
        "find /var/log -name auth.log",
        r#"grep "connection refused" /var/log/messages"#,
    ];
    for g in good {
        assert!(p(g), "should accept: {}", g);
    }
}
