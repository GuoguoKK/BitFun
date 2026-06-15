#[test]
fn debug_js() {
    let cmd = r#"node -e "require('fs').writeFileSync('/tmp/test', 'hi')""#;
    let expanded = super::expand_env_vars(cmd);
    eprintln!("EXPANDED: [{}]", expanded);
    let re = regex::Regex::new(r#"\b(?:node|bun|deno)\s+(?:-[eE]\s+|--eval\s+)(["'])(.+?)\1"#).unwrap();
    if let Some(c) = re.captures(&expanded) {
        eprintln!("CODE: [{}]", &c[2]);
    } else {
        eprintln!("NO CAPTURE");
    }
}
