#![allow(clippy::expect_used)]

use std::io::Write;

#[test]
fn invalid_config_exits_with_useful_context_before_startup() {
    let path = std::env::temp_dir().join(format!("forge-mcp-config-{}.toml", std::process::id()));
    for (input, expected) in [
        ("[server", "failed to parse config file"),
        (
            "agents = []\nforges = []\n[server]\nlisten = 8443",
            "failed to parse config file",
        ),
        (
            "agents = []\nforges = []\n[server]\nlisten = \"a\"\nlisten = \"b\"",
            "failed to parse config file",
        ),
        (
            "agents = []\nforges = []\n[server]\nlisten = \"127.0.0.1:0\"\ncommit_author_name = \"Synthetic\"",
            "invalid configuration: server.commit_author_email is required",
        ),
    ] {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("create synthetic config");
        file.write_all(input.as_bytes()).expect("write config");
        drop(file);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_server"))
            .arg(&path)
            .output();
        std::fs::remove_file(&path).expect("remove synthetic config");
        let output = output.expect("run server validation");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{stderr}");
        assert!(stderr.contains(expected), "{stderr}");
        if expected == "failed to parse config file" {
            assert!(
                stderr.contains(path.to_str().expect("config path")),
                "{stderr}"
            );
        }
        assert!(!String::from_utf8_lossy(&output.stdout).contains("forge-mcp starting"));
    }
}
