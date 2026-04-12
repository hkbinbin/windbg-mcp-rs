#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn collect_host_state_sync_commands(command: &str) -> Vec<String> {
    command
        .split([';', '\n', '\r'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter(|segment| needs_host_state_sync(segment))
        .map(str::to_string)
        .collect()
}

#[cfg_attr(not(test), allow(dead_code))]
fn needs_host_state_sync(command: &str) -> bool {
    let token = command.split_whitespace().next().unwrap_or_default();
    matches!(
        token.to_ascii_lowercase().as_str(),
        "sxe" | "sxd" | "sxn" | "sxi" | "sxr" | "sx-"
    )
}

#[cfg(test)]
mod tests {
    use super::collect_host_state_sync_commands;

    #[test]
    fn detects_single_filter_mutation() {
        assert_eq!(
            collect_host_state_sync_commands("sxe ld:ShadowGateSys"),
            vec!["sxe ld:ShadowGateSys".to_string()]
        );
    }

    #[test]
    fn ignores_non_filter_commands() {
        assert!(collect_host_state_sync_commands("bp nt!NtOpenFile").is_empty());
    }

    #[test]
    fn collects_filter_mutations_from_command_chains() {
        assert_eq!(
            collect_host_state_sync_commands("bc *; sxe ld:ShadowGateSys; sx"),
            vec!["sxe ld:ShadowGateSys".to_string()]
        );
    }

    #[test]
    fn handles_multiline_commands() {
        assert_eq!(
            collect_host_state_sync_commands("sxd ld:foo\r\nsxe ld:bar"),
            vec!["sxd ld:foo".to_string(), "sxe ld:bar".to_string()]
        );
    }
}
