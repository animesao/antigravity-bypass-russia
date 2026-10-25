#![allow(dead_code)]

#[cfg(windows)]
use crate::net::provider::NRPT_TAG;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignRule {
    pub id: String,
    pub namespaces: Vec<String>,
    pub nameservers: Vec<String>,
    pub display_name: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NrptInventory {
    pub foreign_rules: Vec<ForeignRule>,
    pub policy_present: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompatibilityPlan {
    pub rules: Vec<(String, String)>,
    pub skipped: Vec<String>,
    pub preserved: Vec<ForeignRule>,
    pub policy_present: bool,
    requested_rules: Vec<(String, String)>,
}

// The initial dot denotes a suffix rule. An exact FQDN and its suffix can
// coexist; only namespaces with the same type and spelling are duplicates.
fn norm_ns(namespace: &str) -> String {
    let namespace = namespace.trim();
    if namespace == "." {
        return ".".into();
    }
    namespace.trim_end_matches('.').to_ascii_lowercase()
}

impl NrptInventory {
    pub fn plan(&self, requested: &[(String, String)]) -> CompatibilityPlan {
        let requested_names: Vec<_> = requested.iter().map(|(name, _)| norm_ns(name)).collect();
        let preserved: Vec<_> = self
            .foreign_rules
            .iter()
            .filter(|rule| {
                rule.namespaces
                    .iter()
                    .any(|name| requested_names.contains(&norm_ns(name)))
            })
            .cloned()
            .collect();
        let mut rules = Vec::new();
        let mut skipped = Vec::new();
        for (name, servers) in requested {
            let name = norm_ns(name);
            let blocked = self.policy_present
                || servers.trim().is_empty()
                || preserved.iter().any(|rule| {
                    rule.namespaces
                        .iter()
                        .any(|foreign| norm_ns(foreign) == name)
                });
            if blocked {
                if !skipped.contains(&name) {
                    skipped.push(name);
                }
            } else {
                rules.push((name, servers.clone()));
            }
        }
        CompatibilityPlan {
            rules,
            skipped,
            preserved,
            policy_present: self.policy_present,
            requested_rules: requested.to_vec(),
        }
    }
}

pub fn inventory() -> Result<NrptInventory, String> {
    #[cfg(windows)]
    {
        registry::inventory_at(registry::HKLM, registry::LOCAL_PATH, registry::POLICY_PATH)
    }
    #[cfg(not(windows))]
    {
        Ok(NrptInventory::default())
    }
}

pub fn apply_compatible_rules(
    plan: &CompatibilityPlan,
    tag: &str,
    display_prefix: &str,
) -> Result<CompatibilityPlan, String> {
    #[cfg(windows)]
    {
        registry::reconcile(
            registry::HKLM,
            registry::LOCAL_PATH,
            registry::POLICY_PATH,
            &plan.requested_rules,
            tag,
            display_prefix,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (plan, tag, display_prefix);
        Ok(plan.clone())
    }
}

pub fn get_nrpt_status_info() -> (usize, Option<String>, bool) {
    #[cfg(windows)]
    {
        let Ok((_, rules)) = registry::read_rules(registry::HKLM, registry::LOCAL_PATH) else {
            return (0, None, false);
        };
        let owned: Vec<_> = rules.iter().filter(|rule| rule.owned()).collect();
        let servers = owned
            .iter()
            .find(|rule| !rule.nameservers.is_empty())
            .map(|rule| rule.nameservers.join(";"));
        let is_relay = owned.iter().any(|rule| {
            rule.nameservers
                .iter()
                .any(|server| server == "127.0.0.53" || server == "127.0.0.1")
        });
        (owned.len(), servers, is_relay)
    }
    #[cfg(target_os = "macos")]
    {
        let mut count = 0;
        let mut servers = None;
        if let Ok(entries) = std::fs::read_dir("/etc/resolver") {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() {
                    continue;
                }
                if let Ok(content) = std::fs::read_to_string(path) {
                    if content.contains("# ANTIGRAVITY-BYPASS-RUSSIA") {
                        count += 1;
                        if servers.is_none() {
                            servers = content.lines().find_map(|line| {
                                line.strip_prefix("nameserver ")
                                    .map(|s| s.trim().to_string())
                            });
                        }
                    }
                }
            }
        }
        let is_relay = matches!(servers.as_deref(), Some("127.0.0.1" | "127.0.0.53"));
        (count, servers, is_relay)
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        (0, None, false)
    }
}

#[cfg(windows)]
pub fn native_remove_nrpt_rules() -> Result<usize, String> {
    registry::remove_owned(registry::HKLM, registry::LOCAL_PATH)
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize)]
pub struct EffectiveIssue {
    pub namespace: String,
    pub reason: String,
}

#[cfg(windows)]
fn effective_check_script(rules: &[(String, String)]) -> Result<String, String> {
    let expected: Vec<_> = rules.iter().map(|(namespace, servers)| {
        serde_json::json!({"Namespace": norm_ns(namespace), "Servers": servers})
    }).collect();
    let json = serde_json::to_string(&expected)
        .map_err(|error| error.to_string())?
        .replace('\'', "''");
    Ok(format!(
        r#"
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$ErrorActionPreference = 'Stop'
try {{
    function Normalize-NrptNamespace([string]$name) {{
        $name = $name.Trim()
        if($name -eq '.') {{ return '.' }}
        $name.TrimEnd('.').ToLowerInvariant()
    }}
    function Normalize-NrptServers([object[]]$items) {{
        @($(foreach($item in $items) {{
            foreach($part in (([string]$item) -split '[;,]')) {{
                $part = $part.Trim()
                if($part) {{ ([System.Net.IPAddress]::Parse($part)).ToString() }}
            }}
        }}) | Sort-Object -Unique)
    }}
    $expected = ConvertFrom-Json -InputObject '{json}'
    $actual = @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop)
    $issues = @(foreach($rule in $expected) {{
        $matching = @($actual | Where-Object {{
            $names = @($_.Namespace | ForEach-Object {{ Normalize-NrptNamespace ([string]$_) }})
            $names -contains $rule.Namespace
        }})
        $reason = $null
        if($matching.Count -eq 0) {{ $reason = 'отсутствует в эффективной политике' }}
        elseif($matching.Count -ne 1) {{ $reason = 'несколько правил в эффективной политике' }}
        else {{
            $wanted = @(Normalize-NrptServers @($rule.Servers))
            $found = @(Normalize-NrptServers @($matching[0].NameServers))
            if(($wanted -join ';') -ne ($found -join ';')) {{ $reason = 'используются другие DNS-серверы' }}
        }}
        if($reason) {{ [pscustomobject]@{{ namespace=[string]$rule.Namespace; reason=$reason }} }}
    }})
    ConvertTo-Json -InputObject @($issues) -Depth 4 -Compress
}} catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
"#
    ))
}

pub fn ineffective_namespaces(rules: &[(String, String)]) -> Result<Vec<EffectiveIssue>, String> {
    #[cfg(windows)]
    {
        if rules.is_empty() {
            return Ok(Vec::new());
        }
        let out = crate::system::powershell::output(&effective_check_script(rules)?)
            .map_err(|error| error.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "Не удалось проверить эффективную NRPT: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        parse_effective_output(&out.stdout)
    }
    #[cfg(not(windows))]
    {
        let _ = rules;
        Ok(Vec::new())
    }
}

#[cfg(windows)]
fn parse_effective_output(bytes: &[u8]) -> Result<Vec<EffectiveIssue>, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| format!("Ответ NRPT не в UTF-8: {error}"))?;
    serde_json::from_str(text.trim_start_matches('\u{feff}').trim())
        .map_err(|error| format!("Не удалось прочитать эффективную NRPT: {error}"))
}

#[cfg(windows)]
mod registry {
    use super::*;
    use std::ptr::null_mut;

    pub(super) const HKLM: usize = 0x80000002u32 as i32 as isize as usize;
    pub(super) const LOCAL_PATH: &str =
        r"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig";
    pub(super) const POLICY_PATH: &str =
        r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig";
    const KEY_READ: u32 = 0x20019;
    const KEY_WRITE: u32 = 0x20006;
    const REG_SZ: u32 = 1;
    const REG_DWORD: u32 = 4;
    const REG_MULTI_SZ: u32 = 7;
    const NOT_FOUND: i32 = 2;
    const MORE_DATA: i32 = 234;
    const NO_MORE_ITEMS: i32 = 259;
    const OWNED_PREFIX: &str = "ANTIGRAVITY_BYPASS_";

    #[link(name = "advapi32")]
    extern "system" {
        fn RegOpenKeyExW(
            key: usize,
            path: *const u16,
            options: u32,
            access: u32,
            result: *mut usize,
        ) -> i32;
        fn RegCreateKeyExW(
            key: usize,
            path: *const u16,
            reserved: u32,
            class: *mut u16,
            options: u32,
            access: u32,
            security: *mut std::ffi::c_void,
            result: *mut usize,
            disposition: *mut u32,
        ) -> i32;
        fn RegEnumKeyExW(
            key: usize,
            index: u32,
            name: *mut u16,
            len: *mut u32,
            reserved: *mut u32,
            class: *mut u16,
            class_len: *mut u32,
            changed: *mut u64,
        ) -> i32;
        fn RegQueryValueExW(
            key: usize,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            len: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: usize,
            name: *const u16,
            reserved: u32,
            kind: u32,
            data: *const u8,
            len: u32,
        ) -> i32;
        fn RegDeleteKeyW(key: usize, path: *const u16) -> i32;
        fn RegCloseKey(key: usize) -> i32;
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Key(usize);
    impl Drop for Key {
        fn drop(&mut self) {
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
    impl Key {
        fn open(root: usize, path: &str, access: u32) -> Result<Option<Self>, String> {
            let mut key = 0;
            let code = unsafe { RegOpenKeyExW(root, wide(path).as_ptr(), 0, access, &mut key) };
            match code {
                0 => Ok(Some(Self(key))),
                NOT_FOUND => Ok(None),
                _ => Err(format!("NRPT: не удалось открыть {path} (код {code})")),
            }
        }
        fn create(root: usize, path: &str) -> Result<Self, String> {
            let mut key = 0;
            let code = unsafe {
                RegCreateKeyExW(
                    root,
                    wide(path).as_ptr(),
                    0,
                    null_mut(),
                    0,
                    KEY_READ | KEY_WRITE,
                    null_mut(),
                    &mut key,
                    null_mut(),
                )
            };
            if code != 0 {
                return Err(format!("NRPT: не удалось создать {path} (код {code})"));
            }
            Ok(Self(key))
        }
        fn value(&self, name: &str) -> Result<Option<(u32, Vec<u8>)>, String> {
            let name_wide = wide(name);
            let mut kind = 0;
            let mut len = 0;
            let code = unsafe {
                RegQueryValueExW(
                    self.0,
                    name_wide.as_ptr(),
                    null_mut(),
                    &mut kind,
                    null_mut(),
                    &mut len,
                )
            };
            if code == NOT_FOUND {
                return Ok(None);
            }
            if code != 0 && code != MORE_DATA {
                return Err(format!("NRPT: чтение {name} (код {code})"));
            }
            for _ in 0..4 {
                if len > 1024 * 1024 {
                    return Err(format!("NRPT: слишком большое значение {name}"));
                }
                let mut bytes = vec![0u8; len as usize];
                let mut actual_len = len;
                let code = unsafe {
                    RegQueryValueExW(
                        self.0,
                        name_wide.as_ptr(),
                        null_mut(),
                        &mut kind,
                        bytes.as_mut_ptr(),
                        &mut actual_len,
                    )
                };
                if code == MORE_DATA {
                    len = actual_len;
                    continue;
                }
                if code != 0 {
                    return Err(format!("NRPT: чтение {name} изменилось (код {code})"));
                }
                bytes.truncate(actual_len as usize);
                return Ok(Some((kind, bytes)));
            }
            Err(format!("NRPT: {name} изменяется другой программой"))
        }
        fn strings(&self, name: &str, multi_allowed: bool) -> Result<Vec<String>, String> {
            let Some((kind, bytes)) = self.value(name)? else {
                return Ok(Vec::new());
            };
            if kind != REG_SZ && !(multi_allowed && kind == REG_MULTI_SZ) {
                return Err(format!("NRPT: неверный тип {name}: {kind}"));
            }
            if bytes.len() % 2 != 0 {
                return Err(format!("NRPT: повреждено значение {name}"));
            }
            let units: Vec<u16> = bytes
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            let mut result = Vec::new();
            for part in units.split(|unit| *unit == 0) {
                if part.is_empty() {
                    continue;
                }
                let text = String::from_utf16(part)
                    .map_err(|_| format!("NRPT: неверный UTF-16 в {name}"))?;
                result.push(text);
                if kind == REG_SZ {
                    break;
                }
            }
            Ok(result)
        }
        fn string(&self, name: &str) -> Result<String, String> {
            Ok(self
                .strings(name, false)?
                .into_iter()
                .next()
                .unwrap_or_default())
        }
        fn names(&self) -> Result<Vec<String>, String> {
            let mut names = Vec::new();
            let mut index = 0;
            loop {
                let mut capacity = 256usize;
                let name = loop {
                    let mut units = vec![0u16; capacity];
                    let mut len = units.len() as u32;
                    let code = unsafe {
                        RegEnumKeyExW(
                            self.0,
                            index,
                            units.as_mut_ptr(),
                            &mut len,
                            null_mut(),
                            null_mut(),
                            null_mut(),
                            null_mut(),
                        )
                    };
                    match code {
                        0 => {
                            break Some(
                                String::from_utf16(&units[..len as usize])
                                    .map_err(|_| "NRPT: неверное имя ключа")?,
                            )
                        }
                        NO_MORE_ITEMS => break None,
                        MORE_DATA if capacity < 65536 => capacity *= 2,
                        _ => return Err(format!("NRPT: перечисление правил (код {code})")),
                    }
                };
                let Some(name) = name else {
                    break;
                };
                names.push(name);
                index += 1;
            }
            Ok(names)
        }
        fn set(&self, name: &str, kind: u32, bytes: &[u8]) -> Result<(), String> {
            let code = unsafe {
                RegSetValueExW(
                    self.0,
                    wide(name).as_ptr(),
                    0,
                    kind,
                    bytes.as_ptr(),
                    bytes.len() as u32,
                )
            };
            if code == 0 {
                Ok(())
            } else {
                Err(format!("NRPT: запись {name} (код {code})"))
            }
        }
        fn set_string(&self, name: &str, value: &str) -> Result<(), String> {
            self.set(
                name,
                REG_SZ,
                &wide(value)
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
        }
        fn set_namespaces(&self, namespaces: &[String]) -> Result<(), String> {
            let mut units = Vec::new();
            for namespace in namespaces {
                units.extend(wide(namespace));
            }
            units.push(0);
            self.set(
                "Name",
                REG_MULTI_SZ,
                &units
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>(),
            )
        }
        fn delete(&self, name: &str) -> Result<(), String> {
            let code = unsafe { RegDeleteKeyW(self.0, wide(name).as_ptr()) };
            if code == 0 || code == NOT_FOUND {
                Ok(())
            } else {
                Err(format!("NRPT: удаление своего правила {name} (код {code})"))
            }
        }
    }

    #[derive(Clone, Debug)]
    pub(super) struct Rule {
        pub id: String,
        pub namespaces: Vec<String>,
        pub nameservers: Vec<String>,
        pub display_name: String,
        comment: String,
    }
    impl Rule {
        pub(super) fn owned(&self) -> bool {
            self.id.starts_with(OWNED_PREFIX)
                || self.comment.contains(NRPT_TAG)
                || self.display_name.contains(NRPT_TAG)
        }
        fn foreign(&self, policy: bool) -> ForeignRule {
            ForeignRule {
                id: if policy {
                    format!("policy:{}", self.id)
                } else {
                    self.id.clone()
                },
                namespaces: self.namespaces.clone(),
                nameservers: self.nameservers.clone(),
                display_name: self.display_name.clone(),
            }
        }
    }
    fn read_rule(parent: &Key, id: &str) -> Result<Rule, String> {
        let key = Key::open(parent.0, id, KEY_READ)?
            .ok_or_else(|| format!("NRPT: правило {id} изменилось во время чтения"))?;
        let mut rule = Rule {
            id: id.to_string(),
            namespaces: key.strings("Name", true)?,
            nameservers: Vec::new(),
            display_name: key.string("DisplayName")?,
            comment: key.string("Comment")?,
        };
        let servers = if key.value("GenericDNSServers")?.is_some() {
            key.string("GenericDNSServers")?
        } else {
            key.string("GenericDNSCAServers")?
        };
        rule.nameservers = servers
            .split(|c: char| c == ';' || c == ',' || c.is_ascii_whitespace())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect();
        if !rule.owned() && rule.namespaces.iter().all(|s| norm_ns(s).is_empty()) {
            return Err(format!("NRPT: у чужого правила {id} не прочитан namespace"));
        }
        Ok(rule)
    }
    pub(super) fn read_rules(root: usize, path: &str) -> Result<(bool, Vec<Rule>), String> {
        let Some(parent) = Key::open(root, path, KEY_READ)? else {
            return Ok((false, Vec::new()));
        };
        let rules = parent
            .names()?
            .iter()
            .map(|id| read_rule(&parent, id))
            .collect::<Result<Vec<_>, _>>()?;
        Ok((true, rules))
    }
    pub(super) fn inventory_at(
        root: usize,
        local_path: &str,
        policy_path: &str,
    ) -> Result<NrptInventory, String> {
        let (_, local) = read_rules(root, local_path)?;
        let (policy_present, policy) = read_rules(root, policy_path)?;
        let foreign_rules = local
            .iter()
            .filter(|rule| !rule.owned())
            .map(|rule| rule.foreign(false))
            .chain(policy.iter().map(|rule| rule.foreign(true)))
            .collect();
        Ok(NrptInventory {
            foreign_rules,
            policy_present,
        })
    }
    fn desired_key(namespace: &str) -> String {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(norm_ns(namespace).as_bytes());
        format!(
            "{OWNED_PREFIX}{}",
            digest[..16]
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>()
        )
    }
    fn validate_rules(rules: &[(String, String)]) -> Result<(), String> {
        let mut names = std::collections::BTreeSet::new();
        for (name, servers) in rules {
            let name = norm_ns(name);
            if name.is_empty() || name.contains('\0') || !names.insert(name.clone()) {
                return Err(format!("NRPT: неверный или повторяющийся namespace {name}"));
            }
            let parts: Vec<_> = servers
                .split([';', ','])
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            if parts.is_empty()
                || parts
                    .iter()
                    .any(|server| server.parse::<std::net::IpAddr>().is_err())
            {
                return Err(format!("NRPT: неверные DNS-серверы для {name}"));
            }
        }
        Ok(())
    }
    fn delete_if_owned(parent: &Key, id: &str) -> Result<bool, String> {
        if Key::open(parent.0, id, KEY_READ)?.is_none() {
            return Ok(false);
        }
        if !read_rule(parent, id)?.owned() {
            return Err(format!(
                "NRPT: правило {id} изменилось другой программой; оно сохранено"
            ));
        }
        parent.delete(id)?;
        Ok(true)
    }
    pub(super) fn reconcile(
        root: usize,
        local_path: &str,
        policy_path: &str,
        requested: &[(String, String)],
        tag: &str,
        display_prefix: &str,
    ) -> Result<CompatibilityPlan, String> {
        if tag.is_empty() || !tag.contains(NRPT_TAG) {
            return Err("NRPT: отсутствует метка владельца".into());
        }
        let current = inventory_at(root, local_path, policy_path)?;
        let applied = current.plan(requested);
        let rules = &applied.rules;
        validate_rules(rules)?;
        let existing = Key::open(root, local_path, KEY_READ | KEY_WRITE)?;
        if existing.is_none() && rules.is_empty() {
            return Ok(applied);
        }
        let parent = match existing {
            Some(parent) => parent,
            None => Key::create(root, local_path)?,
        };
        let mut desired = std::collections::BTreeSet::new();
        for (namespace, servers) in rules {
            let namespace = norm_ns(namespace);
            let servers = servers
                .split([';', ','])
                .map(str::trim)
                .filter(|server| !server.is_empty())
                .collect::<Vec<_>>()
                .join(";");
            let id = desired_key(&namespace);
            if Key::open(parent.0, &id, KEY_READ)?.is_some() && !read_rule(&parent, &id)?.owned() {
                return Err(format!(
                    "NRPT: имя {id} занято чужим правилом; оно сохранено"
                ));
            }
            let key = Key::create(parent.0, &id)?;
            // Ownership first also identifies a partially written new key if a
            // later write fails. Reconciliation removes it on the next attempt.
            key.set_string("Comment", tag)?;
            key.set_string("DisplayName", &format!("{display_prefix} ({namespace})"))?;
            key.set("Version", REG_DWORD, &2u32.to_le_bytes())?;
            key.set_namespaces(&[namespace])?;
            key.set_string("GenericDNSServers", &servers)?;
            key.set_string("IPSECCARestriction", "")?;
            key.set("ConfigOptions", REG_DWORD, &8u32.to_le_bytes())?;
            desired.insert(id);
        }
        // Remove ordinal/legacy GUID rules only after every planned replacement
        // was written. An empty plan intentionally retires all owned rules.
        let remaining = parent
            .names()?
            .iter()
            .map(|id| read_rule(&parent, id))
            .collect::<Result<Vec<_>, _>>()?;
        for rule in remaining {
            if rule.owned() && !desired.contains(&rule.id) {
                delete_if_owned(&parent, &rule.id)?;
            }
        }
        Ok(applied)
    }
    pub(super) fn remove_owned(root: usize, path: &str) -> Result<usize, String> {
        let Some(parent) = Key::open(root, path, KEY_READ | KEY_WRITE)? else {
            return Ok(0);
        };
        let rules = parent
            .names()?
            .iter()
            .map(|id| read_rule(&parent, id))
            .collect::<Result<Vec<_>, _>>()?;
        let mut removed = 0;
        for rule in rules {
            if rule.owned() && delete_if_owned(&parent, &rule.id)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        const HKCU: usize = 0x80000001u32 as i32 as isize as usize;
        struct Fixture {
            path: String,
            local: String,
            policy: String,
        }
        impl Fixture {
            fn new() -> Self {
                let nonce = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos();
                let path = format!(
                    r"Software\AntigravityNrptTests\{}-{nonce}",
                    std::process::id()
                );
                let local = format!(r"{path}\local");
                let policy = format!(r"{path}\policy");
                Self {
                    path,
                    local,
                    policy,
                }
            }
            fn add(&self, id: &str, names: &[&str], servers: &str, comment: &str) {
                let parent = Key::create(HKCU, &self.local).unwrap();
                let key = Key::create(parent.0, id).unwrap();
                key.set_namespaces(
                    &names
                        .iter()
                        .map(|name| name.to_string())
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                key.set_string("GenericDNSServers", servers).unwrap();
                key.set_string("Comment", comment).unwrap();
                key.set_string("DisplayName", "Other DNS application")
                    .unwrap();
                key.set_string("UntouchedValue", "foreign bytes").unwrap();
            }
            fn apply(&self, requested: &[(String, String)]) -> CompatibilityPlan {
                reconcile(
                    HKCU,
                    &self.local,
                    &self.policy,
                    requested,
                    NRPT_TAG,
                    "Test DNS",
                )
                .unwrap()
            }
        }
        impl Drop for Fixture {
            fn drop(&mut self) {
                // Only delete the isolated, process-specific HKCU fixture.
                for path in [&self.local, &self.policy] {
                    if let Ok(Some(parent)) = Key::open(HKCU, path, KEY_READ | KEY_WRITE) {
                        for id in parent.names().unwrap_or_default() {
                            let _ = parent.delete(&id);
                        }
                    }
                    unsafe {
                        RegDeleteKeyW(HKCU, wide(path).as_ptr());
                    }
                }
                unsafe {
                    RegDeleteKeyW(HKCU, wide(&self.path).as_ptr());
                }
            }
        }
        #[test]
        fn reconcile_reapply_skips_foreign_and_retires_only_stale_owned_keys() {
            let fixture = Fixture::new();
            fixture.add(
                "{foreign}",
                &["foreign.test", ".thirdparty.test"],
                "192.0.2.1",
                "VPN",
            );
            fixture.add("{legacy-owned}", &["old.test"], "127.0.0.53", NRPT_TAG);
            fixture.add("ANTIGRAVITY_BYPASS_003", &["stale.test"], "127.0.0.53", "");
            let full = vec![
                ("one.test".into(), "127.0.0.53".into()),
                ("two.test".into(), "127.0.0.53".into()),
            ];
            fixture.apply(&full);
            fixture.apply(&full);
            let (_, first) = read_rules(HKCU, &fixture.local).unwrap();
            assert_eq!(first.iter().filter(|r| r.owned()).count(), 2);
            fixture.add("{new-vpn}", &["ONE.TEST."], "192.0.2.2", "VPN");
            let partial = fixture.apply(&full);
            assert_eq!(partial.skipped, vec!["one.test"]);
            let (_, second) = read_rules(HKCU, &fixture.local).unwrap();
            assert_eq!(second.iter().filter(|r| r.owned()).count(), 1);
            assert!(!second
                .iter()
                .any(|r| r.owned() && r.namespaces.contains(&"one.test".to_string())));
            let parent = Key::open(HKCU, &fixture.local, KEY_READ | KEY_WRITE)
                .unwrap()
                .unwrap();
            let foreign = Key::open(parent.0, "{foreign}", KEY_READ).unwrap().unwrap();
            assert_eq!(foreign.string("UntouchedValue").unwrap(), "foreign bytes");
            assert_eq!(
                foreign.strings("Name", true).unwrap(),
                vec!["foreign.test", ".thirdparty.test"]
            );
            parent.delete("{new-vpn}").unwrap();
            fixture.apply(&full);
            assert_eq!(
                read_rules(HKCU, &fixture.local)
                    .unwrap()
                    .1
                    .iter()
                    .filter(|r| r.owned())
                    .count(),
                2
            );
            assert_eq!(remove_owned(HKCU, &fixture.local).unwrap(), 2);
            assert_eq!(read_rules(HKCU, &fixture.local).unwrap().1.len(), 1);
        }
        #[test]
        fn empty_policy_root_retires_owned_rules_without_touching_policy() {
            let fixture = Fixture::new();
            let requested = vec![("one.test".into(), "127.0.0.53".into())];
            fixture.apply(&requested);
            let _policy = Key::create(HKCU, &fixture.policy).unwrap();
            let plan = fixture.apply(&requested);
            assert!(plan.policy_present);
            assert!(plan.rules.is_empty());
            assert_eq!(plan.skipped, vec!["one.test"]);
            assert!(read_rules(HKCU, &fixture.local).unwrap().1.is_empty());
            assert!(Key::open(HKCU, &fixture.policy, KEY_READ)
                .unwrap()
                .is_some());
        }
        #[test]
        fn all_skipped_apply_and_rollback_preserve_foreign_values_byte_for_byte() {
            let fixture = Fixture::new();
            fixture.add(
                "{vpn}",
                &["one.test", ".two.test"],
                "192.0.2.1;2001:db8::1",
                "VPN configuration",
            );
            fixture.add("{old-owned}", &["one.test"], "127.0.0.53", NRPT_TAG);
            let parent = Key::open(HKCU, &fixture.local, KEY_READ).unwrap().unwrap();
            let vpn = Key::open(parent.0, "{vpn}", KEY_READ | KEY_WRITE)
                .unwrap()
                .unwrap();
            vpn.set("CustomBinary", 3, &[0, 255, 42, 17]).unwrap();
            let fields = [
                "Name",
                "GenericDNSServers",
                "Comment",
                "DisplayName",
                "UntouchedValue",
                "CustomBinary",
            ];
            let before: Vec<_> = fields.iter().map(|name| vpn.value(name).unwrap()).collect();
            let plan = fixture.apply(&[
                ("one.test".into(), "127.0.0.53".into()),
                (".two.test".into(), "127.0.0.53".into()),
            ]);
            assert!(plan.rules.is_empty());
            assert_eq!(plan.skipped, vec!["one.test", ".two.test"]);
            assert_eq!(read_rules(HKCU, &fixture.local).unwrap().1.len(), 1);
            assert_eq!(remove_owned(HKCU, &fixture.local).unwrap(), 0);
            let after: Vec<_> = fields.iter().map(|name| vpn.value(name).unwrap()).collect();
            assert_eq!(after, before);
        }
        #[test]
        fn inventory_reads_large_multi_namespace_values_and_policy_rules() {
            let fixture = Fixture::new();
            let names: Vec<_> = (0..300).map(|i| format!("host{i}.example.test")).collect();
            fixture.add(
                "{large}",
                &names.iter().map(String::as_str).collect::<Vec<_>>(),
                "192.0.2.1;2001:db8::1",
                "VPN",
            );
            let policy = Key::create(HKCU, &fixture.policy).unwrap();
            let key = Key::create(policy.0, "{policy}").unwrap();
            key.set_namespaces(&[".corp.test".into()]).unwrap();
            let inv = inventory_at(HKCU, &fixture.local, &fixture.policy).unwrap();
            assert!(inv.policy_present);
            assert_eq!(inv.foreign_rules[0].namespaces, names);
            assert_eq!(
                inv.foreign_rules[0].nameservers,
                vec!["192.0.2.1", "2001:db8::1"]
            );
            assert!(inv
                .foreign_rules
                .iter()
                .any(|rule| rule.id == "policy:{policy}"));
        }
        #[test]
        fn fresh_collision_is_skipped_and_unreadable_namespace_type_is_an_error() {
            let fixture = Fixture::new();
            let requested = vec![("one.test".into(), "127.0.0.53".into())];
            let old_plan = inventory_at(HKCU, &fixture.local, &fixture.policy)
                .unwrap()
                .plan(&requested);
            fixture.add("{vpn}", &["one.test"], "192.0.2.1", "VPN");
            let refreshed = reconcile(
                HKCU,
                &fixture.local,
                &fixture.policy,
                &old_plan.requested_rules,
                NRPT_TAG,
                "DNS",
            )
            .unwrap();
            assert_eq!(refreshed.skipped, vec!["one.test"]);
            assert!(refreshed.rules.is_empty());
            let parent = Key::open(HKCU, &fixture.local, KEY_READ).unwrap().unwrap();
            let foreign = Key::open(parent.0, "{vpn}", KEY_READ | KEY_WRITE)
                .unwrap()
                .unwrap();
            foreign.set("Name", REG_DWORD, &1u32.to_le_bytes()).unwrap();
            assert!(inventory_at(HKCU, &fixture.local, &fixture.policy).is_err());
            assert_eq!(foreign.string("UntouchedValue").unwrap(), "foreign bytes");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn foreign(names: &[&str]) -> ForeignRule {
        ForeignRule {
            id: "vpn-rule".into(),
            namespaces: names.iter().map(|name| name.to_string()).collect(),
            nameservers: vec!["192.0.2.1".into()],
            display_name: "VPN".into(),
        }
    }
    #[test]
    fn planner_preserves_suffix_type_and_skips_only_identical_foreign_namespaces() {
        let inv = NrptInventory {
            foreign_rules: vec![foreign(&["EXAMPLE.TEST.", ".elsewhere.test"])],
            policy_present: false,
        };
        let requested = vec![
            ("example.test".into(), "127.0.0.53".into()),
            (".example.test".into(), "127.0.0.53".into()),
            ("child.example.test".into(), "127.0.0.53".into()),
        ];
        let plan = inv.plan(&requested);
        assert_eq!(plan.skipped, vec!["example.test"]);
        assert_eq!(plan.rules.len(), 2);
        assert_eq!(plan.rules[0].0, ".example.test");
        assert_eq!(plan.preserved, inv.foreign_rules);
    }
    #[test]
    fn parent_child_and_default_foreign_namespaces_can_coexist() {
        let inv = NrptInventory {
            foreign_rules: vec![foreign(&[
                ".",
                ".test",
                "child.example.test",
                ".child.example.test",
            ])],
            policy_present: false,
        };
        let plan = inv.plan(&[
            ("example.test".into(), "127.0.0.53".into()),
            (".example.test".into(), "127.0.0.53".into()),
        ]);
        assert_eq!(plan.rules.len(), 2);
        assert!(plan.skipped.is_empty());
        assert!(plan.preserved.is_empty());
        assert_eq!(norm_ns(" .EXAMPLE.TEST. "), ".example.test");
        assert_eq!(norm_ns("."), ".");
    }
    #[test]
    fn policy_presence_suppresses_all_local_rules_even_without_matching_foreign_rule() {
        let inv = NrptInventory {
            foreign_rules: Vec::new(),
            policy_present: true,
        };
        let plan = inv.plan(&[
            ("one.test".into(), "127.0.0.53".into()),
            (".two.test".into(), "127.0.0.53".into()),
        ]);
        assert!(plan.rules.is_empty());
        assert_eq!(plan.skipped, vec!["one.test", ".two.test"]);
        assert!(plan.policy_present);
    }
    #[test]
    fn empty_nameserver_plan_preserves_hosts_only_mode_on_refresh() {
        let inv = NrptInventory::default();
        let requested = vec![
            ("one.test".into(), "".into()),
            (".two.test".into(), " \t ".into()),
            ("three.test".into(), "127.0.0.53".into()),
        ];
        let plan = inv.plan(&requested);
        assert_eq!(plan.skipped, vec!["one.test", ".two.test"]);
        assert_eq!(plan.rules, vec![("three.test".into(), "127.0.0.53".into())]);
        assert_eq!(inv.plan(&plan.requested_rules), plan);
    }

    #[cfg(windows)]
    fn mock_effective(
        expected: &[(String, String)],
        body: &str,
    ) -> Result<Vec<EffectiveIssue>, String> {
        let script = format!(
            "function Get-DnsClientNrptPolicy {{ {body} }}\n{}",
            effective_check_script(expected).unwrap()
        );
        let out = crate::system::powershell::command()
            .unwrap()
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
            .unwrap();
        if !out.status.success() {
            return Err(String::from_utf8(out.stderr).unwrap());
        }
        parse_effective_output(&out.stdout)
    }
    #[cfg(windows)]
    #[test]
    fn effective_policy_accepts_ip_objects_and_reports_override_or_empty_servers() {
        let expected = vec![("example.test".into(), "127.0.0.53;::1".into())];
        for (servers, count) in [
            ("@([System.Net.IPAddress]::Parse('::1'), [System.Net.IPAddress]::Parse('127.0.0.53'))", 0),
            ("@('127.0.0.53;0:0:0:0:0:0:0:1')", 0),
            ("@('::1','8.8.8.8')", 1),
            ("@()", 1),
        ] {
            let body = format!("[pscustomobject]@{{ Namespace=@('EXAMPLE.TEST.'); NameServers={servers} }}");
            let issues = mock_effective(&expected, &body).unwrap();
            assert_eq!(issues.len(), count);
            if count > 0 { assert_eq!(issues[0].namespace, "example.test"); }
        }
    }
    #[cfg(windows)]
    #[test]
    fn effective_policy_reports_each_missing_duplicate_and_overridden_namespace() {
        let expected = vec![
            ("one.test".into(), "127.0.0.53".into()),
            ("two.test".into(), "127.0.0.53".into()),
            (".one.test".into(), "127.0.0.53".into()),
            ("missing.test".into(), "127.0.0.53".into()),
        ];
        let body = "[pscustomobject]@{Namespace=@('one.test');NameServers='127.0.0.53'}; [pscustomobject]@{Namespace=@('two.test');NameServers='8.8.8.8'}; [pscustomobject]@{Namespace=@('.one.test');NameServers='127.0.0.53'}; [pscustomobject]@{Namespace=@('.ONE.TEST.');NameServers='127.0.0.53'}";
        let issues = mock_effective(&expected, body).unwrap();
        assert_eq!(
            issues
                .iter()
                .map(|issue| issue.namespace.as_str())
                .collect::<Vec<_>>(),
            vec!["two.test", ".one.test", "missing.test"]
        );
        assert!(issues[1].reason.contains("несколько"));
        assert!(issues[2].reason.contains("отсутствует"));
    }
    #[cfg(windows)]
    #[test]
    fn effective_policy_query_failure_is_an_error_with_utf8_message() {
        let expected = vec![("example.test".into(), "127.0.0.53".into())];
        assert!(mock_effective(&expected, "throw 'Ошибка проверки сети'")
            .unwrap_err()
            .contains("Ошибка проверки сети"));
        assert_eq!(mock_effective(&expected, "return @()").unwrap().len(), 1);
        assert!(parse_effective_output(b"not json").is_err());
    }
}
