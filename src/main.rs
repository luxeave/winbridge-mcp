use anyhow::Result;
use rmcp::{
    handler::server::tool::{Parameters, ToolRouter},
    handler::server::wrapper::Json,
    model::{
        CallToolResult, Content, ErrorCode, ErrorData as McpError, Implementation, ProtocolVersion,
        ServerCapabilities, ServerInfo,
    },
    schemars::JsonSchema,
    serde::{Deserialize, Serialize},
    serde_json::{json, Value},
    service::ServiceExt,
    tool, tool_handler, tool_router, ServerHandler,
};
use tokio::{io::{stdin, stdout}, process::Command};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Return an MCP error (Internal Error) with message and optional data.
fn mcp_internal(msg: impl Into<String>, data: Option<Value>) -> McpError {
    McpError::new(ErrorCode::InternalError, msg.into(), data)
}

/// Return an MCP error (Invalid Params).
fn mcp_invalid(msg: impl Into<String>) -> McpError {
    McpError::invalid_params(msg.into(), None)
}

/// Run a PowerShell pipeline and parse its JSON output.
/// The provided `pipeline` should **not** include ConvertTo-Json; we add it with sane depth.
async fn ps_json(pipeline: &str) -> std::result::Result<Value, McpError> {
    // Wrap the pipeline in a script block so we can set preferences safely.
    let script = format!(
        r#"$ProgressPreference='SilentlyContinue'; try {{ {pipeline} | ConvertTo-Json -Depth 6 }} catch {{ $_ | Out-String }}"#
    );

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .output()
        .await
        .map_err(|e| mcp_internal(format!("Failed to start PowerShell: {e}"), None))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        return Err(mcp_internal(
            "PowerShell pipeline failed",
            Some(json!({ "stderr": stderr })),
        ));
    }

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    // Try to parse JSON. If parsing fails, return text as an error payload.
    serde_json::from_str::<Value>(&stdout)
        .map_err(|e| mcp_internal(format!("JSON parse error: {e}"), Some(json!({ "raw": stdout }))))
}

/// Best-effort input sanitization for registry paths to avoid weird injections.
/// We allow HKLM:\SOFTWARE, HKLM:\SYSTEM, HKCU:\Software only.
fn validate_registry_path(path: &str) -> std::result::Result<(), McpError> {
    let path_upper = path.to_ascii_uppercase();
    let allowed = path_upper.starts_with("HKLM:\\SOFTWARE")
        || path_upper.starts_with("HKLM:\\SYSTEM")
        || path_upper.starts_with("HKCU:\\SOFTWARE");
    let no_bad_chars = !path.contains('`') && !path.contains(';') && !path.contains('\n') && !path.contains('\r');
    if !allowed {
        return Err(mcp_invalid(
            "Only HKLM:\\SOFTWARE, HKLM:\\SYSTEM, and HKCU:\\Software are allowed.",
        ));
    }
    if !no_bad_chars {
        return Err(mcp_invalid("Disallowed characters in registry path."));
    }
    Ok(())
}

#[derive(Clone)]
pub struct WinBridge {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl WinBridge {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    // --- Tool: OS info -------------------------------------------------------

    /// Basic OS info and uptime (read-only).
    #[tool(name = "os_info", description = "Get OS caption, version, build, architecture, hostname, last boot time, and uptime (hours).", annotations(read_only_hint = true))]
    async fn os_info(&self) -> std::result::Result<Json<Value>, McpError> {
        let ps = r#"
            $os = Get-CimInstance Win32_OperatingSystem;
            [pscustomobject]@{
              ComputerName   = $os.CSName
              Caption        = $os.Caption
              Version        = $os.Version
              BuildNumber    = $os.BuildNumber
              OSArchitecture = $os.OSArchitecture
              LastBootUpTime = $os.LastBootUpTime
              UptimeHours    = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalHours, 2)
            }
        "#;
        Ok(Json(ps_json(ps).await?))
    }

    // --- Tool: Local users ----------------------------------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct UsersParams {
        /// Only return enabled users.
        #[serde(default)]
        only_enabled: bool,
    }

    #[tool(name = "local_users", description = "List local users (Name, Enabled, LastLogon). Optional: only_enabled.", annotations(read_only_hint = true))]
    async fn local_users(&self, Parameters(p): Parameters<UsersParams>) -> std::result::Result<Json<Value>, McpError> {
        let filter = if p.only_enabled { r"| Where-Object { $_.Enabled }" } else { "" };
        let ps = format!(
            r#"Get-LocalUser | Select-Object Name,Enabled,LastLogon {filter} | Sort-Object Name"#
        );
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: Local groups (with optional members) ---------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct GroupsParams {
        /// Include group members (can be slower). Default: true
        #[serde(default = "default_true")]
        include_members: bool,
    }
    fn default_true() -> bool { true }

    #[tool(name = "local_groups", description = "List local groups. Optionally include members.", annotations(read_only_hint = true))]
    async fn local_groups(&self, Parameters(p): Parameters<GroupsParams>) -> std::result::Result<Json<Value>, McpError> {
        let ps = if p.include_members {
            r#"
            $out = foreach($g in Get-LocalGroup) {
              [pscustomobject]@{
                Group   = $g.Name
                Members = (Get-LocalGroupMember -Group $g.Name -ErrorAction SilentlyContinue |
                           Select-Object -ExpandProperty Name)
              }
            }
            $out | Sort-Object Group
            "#
        } else {
            r#"Get-LocalGroup | Select-Object Name | Sort-Object Name"#
        };
        Ok(Json(ps_json(ps).await?))
    }

    // --- Tool: Installed programs (registry-based) ---------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct ProgramsParams {
        /// Optional case-insensitive filter on DisplayName
        #[serde(default)]
        name_contains: Option<String>,
        /// Limit results (default 200)
        #[serde(default = "def_limit_200")]
        limit: u32,
    }
    fn def_limit_200() -> u32 { 200 }

    #[tool(name = "installed_programs", description = "List installed programs from registry (DisplayName, Version, Publisher, InstallDate).", annotations(read_only_hint = true))]
    async fn installed_programs(&self, Parameters(p): Parameters<ProgramsParams>) -> std::result::Result<Json<Value>, McpError> {
        let mut ps = r#"
          $paths = @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
          );
          $progs = foreach ($p in $paths) {
            Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
          } | Where-Object { $_.DisplayName } |
              Select-Object @{n='DisplayName';e={$_.DisplayName}},
                            @{n='DisplayVersion';e={$_.DisplayVersion}},
                            @{n='Publisher';e={$_.Publisher}},
                            @{n='InstallDate';e={$_.InstallDate}} |
              Sort-Object DisplayName
        "#.to_string();

        if let Some(s) = p.name_contains.as_ref() {
            // Quote in PowerShell - use double quotes; escape embedded quotes
            let q = s.replace('"', "`\"");
            ps.push_str(&format!(r#" ; $progs = $progs | Where-Object {{ $_.DisplayName -like "*{q}*" }}"#));
        }
        ps.push_str(&format!(r#" ; $progs | Select-Object -First {}"#, p.limit));
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: Services -------------------------------------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct ServicesParams {
        /// Filter by State: Running/Stopped (case-insensitive)
        #[serde(default)]
        state: Option<String>,
        /// Filter by StartMode: Auto/Manual/Disabled
        #[serde(default)]
        start_mode: Option<String>,
        /// Limit (default 500)
        #[serde(default = "def_limit_500")]
        limit: u32,
    }
    fn def_limit_500() -> u32 { 500 }

    #[tool(name = "services", description = "List Windows services via CIM (Name, DisplayName, State, StartMode, StartName, PathName).", annotations(read_only_hint = true))]
    async fn services(&self, Parameters(p): Parameters<ServicesParams>) -> std::result::Result<Json<Value>, McpError> {
        let mut ps = r#"
          $svc = Get-CimInstance Win32_Service |
                 Select-Object Name,DisplayName,State,StartMode,StartName,PathName
        "#.to_string();
        if let Some(s) = p.state.as_ref() {
            let q = s.replace('"', "`\"");
            ps.push_str(&format!(r#" ; $svc = $svc | Where-Object {{ $_.State -ieq "{q}" }}"#));
        }
        if let Some(m) = p.start_mode.as_ref() {
            let q = m.replace('"', "`\"");
            ps.push_str(&format!(r#" ; $svc = $svc | Where-Object {{ $_.StartMode -ieq "{q}" }}"#));
        }
        ps.push_str(&format!(r#" ; $svc | Sort-Object Name | Select-Object -First {}"#, p.limit));
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: Firewall rules (summary) --------------------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct FirewallParams {
        /// Inbound/Outbound
        #[serde(default)]
        direction: Option<String>,
        /// Only enabled rules (default true)
        #[serde(default = "default_true")]
        only_enabled: bool,
        /// Limit (default 500)
        #[serde(default = "def_limit_500")]
        limit: u32,
    }

    #[tool(name = "firewall_rules", description = "List Windows Firewall rules (DisplayName, Enabled, Direction, Action, Profile).", annotations(read_only_hint = true))]
    async fn firewall_rules(&self, Parameters(p): Parameters<FirewallParams>) -> std::result::Result<Json<Value>, McpError> {
        let mut ps = r#"
          $rules = Get-NetFirewallRule |
                   Select-Object DisplayName,Enabled,Direction,Action,Profile
        "#.to_string();
        if p.only_enabled {
            ps.push_str(r#" ; $rules = $rules | Where-Object { $_.Enabled }"#);
        }
        if let Some(d) = p.direction.as_ref() {
            let q = d.replace('"', "`\"");
            ps.push_str(&format!(r#" ; $rules = $rules | Where-Object {{ $_.Direction -ieq "{q}" }}"#));
        }
        ps.push_str(&format!(r#" ; $rules | Sort-Object DisplayName | Select-Object -First {}"#, p.limit));
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: Scheduled tasks ------------------------------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct TasksParams {
        /// Filter by State (e.g., Ready, Running, Disabled)
        #[serde(default)]
        state: Option<String>,
        /// Limit (default 500)
        #[serde(default = "def_limit_500")]
        limit: u32,
    }

    #[tool(name = "scheduled_tasks", description = "List scheduled tasks with last/next run time.", annotations(read_only_hint = true))]
    async fn scheduled_tasks(&self, Parameters(p): Parameters<TasksParams>) -> std::result::Result<Json<Value>, McpError> {
        let mut ps = r#"
          $tasks = Get-ScheduledTask
          $out = foreach($t in $tasks) {
            $info = $null
            try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath } catch {}
            [pscustomobject]@{
              TaskName    = $t.TaskName
              TaskPath    = $t.TaskPath
              State       = $t.State
              LastRunTime = $info.LastRunTime
              NextRunTime = $info.NextRunTime
            }
          }
        "#.to_string();
        if let Some(s) = p.state.as_ref() {
            let q = s.replace('"', "`\"");
            ps.push_str(&format!(r#" ; $out = $out | Where-Object {{ $_.State -ieq "{q}" }}"#));
        }
        ps.push_str(&format!(r#" ; $out | Sort-Object TaskName | Select-Object -First {}"#, p.limit));
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: SMB shares -----------------------------------------------------

    #[tool(name = "shares", description = "List SMB shares (Name, Path, Description, FolderEnumerationMode, EncryptData).", annotations(read_only_hint = true))]
    async fn shares(&self) -> std::result::Result<Json<Value>, McpError> {
        let ps = r#"Get-SmbShare | Select-Object Name,Path,Description,FolderEnumerationMode,EncryptData | Sort-Object Name"#;
        Ok(Json(ps_json(ps).await?))
    }

    // --- Tool: Network configuration -----------------------------------------

    #[tool(name = "network_config", description = "Per-adapter IPv4/IPv6 and DNS server configuration.", annotations(read_only_hint = true))]
    async fn network_config(&self) -> std::result::Result<Json<Value>, McpError> {
        let ps = r#"
          Get-NetIPConfiguration | ForEach-Object {
            [pscustomobject]@{
              InterfaceAlias = $_.InterfaceAlias
              IPv4           = ($_.IPv4Address  | ForEach-Object { $_.IPAddress } | Where-Object { $_ } ) -join ','
              IPv6           = ($_.IPv6Address  | ForEach-Object { $_.IPAddress } | Where-Object { $_ } ) -join ','
              DNSServers     = ($_.DNSServer    | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ } ) -join ','
            }
          } | Sort-Object InterfaceAlias
        "#;
        Ok(Json(ps_json(ps).await?))
    }

    // --- Tool: Hotfixes (installed updates) ----------------------------------

    #[tool(name = "hotfixes", description = "List installed hotfixes (KBs) via Get-HotFix.", annotations(read_only_hint = true))]
    async fn hotfixes(&self) -> std::result::Result<Json<Value>, McpError> {
        let ps = r#"Get-HotFix | Select-Object HotFixID,Description,InstalledOn | Sort-Object InstalledOn -Descending"#;
        Ok(Json(ps_json(ps).await?))
    }

    // --- Tool: Open ports (listening TCP) ------------------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct PortsParams {
        /// Limit (default 500)
        #[serde(default = "def_limit_500")]
        limit: u32,
    }

    #[tool(name = "open_ports", description = "List listening TCP ports with owning process.", annotations(read_only_hint = true))]
    async fn open_ports(&self, Parameters(p): Parameters<PortsParams>) -> std::result::Result<Json<Value>, McpError> {
        let ps = format!(
            r#"
            $rows = Get-NetTCPConnection -State Listen |
              Select-Object LocalAddress,LocalPort,OwningProcess
            $out = foreach ($r in $rows) {{
              $proc = $null
              try {{ $proc = Get-Process -Id $r.OwningProcess -ErrorAction Stop }} catch {{}}
              [pscustomobject]@{{
                LocalAddress = $r.LocalAddress
                LocalPort    = $r.LocalPort
                ProcessId    = $r.OwningProcess
                ProcessName  = $proc.Name
              }}
            }}
            $out | Sort-Object LocalPort | Select-Object -First {limit}
            "#,
            limit = p.limit
        );
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: Event log (recent) --------------------------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct EventParams {
        /// Log name (e.g., System, Security, Application). Default: System
        #[serde(default = "def_system")]
        log_name: String,
        /// Level filter (e.g., Error, Warning, Information, Critical)
        #[serde(default)]
        level: Option<String>,
        /// Maximum events (default 200)
        #[serde(default = "def_limit_200")]
        max_events: u32,
    }
    fn def_system() -> String { "System".to_string() }

    #[tool(name = "event_log_recent", description = "Return recent events from a Windows event log with optional level filter.", annotations(read_only_hint = true))]
    async fn event_log_recent(&self, Parameters(p): Parameters<EventParams>) -> std::result::Result<Json<Value>, McpError> {
        let mut ps = format!(
            r#"$ev = Get-WinEvent -LogName "{log}" -MaxEvents {n} | Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message"#,
            log = p.log_name.replace('"', "`\""),
            n = p.max_events
        );
        if let Some(level) = p.level.as_ref() {
            let q = level.replace('"', "`\"");
            ps.push_str(&format!(r#" ; $ev = $ev | Where-Object {{ $_.LevelDisplayName -ieq "{q}" }}"#));
        }
        ps.push_str(" ; $ev");
        Ok(Json(ps_json(&ps).await?))
    }

    // --- Tool: Read registry key (restricted roots) ---------------------------

    #[derive(Serialize, Deserialize, JsonSchema)]
    struct RegParams {
        /// Registry path (HKLM:\SOFTWARE..., HKLM:\SYSTEM..., HKCU:\Software...)
        path: String,
        /// Optional specific value names to return. If empty, return all properties.
        #[serde(default)]
        names: Vec<String>,
    }

    #[tool(name = "read_registry_key", description = "Read a registry key (restricted to HKLM:\\SOFTWARE, HKLM:\\SYSTEM, HKCU:\\Software).", annotations(read_only_hint = true))]
    async fn read_registry_key(&self, Parameters(p): Parameters<RegParams>) -> std::result::Result<Json<Value>, McpError> {
        validate_registry_path(&p.path)?;
        let names_arr = if p.names.is_empty() {
            String::from("$null")
        } else {
            // Build a PowerShell array of quoted names
            let items: Vec<String> = p
                .names
                .into_iter()
                .map(|n| format!("\"{}\"", n.replace('"', "`\"")))
                .collect();
            format!("@({})", items.join(","))
        };

        let ps = format!(
            r#"
            $item = Get-ItemProperty -Path "{path}" -ErrorAction Stop
            if ({names} -eq $null) {{
              # Drop PS* meta fields; keep real properties
              $props = $item.PSObject.Properties | Where-Object {{ $_.Name -notmatch '^PS' }} |
                       ForEach-Object {{ @{{ name=$_.Name; value=$_.Value }} }}
            }} else {{
              $props = foreach($n in {names}) {{
                try {{ @{{ name=$n; value = $item.$n }} }} catch {{ @{{ name=$n; value=$null }} }}
              }}
            }}
            [pscustomobject]@{{ Path = "{path}"; Properties = $props }}
            "#,
            path = p.path.replace('"', "`\""),
            names = names_arr
        );

        Ok(Json(ps_json(&ps).await?))
    }
}

// Implement the MCP server handler and advertise capabilities.
#[tool_handler]
impl ServerHandler for WinBridge {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools() // this server only uses tools
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("Read-only Windows Server 2022 bridge for vuln assessment. All tools are non-destructive.".to_string()),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Logging setup (control with RUST_LOG, e.g., RUST_LOG=info)
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer())
        .init();

    // stdio transport per MCP spec; host spawns this process.
    let transport = (stdin(), stdout());

    // Serve; blocks until the peer disconnects.
    let service = WinBridge::new().serve(transport).await?;
    service.waiting().await?;
    Ok(())
}