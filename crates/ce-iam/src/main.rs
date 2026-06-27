//! `ce-iam` — command-line IAM over CE capabilities.
//!
//! Subcommands:
//!   * `whoami`   — print this machine's CE node id (the principal it acts as).
//!   * `grant`    — mint or attenuate a grant (capability chain) for an audience.
//!   * `verify`   — check whether a grant authorizes an action on a node (offline + on-chain revoke).
//!   * `revoke`   — submit an on-chain `RevokeCapability` for a `(this-issuer, nonce)` you minted.
//!   * `revoked`  — list / inspect the on-chain revoked set.
//!   * `policy`   — author / validate / inspect policy documents and grant tokens.
//!   * `role`     — manage the durable role/policy catalog (put/get/list/rm, attach/detach, …).
//!   * `wallet`   — store, list, show, and remove held grant tokens.
//!   * `root`     — manage and rotate accepted root keys.
//!   * `device`   — enroll/manage this operator's devices (claim/request/list/approve/revoke) over the
//!                  `ce-iam-core` [`DeviceStore`] + the P-256<->NodeId cap bridge.
//!   * `secret`   — the secrets vault (gen/put/get/rotate/list/rm/grant/use) over the
//!                  `ce-iam-core` [`Vault`] on the mesh ce-kv store. A secret value is NEVER printed.
//!
//! Money is never printed as a float; capability conditions use whole-credit ceilings. Output is
//! plain, scriptable text (and `--json` where structured output helps). No emojis.

use anyhow::{Context, Result, anyhow, bail};
use ce_iam::Identity;
use ce_iam::{
    CachedRevocationSet, CatalogStore, Conditions, DeviceKey, DeviceStore, Iam, MeshKvStore, Policy,
    Principal, ResourceMatch, RevocationPolicy, RevocationSet, Role, Roots, Vault, WalletStore,
    ce_cloud_action_universe, device::RevokeOutcome, iam_dir, simple_policy,
};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "ce-iam",
    version,
    about = "IAM over CE capabilities: mint, attenuate, verify, revoke, and manage roles/wallet/roots."
)]
struct Cli {
    /// Identity + state data dir (holds identity/node.key and iam/). Defaults to the standard CE
    /// data dir.
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,

    /// CE node HTTP API base URL (for on-chain revocation lookups and revoke submission).
    #[arg(long, global = true, default_value = ce_rs::DEFAULT_BASE_URL)]
    node: String,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print this machine's CE node id (the principal it acts as).
    Whoami(WhoamiArgs),
    /// Mint a root grant, or attenuate an existing one, for an audience principal.
    Grant(GrantArgs),
    /// Verify whether a grant token authorizes an action on a node.
    Verify(VerifyArgs),
    /// Submit an on-chain RevokeCapability for a nonce this node issued.
    Revoke(RevokeArgs),
    /// List or inspect the on-chain revoked capability set.
    Revoked(RevokedArgs),
    /// Author, validate, or inspect policy documents and grant tokens.
    #[command(subcommand)]
    Policy(PolicyCmd),
    /// Manage the durable role/policy catalog.
    #[command(subcommand)]
    Role(RoleCmd),
    /// Store and manage held grant tokens.
    #[command(subcommand)]
    Wallet(WalletCmd),
    /// Manage and rotate accepted root keys.
    #[command(subcommand)]
    Root(RootCmd),
    /// Enroll and manage this operator's devices (the P-256<->NodeId device registry).
    #[command(subcommand)]
    Device(DeviceCmd),
    /// The secrets vault: generate/store/rotate/reveal secrets and grant apps read access. A secret
    /// value is NEVER printed.
    #[command(subcommand)]
    Secret(SecretCmd),
    /// Run the passwordless browser<->node auth responder: announce this node, and vouch (mint a
    /// node-signed capability) for browsers that ask, so "your local node is your login".
    NodeAuth(NodeAuthArgs),
}

#[derive(Args)]
struct NodeAuthArgs {
    /// Local CE node HTTP API base URL.
    #[arg(long, default_value = ce_rs::DEFAULT_BASE_URL)]
    api: String,
    /// CE node API token (else discovered from $CE_API_TOKEN / the data dir).
    #[arg(long)]
    token: Option<String>,
    /// A human label announced for this node (defaults to the node id's first 8 hex chars).
    #[arg(long, default_value = "")]
    label: String,
    /// An optional owner tag announced alongside the node (e.g. your handle).
    #[arg(long)]
    owner: Option<String>,
    /// Do NOT auto-issue caps: log requests and wait (interactive approval is a follow-up). By
    /// default every well-formed request from a browser is vouched.
    #[arg(long)]
    no_approve: bool,
}

#[derive(Args)]
struct WhoamiArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

/// Shared condition flags so every grant/policy author surface exposes the full caveat set.
#[derive(Args, Clone)]
struct ConditionArgs {
    /// Expiry as seconds-from-now (e.g. `--expires-in 3600`). 0 = never.
    #[arg(long, default_value_t = 0)]
    expires_in: u64,
    /// Activation delay: grant is not valid until this many seconds from now.
    #[arg(long, default_value_t = 0)]
    activates_in: u64,
    /// Ceiling: max CPU cores a deploy under this grant may request.
    #[arg(long)]
    max_cpu: Option<u32>,
    /// Ceiling: max memory (MB).
    #[arg(long)]
    max_mem_mb: Option<u32>,
    /// Ceiling: max whole credits spendable.
    #[arg(long)]
    max_credits: Option<u64>,
    /// Restrict tunnels under this grant to this remote port (repeatable).
    #[arg(long = "allowed-port")]
    allowed_ports: Vec<u16>,
    /// Confine sync/file writes under this grant to paths beneath this prefix.
    #[arg(long)]
    path_prefix: Option<String>,
}

#[derive(Args)]
struct GrantArgs {
    /// Audience: the 64-hex node id receiving the grant.
    #[arg(long)]
    to: String,
    /// Actions to allow (repeatable). Supports `prefix:*` and `*` against the action universe.
    #[arg(long = "action")]
    actions: Vec<String>,
    /// Resource scope: `*`/`any`, a 64-hex node id, `tag:<t>`, or `all-of:a,b`.
    #[arg(long, default_value = "*")]
    resource: String,
    #[command(flatten)]
    conditions: ConditionArgs,
    /// Issuer-chosen nonce naming this grant for revocation. Unique per issuer.
    #[arg(long)]
    nonce: u64,
    /// Attenuate this parent grant token instead of minting a fresh root (sub-delegation).
    #[arg(long)]
    parent: Option<String>,
    /// Mint from a named catalog role instead of inline actions (root grants only).
    #[arg(long)]
    role: Option<String>,
    /// Emit JSON instead of just the token.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// The grant token (hex capability chain) to check. Or use `--wallet-label`.
    #[arg(long)]
    token: Option<String>,
    /// Reference a token stored in the wallet by its label instead of `--token`.
    #[arg(long)]
    wallet_label: Option<String>,
    /// Requester: the 64-hex node id presenting the grant (the expected leaf audience).
    #[arg(long)]
    requester: String,
    /// Action string to check (e.g. `storage:read`).
    #[arg(long)]
    action: String,
    /// The node the action targets (64-hex). Defaults to this machine's node id.
    #[arg(long)]
    on_node: Option<String>,
    /// Self-tags the target node advertises (repeatable), used for tag/all-of resource matches.
    #[arg(long = "tag")]
    tags: Vec<String>,
    /// Skip the on-chain revocation lookup (verify against an empty revoke set).
    #[arg(long)]
    no_revocation_check: bool,
    /// Deny if the revocation set cannot be fetched and the cached snapshot is stale (fail-closed).
    /// Without this flag, a fetch failure falls back to the last-known-good snapshot (fail-open).
    #[arg(long)]
    fail_closed: bool,
    /// Freshness window (seconds) for the cached revocation snapshot used by --fail-closed.
    #[arg(long, default_value_t = 300)]
    revocation_ttl: u64,
    /// Also accept chains rooted at these configured roots (from `root add`), at the current time.
    #[arg(long)]
    use_roots: bool,
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RevokeArgs {
    /// The nonce of a grant this node issued, to revoke on-chain.
    #[arg(long)]
    nonce: u64,
}

#[derive(Args)]
struct RevokedArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Build a single-statement Allow policy document from flags and print it as JSON.
    New(PolicyNewArgs),
    /// Validate a policy document (from a file or stdin) and report what it grants.
    Validate(PolicyValidateArgs),
    /// Inspect a grant token: decode it and print its scope (does not verify against a node).
    Inspect(PolicyInspectArgs),
}

#[derive(Args)]
struct PolicyNewArgs {
    #[arg(long = "action", required = true)]
    actions: Vec<String>,
    #[arg(long, default_value = "*")]
    resource: String,
    #[command(flatten)]
    conditions: ConditionArgs,
}

#[derive(Args)]
struct PolicyValidateArgs {
    /// Path to a policy JSON file. Reads stdin if omitted.
    file: Option<PathBuf>,
}

#[derive(Args)]
struct PolicyInspectArgs {
    /// The grant token (hex capability chain).
    token: String,
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum RoleCmd {
    /// Create or replace a role from a policy file (or stdin) under a name.
    Put(RolePutArgs),
    /// Print a role as JSON.
    Get(RoleGetArgs),
    /// List role (and policy) names in the catalog.
    List(RoleListArgs),
    /// Remove a role.
    Rm(RoleRmArgs),
    /// Attach a role to a principal.
    Attach(RoleAttachArgs),
    /// Detach a role from a principal.
    Detach(RoleAttachArgs),
    /// Show the effective grants the catalog would mint for a principal.
    EffectiveGrants(EffectiveGrantsArgs),
    /// Print the catalog audit trail.
    Audit(AuditArgs),
    /// Compact the durable catalog op-log (snapshot current state, discard history).
    Compact,
}

#[derive(Args)]
struct RolePutArgs {
    /// Role name.
    name: String,
    /// Policy JSON file. Reads stdin if omitted.
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Optional description.
    #[arg(long)]
    description: Option<String>,
}

#[derive(Args)]
struct RoleGetArgs {
    name: String,
}

#[derive(Args)]
struct RoleListArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RoleRmArgs {
    name: String,
}

#[derive(Args)]
struct RoleAttachArgs {
    /// Principal (64-hex node id).
    principal: String,
    /// Role name.
    role: String,
}

#[derive(Args)]
struct EffectiveGrantsArgs {
    /// Principal (64-hex node id).
    principal: String,
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AuditArgs {
    /// Only entries after this version.
    #[arg(long, default_value_t = 0)]
    since: u64,
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum WalletCmd {
    /// Store a grant token under a label.
    Add(WalletAddArgs),
    /// List stored grant labels.
    List(WalletListArgs),
    /// Show a stored grant: its token and decoded scope.
    Show(WalletShowArgs),
    /// Remove a stored grant by label.
    Rm(WalletRmArgs),
}

#[derive(Args)]
struct WalletAddArgs {
    /// Label to store the grant under.
    label: String,
    /// The grant token (hex). Reads stdin if omitted.
    token: Option<String>,
    /// Optional note.
    #[arg(long)]
    note: Option<String>,
}

#[derive(Args)]
struct WalletListArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct WalletShowArgs {
    label: String,
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct WalletRmArgs {
    label: String,
}

#[derive(Subcommand)]
enum RootCmd {
    /// Add (or replace) an accepted root key with an optional validity window.
    Add(RootAddArgs),
    /// List configured roots (and whether each is accepted now).
    List(RootListArgs),
    /// Retire a root at a given time (sets its not_after; overlap-safe).
    Retire(RootRetireArgs),
    /// Hard-remove a root.
    Rm(RootRmArgs),
    /// Re-issue a single-link root grant under this node's key (root-rotation migration).
    Reissue(RootReissueArgs),
}

#[derive(Args)]
struct RootAddArgs {
    /// Root node id (64-hex).
    key: String,
    /// Optional label.
    #[arg(long)]
    label: Option<String>,
    /// Accepted starting this many seconds from now (0 = immediately).
    #[arg(long, default_value_t = 0)]
    valid_in: u64,
    /// Accepted for this many seconds from the start (0 = never retires).
    #[arg(long, default_value_t = 0)]
    valid_for: u64,
}

#[derive(Args)]
struct RootListArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RootRetireArgs {
    /// Root node id (64-hex).
    key: String,
    /// Retire this many seconds from now (0 = now).
    #[arg(long, default_value_t = 0)]
    in_secs: u64,
}

#[derive(Args)]
struct RootRmArgs {
    key: String,
}

#[derive(Args)]
struct RootReissueArgs {
    /// The single-link root grant token to migrate under this node's key.
    token: String,
    /// Nonce for the re-issued grant.
    #[arg(long)]
    nonce: u64,
    /// Emit JSON instead of just the token.
    #[arg(long)]
    json: bool,
}

// ---- device subcommand (over ce_iam_core::DeviceStore + the cap bridge) ---------------------------

#[derive(Subcommand)]
enum DeviceCmd {
    /// TOFU first claim: become the admin device if no admin exists yet (binds this node id).
    Claim(DeviceClaimArgs),
    /// Request enrollment as a pending device (an admin approves it).
    Request(DeviceRequestArgs),
    /// List enrolled/pending devices.
    List(DeviceListArgs),
    /// Approve a pending device, promoting it to admin.
    Approve(DeviceIdArgs),
    /// Revoke (remove) a device. The last admin cannot be revoked.
    Revoke(DeviceIdArgs),
}

#[derive(Args)]
struct DeviceClaimArgs {
    /// The device id to claim as admin.
    device_id: String,
    /// The device's compact ECDSA pub (base64url of 04||x||y) used to authenticate it.
    #[arg(long = "pub")]
    pub_b64: String,
    /// The device's CE NodeId (64-hex) — the cap principal a minted grant binds to. Defaults to this
    /// machine's node id.
    #[arg(long)]
    node_id: Option<String>,
}

#[derive(Args)]
struct DeviceRequestArgs {
    /// The device id requesting enrollment.
    device_id: String,
    /// The device's compact ECDSA pub (base64url of 04||x||y).
    #[arg(long = "pub")]
    pub_b64: String,
    /// The device's CE NodeId (64-hex). Defaults to this machine's node id.
    #[arg(long)]
    node_id: Option<String>,
    /// A human label for the device.
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Args)]
struct DeviceListArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct DeviceIdArgs {
    /// The device id.
    device_id: String,
}

// ---- secret subcommand (over ce_iam_core::secrets::Vault on the mesh ce-kv store) -----------------

#[derive(Subcommand)]
enum SecretCmd {
    /// Establish the vault on this (owner) device, or re-enroll the owner. Idempotent.
    Init(SecretInitArgs),
    /// Re-establish the vault from THIS owner key alone (re-derives the master). Owner is never locked
    /// out, even after a store wipe.
    Recover(SecretInitArgs),
    /// Generate + store a secret under a name by type (the value is never displayed).
    Gen(SecretGenArgs),
    /// Store an existing secret value from stdin under a name (never echoed).
    Put(SecretPutArgs),
    /// Reveal a secret's raw value — for piping/injection only. Refuses a TTY unless --force.
    Get(SecretGetArgs),
    /// Generate a fresh value for an existing secret, bumping its version.
    Rotate(SecretNameArgs),
    /// List secret names + type + version + fingerprint (never values).
    List(SecretListArgs),
    /// Delete a named secret.
    Rm(SecretNameArgs),
    /// Issue a signed read-grant to an app/audience for one or more secrets.
    Grant(SecretGrantArgs),
    /// Run a command with named secrets injected as environment variables.
    Use(SecretUseArgs),
    /// Issue a ONE-TIME enrolment token so a fresh, unattended device (a VM, a CI runner) can self-join
    /// this account hands-free — no human running `approve`. Hand the printed token to the device out of
    /// band (cloud-init, a sealed env var). Run on an ENROLLED device.
    EnrolIssue(SecretEnrolIssueArgs),
    /// Redeem a one-time enrolment token on THIS fresh device: recover the account master, enroll this
    /// device, and burn the token. Afterwards the vault reads the SAME account mesh-wide.
    EnrolRedeem(SecretEnrolRedeemArgs),
}

/// Shared flags selecting the vault: namespace + which CE node to reach the mesh ce-kv through.
#[derive(Args, Clone)]
struct VaultArgs {
    /// Vault namespace (folds into the owner-master derivation salt and the ce-kv topic). Defaults to
    /// this device id, giving each operator a private vault.
    #[arg(long, global = true)]
    ns: Option<String>,
    /// The CE node HTTP base to reach the mesh ce-kv service through. Defaults to --node.
    #[arg(long, global = true)]
    kv_node: Option<String>,
}

#[derive(Args)]
struct SecretInitArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// A label for this device in the vault.
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Args)]
struct SecretGenArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// Secret name.
    name: String,
    /// Secret type: token, hex, password, base64, uuid, aes-256 (keypair types are not yet supported
    /// in the Rust CLI — see the gap notes).
    #[arg(long = "type", default_value = "token")]
    kind: String,
    /// Length in bytes for length-bearing types (token/hex/password/base64).
    #[arg(long)]
    length: Option<usize>,
}

#[derive(Args)]
struct SecretPutArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// Secret name.
    name: String,
    /// Type label recorded with the secret.
    #[arg(long = "type", default_value = "opaque")]
    kind: String,
}

#[derive(Args)]
struct SecretGetArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// Secret name.
    name: String,
    /// Emit the raw value to a TTY anyway (by default revealing to a terminal is refused).
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct SecretNameArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// Secret name.
    name: String,
}

#[derive(Args)]
struct SecretListArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct SecretGrantArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// The app/audience receiving read access.
    audience: String,
    /// Comma-separated secret names to grant read access to.
    #[arg(long)]
    read: String,
    /// Optional ISO-8601 expiry timestamp (e.g. 2026-12-31T00:00:00.000Z).
    #[arg(long)]
    expires: Option<String>,
}

#[derive(Args)]
struct SecretEnrolIssueArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// A label recorded for the device that will redeem this token.
    #[arg(long, default_value = "")]
    label: String,
    /// Validity window in seconds (default 1 hour). The token cannot be redeemed after it elapses.
    #[arg(long, default_value_t = 3600)]
    ttl: u64,
}

#[derive(Args)]
struct SecretEnrolRedeemArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// The one-time token printed by `secret enrol-issue` (format `<id>.<secret>`). Reads stdin if `-`.
    token: String,
    /// A label for THIS device in the vault.
    #[arg(long, default_value = "")]
    label: String,
}

#[derive(Args)]
struct SecretUseArgs {
    #[command(flatten)]
    vault: VaultArgs,
    /// Secret names to inject, followed by `--` and the command to run.
    #[arg(trailing_var_arg = true, required = true)]
    rest: Vec<String>,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Resolve the identity data dir: explicit flag, else the standard CE data dir
/// (`<data>/ce/identity`). We mirror the node's layout so `ce-iam` acts as the same principal.
fn identity_dir(explicit: &Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.join("identity"));
    }
    let dirs = directories::ProjectDirs::from("", "", "ce")
        .ok_or_else(|| anyhow!("cannot determine the default CE data dir; pass --data-dir"))?;
    Ok(dirs.data_dir().join("identity"))
}

fn load_identity(explicit: &Option<PathBuf>) -> Result<Identity> {
    let dir = identity_dir(explicit)?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating identity dir {}", dir.display()))?;
    Identity::load_or_generate(&dir).context("loading CE identity")
}

fn iam_service() -> Iam {
    Iam::new().with_action_universe(ce_cloud_action_universe())
}

fn build_conditions(c: &ConditionArgs) -> Conditions {
    let now = now_secs();
    Conditions {
        // Saturating so a huge --expires-in/--activates-in can never wrap to a tiny/garbage value.
        not_after: if c.expires_in == 0 {
            None
        } else {
            Some(now.saturating_add(c.expires_in))
        },
        not_before: if c.activates_in == 0 {
            None
        } else {
            Some(now.saturating_add(c.activates_in))
        },
        max_cpu: c.max_cpu,
        max_mem_mb: c.max_mem_mb,
        max_credits: c.max_credits,
        allowed_ports: if c.allowed_ports.is_empty() {
            None
        } else {
            Some(c.allowed_ports.clone())
        },
        path_prefix: c.path_prefix.clone(),
    }
}

fn read_file_or_stdin(file: &Option<PathBuf>) -> Result<String> {
    match file {
        Some(f) => std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display())),
        None => {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("reading stdin")?;
            Ok(s)
        }
    }
}

fn read_arg_or_stdin(arg: &Option<String>) -> Result<String> {
    match arg {
        Some(s) => Ok(s.clone()),
        None => {
            use std::io::Read;
            let mut s = String::new();
            std::io::stdin()
                .read_to_string(&mut s)
                .context("reading stdin")?;
            Ok(s.trim().to_string())
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match &cli.cmd {
        Command::Whoami(a) => cmd_whoami(&cli, a),
        Command::Grant(a) => cmd_grant(&cli, a),
        Command::Verify(a) => cmd_verify(&cli, a).await,
        Command::Revoke(a) => cmd_revoke(&cli, a).await,
        Command::Revoked(a) => cmd_revoked(&cli, a).await,
        Command::Policy(p) => cmd_policy(&cli, p),
        Command::Role(r) => cmd_role(&cli, r),
        Command::Wallet(w) => cmd_wallet(&cli, w),
        Command::Root(r) => cmd_root(&cli, r),
        Command::Device(d) => cmd_device(&cli, d),
        Command::Secret(s) => cmd_secret(&cli, s).await,
        Command::NodeAuth(a) => cmd_node_auth(&cli, a).await,
    }
}

/// Run the passwordless browser<->node auth responder until Ctrl-C.
async fn cmd_node_auth(cli: &Cli, a: &NodeAuthArgs) -> Result<()> {
    use ce_iam::NodeAuthResponder;
    let identity = load_identity(&cli.data_dir)?;
    let node_id = identity.node_id_hex();
    let client =
        ce_rs::CeClient::with_token(&a.api, a.token.clone().or_else(ce_rs::discover_api_token));
    // The node is its own capability root; minting only signs, so no accepted roots are needed here.
    let iam = Iam::new();
    let label = if a.label.is_empty() { node_id[..8.min(node_id.len())].to_string() } else { a.label.clone() };
    let responder =
        NodeAuthResponder::new(client, identity, iam, label, a.owner.clone(), !a.no_approve);
    eprintln!(
        "node-auth responder for node {node_id} — announcing on `ce-iam/nodes/announce`, vouching on \
         requests. Ctrl-C to stop."
    );
    responder
        .run(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
}

fn cmd_whoami(cli: &Cli, a: &WhoamiArgs) -> Result<()> {
    let identity = load_identity(&cli.data_dir)?;
    let id = identity.node_id_hex();
    if a.json {
        println!("{}", serde_json::json!({ "node_id": id }));
    } else {
        println!("{id}");
    }
    Ok(())
}

fn open_catalog_store(cli: &Cli) -> Result<CatalogStore> {
    let dir = iam_dir(cli.data_dir.as_deref()).map_err(|e| anyhow!("{e}"))?;
    CatalogStore::open(&dir).map_err(|e| anyhow!("opening catalog: {e}"))
}

fn open_wallet(cli: &Cli) -> Result<WalletStore> {
    let dir = iam_dir(cli.data_dir.as_deref()).map_err(|e| anyhow!("{e}"))?;
    WalletStore::open(&dir).map_err(|e| anyhow!("opening wallet: {e}"))
}

fn open_roots(cli: &Cli) -> Result<Roots> {
    let dir = iam_dir(cli.data_dir.as_deref()).map_err(|e| anyhow!("{e}"))?;
    Roots::open(&dir).map_err(|e| anyhow!("opening roots: {e}"))
}

fn cmd_grant(cli: &Cli, a: &GrantArgs) -> Result<()> {
    let identity = load_identity(&cli.data_dir)?;
    let iam = iam_service();
    let audience = Principal::parse(&a.to).context("parsing --to")?;

    let grant = if let Some(role) = &a.role {
        if a.parent.is_some() {
            bail!("--role mints a root grant and cannot be combined with --parent");
        }
        let store = open_catalog_store(cli)?;
        iam.mint_role(&identity, audience, store.catalog(), role, a.nonce)
            .map_err(|e| anyhow!("{e}"))?
    } else {
        if a.actions.is_empty() {
            bail!("provide --action (one or more) or --role");
        }
        let resource = ResourceMatch::parse(&a.resource).map_err(|e| anyhow!("{e}"))?;
        let conditions = build_conditions(&a.conditions);
        let policy = simple_policy(a.actions.clone(), resource, conditions);
        match &a.parent {
            None => iam
                .mint(&identity, audience, &policy, a.nonce)
                .map_err(|e| anyhow!("{e}"))?,
            Some(parent_token) => {
                let parent = iam
                    .decode(parent_token)
                    .map_err(|e| anyhow!("decoding --parent: {e}"))?;
                iam.attenuate(&identity, &parent, audience, &policy, a.nonce)
                    .map_err(|e| anyhow!("{e}"))?
            }
        }
    };

    if a.json {
        let scope = iam.inspect(&grant.token).map_err(|e| anyhow!("{e}"))?;
        println!(
            "{}",
            serde_json::json!({ "token": grant.token, "scope": scope })
        );
    } else {
        println!("{}", grant.token);
    }
    Ok(())
}

async fn cmd_verify(cli: &Cli, a: &VerifyArgs) -> Result<()> {
    let identity = load_identity(&cli.data_dir)?;
    let mut iam = iam_service();
    let now = now_secs();

    // Optionally honor configured roots valid at `now`.
    if a.use_roots {
        let roots = open_roots(cli)?;
        iam = iam.with_accepted_roots(roots.accepted_at(now));
    }

    let requester = Principal::parse(&a.requester).context("parsing --requester")?;
    let on_node = match &a.on_node {
        Some(h) => Principal::parse(h).context("parsing --on-node")?.node_id(),
        None => identity.node_id(),
    };

    // Resolve the token from --token or --wallet-label.
    let token = match (&a.token, &a.wallet_label) {
        (Some(t), None) => t.clone(),
        (None, Some(label)) => {
            let wallet = open_wallet(cli)?;
            wallet
                .token(label)
                .ok_or_else(|| anyhow!("no grant labeled '{label}' in the wallet"))?
                .to_string()
        }
        (Some(_), Some(_)) => bail!("pass exactly one of --token or --wallet-label"),
        (None, None) => bail!("pass --token or --wallet-label"),
    };

    // Resolve the revocation set with a freshness/fail-closed policy.
    let revset = resolve_revocation(cli, a, now).await?;

    let result = iam.verify(
        &on_node,
        &a.tags,
        now,
        &requester,
        &a.action,
        &token,
        &revset.predicate(),
    );

    match result {
        Ok(()) => {
            if a.json {
                println!("{}", serde_json::json!({ "authorized": true }));
            } else {
                println!(
                    "ALLOW: {} may '{}' on {}",
                    requester,
                    a.action,
                    hex::encode(on_node)
                );
            }
            Ok(())
        }
        Err(e) => {
            if a.json {
                println!(
                    "{}",
                    serde_json::json!({ "authorized": false, "reason": e.to_string() })
                );
            } else {
                println!("DENY: {e}");
            }
            std::process::exit(1);
        }
    }
}

/// Build the revocation set for `verify`, honoring `--no-revocation-check`, fail-open (default), and
/// `--fail-closed` with a TTL'd last-known-good cache.
async fn resolve_revocation(cli: &Cli, a: &VerifyArgs, now: u64) -> Result<RevocationSet> {
    if a.no_revocation_check {
        return Ok(RevocationSet::empty());
    }
    let policy = if a.fail_closed {
        RevocationPolicy::FailClosed
    } else {
        RevocationPolicy::FailOpen
    };
    let cache_path = iam_dir(cli.data_dir.as_deref())
        .map_err(|e| anyhow!("{e}"))?
        .join("revocation-cache.json");
    let mut cached =
        CachedRevocationSet::load(&cache_path, a.revocation_ttl).map_err(|e| anyhow!("{e}"))?;

    let client = ce_rs::CeClient::new(cli.node.clone());
    match cached.refresh(&client, now, Some(&cache_path)).await {
        Ok(()) => Ok(cached.set()),
        Err(e) => match policy {
            RevocationPolicy::FailOpen => {
                // Use the last-known-good snapshot (possibly empty). Rely on short expiries.
                eprintln!(
                    "warning: revocation fetch from {} failed ({e}); using last-known-good snapshot \
                     (fetched_at={}, fresh={})",
                    cli.node,
                    cached.fetched_at,
                    cached.is_fresh(now)
                );
                Ok(cached.set())
            }
            RevocationPolicy::FailClosed => {
                if cached.is_fresh(now) {
                    eprintln!(
                        "warning: revocation fetch failed ({e}); cached snapshot still fresh, using it"
                    );
                    Ok(cached.set())
                } else {
                    bail!(
                        "could not fetch revocation set from {} and the cached snapshot is stale; \
                         failing closed (deny). Error: {e}",
                        cli.node
                    )
                }
            }
        },
    }
}

async fn cmd_revoke(cli: &Cli, a: &RevokeArgs) -> Result<()> {
    let token = ce_rs::discover_api_token();
    let tx_id = ce_iam::revocation::submit_revoke(&cli.node, token.as_deref(), a.nonce)
        .await
        .map_err(|e| anyhow!("submitting revocation to {}: {e}", cli.node))?;
    if tx_id.is_empty() {
        println!(
            "submitted RevokeCapability for nonce {} (effective when mined)",
            a.nonce
        );
    } else {
        println!(
            "submitted RevokeCapability for nonce {} as tx {} (effective when mined)",
            a.nonce, tx_id
        );
    }
    Ok(())
}

async fn cmd_revoked(cli: &Cli, a: &RevokedArgs) -> Result<()> {
    let client = ce_rs::CeClient::new(cli.node.clone());
    let set = RevocationSet::fetch(&client)
        .await
        .map_err(|e| anyhow!("fetching revoked set from {}: {e}", cli.node))?;
    let pairs = client
        .revoked()
        .await
        .map_err(|e| anyhow!("fetching revoked set from {}: {e}", cli.node))?;
    if a.json {
        let rows: Vec<_> = pairs
            .iter()
            .map(|(issuer, nonce)| serde_json::json!({ "issuer": issuer, "nonce": nonce }))
            .collect();
        println!(
            "{}",
            serde_json::json!({ "count": set.len(), "revoked": rows })
        );
    } else {
        println!("revoked entries: {}", set.len());
        for (issuer, nonce) in &pairs {
            println!("  {issuer}  nonce={nonce}");
        }
    }
    Ok(())
}

fn cmd_policy(cli: &Cli, p: &PolicyCmd) -> Result<()> {
    match p {
        PolicyCmd::New(a) => {
            let resource = ResourceMatch::parse(&a.resource).map_err(|e| anyhow!("{e}"))?;
            let conditions = build_conditions(&a.conditions);
            let policy = simple_policy(a.actions.clone(), resource, conditions);
            println!("{}", policy.to_json());
            Ok(())
        }
        PolicyCmd::Validate(a) => {
            let text = read_file_or_stdin(&a.file)?;
            let policy = Policy::from_json(&text).map_err(|e| anyhow!("{e}"))?;
            let iam = iam_service();
            // Compile-check via mint_policy with an in-memory identity — supports multi-scope docs and
            // never writes a key to disk.
            let scratch = Identity::from_secret_bytes(&[0u8; 32]);
            let grants = iam
                .mint_policy(&scratch, Principal(scratch.node_id()), &policy, 0)
                .map_err(|e| anyhow!("policy does not compile to a grant: {e}"))?;
            println!(
                "OK: {} statement(s); compiles to {} capability grant(s)",
                policy.statements.len(),
                grants.len()
            );
            Ok(())
        }
        PolicyCmd::Inspect(a) => {
            let _ = cli;
            let iam = iam_service();
            let scope = iam.inspect(&a.token).map_err(|e| anyhow!("{e}"))?;
            if a.json {
                println!("{}", serde_json::to_string_pretty(&scope)?);
            } else {
                print_scope(&scope);
            }
            Ok(())
        }
    }
}

fn print_scope(scope: &ce_iam::Scope) {
    println!("root issuer : {}", scope.root_issuer);
    println!("audience    : {}", scope.audience);
    println!("depth       : {}", scope.depth);
    println!("abilities   : {}", scope.abilities.join(", "));
    println!("resource    : {}", scope.resource);
    println!(
        "expires     : {}",
        if scope.not_after == 0 {
            "never".to_string()
        } else {
            scope.not_after.to_string()
        }
    );
}

fn cmd_role(cli: &Cli, r: &RoleCmd) -> Result<()> {
    let actor = load_identity(&cli.data_dir)
        .ok()
        .map(|id| Principal(id.node_id()));
    match r {
        RoleCmd::Put(a) => {
            let text = read_file_or_stdin(&a.policy)?;
            let policy = Policy::from_json(&text).map_err(|e| anyhow!("{e}"))?;
            let role = Role {
                name: a.name.clone(),
                description: a.description.clone(),
                policy,
            };
            let mut store = open_catalog_store(cli)?;
            store
                .apply(ce_iam::CatalogOp::PutRole(role), actor.as_ref())
                .map_err(|e| anyhow!("{e}"))?;
            println!(
                "put role '{}' (catalog version {})",
                a.name,
                store.op_count()
            );
            Ok(())
        }
        RoleCmd::Get(a) => {
            let store = open_catalog_store(cli)?;
            let role = store
                .catalog()
                .get_role(&a.name)
                .ok_or_else(|| anyhow!("no such role '{}'", a.name))?;
            println!("{}", role.to_json());
            Ok(())
        }
        RoleCmd::List(a) => {
            let store = open_catalog_store(cli)?;
            let cat = store.catalog();
            if a.json {
                println!(
                    "{}",
                    serde_json::json!({ "roles": cat.list_roles(), "policies": cat.list_policies() })
                );
            } else {
                println!("roles:");
                for n in cat.list_roles() {
                    println!("  {n}");
                }
                let pols = cat.list_policies();
                if !pols.is_empty() {
                    println!("policies:");
                    for n in pols {
                        println!("  {n}");
                    }
                }
            }
            Ok(())
        }
        RoleCmd::Rm(a) => {
            let mut store = open_catalog_store(cli)?;
            store
                .apply(
                    ce_iam::CatalogOp::RemoveRole(a.name.clone()),
                    actor.as_ref(),
                )
                .map_err(|e| anyhow!("{e}"))?;
            println!("removed role '{}'", a.name);
            Ok(())
        }
        RoleCmd::Attach(a) => {
            let principal = Principal::parse(&a.principal).context("parsing principal")?;
            let mut store = open_catalog_store(cli)?;
            store
                .apply(
                    ce_iam::CatalogOp::AttachRole {
                        principal,
                        role: a.role.clone(),
                    },
                    actor.as_ref(),
                )
                .map_err(|e| anyhow!("{e}"))?;
            println!("attached role '{}' to {}", a.role, principal);
            Ok(())
        }
        RoleCmd::Detach(a) => {
            let principal = Principal::parse(&a.principal).context("parsing principal")?;
            let mut store = open_catalog_store(cli)?;
            store
                .apply(
                    ce_iam::CatalogOp::DetachRole {
                        principal,
                        role: a.role.clone(),
                    },
                    actor.as_ref(),
                )
                .map_err(|e| anyhow!("{e}"))?;
            println!("detached role '{}' from {}", a.role, principal);
            Ok(())
        }
        RoleCmd::EffectiveGrants(a) => {
            let principal = Principal::parse(&a.principal).context("parsing principal")?;
            let store = open_catalog_store(cli)?;
            let eff = store
                .catalog()
                .effective_grants(&principal)
                .map_err(|e| anyhow!("{e}"))?;
            if a.json {
                println!("{}", serde_json::to_string_pretty(&eff)?);
            } else if eff.is_empty() {
                println!("(no effective grants)");
            } else {
                for g in &eff {
                    println!(
                        "abilities: {}  resource: {:?}  from-roles: {}",
                        g.abilities.join(", "),
                        g.resource,
                        g.from_roles.join(", ")
                    );
                }
            }
            Ok(())
        }
        RoleCmd::Audit(a) => {
            let store = open_catalog_store(cli)?;
            let entries = store.catalog().audit_since(a.since);
            if a.json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else {
                for e in &entries {
                    println!(
                        "v{}  {}  {}  actor={}",
                        e.version,
                        e.action,
                        e.target,
                        e.actor.as_deref().unwrap_or("-")
                    );
                }
            }
            Ok(())
        }
        RoleCmd::Compact => {
            let mut store = open_catalog_store(cli)?;
            store.compact().map_err(|e| anyhow!("{e}"))?;
            println!("compacted catalog op-log to {} ops", store.op_count());
            Ok(())
        }
    }
}

fn cmd_wallet(cli: &Cli, w: &WalletCmd) -> Result<()> {
    let iam = iam_service();
    match w {
        WalletCmd::Add(a) => {
            let token = read_arg_or_stdin(&a.token)?;
            let mut wallet = open_wallet(cli)?;
            wallet
                .add(&iam, a.label.clone(), token, a.note.clone(), now_secs())
                .map_err(|e| anyhow!("{e}"))?;
            println!("stored grant '{}'", a.label);
            Ok(())
        }
        WalletCmd::List(a) => {
            let wallet = open_wallet(cli)?;
            if a.json {
                let rows: Vec<_> = wallet.list().into_iter().collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if wallet.is_empty() {
                println!("(wallet empty)");
            } else {
                for e in wallet.list() {
                    println!(
                        "{}  ({} bytes){}",
                        e.label,
                        e.token.len(),
                        e.note
                            .as_deref()
                            .map(|n| format!("  {n}"))
                            .unwrap_or_default()
                    );
                }
            }
            Ok(())
        }
        WalletCmd::Show(a) => {
            let wallet = open_wallet(cli)?;
            let entry = wallet
                .get(&a.label)
                .ok_or_else(|| anyhow!("no grant labeled '{}'", a.label))?;
            let scope = iam.inspect(&entry.token).map_err(|e| anyhow!("{e}"))?;
            if a.json {
                println!(
                    "{}",
                    serde_json::json!({ "label": entry.label, "token": entry.token, "scope": scope })
                );
            } else {
                println!("label   : {}", entry.label);
                println!("token   : {}", entry.token);
                print_scope(&scope);
            }
            Ok(())
        }
        WalletCmd::Rm(a) => {
            let mut wallet = open_wallet(cli)?;
            if wallet.remove(&a.label).map_err(|e| anyhow!("{e}"))? {
                println!("removed grant '{}'", a.label);
            } else {
                println!("no grant labeled '{}'", a.label);
            }
            Ok(())
        }
    }
}

fn cmd_root(cli: &Cli, r: &RootCmd) -> Result<()> {
    match r {
        RootCmd::Add(a) => {
            let key = Principal::parse(&a.key).context("parsing root key")?;
            let now = now_secs();
            let not_before = if a.valid_in == 0 {
                0
            } else {
                now.saturating_add(a.valid_in)
            };
            let not_after = if a.valid_for == 0 {
                0
            } else {
                let start = if not_before == 0 { now } else { not_before };
                start.saturating_add(a.valid_for)
            };
            let mut roots = open_roots(cli)?;
            roots
                .add(key, a.label.clone(), not_before, not_after)
                .map_err(|e| anyhow!("{e}"))?;
            println!("added root {key} (not_before={not_before}, not_after={not_after})");
            Ok(())
        }
        RootCmd::List(a) => {
            let roots = open_roots(cli)?;
            let now = now_secs();
            if a.json {
                println!("{}", serde_json::to_string_pretty(&roots.all())?);
            } else if roots.is_empty() {
                println!("(no configured roots)");
            } else {
                for e in roots.all() {
                    println!(
                        "{}  label={}  not_before={}  not_after={}  accepted_now={}",
                        e.key,
                        e.label.as_deref().unwrap_or("-"),
                        e.not_before,
                        e.not_after,
                        e.accepted_at(now)
                    );
                }
            }
            Ok(())
        }
        RootCmd::Retire(a) => {
            let key = Principal::parse(&a.key).context("parsing root key")?;
            let at = now_secs().saturating_add(a.in_secs);
            let mut roots = open_roots(cli)?;
            if roots.retire(&key, at).map_err(|e| anyhow!("{e}"))? {
                println!("retiring root {key} at {at}");
            } else {
                println!("no such root {key}");
            }
            Ok(())
        }
        RootCmd::Rm(a) => {
            let key = Principal::parse(&a.key).context("parsing root key")?;
            let mut roots = open_roots(cli)?;
            if roots.remove(&key).map_err(|e| anyhow!("{e}"))? {
                println!("removed root {key}");
            } else {
                println!("no such root {key}");
            }
            Ok(())
        }
        RootCmd::Reissue(a) => {
            let identity = load_identity(&cli.data_dir)?;
            let iam = iam_service();
            let grant = iam
                .decode(&a.token)
                .map_err(|e| anyhow!("decoding token: {e}"))?;
            let reissued = iam
                .reissue_under(&identity, &grant, a.nonce)
                .map_err(|e| anyhow!("{e}"))?;
            if a.json {
                let scope = iam.inspect(&reissued.token).map_err(|e| anyhow!("{e}"))?;
                println!(
                    "{}",
                    serde_json::json!({ "token": reissued.token, "scope": scope })
                );
            } else {
                println!("{}", reissued.token);
            }
            Ok(())
        }
    }
}

// ---- device commands -----------------------------------------------------------------------------

/// Open the operator's device registry under the IAM data dir (`<iam>/devices.json`), no env seeds.
fn open_device_store(cli: &Cli) -> Result<DeviceStore> {
    let dir = iam_dir(cli.data_dir.as_deref()).map_err(|e| anyhow!("{e}"))?;
    DeviceStore::open(&dir, &[]).context("opening device store")
}

/// Resolve the CE NodeId to bind a device to: an explicit 64-hex, else this machine's node id.
fn resolve_node_id(cli: &Cli, explicit: &Option<String>) -> Result<String> {
    match explicit {
        Some(s) => {
            // Validate it parses as a principal so we never persist a malformed binding.
            Principal::parse(s).context("parsing --node-id")?;
            Ok(s.clone())
        }
        None => Ok(load_identity(&cli.data_dir)?.node_id_hex()),
    }
}

fn cmd_device(cli: &Cli, d: &DeviceCmd) -> Result<()> {
    match d {
        DeviceCmd::Claim(a) => {
            let node_id = resolve_node_id(cli, &a.node_id)?;
            let store = open_device_store(cli)?;
            if store.claim(&a.device_id, &a.pub_b64, &node_id)? {
                println!("claimed device '{}' as admin (node_id={node_id})", a.device_id);
                Ok(())
            } else {
                bail!("an admin device already exists — use `device request` then `device approve`");
            }
        }
        DeviceCmd::Request(a) => {
            let node_id = resolve_node_id(cli, &a.node_id)?;
            let store = open_device_store(cli)?;
            let role = store.request(&a.device_id, &a.pub_b64, &node_id, &a.label)?;
            println!("device '{}' is now {role} (node_id={node_id})", a.device_id);
            Ok(())
        }
        DeviceCmd::List(a) => {
            let store = open_device_store(cli)?;
            let devices = store.list();
            if a.json {
                let rows: Vec<_> = devices
                    .iter()
                    .map(|(id, dev)| {
                        serde_json::json!({
                            "id": id,
                            "role": dev.role,
                            "label": dev.label,
                            "node_id": dev.node_id,
                            "added_ts": dev.added_ts,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if devices.is_empty() {
                println!("(no devices enrolled — run `device claim`)");
            } else {
                for (id, dev) in &devices {
                    println!(
                        "{id}  {}  {}  node_id={}",
                        dev.role,
                        if dev.label.is_empty() { "-" } else { &dev.label },
                        if dev.node_id.is_empty() { "-" } else { &dev.node_id }
                    );
                }
            }
            Ok(())
        }
        DeviceCmd::Approve(a) => {
            let store = open_device_store(cli)?;
            if store.approve(&a.device_id)? {
                println!("approved device '{}' (now admin)", a.device_id);
                Ok(())
            } else {
                bail!("no pending device '{}' to approve", a.device_id);
            }
        }
        DeviceCmd::Revoke(a) => {
            let store = open_device_store(cli)?;
            match store.revoke(&a.device_id)? {
                RevokeOutcome::Removed => {
                    println!("revoked device '{}'", a.device_id);
                    Ok(())
                }
                RevokeOutcome::NotFound => bail!("no such device '{}'", a.device_id),
                RevokeOutcome::LastAdmin => {
                    bail!("refusing to revoke the last admin device (would lock the operator out)")
                }
            }
        }
    }
}

// ---- secret commands (the vault) -----------------------------------------------------------------

/// Persist/load this operator's vault device key under `<iam>/secrets-device.json` (mode 0600), the
/// Rust analogue of ce-secrets' `loadOrCreateDeviceKey`. The same P-256 device identity is reused
/// across invocations so the owner keeps reading their vault.
fn load_or_create_device_key(cli: &Cli) -> Result<DeviceKey> {
    let dir = iam_dir(cli.data_dir.as_deref()).map_err(|e| anyhow!("{e}"))?;
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let path = dir.join("secrets-device.json");
    if path.exists() {
        let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        if !raw.trim().is_empty() {
            return DeviceKey::from_json(&raw).context("parse device key");
        }
    }
    let dk = DeviceKey::generate().context("generate device key")?;
    let json = dk.to_json()?;
    std::fs::write(&path, json.as_bytes()).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!("(generated this device's vault key in {})", path.display());
    Ok(dk)
}

/// Build a [`Vault`] over the mesh ce-kv store for the given vault flags. The namespace defaults to
/// the device id (a private per-operator vault); the kv node defaults to `--node`.
fn open_vault(cli: &Cli, v: &VaultArgs) -> Result<Vault<MeshKvStore>> {
    let device = load_or_create_device_key(cli)?;
    let ns = v.ns.clone().unwrap_or_else(|| device.id.clone());
    let kv_node = v.kv_node.clone().unwrap_or_else(|| cli.node.clone());
    let token = ce_rs::discover_api_token();
    let store = MeshKvStore::connect(&ns, kv_node, token);
    Ok(Vault::new(store, device, ns))
}

/// Generate secret material for a type, mirroring `ce-secrets/src/crypto.mjs::generate`. Returns the
/// canonical STRING form (as bytes) so revealing it yields a clean, usable value.
fn generate_secret_material(kind: &str, length: Option<usize>) -> Result<Vec<u8>> {
    use ce_secrets_rs::encoding::{b64url_encode, hex_encode};
    let kind = kind.to_lowercase();
    let s = match kind.as_str() {
        "token" | "hex" => {
            let n = length.unwrap_or(32);
            let mut b = vec![0u8; n];
            ce_secrets_rs::fill_random(&mut b);
            hex_encode(&b)
        }
        "password" | "pass" => {
            const PW: &[u8] =
                b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";
            let n = length.unwrap_or(24);
            let mut r = vec![0u8; n];
            ce_secrets_rs::fill_random(&mut r);
            r.iter().map(|b| PW[(*b as usize) % PW.len()] as char).collect()
        }
        "base64" => {
            let n = length.unwrap_or(32);
            let mut b = vec![0u8; n];
            ce_secrets_rs::fill_random(&mut b);
            b64url_encode(&b)
        }
        "uuid" => uuid_v4(),
        "aes-256" | "aes256" => {
            let mut b = [0u8; 32];
            ce_secrets_rs::fill_random(&mut b);
            hex_encode(&b)
        }
        other => bail!(
            "unsupported secret type '{other}'. Supported: token, hex, password, base64, uuid, \
             aes-256. (Keypair types ed25519/x25519/rsa-* require WebCrypto key export and are not \
             yet ported to the Rust CLI — generate them with the JS `ce-secrets` for now.)"
        ),
    };
    Ok(s.into_bytes())
}

/// A random RFC-4122 v4 UUID string — the analogue of `crypto.randomUUID()`.
fn uuid_v4() -> String {
    let mut b = [0u8; 16];
    ce_secrets_rs::fill_random(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 10
    let h = ce_secrets_rs::encoding::hex_encode(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

async fn cmd_secret(cli: &Cli, s: &SecretCmd) -> Result<()> {
    match s {
        SecretCmd::Init(a) => {
            let vault = open_vault(cli, &a.vault)?;
            if vault.init(&a.label).await? {
                println!("vault created; this device ({}) is enrolled as owner.", vault.device().id);
            } else if vault.is_enrolled().await? {
                println!("vault already exists; this device is already enrolled.");
            } else {
                println!(
                    "a vault already exists. run `secret recover` to re-establish from this owner \
                     key, or pair this device from a trusted one."
                );
            }
            Ok(())
        }
        SecretCmd::Recover(a) => {
            let vault = open_vault(cli, &a.vault)?;
            vault.recover(&a.label).await?;
            println!("vault recovered; this device ({}) is the owner and re-enrolled.", vault.device().id);
            Ok(())
        }
        SecretCmd::Gen(a) => {
            let vault = open_vault(cli, &a.vault)?;
            require_enrolled(&vault).await?;
            let material = generate_secret_material(&a.kind, a.length)?;
            let meta = vault.put_secret(&a.name, &material, &a.kind).await?;
            println!(
                "stored {}  type={}  v{}  fp={}  (value never displayed)",
                meta.name, meta.kind, meta.version, meta.fp
            );
            Ok(())
        }
        SecretCmd::Put(a) => {
            let vault = open_vault(cli, &a.vault)?;
            require_enrolled(&vault).await?;
            let value = read_secret_value()?;
            if value.is_empty() {
                bail!("empty value");
            }
            let meta = vault.put_secret(&a.name, value.as_bytes(), &a.kind).await?;
            println!("stored {}  v{}  fp={}  (not displayed)", meta.name, meta.version, meta.fp);
            Ok(())
        }
        SecretCmd::Get(a) => {
            let vault = open_vault(cli, &a.vault)?;
            // Refuse to reveal onto an interactive terminal unless forced (no accidental shoulder-leak).
            if std::io::IsTerminal::is_terminal(&std::io::stdout()) && !a.force {
                bail!(
                    "refusing to print a secret to a terminal; pipe it (e.g. `... | cat`) or pass \
                     --force. Prefer `secret use` to inject without revealing."
                );
            }
            let revealed = vault.get_secret(&a.name).await?;
            use std::io::Write;
            std::io::stdout().write_all(&revealed.bytes).context("writing secret to stdout")?;
            Ok(())
        }
        SecretCmd::Rotate(a) => {
            let vault = open_vault(cli, &a.vault)?;
            require_enrolled(&vault).await?;
            // Re-derive material of the SAME stored type, bumping the version.
            let existing = vault.get_secret(&a.name).await.context("no such secret to rotate")?;
            let material = generate_secret_material(&existing.kind, None)?;
            let meta = vault.put_secret(&a.name, &material, &existing.kind).await?;
            println!("rotated {} -> v{}  fp={}  (not displayed)", meta.name, meta.version, meta.fp);
            Ok(())
        }
        SecretCmd::List(a) => {
            let vault = open_vault(cli, &a.vault)?;
            let list = vault.list_secrets().await?;
            if a.json {
                let rows: Vec<_> = list
                    .iter()
                    .map(|m| {
                        serde_json::json!({
                            "name": m.name, "type": m.kind, "version": m.version,
                            "fp": m.fp, "public": m.public, "created_at": m.created_at,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if list.is_empty() {
                println!("(no secrets yet — `secret gen <name> --type token`)");
            } else {
                for m in &list {
                    println!("{:<24} {:<12} v{}  fp={}", m.name, m.kind, m.version, m.fp);
                }
            }
            Ok(())
        }
        SecretCmd::Rm(a) => {
            let vault = open_vault(cli, &a.vault)?;
            vault.delete_secret(&a.name).await?;
            println!("deleted secret '{}'", a.name);
            Ok(())
        }
        SecretCmd::Grant(a) => {
            let vault = open_vault(cli, &a.vault)?;
            require_enrolled(&vault).await?;
            let read: Vec<String> = a
                .read
                .split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect();
            if read.is_empty() {
                bail!("--read <name,name> required");
            }
            let g = vault.issue_grant(&a.audience, &read, a.expires.clone()).await?;
            println!("granted {}: read {}", a.audience, read.join(", "));
            println!("grant id: {}", g.id);
            println!("token (give this to the app):\n{}", g.token);
            Ok(())
        }
        SecretCmd::Use(a) => {
            // Split `rest` at `--` into [names...] -- [command...].
            let split = a.rest.iter().position(|x| x == "--");
            let (names, command): (&[String], &[String]) = match split {
                Some(i) => (&a.rest[..i], &a.rest[i + 1..]),
                None => bail!("usage: secret use <name…> -- <command…>"),
            };
            if names.is_empty() || command.is_empty() {
                bail!("need at least one <name> and a command after --");
            }
            let vault = open_vault(cli, &a.vault)?;
            require_enrolled(&vault).await?;
            let mut cmd = std::process::Command::new(&command[0]);
            cmd.args(&command[1..]);
            for name in names {
                let revealed = vault.get_secret(name).await.with_context(|| format!("reveal {name}"))?;
                cmd.env(env_name(name), String::from_utf8_lossy(&revealed.bytes).into_owned());
            }
            let status = cmd.status().with_context(|| format!("spawning {}", command[0]))?;
            std::process::exit(status.code().unwrap_or(0));
        }
        SecretCmd::EnrolIssue(a) => {
            let vault = open_vault(cli, &a.vault)?;
            require_enrolled(&vault).await?;
            let token = vault.issue_enrol_token(&a.label, a.ttl).await?;
            eprintln!(
                "one-time enrol token (valid {}s) — hand it to the new device out of band, then run \
                 `ce-iam secret enrol-redeem <token>` there:",
                a.ttl
            );
            // The token itself is the only thing on stdout, so it pipes cleanly into cloud-init/secrets.
            println!("{token}");
            Ok(())
        }
        SecretCmd::EnrolRedeem(a) => {
            let vault = open_vault(cli, &a.vault)?;
            let token = if a.token == "-" {
                read_secret_value()?
            } else {
                a.token.clone()
            };
            vault.redeem_enrol_token(&token, &a.label).await?;
            println!("enrolled this device — the vault now reads the same account mesh-wide");
            Ok(())
        }
    }
}

/// Deny secret-writing ops unless this device is enrolled (mirrors the JS `enrolledCtx`).
async fn require_enrolled(vault: &Vault<MeshKvStore>) -> Result<()> {
    if vault.is_enrolled().await? {
        return Ok(());
    }
    if !vault.exists().await? {
        bail!("no vault yet — run `secret init`");
    }
    bail!("this device is not enrolled — pair it and approve it from a trusted device");
}

/// Map a secret name to an env var name: uppercased, non-alphanumerics -> `_` (matches `envName`).
fn env_name(name: &str) -> String {
    name.to_uppercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Read a secret value: from stdin if piped, else prompt on the TTY (best-effort, line-based).
fn read_secret_value() -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut s = String::new();
        stdin.lock().read_line(&mut s).context("reading value from stdin")?;
        return Ok(s.trim_end_matches(['\r', '\n']).to_string());
    }
    eprint!("paste value (visible): ");
    std::io::stderr().flush().ok();
    let mut s = String::new();
    stdin.lock().read_line(&mut s).context("reading value")?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}
