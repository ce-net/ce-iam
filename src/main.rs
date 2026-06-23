//! `ce-iam` — command-line IAM over CE capabilities.
//!
//! Subcommands:
//!   * `whoami`  — print this machine's CE node id (the principal it acts as).
//!   * `grant`   — mint or attenuate a grant (capability chain) for an audience.
//!   * `verify`  — check whether a grant authorizes an action on a node (offline + on-chain revoke).
//!   * `revoke`  — submit an on-chain `RevokeCapability` for a `(this-issuer, nonce)` you minted.
//!   * `policy`  — author / validate / inspect policy documents and grant tokens.
//!
//! Money is never printed as a float; capability conditions use whole-credit ceilings. Output is
//! plain, scriptable text (and `--json` where structured output helps). No emojis.

use anyhow::{Context, Result, anyhow, bail};
use ce_iam::{
    Conditions, Iam, Principal, ResourceMatch, RevocationSet, ce_cloud_action_universe,
    simple_policy,
};
use ce_iam::{Identity, Policy};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser)]
#[command(
    name = "ce-iam",
    version,
    about = "IAM over CE capabilities: mint, attenuate, verify, and revoke scoped grants."
)]
struct Cli {
    /// Identity data dir (holds identity/node.key). Defaults to the standard CE data dir.
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
    /// Author, validate, or inspect policy documents and grant tokens.
    #[command(subcommand)]
    Policy(PolicyCmd),
}

#[derive(Args)]
struct WhoamiArgs {
    /// Emit JSON instead of plain text.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct GrantArgs {
    /// Audience: the 64-hex node id receiving the grant.
    #[arg(long)]
    to: String,
    /// Actions to allow (repeatable). Supports `prefix:*` and `*` against the action universe.
    #[arg(long = "action", required = true)]
    actions: Vec<String>,
    /// Resource scope: `*`/`any`, a 64-hex node id, `tag:<t>`, or `all-of:a,b`.
    #[arg(long, default_value = "*")]
    resource: String,
    /// Expiry as seconds-from-now (e.g. `--expires-in 3600`). 0 = never.
    #[arg(long, default_value_t = 0)]
    expires_in: u64,
    /// Ceiling: max CPU cores a deploy under this grant may request.
    #[arg(long)]
    max_cpu: Option<u32>,
    /// Ceiling: max memory (MB).
    #[arg(long)]
    max_mem_mb: Option<u32>,
    /// Ceiling: max whole credits spendable.
    #[arg(long)]
    max_credits: Option<u64>,
    /// Issuer-chosen nonce naming this grant for revocation. Unique per issuer.
    #[arg(long)]
    nonce: u64,
    /// Attenuate this parent grant token instead of minting a fresh root (sub-delegation).
    #[arg(long)]
    parent: Option<String>,
    /// Emit JSON instead of just the token.
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// The grant token (hex capability chain) to check.
    #[arg(long)]
    token: String,
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
    #[arg(long, default_value_t = 0)]
    expires_in: u64,
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

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
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

fn build_conditions(expires_in: u64, max_cpu: Option<u32>, max_mem_mb: Option<u32>, max_credits: Option<u64>) -> Conditions {
    Conditions {
        not_after: if expires_in == 0 { None } else { Some(now_secs() + expires_in) },
        max_cpu,
        max_mem_mb,
        max_credits,
        ..Default::default()
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
        Command::Policy(p) => cmd_policy(p),
    }
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

fn cmd_grant(cli: &Cli, a: &GrantArgs) -> Result<()> {
    let identity = load_identity(&cli.data_dir)?;
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let audience = Principal::parse(&a.to).context("parsing --to")?;
    let resource = ResourceMatch::parse(&a.resource).map_err(|e| anyhow!("{e}"))?;
    let conditions = build_conditions(a.expires_in, a.max_cpu, a.max_mem_mb, a.max_credits);
    let policy = simple_policy(a.actions.clone(), resource, conditions);

    let grant = match &a.parent {
        None => iam.mint(&identity, audience, &policy, a.nonce).map_err(|e| anyhow!("{e}"))?,
        Some(parent_token) => {
            let parent = iam.decode(parent_token).map_err(|e| anyhow!("decoding --parent: {e}"))?;
            iam.attenuate(&identity, &parent, audience, &policy, a.nonce)
                .map_err(|e| anyhow!("{e}"))?
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
    let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
    let requester = Principal::parse(&a.requester).context("parsing --requester")?;

    let on_node = match &a.on_node {
        Some(h) => Principal::parse(h).context("parsing --on-node")?.node_id(),
        None => identity.node_id(),
    };

    // Fetch the on-chain revocation set unless told to skip. A node that is down or errors must not
    // crash verification — we surface a clear error and let the operator decide.
    let revset = if a.no_revocation_check {
        RevocationSet::empty()
    } else {
        let client = ce_rs::CeClient::new(cli.node.clone());
        match RevocationSet::fetch(&client).await {
            Ok(s) => s,
            Err(e) => bail!(
                "could not fetch on-chain revocation set from {}: {e}\n\
                 (re-run with --no-revocation-check to verify offline against expiries only)",
                cli.node
            ),
        }
    };

    let result = iam.verify(
        &on_node,
        &a.tags,
        now_secs(),
        &requester,
        &a.action,
        &a.token,
        &revset.predicate(),
    );

    match result {
        Ok(()) => {
            if a.json {
                println!("{}", serde_json::json!({ "authorized": true }));
            } else {
                println!("ALLOW: {} may '{}' on {}", requester, a.action, hex::encode(on_node));
            }
            Ok(())
        }
        Err(e) => {
            if a.json {
                println!("{}", serde_json::json!({ "authorized": false, "reason": e.to_string() }));
            } else {
                println!("DENY: {e}");
            }
            // Non-zero exit so scripts can branch on authorization.
            std::process::exit(1);
        }
    }
}

async fn cmd_revoke(cli: &Cli, a: &RevokeArgs) -> Result<()> {
    // Revocation is an on-chain action submitted by the node holding the issuer key. The CLI calls
    // the node's authenticated POST /capabilities/revoke endpoint (the one endpoint ce-rs does not
    // wrap, so ce-iam issues it directly).
    let token = ce_rs::discover_api_token();
    let tx_id = ce_iam::revocation::submit_revoke(&cli.node, token.as_deref(), a.nonce)
        .await
        .map_err(|e| anyhow!("submitting revocation to {}: {e}", cli.node))?;
    if tx_id.is_empty() {
        println!("submitted RevokeCapability for nonce {} (effective when mined)", a.nonce);
    } else {
        println!(
            "submitted RevokeCapability for nonce {} as tx {} (effective when mined)",
            a.nonce, tx_id
        );
    }
    Ok(())
}

fn cmd_policy(p: &PolicyCmd) -> Result<()> {
    match p {
        PolicyCmd::New(a) => {
            let resource = ResourceMatch::parse(&a.resource).map_err(|e| anyhow!("{e}"))?;
            let conditions = build_conditions(a.expires_in, None, None, None);
            let policy = simple_policy(a.actions.clone(), resource, conditions);
            println!("{}", policy.to_json());
            Ok(())
        }
        PolicyCmd::Validate(a) => {
            let text = match &a.file {
                Some(f) => std::fs::read_to_string(f).with_context(|| format!("reading {}", f.display()))?,
                None => {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s).context("reading stdin")?;
                    s
                }
            };
            let policy = Policy::from_json(&text).map_err(|e| anyhow!("{e}"))?;
            // Compile against the cloud universe to surface deny/wildcard/empty errors now.
            let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
            // mint with a throwaway identity+audience just exercises compilation; we don't print it.
            let scratch = scratch_identity()?;
            iam.mint(&scratch, Principal(scratch.node_id()), &policy, 0)
                .map_err(|e| anyhow!("policy does not compile to a grant: {e}"))?;
            println!("OK: {} statement(s); compiles to a capability grant", policy.statements.len());
            Ok(())
        }
        PolicyCmd::Inspect(a) => {
            let iam = Iam::new().with_action_universe(ce_cloud_action_universe());
            let scope = iam.inspect(&a.token).map_err(|e| anyhow!("{e}"))?;
            if a.json {
                println!("{}", serde_json::to_string_pretty(&scope)?);
            } else {
                println!("root issuer : {}", scope.root_issuer);
                println!("audience    : {}", scope.audience);
                println!("depth       : {}", scope.depth);
                println!("abilities   : {}", scope.abilities.join(", "));
                println!("resource    : {}", scope.resource);
                println!(
                    "expires     : {}",
                    if scope.not_after == 0 { "never".to_string() } else { scope.not_after.to_string() }
                );
            }
            Ok(())
        }
    }
}

/// A throwaway identity in a temp dir, used only to exercise policy compilation in `policy validate`.
fn scratch_identity() -> Result<Identity> {
    let dir = std::env::temp_dir().join(format!("ce-iam-scratch-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    Identity::load_or_generate(&dir).context("scratch identity")
}
