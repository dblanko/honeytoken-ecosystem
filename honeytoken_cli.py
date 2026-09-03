#!/usr/bin/env python3
"""
honeytoken_cli.py -- generate and clean up honeytoken decoys.

Commands:
    honeytoken generate --output ./decoys --canary-domain canary.example.com
    honeytoken clean --vault ./decoys/tokens_vault.json
    honeytoken ci-env --format github-actions   # print values for CI secrets

Install:
    pip install click
    (or use requirements.txt)

Run without installing as a package:
    python3 honeytoken_cli.py generate
"""

import base64
import json
import os
import secrets
import string
import sys
import uuid
from datetime import datetime, timezone

try:
    import click
except ImportError:
    print("Missing dependency: pip install click", file=sys.stderr)
    sys.exit(1)


DEFAULT_CANARY_DOMAIN = "canary.example.com"
VAULT_FILENAME = "tokens_vault.json"


# ---------- Token value generation ----------

def rand_str(length: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def new_id() -> str:
    return uuid.uuid4().hex[:12]


def make_aws_key(label: str, canary_domain: str) -> dict:
    canary_id = new_id()
    access_key_id = "AKIA" + rand_str(16, string.ascii_uppercase + string.digits)
    secret_key = base64.b64encode(secrets.token_bytes(30)).decode()[:40]
    return {
        "type": "aws",
        "label": label,
        "canary_id": canary_id,
        "aws_access_key_id": access_key_id,
        "aws_secret_access_key": secret_key,
        "internal_api_endpoint": f"https://{canary_domain}/hit/{canary_id}",
        "note": "For a real trigger, deploy the terraform/ module (IAM + CloudTrail + EventBridge).",
    }


def make_github_token(label: str, canary_domain: str) -> dict:
    canary_id = new_id()
    token = "ghp_" + rand_str(36, string.ascii_letters + string.digits)
    return {
        "type": "github",
        "label": label,
        "canary_id": canary_id,
        "github_token": token,
        "internal_api_endpoint": f"https://{canary_domain}/hit/{canary_id}",
        "note": "A real trigger needs a decoy endpoint or GitHub audit log monitoring -- see README limitations.",
    }


def make_slack_webhook(label: str, canary_domain: str) -> dict:
    canary_id = new_id()
    fake_team = rand_str(9, string.ascii_uppercase)
    fake_id = rand_str(9, string.ascii_uppercase)
    fake_secret = rand_str(24)
    url = f"https://{canary_domain}/slack/{canary_id}/T{fake_team}/B{fake_id}/{fake_secret}"
    return {
        "type": "slack_webhook",
        "label": label,
        "canary_id": canary_id,
        "slack_webhook_url": url,
        "note": "Reliable trigger -- any POST to this URL is caught by the Worker instantly.",
    }


def make_db_connection_string(label: str, canary_domain: str) -> dict:
    canary_id = new_id()
    user = "svc_" + rand_str(6, string.ascii_lowercase)
    password = rand_str(20)
    db = "prod_" + rand_str(5, string.ascii_lowercase)
    host = f"{canary_id}.db.{canary_domain}"
    conn = f"postgresql://{user}:{password}@{host}:5432/{db}?sslmode=require"
    return {
        "type": "postgres_dsn",
        "label": label,
        "canary_id": canary_id,
        "connection_string": conn,
        "note": "The hostname needs to resolve to the box running fake_postgres_listener.py.",
    }


def make_azure_credentials(label: str, canary_domain: str) -> dict:
    canary_id = new_id()
    client_id = str(uuid.uuid4())
    tenant_id = str(uuid.uuid4())
    client_secret = rand_str(40, string.ascii_letters + string.digits + "._~")
    return {
        "type": "azure",
        "label": label,
        "canary_id": canary_id,
        "azure_client_id": client_id,
        "azure_tenant_id": tenant_id,
        "azure_client_secret": client_secret,
        "internal_api_endpoint": f"https://{canary_domain}/azure-hit/{canary_id}",
        "note": "For a real trigger, deploy the azure/ Terraform module (App Registration + Event Grid on Activity Log). Path is /azure-hit/, not /hit/ -- the Worker needs the Azure-specific handler for the Event Grid validation handshake.",
    }


def build_all(canary_domain: str) -> list:
    return [
        make_aws_key("prod-backup-script", canary_domain),
        make_azure_credentials("legacy-billing-service", canary_domain),
        make_github_token("ci-deploy-readonly", canary_domain),
        make_slack_webhook("alerts-finance-channel", canary_domain),
        make_db_connection_string("legacy-reporting-db", canary_domain),
    ]


# ---------- CLI ----------

@click.group()
def cli():
    """Honeytoken CLI -- generate and clean up decoy credentials."""
    pass


@cli.command()
@click.option("--output", "-o", default="./decoys", show_default=True,
              help="Directory for decoy files and the vault.")
@click.option("--canary-domain", default=DEFAULT_CANARY_DOMAIN, show_default=True,
              help="Domain where your Cloudflare Worker is deployed.")
@click.option("--gitignore/--no-gitignore", default=True, show_default=True,
              help="Automatically add generated files to the project's .gitignore.")
def generate(output, canary_domain, gitignore):
    """Generate a set of honeytoken decoys and write the decoy files."""
    os.makedirs(output, exist_ok=True)
    tokens = build_all(canary_domain)

    vault_path = os.path.join(output, VAULT_FILENAME)
    vault = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "canary_domain": canary_domain,
        "tokens": tokens,
    }
    with open(vault_path, "w", encoding="utf-8") as f:
        json.dump(vault, f, ensure_ascii=False, indent=2)
    click.echo(f"[+] Vault written to {vault_path} (do NOT commit this file)")

    by_type = {t["type"]: t for t in tokens}
    generated_files = []

    aws_path = os.path.join(output, ".aws_credentials")
    with open(aws_path, "w") as f:
        f.write("[default]\n")
        f.write(f"aws_access_key_id = {by_type['aws']['aws_access_key_id']}\n")
        f.write(f"aws_secret_access_key = {by_type['aws']['aws_secret_access_key']}\n")
    generated_files.append(aws_path)

    azure_path = os.path.join(output, ".azure_credentials")
    with open(azure_path, "w") as f:
        f.write("# az login --service-principal -u $AZURE_CLIENT_ID -p $AZURE_CLIENT_SECRET --tenant $AZURE_TENANT_ID\n")
        f.write(f"AZURE_CLIENT_ID={by_type['azure']['azure_client_id']}\n")
        f.write(f"AZURE_CLIENT_SECRET={by_type['azure']['azure_client_secret']}\n")
        f.write(f"AZURE_TENANT_ID={by_type['azure']['azure_tenant_id']}\n")
    generated_files.append(azure_path)

    env_path = os.path.join(output, ".env")
    with open(env_path, "w") as f:
        f.write(f"GITHUB_TOKEN={by_type['github']['github_token']}\n")
        f.write(f"SLACK_WEBHOOK_URL={by_type['slack_webhook']['slack_webhook_url']}\n")
        f.write(f"DATABASE_URL={by_type['postgres_dsn']['connection_string']}\n")
        f.write(f"AZURE_CLIENT_ID={by_type['azure']['azure_client_id']}\n")
        f.write(f"AZURE_CLIENT_SECRET={by_type['azure']['azure_client_secret']}\n")
        f.write(f"AZURE_TENANT_ID={by_type['azure']['azure_tenant_id']}\n")
    generated_files.append(env_path)

    env_example_path = os.path.join(output, ".env.example")
    with open(env_example_path, "w") as f:
        f.write("# Example for CI secrets -- fill in the real values from .env\n")
        f.write("GITHUB_TOKEN=\nSLACK_WEBHOOK_URL=\nDATABASE_URL=\nAZURE_CLIENT_ID=\nAZURE_CLIENT_SECRET=\nAZURE_TENANT_ID=\n")
    generated_files.append(env_example_path)

    config_path = os.path.join(output, "config.json")
    with open(config_path, "w") as f:
        json.dump({
            "aws": {
                "access_key_id": by_type["aws"]["aws_access_key_id"],
                "secret_access_key": by_type["aws"]["aws_secret_access_key"],
            },
            "azure": {
                "client_id": by_type["azure"]["azure_client_id"],
                "client_secret": by_type["azure"]["azure_client_secret"],
                "tenant_id": by_type["azure"]["azure_tenant_id"],
            },
            "slack_webhook": by_type["slack_webhook"]["slack_webhook_url"],
        }, f, indent=2)
    generated_files.append(config_path)

    click.echo(f"[+] Decoy files written to {output}/")

    if gitignore:
        _append_to_gitignore(output, [vault_path] + generated_files)

    click.echo("\ncanary_id summary for tracking:")
    for t in tokens:
        note = "  (experimental — see README, Activity Log detection currently doesn't work)" if t["type"] == "azure" else ""
        click.echo(f"  [{t['type']:14}] {t['label']:24} id={t['canary_id']}{note}")


def _append_to_gitignore(output_dir, paths):
    """Adds the generated file paths to .gitignore so they don't get
    committed by accident -- unless you actually want a decoy sitting
    in a real commit somewhere, which is a legitimate placement strategy
    too, just do it deliberately."""
    gitignore_path = ".gitignore"
    existing = ""
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r") as f:
            existing = f.read()

    to_add = []
    for p in paths:
        rel = os.path.relpath(p)
        if rel not in existing:
            to_add.append(rel)

    if not to_add:
        return

    with open(gitignore_path, "a") as f:
        f.write("\n# --- honeytoken decoys (generated by honeytoken_cli.py) ---\n")
        for p in to_add:
            f.write(p + "\n")
    click.echo(f"[+] Added to .gitignore: {', '.join(to_add)}")


@cli.command()
@click.option("--vault", "-v", default="./decoys/tokens_vault.json", show_default=True,
              help="Path to the tokens_vault.json created by `generate`.")
@click.option("--yes", is_flag=True, help="Skip the confirmation prompt.")
def clean(vault, yes):
    """Remove every decoy file tied to the given vault. Useful in CI:
    decoys get generated for a test environment and wiped before the
    real deploy goes out."""
    if not os.path.exists(vault):
        click.echo(f"[!] Vault not found: {vault}", err=True)
        sys.exit(1)

    output_dir = os.path.dirname(vault) or "."
    candidates = [
        os.path.join(output_dir, name)
        for name in (".aws_credentials", ".azure_credentials", ".env", ".env.example", "config.json", VAULT_FILENAME)
    ]
    existing = [p for p in candidates if os.path.exists(p)]

    if not existing:
        click.echo("[i] Nothing to remove.")
        return

    click.echo("About to delete:")
    for p in existing:
        click.echo(f"  - {p}")

    if not yes and not click.confirm("Continue?"):
        click.echo("Cancelled.")
        return

    for p in existing:
        os.remove(p)
    click.echo(f"[+] Removed {len(existing)} file(s).")


@cli.command(name="ci-env")
@click.option("--vault", "-v", default="./decoys/tokens_vault.json", show_default=True)
@click.option("--format", "fmt", type=click.Choice(["github-actions", "dotenv"]),
              default="github-actions", show_default=True)
def ci_env(vault, fmt):
    """Print decoy values in a format you can paste straight into
    CI secrets (GitHub Actions Secrets, etc)."""
    if not os.path.exists(vault):
        click.echo(f"[!] Vault not found: {vault}. Run `generate` first.", err=True)
        sys.exit(1)

    with open(vault, "r", encoding="utf-8") as f:
        data = json.load(f)

    by_type = {t["type"]: t for t in data["tokens"]}

    pairs = {
        "GITHUB_TOKEN": by_type["github"]["github_token"],
        "SLACK_WEBHOOK_URL": by_type["slack_webhook"]["slack_webhook_url"],
        "DATABASE_URL": by_type["postgres_dsn"]["connection_string"],
        "AWS_ACCESS_KEY_ID": by_type["aws"]["aws_access_key_id"],
        "AWS_SECRET_ACCESS_KEY": by_type["aws"]["aws_secret_access_key"],
        "AZURE_CLIENT_ID": by_type["azure"]["azure_client_id"],
        "AZURE_CLIENT_SECRET": by_type["azure"]["azure_client_secret"],
        "AZURE_TENANT_ID": by_type["azure"]["azure_tenant_id"],
    }

    if fmt == "dotenv":
        for k, v in pairs.items():
            click.echo(f"{k}={v}")
    else:
        click.echo("# Paste into Settings -> Secrets and variables -> Actions")
        for k, v in pairs.items():
            click.echo(f"gh secret set {k} --body \"{v}\"")


if __name__ == "__main__":
    cli()
