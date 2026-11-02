# Honeytoken Ecosystem

A small, self-hosted toolkit for generating and monitoring honeytokens: fake API keys, webhooks, and DB connection strings that you scatter around your repos, configs, and CI. Nobody legitimate ever touches these. If one gets used, you get a Telegram alert with the attacker's IP, geo, and user agent within seconds (the AWS path depends on CloudTrail delivery: seconds in two recent test runs, up to 15-25 minutes in earlier ones -- more on that below).

Zero infrastructure cost if you stay on free tiers: generation is a local Python CLI, the catcher runs on Cloudflare Workers (100k requests/day free), and the optional cloud integrations (AWS or Azure) are just an identity with zero permissions plus that cloud's native event pipeline -- no Lambda, no Azure Function, no server to babysit.

## Responsible use

This is a defensive tool: decoys you plant in infrastructure you own or are authorized to test, to catch unauthorized use of secrets. A few things worth being upfront about:

- Only deploy honeytokens in environments you own or have explicit authorization to instrument (your own repos, your own CI, your own cloud accounts). Don't scatter these in shared or third-party systems without permission.
- `tokens_vault.json` is your private map of what's fake and where it lives — it's auto-added to `.gitignore`, but double-check before every commit, especially if you're scripting this.
- The alert screenshots in this README have had the real IP addresses and AWS account ID redacted. If you fork this and post your own screenshots, check yours too — the alert bodies include your public IP and (for the AWS path) your account ID by design, since that's the whole point of the alert.
- The Azure module currently creates a real App Registration + Service Principal in your tenant even though detection doesn't work yet (see below) — that's still a live credential sitting in your directory, so the same "only in infrastructure you own" rule applies, and you may want to clean it up (`terraform destroy` in `azure/`) if you're not actively working on the detection gap.
- Parts of this documentation were drafted with the help of an AI writing assistant, based on the maintainer's own hands-on testing and findings. The technical claims, error codes, and diagnostic conclusions throughout this README (the AWS and Azure sections in particular) come from direct testing by the maintainer, not from the AI tool.

## Prerequisites

Nothing here is expensive, but there's more setup than the Quickstart alone lets on, and none of it is optional the first time you read it -- so here's the honest list before you start.

**Accounts you'll need to create:**

| Account | Cost | What it's for |
|---|---|---|
| Cloudflare | Free, no card | Runs the Worker that catches HTTP-based triggers |
| Telegram | Free | Where alerts land -- create a bot via `@BotFather` |
| AWS | Free tier, **card required for verification** (won't be charged for the resources this project creates) | Only if you want the real AWS honeytoken -- skip if you're just doing webhook/DB decoys |
| Azure | Free tier, **card required for verification**, same deal as AWS | Only if you want to poke at the Azure honeytoken -- it currently doesn't detect anything (see the Azure section below), so there's little reason to set this up unless you're working on fixing it |
| A VPS provider (Hetzner, Vultr, etc.) | A few euros/month, or use hourly billing for a couple hours | Only if you want the DB honeytoken reachable from a real domain instead of localhost |

**Tools you'll need installed locally:**

- **Python 3.8+** and `pip` -- always required, this is what runs `honeytoken_cli.py` (the DB listener needs **Python 3.11+** only if you run it without Docker -- the Docker image already has it)
- **Node.js + npm** -- required to install `wrangler` (Cloudflare's CLI), which you need for step 2 below no matter what
- **Docker** -- only if you're using the DB honeytoken
- **Terraform CLI + AWS CLI** -- only if you're using the AWS honeytoken
- **Terraform CLI + Azure CLI** -- only if you're using the Azure honeytoken

**Credentials Terraform needs (AWS and Azure paths only):** Terraform creates the honeytoken identity *for* you, so it has to run under *your* real account first. Before `terraform apply`, authenticate as yourself -- `aws configure` (or set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_DEFAULT_REGION`) for AWS, `az login` for Azure. Without this, `terraform apply` stops with `No valid credential sources found`. These are *not* the honeytoken keys -- those are what the apply produces.

**On Windows:** the commands in this guide are bash. Use them as-is on Linux, macOS or WSL. For native PowerShell, jump to [Windows (PowerShell, without WSL)](#windows-powershell-without-wsl) -- line continuation, `python` vs `python3`, `curl` and a few first-run errors all differ. (Separately, `wrangler` and WSL occasionally fight each other over binary architecture -- see the gotchas section near the bottom.)

**Two ways to go through this:**

- **Minimal path** -- Cloudflare + Telegram only, skip steps 5 and 6 below. Gets you working webhook and (localhost-only) DB honeytokens in about 10 minutes, no AWS account, no VPS, no Docker even.
- **Full path** -- everything, including a real internet-reachable DB honeytoken and a genuine AWS credential trap. Budget an evening, not because any single step is hard, but because the AWS piece involves waiting on CloudTrail delivery (see the AWS gotchas section) and because setting up your own domain for the DB listener takes a bit of DNS back-and-forth.

The Dockerfile in this repo packages **only the DB listener** (`fake_postgres_listener.py`). It doesn't containerize the Worker (that's not how Cloudflare Workers deploy -- `wrangler` pushes code to Cloudflare's own infrastructure, not to a container you run), the CLI, or the Terraform module. If you were hoping for one `docker run` that stands up the whole thing, that doesn't exist yet -- see Roadmap.

## Architecture

```mermaid
flowchart LR
    subgraph Gen["1. Generate"]
        CLI["honeytoken_cli.py<br/>generate"]
    end

    subgraph Deploy["2. Place"]
        Repo[("git repo /<br/>CI secrets / backups")]
        AWSUser["IAM user with<br/>zero permissions (Terraform)"]
        AzureSP["Service Principal with<br/>zero roles (Terraform)"]
    end

    subgraph Trigger["3. Trigger"]
        Attacker(["Attacker"])
        Worker["Cloudflare Worker<br/>+ dedup (memory + KV)"]
        Listener["fake_postgres_listener.py<br/>(Docker on a VPS)"]
        CT["CloudTrail<br/>+ EventBridge"]
        AL["Activity Log<br/>+ Event Grid"]
    end

    subgraph Alert["4. Alert"]
        TG["Telegram bot"]
    end

    CLI -->|"decoy files"| Repo
    CLI -.->|"optional"| AWSUser
    CLI -.->|"optional"| AzureSP
    Repo -->|"leaked"| Attacker
    AWSUser -->|"key leaked"| Attacker
    AzureSP -->|"secret leaked"| Attacker
    Attacker -->|"uses webhook URL"| Worker
    Attacker -->|"connects with DB DSN"| Listener
    Attacker -->|"calls AWS API"| CT
    Attacker -->|"calls Azure API"| AL
    CT -->|"POST via API Destination"| Worker
    AL -.->|"POST via Event Grid<br/>(does not currently fire — see below)"| Worker
    Worker -->|"enrich: IP, geo, UA, dedup"| TG
    Listener -->|"classify, dedup, enrich: IP, geo"| TG
```

## Demo

A leaked webhook, DB connection string, or AWS key gets used → an alert lands in Telegram within seconds (AWS timing depends on CloudTrail delivery — see the gotchas below; Azure currently doesn't fire at all — see the Azure section below).

<table>
<tr>
<td><img src="docs/screenshots/alert-manual-test.png" width="400" alt="Manual test alert"></td>
<td><img src="docs/screenshots/alert-slack-webhook.png" width="400" alt="Slack webhook alert"></td>
</tr>
<tr>
<td align="center"><sub>Manual curl against the Worker</sub></td>
<td align="center"><sub>Decoy Slack webhook used by a simulated attacker</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/alert-db-connection.png" width="400" alt="DB connection string alert"></td>
<td><img src="docs/screenshots/alert-aws-cloudtrail.png" width="400" alt="AWS CloudTrail alert"></td>
</tr>
<tr>
<td align="center"><sub>Postgres DSN used: a real client logged in with the decoy user</sub></td>
<td align="center"><sub>AWS honeytoken key used, caught via CloudTrail → EventBridge</sub></td>
</tr>
</table>

## What's in here

| File / directory | What it does |
|---|---|
| `honeytoken_cli.py` | CLI: `generate` (create decoys), `clean` (wipe them), `ci-env` (dump values for CI secrets) |
| `cloudflare_worker.js` | Serverless catcher for HTTP-based triggers, with dedup (in-memory plus KV), HTML alerts with a plain-text fallback, and retries |
| `fake_postgres_listener.py` | Fake Postgres endpoint for the DB honeytoken: classifies every connection (decoy login, other login, SSL probe, scanner noise) and alerts only on the decoy login (runs fine in Docker) |
| `Dockerfile`, `docker-compose.yml` | Packaging for the DB listener only -- doesn't cover the Worker, CLI, or Terraform |
| `terraform/` | AWS: IAM user with no permissions + CloudTrail (with a data-event selector scoped to a decoy S3 bucket) + EventBridge -> Worker, no Lambda |
| `azure/` | Azure: App Registration + Service Principal with zero roles + Event Grid on Activity Log -> Worker. Deploys cleanly but the core detection does not currently work -- see the Azure section below for what was tested and why |
| `wrangler.toml` | Worker deploy config, including the KV namespace |

## Quickstart

### 1. Telegram bot

Talk to `@BotFather`, `/newbot`, grab the `TELEGRAM_BOT_TOKEN`. Send the bot any message, then hit `https://api.telegram.org/bot<TOKEN>/getUpdates` and pull `chat.id` out of the response.

### 2. Deploy the Cloudflare Worker

```bash
npm install -g wrangler
wrangler login

# production namespace -> paste the returned id into wrangler.toml as `id`
wrangler kv namespace create HONEYTOKEN_KV

# preview namespace -> paste the returned id into wrangler.toml as `preview_id`
wrangler kv namespace create HONEYTOKEN_KV --preview

wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID
wrangler deploy
```

You'll get a `*.workers.dev` URL. If you want your own domain instead, see the wrangler.toml comments -- and read the gotcha about routes ordering further down, it'll save you twenty minutes.

Before generating any decoys, check that the Worker and Telegram are actually connected:

```bash
curl -X POST "https://<your-worker>.workers.dev/hit/test-manual-id" \
  -H "Content-Type: application/json" \
  -d '{"probe":"hello"}'
```

A "HONEYTOKEN TRIGGERED" message should land in Telegram within seconds. If it doesn't, fix this before going further -- nothing downstream will work either.

### 3. Generate decoys

```bash
pip install -r requirements.txt

python3 honeytoken_cli.py generate \
  --output ./decoys \
  --canary-domain your-worker-domain.workers.dev
```

This writes `decoys/tokens_vault.json` (your private record of what's fake -- never commit it) plus the actual decoy files (`.aws_credentials`, `.azure_credentials`, `.env`, `config.json`), auto-added to `.gitignore`.

On recent Debian/Ubuntu releases, `pip install` into the system Python is refused (PEP 668, `externally-managed-environment`) -- create a virtualenv first: `python3 -m venv venv && source venv/bin/activate`.

To check that a decoy actually fires, take `slack_webhook_url` from `decoys/tokens_vault.json` and POST to it, the way a bot that found it would:

```bash
curl -X POST "<slack_webhook_url>" -H "Content-Type: application/json" -d '{"text":"test message from attacker simulation"}'
```

The alert carries that decoy's own canary_id, so you can see the whole chain (decoy -> Worker -> Telegram) working without typing an id by hand.

### 4. Scatter them

Old git branches, `.env.bak` files, an internal wiki page, public Docker image layers, a CI variable named something believable like `PROD_DB_BACKUP_URL`, a shared drive nobody's cleaned up since 2022. For CI secrets specifically:

```bash
python3 honeytoken_cli.py ci-env --format github-actions
```

### 5. (optional) DB honeytoken via Docker

```bash
cp .env.example .env   # fill in TELEGRAM_*
docker compose up -d --build
```

On start the listener sends one "HONEYTOKEN DB LISTENER STARTED" message to Telegram. If it doesn't arrive, the token or chat id in `.env` is wrong (the container log says so), and real alerts won't arrive either. The hostname in the DSN must resolve to this machine (an A record pointing at the VPS) and port 5432 must be reachable.

**Which logins count as the decoy.** Decoys made by `honeytoken_cli.py` use a user like `svc_xxxxxx` and a database like `prod_xxxxx`. The listener recognises that shape on its own, so there is nothing to configure. If your DSN uses other names, uncomment `DECOY_USERS` / `DECOY_DATABASES` in `.env` and put the exact user and database from the DSN there (random names only -- never `postgres`, `admin`, `test`). A match on either one is enough.

**What alerts and what doesn't:**

| Traffic | Result |
|---|---|
| A Postgres login with the decoy user or database | Telegram alert (user, database, TLS, IP, geo, provider) |
| A Postgres login with any other user (`postgres`, `app`, ...) | `[login-scan]` in the container log only |
| SSL request, then hang-up before any login | `[ssl-probe]` in the log only |
| HTTP, bare TLS handshakes, SMB/SIP/RTSP probes, empty connections | `[noise]` in the log only |

To test it, connect with the `connection_string` from `decoys/tokens_vault.json`: `psql "<connection_string>"` produces one alert (psql then reports a connection error -- expected, the listener isn't a real database). Logging in as `postgres` instead only writes `[login-scan]` to the log. To see what the internet has been throwing at the port:

```bash
docker compose logs --since 24h | grep -Eo '\[(login-scan|ssl-probe|noise|limit)\]' | sort | uniq -c
```

Three things that trip people up here:

- The filename has to change from `.env.example` to exactly `.env` -- Docker Compose only looks for `.env`, nothing else. The `cp` command above does this automatically, but if you're copying the file by hand in a file manager instead of the terminal, renaming it is a separate step you have to remember -- just dragging a copy over won't do it.
- `.env` won't show up in a plain `ls` afterwards -- files starting with a dot are hidden by default on Linux/macOS. That's normal, not a sign the copy failed. Use `ls -a` or `cat .env` to confirm it's there.
- On Windows, Docker Desktop needs either the WSL2 backend or Hyper-V. Hyper-V requires Windows Pro/Enterprise/Education -- it's not available on Windows Home.

### 6. (optional) Real AWS honeytoken

Terraform runs as *you*, not as the honeytoken -- authenticate to your own AWS account first (see Prerequisites). Use the `aws` canary_id from `decoys/tokens_vault.json` in the URL.

```bash
cd terraform
terraform init
terraform apply \
  -var="worker_alert_url=https://your-worker-domain/hit/<canary_id>" \
  -var="aws_region=eu-central-1"
```

Creates an IAM user with an explicit deny-all policy (that user's access key is the honeytoken), a CloudTrail trail with its own log bucket, a decoy S3 bucket (`company-db-backups-<account id>`) with a data-event selector scoped to just that bucket, and an EventBridge rule that POSTs straight to your Worker when the key gets used. Read the decoy key back with `terraform output canary_access_key_id` and `terraform output -raw canary_secret_access_key`. See the "AWS gotchas" section below before you run this, it'll save you a debugging afternoon.

**Keep `terraform.tfstate`.** Run `apply` from one working folder and keep the state file there -- it's the only record of what Terraform created (it's gitignored on purpose, since it holds the decoy secret in plaintext). Lose it, or run Terraform from a fresh copy of the repo, and Terraform will think nothing exists: `plan` offers to create everything again and `destroy` has nothing to destroy.

### 6.5. (optional) Real Azure honeytoken

Sign in to your tenant first with `az login`, and use the `azure` canary_id from the vault.

```bash
cd azure
terraform init
terraform apply \
  -var="worker_alert_url=https://your-worker-domain/azure-hit/<canary_id>"
```

Same idea as the AWS module -- an identity with zero permissions, wired to that cloud's native audit pipeline (Azure Activity Log, via Event Grid) which POSTs to the same Worker. **This module is currently confirmed broken -- read the Azure section below before running it.** Everything deploys cleanly and the webhook handshake works, but live testing showed Activity Log never records the honeytoken's calls, so no alert will fire on a real compromise. It's included because the infrastructure code is a reasonable starting point for fixing this, not because it works today.

### 7. Cleanup (e.g. before deploying to a real environment)

```bash
python3 honeytoken_cli.py clean --vault ./decoys/tokens_vault.json --yes
```

That removes the local decoy files. The cloud resources are separate -- remove them with `terraform destroy`, from the same folder you ran `apply` in (it needs `terraform.tfstate`) and with the same `-var` values:

```bash
cd terraform
terraform destroy \
  -var="worker_alert_url=https://your-worker-domain/hit/<canary_id>" \
  -var="aws_region=eu-central-1"
```

Same idea in `azure/`. On Azure, `destroy` can fail partway with a `404 Directory_ObjectNotFound` while removing the application password (Entra ID is eventually consistent, the same replication lag that can make `apply` sit on "Still creating..." for a few minutes). Wait a bit and run `destroy` again -- the second pass finishes the job.

## Windows (PowerShell, without WSL)

The Quickstart above is written in bash. On Linux, macOS or WSL use it as is. On native Windows PowerShell the same steps work, with the differences below. This section was checked on a clean Windows machine without WSL, except for the Docker-based DB honeytoken (Docker Desktop needs hardware virtualization, which wasn't available on the test machine) and the Azure module (not re-tested on Windows).

**Install** (regular Windows installers, no WSL needed):

- Python 3.8+ from python.org -- tick "Add python.exe to PATH". Check with `python --version` (on Windows the command is `python`, not `python3`).
- Node.js (LTS) from nodejs.org.
- Terraform: download the Windows AMD64 zip from HashiCorp, put `terraform.exe` in the folder you run it from and call it as `.\terraform`. `winget install HashiCorp.Terraform` works on some machines, but it can be blocked by policy.
- AWS CLI, only if you want `aws configure` -- environment variables work too (below).
- The project itself: "Download ZIP" on GitHub and extract it. No git needed.

**Allow npm to run.** Out of the box PowerShell blocks `npm` ("running scripts is disabled on this system"). Once per user, no admin needed:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then `npm install -g wrangler`. If wrangler won't start afterwards because npm skipped its install scripts, retry with `npm install -g --allow-scripts=esbuild,workerd wrangler`. (This showed up on one machine and depends on your npm version and settings.)

**Write commands as one-liners.** The `\` at the end of a line in the bash examples does nothing in PowerShell, so a pasted multi-line command runs line by line and fails. PowerShell's own continuation character is a backtick, and it has to be the very last character on the line -- a single trailing space breaks it. Everything below is a one-liner for that reason.

**Don't use `curl` for the tests.** In PowerShell `curl` is an alias for `Invoke-WebRequest`, and quoting JSON for `curl.exe` is a mess. `Invoke-RestMethod` avoids the problem.

Step 2 -- Worker (the last line is the connectivity check):

```powershell
wrangler login
wrangler kv namespace create HONEYTOKEN_KV
wrangler kv namespace create HONEYTOKEN_KV --preview
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put TELEGRAM_CHAT_ID
wrangler deploy
Invoke-RestMethod -Uri "https://<your-worker>.workers.dev/hit/test-manual-id" -Method Post -ContentType "application/json" -Body '{"probe":"hello"}'
```

Steps 3 and 4 -- decoys, a test hit, CI export:

```powershell
pip install -r requirements.txt
python honeytoken_cli.py generate --output ./decoys --canary-domain your-worker-domain.workers.dev
Get-ChildItem -Path ./decoys -Force
Invoke-RestMethod -Uri "<slack_webhook_url from tokens_vault.json>" -Method Post -ContentType "application/json" -Body '{"text":"test message from attacker simulation"}'
python honeytoken_cli.py ci-env --format github-actions
```

No virtualenv is needed on Windows -- the python.org build installs packages for your user.

Step 6 -- AWS:

```powershell
$env:AWS_ACCESS_KEY_ID="<your own admin key>"
$env:AWS_SECRET_ACCESS_KEY="<your own admin secret>"
$env:AWS_DEFAULT_REGION="eu-central-1"
cd terraform
.\terraform init
.\terraform apply -var="worker_alert_url=https://your-worker-domain/hit/<aws_canary_id>" -var="aws_region=eu-central-1"
.\terraform output canary_access_key_id
.\terraform output -raw canary_secret_access_key
```

Those environment variables only live in the current PowerShell window, and they are *your* credentials, not the decoy's. Use the same region in `$env:AWS_DEFAULT_REGION` and in `aws_region`. If `terraform` is on your PATH, drop the `.\`.

To simulate an attacker without installing the AWS CLI, `pip install boto3` and run the decoy key through STS:

```powershell
python -c "import boto3; print(boto3.client('sts', aws_access_key_id='<decoy key id>', aws_secret_access_key='<decoy secret>', region_name='eu-central-1').get_caller_identity())"
```

The alert normally arrives within minutes, but CloudTrail delivery can be much slower -- see the AWS gotchas.

Cleanup: `python honeytoken_cli.py clean --vault ./decoys/tokens_vault.json --yes`, then `.\terraform destroy` with the same `-var` values, from the folder you ran `apply` in.

**WSL is an alternative.** If you'd rather follow the bash Quickstart, WSL works. `wsl --install` sets up WSL 2, which needs hardware virtualization to be enabled -- the same thing Docker Desktop needs. Microsoft's docs say WSL 1 doesn't need it (`wsl --set-default-version 1` before installing a distro); that route hasn't been tested with this project.

## Honest limitations

- **Slack/Discord webhooks are the most reliable trigger.** They're just a URL -- anything touching them gets caught, full stop. The DB connection string is just as reliable for anyone who actually uses it (see the next point).
- **A DB decoy on a public IP gets scanned within minutes, so the listener only alerts on the decoy login.** An open port 5432 attracts internet-wide scanners: plain HTTP and TLS probes, SMB/RTSP/SIP probes, and logins with default usernames (`postgres`, `app`, `umami`). All of that is classified and written to the container log (`[noise]`, `[ssl-probe]`, `[login-scan]`) and none of it reaches Telegram -- only a login with the decoy's own user or database does. The trade-off: someone who takes only the host from the DSN and logs in as `postgres` isn't alerted (set `ALERT_ON_UNMATCHED=1` if you want those too, and expect noise). So far this was verified with my own connections and CI runs; I haven't yet seen a third party use a leaked DSN.
- **DB listener details worth knowing.** The default shape (`svc_` + 6 lowercase letters, `prod_` + 5) can match by coincidence if a bot happens to try such a name -- set explicit random `DECOY_USERS` / `DECOY_DATABASES` if that worries you. The certificate is self-signed, so `sslmode=require` works but `verify-ca` / `verify-full` clients can't complete the handshake and won't be identified. Dedup is per source IP, in memory (5 minutes, a digest every 50th repeat) and resets when the container restarts. The alerting IP is looked up on ip-api.com over plain HTTP; set `GEO_LOOKUP=0` to turn that off (the Worker honours the same variable).
- **A bare AWS key, Azure credential, or GitHub token doesn't call home by itself.** It's just a string. For AWS and Azure you need the respective Terraform module (see below). For GitHub there's no equivalent free path -- real audit-log monitoring on personal tokens is a GitHub Enterprise feature, not something you can bolt on for free.
- **Dedup is best-effort.** The Worker's window is 5 minutes per (canary_id, IP) pair, with a digest every 50th repeat (the DB listener uses the same window per IP). It cuts down noise from scanners a lot, doesn't eliminate it -- a distributed botnet hitting from different IPs will still generate separate alerts, and that's fine, that's actually the interesting case. KV has no atomic check-and-set, so a burst that lands on several Worker instances at once can still produce more than one alert. Cloudflare's free KV plan allows 1,000 writes per day; the Worker writes once per window rather than per request, and if KV fails it falls back to in-memory dedup and still sends the alert -- an alert is never dropped because of KV.
- **The AWS alert's source IP is only as trustworthy as the payload.** Unless `CANARY_SHARED_SECRET` (Worker) and `worker_shared_secret` (Terraform) are set, the Worker can't verify that the event came from your EventBridge rule, so the attacker IP in the alert is as reported in the request body, and anyone who knows the Worker URL could forge such an alert. The alert says so when the secret is missing.
- **This isn't a GitGuardian or Thinkst Canary replacement.** It's a lightweight thing for people who don't need (or can't justify) a whole platform for this one feature.

## AWS gotchas (learned by actually testing this, not by reading docs)

I built the first version of the Terraform module assuming CloudTrail's free 90-day event history would feed EventBridge automatically. It doesn't. Two things had to be fixed (a third turned up later -- see item 3) after a full end-to-end test kept coming up silent on real AWS calls even though a manually crafted `aws events put-events` fired instantly:

1. **You need an actual CloudTrail Trail.** Events sitting in the free Event History (what `aws cloudtrail lookup-events` shows you) are *not* forwarded to EventBridge. Only events captured by a configured Trail are. The module now creates a minimal Trail with its own S3 bucket for log storage.

2. **EventBridge drops read-only management events by default.** `GetCallerIdentity`, `ListBuckets`, any `DescribeXxx` call -- exactly the kind of recon an attacker does first -- gets silently filtered unless the rule's `state` is set to `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` instead of the default `ENABLED`. Both are wired into `terraform/main.tf` now.

3. **Data events aren't covered by the management-events fix.** `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` only affects management-plane calls (`ListBuckets`, `GetCallerIdentity`). Object-level S3 operations (`ListObjects`, `GetObject`, `PutObject`) are data events and aren't logged by CloudTrail at all unless the Trail has an explicit data event selector configured -- confirmed by testing all three call types (management, data-read, data-write) against a real deny-all key. The Terraform module now scopes a data event selector to just the decoy bucket, keeping logging volume (and cost) minimal.

Enabling data event logging broadly (e.g. across all buckets in an account) can be expensive — CloudTrail bills per logged event, and a busy production bucket generates a lot of them. Scoping the data event selector to just the decoy bucket's ARN keeps the fix free in practice: a bucket that exists purely as bait sees essentially zero legitimate traffic, so there's nothing to pay for except the rare case someone actually touches it — which is exactly the case you want to catch.

Also worth knowing before you test:

- **Match your region.** `variables.tf` defaults `aws_region` to `us-east-1`. If your AWS CLI profile defaults to something else, the honeytoken IAM user and the EventBridge rule end up in different regions relative to where you're checking, and everything looks broken when it's actually just split across two places. Pass `-var="aws_region=..."` explicitly and match it to your CLI's default region. And don't assume any European-sounding region will do: `eu-central-1` (Frankfurt), `eu-north-1` (Stockholm) and `eu-west-1` (Ireland) are three separate regions, as far as AWS is concerned.
- **CloudTrail delivery time varies.** In two recent CI test runs the alert arrived within the same minute as the API call, while earlier tests took 15-25 minutes, so budget for the longer case the first time. CloudTrail delivery has its own pipeline delay that has nothing to do with your setup. A manual `aws events put-events` test bypasses all of that and fires in seconds, which is a great way to confirm the Worker/Telegram side works, but it will NOT tell you whether the CloudTrail path is wired up correctly. Test both.
- **`GetCallerIdentity` requires zero IAM permissions to succeed**, even for a deny-all user -- it's a built-in AWS exception. If you're simulating an attacker probing the key, use something that actually returns `AccessDenied`, like `aws s3 ls`. Both get logged either way, but AccessDenied is a more honest simulation and shows up cleaner in the alert.

## Azure module -- currently broken, here's exactly how and why

Unlike the AWS module, **this one was tested end to end against a live tenant and the core detection path did not work.** Not "unverified" -- actually tried, actually failed, in a specific and now well-understood way. Read this before you spend time on it.

**What works fine:** `azure/main.tf` creates an App Registration + Service Principal with zero role assignments without issue -- the client_id + client_secret pair is the honeytoken, same idea as the AWS access key. The Event Grid System Topic and webhook subscription deploy cleanly, and the `/azure-hit/` validation handshake in the Worker works -- the subscription reaches `Succeeded` provisioning state.

**What doesn't work: Activity Log never records the honeytoken's failed calls, at all.** Three different live attempts, each waited out 15-40 minutes, each confirmed as a genuine `AuthorizationFailed` response directly from Azure's API (not a local CLI error):

1. A read call (`GET .../resourcegroups`) at the subscription level
2. A write call (`PUT .../resourcegroups/<name>`) at the subscription level
3. An action call (`POST .../storageAccounts/<name>/listKeys`) against a real, pre-existing Storage Account

All three produced a clean `AuthorizationFailed` from Azure. None of them showed up in `az monitor activity-log list`, and Event Grid's own `PublishSuccessCount` metric stayed at a confirmed `0.0` across every 5-minute bucket for the full test window -- meaning nothing was even offered to Event Grid, not "offered but filtered out." So the `advanced_filter` mentioned in earlier drafts of this section was never actually the bottleneck; the problem is upstream of it.

**Working theory (not confirmed by Microsoft docs, just the most coherent explanation that fits all three test results):** Activity Log's "Administrative" category appears to be populated by individual resource providers reporting their own operations -- including their own internal failures. A zero-permission identity gets rejected by Azure's RBAC/authorization layer *before* the request is ever handed off to a resource provider. If that's right, there's no resource-provider-level activity to log in the first place, because the resource provider never saw the request -- it was blocked at the front door. This would explain why even a call against a specific, real Storage Account (test 3) behaved identically to a generic subscription-level call (tests 1 and 2): all three were rejected at the same platform layer, before reaching any resource provider.

**What this means for using this module right now:** don't rely on it. A zero-permission Service Principal's stolen credentials, if used, will not currently generate a Telegram alert through this path, despite the whole pipeline (Activity Log -> Event Grid -> Worker -> Telegram) being correctly wired and the webhook handshake working. The failure mode here is quiet and total -- exactly the kind of thing this project's AWS section warns about, except this time the investigation ran out of leads rather than finding the fix.

**Why the obvious free workarounds don't exist, either -- three dead ends, each confirmed:**

- **Entra ID P1 free trial** -- blocked outright for the test account with a 401 pointing at insufficient Global Administrator rights. This can happen for reasons unrelated to the trial itself (e.g. an account's prior identity/billing history triggering Microsoft's abuse-prevention checks), so your mileage may vary, but it's not a given that "just start a free trial" works on the first try.
- **Reading Sign-in Logs directly via Microsoft Graph** (`GET /v1.0/auditLogs/signIns`), bypassing Diagnostic Settings entirely, with a dedicated App Registration granted `AuditLog.Read.All` application permission and admin consent -- returns a clean, unambiguous `403 Authentication_RequestFromNonPremiumTenantOrB2CTenant`. Confirmed with a real request, real permission, real consent. Microsoft enforces the P1/P2 requirement at the API layer itself, not just at the export/Diagnostic Settings layer -- there's no permission that unlocks this endpoint on a free tenant.
- **Microsoft 365 Developer Program instant sandbox** (which normally hands out a free E5 tenant, Entra ID P2 included) -- as of this testing, sign-up for personal accounts (Gmail/Outlook without an active Visual Studio Professional/Enterprise subscription or partner program membership) is closed. Not a bug, not a config issue -- Microsoft's own program status confirms free sandbox registration is currently paused for this account category.

Three independent paths, three independent confirmations, zero free options remaining. If you want Sign-in Logs, budget for an actual Entra ID P1 license (roughly $6-7/user/month at time of writing) -- there's no way around paying for it that was found here.

**Two directions worth trying if you want to pick this up:**

- **Give the honeytoken a real, narrow permission scoped only to a decoy resource group** (e.g. `Reader` on `honeytoken-canary-rg` and nothing else) so a call actually reaches a resource provider and succeeds, rather than being blocked at the RBAC layer. This changes the design from "zero permissions, catch the denial" to "trivial permissions on worthless resources, catch the use" -- a different but still valid honeytoken shape, and the only one of the two options that's actually free. Untested.
- **Entra ID Sign-in Logs**, which capture the authentication step itself rather than the API call, and expose the attacker's IP/geo directly in the log record (unlike Activity Log, which doesn't reliably include it). Requires a paid Entra ID P1 license, confirmed above -- no free path exists. If pursued, the architecture is: Sign-in Logs -> Diagnostic Settings -> Storage Account (cheaper) or Event Hub (faster, but Event Hub has no free tier and costs roughly $10+/month just sitting idle) -> a polling Logic App (Consumption tier) -> the same Worker, on a new `/azure-signin-hit/` path.

Until one of those is tried and confirmed working, treat the Azure honeytoken as **generated but not actually monitored** -- the credential looks real and gets scattered like any other decoy, but a real compromise of it will currently go undetected through this pipeline.

**The webhook validation handshake is handled correctly, for what it's worth.** Event Grid refuses to create a webhook subscription unless the endpoint responds correctly to a validation event first -- this isn't optional. The Worker's `/azure-hit/` path (separate from `/hit/`) handles this, and the subscription did reach `Succeeded` state during testing. If you're debugging this further, that part isn't where the problem is.

**One thing this whole investigation accidentally proved beyond doubt: the delivery pipeline itself is fully live.** While tearing down test infrastructure (deleting a Storage Account created for one of the earlier tests), Azure cascaded that into deleting its associated Event Grid subscription -- and Event Grid, as part of that teardown, fired a real `Microsoft.EventGrid.SubscriptionDeletedEvent` straight into the Worker's `/azure-hit/` endpoint. It showed up in Telegram seconds later, fully parsed, no errors. So however this Activity Log limitation eventually gets resolved, it won't be fighting the transport layer -- Event Grid -> Worker -> Telegram already works end to end, confirmed by an event Microsoft's own infrastructure generated, not a manual test. The missing piece really is scoped to "what triggers a real Activity Log event for a zero-permission identity," nothing downstream of that.

That discovery also surfaced a real false-positive source, now fixed: Event Grid's own lifecycle notifications (subscription created/updated/deleted, validation events, etc.) arrive on the same webhook and look just like real events on the wire -- the `SubscriptionDeletedEvent` above generated a bogus "AZURE HONEYTOKEN TRIGGERED" alert with every field showing `unknown`, because system events don't carry Activity Log fields like `claims`/`caller`/`resourceId`. The Worker now skips anything with an `eventType` starting with `Microsoft.EventGrid.` before it reaches the alerting logic -- if you're running an older copy of `cloudflare_worker.js`, deleting Azure test resources may generate a spurious Telegram alert until you update it.

<img src="docs/screenshots/alert-azure-false-positive.png" width="400" alt="Spurious Azure alert with unknown fields, from before the Event Grid system-event filter was added">

<sub>The false positive this section describes -- every field `unknown` because it's Event Grid's own `SubscriptionDeletedEvent`, not a real Activity Log entry. This is what the bug looked like before the fix; you shouldn't see this with the current Worker code.</sub>

## Other things that bit me during testing (leaving these here so they don't bite you)

- **`wrangler.toml` and TOML table ordering.** If you add a `routes = [...]` block *after* a `[[kv_namespaces]]` section, TOML parses it as a property of that table, not a top-level key, and wrangler silently ignores it. Put `routes` before any `[[table]]` block, or just use a Custom Domain from the dashboard instead, which creates the DNS record for you and sidesteps the whole issue.
- **`wrangler` and WSL don't always get along.** If you've got Node/npm installed on the Windows side and you're calling `wrangler` from inside WSL, you can end up with a Windows-compiled `workerd` binary in a Linux environment, which crashes immediately. Simplest fix: install Node and wrangler natively inside WSL, or just run wrangler from PowerShell instead and leave AWS CLI/Terraform/Docker in WSL. Mixing shells across a project is mildly annoying but works fine.
- **`terraform apply` wants the literal word `yes`, not `y`.** Obvious in hindsight, easy to fumble if you paste a multi-line command and a stray `-var=` flag gets mangled -- Terraform will then interactively prompt for that variable's value instead of showing the plan, and typing "yes" into that prompt does not mean what you think it means. Run the command as one line if your terminal is doing anything weird with line wraps.
- **A missing or empty `.env` fails differently depending on how it's missing.** No `.env` file at all -- `docker compose up` refuses to start and tells you so, which is fine. But an `.env` that exists with blank `TELEGRAM_BOT_TOKEN`/`TELEGRAM_CHAT_ID` (easy to do if you copy `.env.example` and forget to fill it in) starts the container just fine and never sends a single alert, with no error anywhere. Both the DB listener and the Worker now log a loud warning on startup / on first alert attempt if these are missing, and the DB listener sends a "LISTENER STARTED" message to Telegram on every start, so a wrong token shows up immediately (and so does a container restart) -- check `docker compose logs` or `wrangler tail` if alerts aren't showing up and everything else looks right.

## Roadmap

- Fix Azure detection -- either scope the honeytoken a narrow real permission on a decoy resource group so calls reach a resource provider and get logged, or pay for Entra ID P1 and use Sign-in Logs (see the Azure section above for the full story on why the current zero-permission approach doesn't get logged by Activity Log, and why the free alternatives were dead ends)
- **Known issue, not urgent:** `honeytoken generate` regenerates *all* five decoy types every time it runs, including new random `canary_id`s for ones you might not have touched. If you've already deployed AWS (or Azure) infrastructure pointing at a specific `canary_id` and then re-run `generate` for an unrelated reason (e.g. to pick up a new decoy type after an update), the vault file drifts out of sync with what's actually deployed -- the deployed infrastructure keeps working, but the vault stops being a reliable source of truth for it. Worth adding a `--only` flag to regenerate a single token type without touching the rest.
- One-command setup that wraps the CLI, `wrangler deploy`, and Terraform behind a single script or container, so this doesn't require five separate tools installed locally -- the current setup assumes a comfort level with CLIs that not every small team has
- *Done in October 2026:* the DB listener now classifies traffic, deduplicates per IP and alerts only on the decoy login, with async I/O, healthcheck and watchdog, resource limits and TLS; the Worker retries delivery, falls back to plain text and survives KV failures.
- DB listener, next: read the TLS SNI to put the canary ID into DB alerts (the hostname in the DSN already encodes it) and to catch logins made with only the host; a daily summary message so silence can be told apart from a dead listener; generate the TLS certificate on first start instead of at image build (needed before shipping a prebuilt image); keep dedup state across restarts; a local GeoIP database instead of ip-api.com
- Worker: atomic dedup with a Durable Object; one alert format across Worker and listener (country, ASN and provider fields differ today)
- More decoy formats -- `.npmrc` / `.piprc` (fake private registry credentials), `kubeconfig` / `docker/config.json` (fake cluster and registry access), and DNS-based canaries (alert when an attacker resolves a hostname that shouldn't exist). To be upfront: Thinkst's Canarytokens already offers kubeconfig and DNS tokens, so the point here is integrating them into this self-hosted pipeline, not claiming a new token type; `.npmrc` appears to be uncovered elsewhere
- Encrypt `tokens_vault.json` at rest instead of storing it as plaintext JSON
- IP geolocation via a proper API for more accurate alerts
- Scheduled token rotation
- Export alerts to a SIEM (Splunk/ELK) alongside Telegram

## Tests

Offline tests that need no Telegram, Cloudflare, AWS or VPS (Telegram, KV and the geo lookup are stubbed):

    python3 tests/test_listener.py   # Python 3.11+ and the `openssl` command
    node tests/test_worker.mjs       # Node 18+

They cover traffic classification, dedup, alert delivery (HTML, plain-text fallback, retries, KV failures) and sanitising of attacker-controlled input. They don't replace live tests against real Cloudflare, Telegram, AWS or Azure.

## Contributing

Issues and PRs welcome — especially around the GitHub-token detection gap and the Azure Activity Log problem (see Honest limitations and the Azure section above) if anyone finds a free-tier path that was missed here. For anything non-trivial, open an issue first so we're aligned before you put work into a PR.

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it in your own stack; just don't point it at infrastructure you don't own or have permission to test.

