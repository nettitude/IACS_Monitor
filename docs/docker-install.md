# IACS_Monitor — Docker installation guide (SQLite)

This guide installs IACS_Monitor as a Docker container: the API, the web console (`/ui`), the
scheduled reviews and the PDF compliance report all run in one container, with the SQLite
database on a Docker volume.

| | |
|---|---|
| Image | `iasc-monitor` (built locally from this repository) |
| Base | `python:3.11-slim-bookworm` |
| Database | SQLite, `/data/iasc_monitor.db` on the named volume `iasc_data` |
| Port | 8000, published on **127.0.0.1 only** by default |
| Runs as | non-root user `iasc` (uid 1000) |

> **Security note.** The API has no login yet (tracker item A-01). Keep the default loopback
> binding and reach the console through an SSH tunnel or an authenticating reverse proxy.
> Never publish port 8000 on an untrusted network.

---

## 1. What the build contains, and why it matches what was tested

The image installs Python packages **only** from `requirements-lock.txt`: every package (direct
and transitive) at the exact version the project was verified with, installed with `--no-deps`,
so nothing else can slip in. `requirements.txt` pins the direct dependencies to the same
versions.

| Package | Version | Package | Version |
|---|---|---|---|
| fastapi | 0.141.1 | starlette | 1.0.0 |
| uvicorn (plain, no `[standard]`) | 0.46.0 | pydantic / pydantic-core | 2.13.3 / 2.46.3 |
| sqlalchemy | 2.1.1 | alembic | 1.20.0 |
| scapy | 2.7.0 | reportlab | 4.4.10 |
| python-multipart | 0.0.26 | apscheduler | 3.11.3 |
| psycopg2-binary | 2.9.13 | defusedxml | 0.7.1 |

Python: 3.11 (verified on 3.11.15). See the verification record (section 15) for exactly what
was tested in a container.

---

## 2. Prerequisites

| Requirement | Minimum |
|---|---|
| Host | Linux, x86_64 or arm64 (Docker Desktop on Windows/macOS works the same way) |
| Docker | Docker Engine 23 or later (BuildKit), with the Compose v2 plugin (`docker compose`) |
| CPU / RAM | 2 cores / 4 GB (large PCAPs and the access-path review are memory-bound) |
| Disk | 2 GB for the image, plus room for the database, uploads and backups |
| Network, at build time | Docker Hub (base image) and PyPI (packages) — or see section 12 for offline installs |

Check Docker:

```bash
docker version            # Server: Version 23.0 or later
docker compose version    # Docker Compose version v2.x or later
```

---

## 3. Get the code

Unpack the delivered tarball and go into the project folder:

```bash
sudo mkdir -p /opt && cd /opt
sudo tar -xzf ~/iacs_monitor_docker.tar.gz      # creates /opt/iasc_monitor
cd /opt/iasc_monitor
ls Dockerfile docker-compose.yml requirements-lock.txt    # all three must exist
```

The commands below are run from this folder.

---

## 4. (Optional) Configure

Settings come from a `.env` file next to `docker-compose.yml`. Create it only if you need to
change a default:

```bash
cat > .env <<'EOF'
# Address and port the console is published on (default 127.0.0.1:8000)
IACS_BIND_ADDR=127.0.0.1
IACS_PORT=8000
# Largest accepted upload in bytes (default 54525952 = 50 MiB PCAP + 2 MiB)
IACS_MAX_REQUEST_BYTES=54525952
# Scheduler on/off at startup (true/false). To pause/resume without a restart
# use the console switch instead (section 8.1).
IACS_REVIEW_ENABLED=true
# Image tag to build/run (default latest) - use a version per release
IACS_IMAGE_TAG=latest
EOF
```

Other application settings (review schedule, retention, etc.) are listed in the README,
"Configuration"; add them under `environment:` in `docker-compose.yml`.

---

## 5. Build the image

```bash
docker compose build
```

or, with an extra version tag:

```bash
./build.sh 1.0.0            # tags iasc-monitor:latest and iasc-monitor:1.0.0
```

**Behind a corporate proxy that inspects TLS**, give the build the proxy's CA certificate and
proxy address:

```bash
PIP_CA=/etc/ssl/certs/corp-ca.pem ./build.sh
# or directly:
docker build --target runtime -t iasc-monitor:latest \
  --secret id=pip_ca,src=/etc/ssl/certs/corp-ca.pem \
  --build-arg HTTPS_PROXY=http://proxy.example:3128 .
```

**For a fully reproducible base image**, pin it by digest:

```bash
docker pull python:3.11-slim-bookworm
docker inspect --format '{{index .RepoDigests 0}}' python:3.11-slim-bookworm
docker build --target runtime -t iasc-monitor:latest \
  --build-arg PYTHON_BASE=python@sha256:<digest> .
```

On an architecture other than x86_64/arm64 add `--build-arg BUILD_TOOLS=true` (installs a
compiler for packages without a prebuilt wheel).

---

## 6. Start

```bash
docker compose up -d
```

Wait until the container reports **healthy** (normally 10–30 seconds; the first start creates
the database):

```bash
docker compose ps                     # STATUS ... (healthy)
curl -s http://127.0.0.1:8000/health  # {"status":"ok"}
docker compose logs | grep -E "Running upgrade|Uvicorn running"
```

The log shows the database migrations (`Running upgrade ... -> 8d9e0f1a2b3c`) followed by
`Uvicorn running on http://0.0.0.0:8000`.

The new database is **completely empty: no sites, no data**. You create the first site when you
upload the first file (section 8).

---

## 7. Open the console

On the Docker host: <http://127.0.0.1:8000/ui>

From your workstation, through an SSH tunnel to the host:

```bash
ssh -L 8000:127.0.0.1:8000 you@docker-host
# then browse to http://127.0.0.1:8000/ui on your workstation
```

---

## 8. First use

1. **Upload Data**: choose the site for the upload (or create one with **+ New site**, for
   example *Plant A*), pick the source type and upload the firewall configuration.
   Config findings are generated automatically. Then upload switch configs, packet captures,
   syslog exports and the approved-hosts baseline the same way.
2. **FW Topology Builder**: assign a Purdue level (and side) to every firewall interface. Until
   this is done, the report states that the level-dependent checks could not run.
3. **Findings**: press **Run reviews now** (or wait for the weekly schedule, section 8.1).
4. **Reports & Diagnostics**: **Download compliance report (PDF)**. Or generate it in the
   container and copy it out:

   ```bash
   docker compose exec iasc-monitor python generate_report.py --site-id 2 --out /data/report.pdf
   docker cp iasc-monitor:/data/report.pdf ./report.pdf
   ```

   (`--site-id` is required when the database holds more than one site; run the command
   without it and it prints the site ids.)

---

### 8.1 Scheduled reviews: on, paused or off

The periodic reviews run automatically on a schedule (default Sundays 02:00 UTC, all sites).

| Want | How | Restart? |
|---|---|---|
| **Pause / resume** the schedule | **Reports & Diagnostics → Periodic reviews**: untick / tick *Run the reviews automatically*. Or `curl -X PUT -H 'Content-Type: application/json' -d '{"enabled": false}' http://127.0.0.1:8000/reviews/schedule` | No — takes effect at the next scheduled time, kept across restarts |
| See the state | the same card (next run, last scheduled run), or `curl -s http://127.0.0.1:8000/reviews/schedule` | — |
| **Switch the scheduler off completely** | `IACS_REVIEW_ENABLED=false` in `.env`, then `docker compose up -d` | Yes — the console switch is then greyed out |
| Change the schedule | `IACS_REVIEW_SCHEDULE` (5-field cron, UTC) under `environment:` in `docker-compose.yml`, then `docker compose up -d` | Yes |

**Run reviews now** works in every case.

## 9. Verify the installation

| Check | Command | Expected |
|---|---|---|
| Container healthy | `docker compose ps` | `(healthy)` |
| API | `curl -s http://127.0.0.1:8000/health` | `{"status":"ok"}` |
| Console | `curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/ui` | `200` |
| Schema at head | `docker compose exec iasc-monitor alembic current` | `8d9e0f1a2b3c (head)` |
| Empty install | `curl -s http://127.0.0.1:8000/sites` | `[]` (before you create a site) |
| Packages = lock | `docker compose exec iasc-monitor python -m pip check` | `No broken requirements found.` |
| Data on the volume | `docker compose exec iasc-monitor ls /data` | `iasc_monitor.db`, `backups`, `tmp`, ... |

---

## 10. Data and persistence

Everything the application stores is in `/data` on the volume `iasc_data`:

| Path | Content |
|---|---|
| `/data/iasc_monitor.db` (+ `-wal`, `-shm`) | the database |
| `/data/iasc_scheduler.lock` | scheduler guard |
| `/data/tmp/` | upload spool files (emptied at every start) |
| `/data/backups/` | backups made with `backup_db.py` |

| Event | Data kept? |
|---|---|
| Container restart or crash | Yes |
| Host reboot (the container restarts automatically: `restart: unless-stopped`) | Yes |
| `docker compose down` then `up -d` | Yes |
| New image / upgrade (section 11) | Yes — migrations run at start |
| `docker compose down -v` | **No — `-v` deletes the volume** |
| `docker volume rm iasc_data`, `docker volume prune`, `docker system prune --volumes` | **No** |
| Resetting / uninstalling Docker Desktop (Windows/macOS) | **No** |

Persistence is not a backup: see section 10.1.

### 10.1 Backup

`backup_db.py` uses SQLite's online-backup API, so it is safe while the application runs (a
plain file copy of a database in WAL mode can be inconsistent). Each backup is checked with
`PRAGMA integrity_check`.

```bash
# one backup -> /data/backups/iasc_monitor-YYYYmmdd-HHMMSS.db
docker compose exec iasc-monitor python backup_db.py

# keep only the newest 14
docker compose exec iasc-monitor python backup_db.py --keep 14

# copy the backups off the volume (store them on another machine)
docker cp iasc-monitor:/data/backups ./iasc-backups
```

Nightly backup from the host's crontab (`crontab -e`):

```
15 2 * * * cd /opt/iasc_monitor && docker compose exec -T iasc-monitor python backup_db.py --keep 14 >> /var/log/iasc-backup.log 2>&1
```

### 10.2 Restore

```bash
cd /opt/iasc_monitor
docker compose stop
docker run --rm --entrypoint sh -v iasc_data:/data -v "$PWD/iasc-backups":/restore:ro \
  iasc-monitor:latest -c 'cp /restore/iasc_monitor-YYYYmmdd-HHMMSS.db /data/iasc_monitor.db \
  && rm -f /data/iasc_monitor.db-wal /data/iasc_monitor.db-shm'
docker compose start
curl -s http://127.0.0.1:8000/health
```

Replace the file name with the backup you want. A backup from an older version is upgraded by
the migrations at start.

---

## 11. Upgrade to a new version

```bash
cd /opt/iasc_monitor
docker compose exec iasc-monitor python backup_db.py          # 1. back up
docker cp iasc-monitor:/data/backups ./iasc-backups
docker tag iasc-monitor:latest iasc-monitor:previous          # 2. keep the old image
sudo tar -xzf ~/iacs_monitor_docker_NEW.tar.gz -C /opt         # 3. new code (keeps your .env)
docker compose build                                            # 4. new image
docker compose up -d                                            # 5. migrations run, then the app
docker compose logs | grep -E "Running upgrade|Uvicorn running"
```

After an upgrade, re-upload the firewall configurations when the release notes say the parser
changed (tracker, "Upgrade notes").

**Roll back:** restore the backup taken in step 1 (section 10.2) and start the old image:
`docker tag iasc-monitor:previous iasc-monitor:latest && docker compose up -d`. A database that
the new version has already migrated must be restored from the backup before the old image is
started.

---

## 12. Offline / air-gapped installation

Build on a machine with internet access, then move the image:

```bash
# connected machine
docker compose build
docker save iasc-monitor:latest | gzip > iasc-monitor-image.tar.gz

# air-gapped host (copy the tarball and the project folder there)
docker load < iasc-monitor-image.tar.gz
cd /opt/iasc_monitor
docker compose up -d --no-build
```

---

## 13. Debugging

Day-to-day debugging is easiest on the host (`uvicorn app.main:app --reload`, `pytest`).
To debug inside the image, use the development override:

```bash
mkdir -p data && sudo chown 1000:1000 data            # database in ./data, owned by uid 1000
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build
```

| Difference from production | Why |
|---|---|
| `dev` image target: pytest and the test tools included | run the suite inside the shipped image |
| `app/`, `ui/`, `tests/` bind-mounted, uvicorn `--reload` | code changes apply without a rebuild |
| database in `./data` on the host | easy to inspect, copy or reset |
| no automatic restart; background reviews off | a failing start stays visible |

Useful commands:

```bash
docker compose logs -f                                          # follow the log
docker compose exec iasc-monitor sh                             # shell in the container
docker compose exec iasc-monitor python -m pytest -q            # test suite (dev target)
docker compose run --rm -e IACS_SKIP_MIGRATIONS=true iasc-monitor sh   # start without migrating
```

Return to production with `docker compose -f docker-compose.yml -f docker-compose.dev.yml down`
and `docker compose up -d`. The development database in `./data` is separate from the
production volume.

---

## 14. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Container restarts; log: `/data is not writable by uid 1000` | a bind-mounted host folder owned by another user | `sudo chown -R 1000:1000 <folder>` |
| Log stops at an `alembic` error | a migration failed | keep the log; start with `IACS_SKIP_MIGRATIONS=true` to inspect; restore the last backup |
| `curl: (7) Failed to connect` from another machine | port published on 127.0.0.1 only (by design) | use an SSH tunnel (section 7); set `IACS_BIND_ADDR` only behind an authenticating proxy |
| Upload rejected with **413** | file larger than `IACS_MAX_REQUEST_BYTES`, or a config expanding beyond the row limits | raise `IACS_MAX_REQUEST_BYTES` in `.env`; see README for `IACS_MAX_RULE_ROWS*` |
| Build fails: `pip ... SSL: CERTIFICATE_VERIFY_FAILED` | TLS-inspecting proxy | build with the proxy CA (section 5) |
| Build fails pulling `python:3.11-slim-bookworm` | no access to Docker Hub | use a registry mirror (`--build-arg PYTHON_BASE=<mirror>/python:3.11-slim-bookworm`) or section 12 |
| `generate_report.py` exits with "this database has N sites" | multi-site database | add `--site-id N` or `--all-sites` |
| Report says checks could not run | no Purdue levels on firewall interfaces | assign levels in FW Topology Builder, re-run the reviews |
| Disk filling up | backups or logs | `--keep N` on backups; container logs are capped at 5 × 20 MB |

---

## 15. Verification record (2026-10-07)

What was run against the image built from this repository's `Dockerfile` with
`requirements-lock.txt`:

| Check | Result |
|---|---|
| Installed packages in the image vs. `requirements-lock.txt` | identical; `pip check`: no broken requirements |
| Full test suite inside the `dev` image (network disabled) | 2419 passed, 4 skipped (the 4 need the operator's legacy database, not shipped) |
| Same suite on the development host | 2423 passed |
| First start on an empty volume | all migrations to head (`8d9e0f1a2b3c`), healthy, **no sites** (`GET /sites` = `[]`), none created by browsing the console |
| Scheduled-reviews switch | paused via `PUT /reviews/schedule`, still paused after a container restart |
| A FortiGate config uploaded, reviews run, PDF generated in the container | findings and report identical to the host run |
| 16 MB / 200,000-packet PCAP upload | ingested; spool files in `/data/tmp` removed afterwards |
| Browser smoke tests against the runtime image | 16/16 console sections, 7/7 pages |
| Persistence: container restart, `down`/`up`, Docker daemon restart (reboot simulation) | data unchanged each time; container came back automatically |
| `backup_db.py` (with `--keep`) | consistent backups, integrity check ok |
| Development override (`docker-compose.dev.yml`) | starts, database in `./data`, `--reload` picks up code changes |
| Unwritable `/data` | clear error message, container does not start |

**Not verified in this environment:** pulling the official `python:3.11-slim-bookworm` base
image (the build sandbox has no Docker Hub access). The image was built on a stand-in base with
the same Python 3.11.15 and no third-party packages, so the dependency installation from the lock
was exercised in full. On the first build on your side, run the checks in section 9; the size of
the image on the official slim base is expected to be a few hundred MB.

---

## 16. Maintainers: updating dependencies

1. Change the pin in `requirements.txt`.
2. Build a clean runtime environment and freeze it into the lock:

   ```bash
   python3.11 -m venv /tmp/lockenv && /tmp/lockenv/bin/pip install -r requirements.txt
   /tmp/lockenv/bin/pip freeze | grep -viE '^(pip|setuptools|wheel)==' | tr 'A-Z_' 'a-z-' | sort > /tmp/lock.txt
   ```

   Replace the package lines of `requirements-lock.txt` with `/tmp/lock.txt` (keep the header).
3. Install the test tools (`pip install --no-deps -r requirements-dev-lock.txt`) and run the full
   suite.
4. Rebuild both targets and run the suite inside the `dev` image:

   ```bash
   docker build --target dev -t iasc-monitor:dev .
   docker run --rm --network none --entrypoint sh iasc-monitor:dev -c 'cd /app && python -m pytest -q'
   ```

Uninstall: `docker compose down` (keeps the data) or `docker compose down -v` (deletes the data),
then `docker rmi iasc-monitor:latest`.
