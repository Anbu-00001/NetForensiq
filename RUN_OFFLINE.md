# Running NetForensiq offline

Everything below works with the machine in airplane mode. The one step that
needs a network is **building the image**, which is done once, elsewhere.

---

## 0. On a machine WITH internet — once

```bash
./scripts/save_airgap_images.sh 1.1
```

Writes `airgap-images/` containing both images, a manifest and SHA-256 sums.
Copy that directory to a USB stick.

> **Why both images.** Compose also starts Postgres. On an air-gapped machine
> `docker compose up` fails when it tries to pull `postgres:17-alpine` — after
> printing enough output to look like it is working. And `docker compose up
> --build` cannot work offline at all: building pulls base images and runs
> `apt-get`, `npm ci` and `pip install`.

## 1. On the offline machine — load

```bash
./scripts/load_airgap_images.sh airgap-images
```

Verifies the transfer before loading. Removable media truncates files silently,
and finding that out mid-demo is unrecoverable.

## 2. Create the volumes

Kept separate on purpose: the database can be reset without touching sealed
exhibits.

```bash
docker volume create netforensiq_db
docker volume create netforensiq_evidence
```

## 3. Generate two keys, once

Reuse the same values every run.

```bash
# Signs sessions and tokens. A new one invalidates every existing login.
export NF_SECRET_KEY="$(openssl rand -base64 48)"

# Encrypts the evidence store. A new one makes every sealed exhibit
# permanently unreadable. There is no recovery path and there is not meant
# to be one.
export NF_EVIDENCE_KEY="$(openssl rand -base64 32)"

umask 077
printf '%s\n%s\n' "$NF_SECRET_KEY" "$NF_EVIDENCE_KEY" > ~/.netforensiq-keys
```

> **Copy `~/.netforensiq-keys` somewhere that is not this machine, now.**
>
> This is not boilerplate caution. Passing `EVIDENCE_ENCRYPTION_KEY`
> explicitly is what stops the key from being generated *inside* the
> container, where recreating that container — a rebuild, an image bump, a
> `docker rm` — takes the key with it. The sealed files survive on their
> volume and become unreadable. That happened here during development, and the
> operator strip caught it: `SEAL DOES NOT VERIFY`, in red, in the sidebar.
>
> The image now defaults the key onto the persisted volume so a naive run
> survives. Supplying it explicitly is still better, because the key then
> never sits on the same disk as the evidence.

## 4. Seed the demonstration dataset

```bash
docker run --rm --network none \
  -e SECRET_KEY="$NF_SECRET_KEY" \
  -e EVIDENCE_ENCRYPTION_KEY="$NF_EVIDENCE_KEY" \
  -e SQLITE_NAME=/app/data/netforensiq.sqlite3 \
  -v netforensiq_db:/app/data \
  -v netforensiq_evidence:/app/evidence_store \
  netforensiq:1.1 \
  sh -c 'python manage.py migrate --noinput && python manage.py seed_demo'
```

`--network none` removes the network entirely — not firewalled, absent. This
step seals a capture, analyses it and issues a Section 63 certificate with no
possibility of reaching anything.

## 5. Run it

```bash
docker run -d --name netforensiq \
  -p 127.0.0.1:8000:8000 \
  -e SECRET_KEY="$NF_SECRET_KEY" \
  -e EVIDENCE_ENCRYPTION_KEY="$NF_EVIDENCE_KEY" \
  -e DEBUG=False \
  -e ALLOWED_HOSTS=127.0.0.1,localhost \
  -e SQLITE_NAME=/app/data/netforensiq.sqlite3 \
  -v netforensiq_db:/app/data \
  -v netforensiq_evidence:/app/evidence_store \
  --restart unless-stopped \
  netforensiq:1.1
```

Open **http://127.0.0.1:8000**

`-p 127.0.0.1:8000:8000` binds to loopback only, so the port is not offered to
anything else on the network the demo laptop happens to be plugged into.

> **Why not `--network none` here?** Publishing a port needs a network
> namespace. Docker does not warn about the combination: `docker run --network
> none -p 127.0.0.1:8000:8000 ...` starts normally, publishes nothing, and
> `docker port` prints an empty line. So this container has a network, and what
> keeps it off the internet is the host being in airplane mode — a fact about
> the host, not about the container. Section 6 removes that dependency.

---

## 6. No route off the machine, provably (recommended)

Instead of relying on the host being offline, put the application on a Docker
`internal` network — containers on it can reach each other and have no route
out — and publish the port through a one-line relay that is attached to both
networks. The relay forwards bytes from `127.0.0.1:8000` to the application and
does nothing else; the application can only reach the relay, and the relay only
forwards to the application.

```bash
export NF_IMAGE=netforensiq:1.0.0                      # the image you loaded
export NF_SECRET_KEY="$(openssl rand -base64 48)"
export NF_EVIDENCE_KEY="$(openssl rand -base64 32)"    # keep a copy elsewhere
docker compose -f docker-compose.airgap.yml up -d
scripts/verify_airgap.sh --control
```

Every compose command needs those variables, `down` and `stop` included, because
compose reads the file before acting and refuses without the keys. Put them in an
env file (mode 0600, not in git) and pass `--env-file ~/.netforensiq.env` each time.

`verify_airgap.sh` prints what it checked. The decisive checks are structural
and come from Docker's own state: every network the application is on is
`internal`, it publishes no port, it is not in host network mode or privileged,
and the relay publishes on `127.0.0.1` only. The outbound-connection probe is
corroboration, and says so: on a host with no network it passes whether or not
the container is isolated. `--control` runs the same probe from an ordinary
container, which must succeed if the host has a network, so a failure from the
application container then means something.

What this does **not** show: that the host itself is offline. Anything else
running on the host can still use the host's network.

Measured 2 Oct 2026 with the image built from this repository: the structural
checks passed, the probe from the application container failed, the probe from
an ordinary container succeeded, and a 10.2 MB capture uploaded through the
relay was accepted in 0.2 s and imported to 118,105 packets, 107,035
conversations and 53 findings — the same counts as a direct connection.

## 7. Updating indicator lists and engine data across the gap

New threat-intelligence feeds and the engine's reference data (tracker signatures,
stalkerware indicators, the top-level-domain list) go stale. They reach an offline
machine as a **signed update bundle**: one JSON file, made on a connected machine,
checked on the evidence workstation before anything in it is used.

**Publisher (connected machine; needs only Python and `cryptography`):**

```bash
python scripts/make_update_bundle.py keygen --out publisher.key     # once; prints the fingerprint
python scripts/make_update_bundle.py build --key publisher.key --spec spec.json --out update-0001.nfupd.json
python scripts/make_update_bundle.py inspect update-0001.nfupd.json
```

`spec.json` is in the header of `scripts/make_update_bundle.py`. Give each lab the key's
**fingerprint by another route** — a call, a printed notice — not only alongside the bundle.

**Evidence workstation:**

```bash
# once per publisher: decide to trust the key. You must type its fingerprint.
docker compose --env-file ~/.netforensiq.env -f docker-compose.airgap.yml exec app \
  python manage.py trust_publisher --name "Cyber Crime PS lab" \
  --public-key <base64> --fingerprint "a1b2c3d4 e5f6a7b8 ..."

# every bundle: look first, then apply
docker cp update-0001.nfupd.json "$(docker compose ... ps -q app)":/tmp/
docker compose ... exec app python manage.py import_update_bundle /tmp/update-0001.nfupd.json --dry-run
docker compose ... exec app python manage.py import_update_bundle /tmp/update-0001.nfupd.json
```

`--dry-run` shows who signed it, whether this machine trusts that key, the sequence number
and expiry, and every problem at once. Applying is all or nothing. It is a command rather than
a web page on purpose: a person at a terminal who must type a fingerprint is the control.

| Threat (The Update Framework's list) | What is done |
|---|---|
| an unsigned or forged bundle | Ed25519 signature; the key must be one you chose to trust |
| an older bundle replayed (rollback) | per-publisher sequence number must increase; the database refuses a duplicate even if two operators race |
| a stale bundle (freeze) | an expiry date, checked against this machine's clock; `--allow-expired` is recorded |
| endless data | limits on the bundle (64 MB), each item (32 MB) and the item count |
| mixing parts of different bundles | one signed manifest names every payload by SHA-256; applied together or not at all |
| the wrong thing installed | only indicator feeds and three named engine files; never the baselines, the detection rules or the known-signers list |
| **a fast-forward by the key's holder** | **not prevented.** Publishing sequence 10^9 would refuse every later honest bundle. The answer is to stop trusting the key |
| **a stolen key** | **not prevented.** One key per publisher, no threshold signing. Remove it with `trust_publisher --remove` |

The clock matters for expiry and an air-gapped machine's clock is only as good as whoever
set it; the status page reports its state. The three engine files are read by the examination
engine from the last applied bundle, and every examination report records the SHA-256 of the
file it actually used.

---

## 8. Checking a release you were handed

A release is a directory: the image archive, bills of materials, a signed manifest
`release-<version>.json`, and a `SHA256SUMS`. Before loading anything:

```bash
python scripts/make_release.py verify release/ --fingerprint "a1b2c3d4 e5f6a7b8 ..."
```

It checks the signature and every artefact's SHA-256 and lists anything in the directory
the manifest does not name. The fingerprint is the author's key as published somewhere
other than in the release itself; without it the check says the files are intact but not
who signed them. Without our tools, `sha256sum -c SHA256SUMS` checks the artefacts against
the sums (which proves nothing about who wrote them).

The manifest also records the source commit and a digest of the source tree. With a
checkout of that commit, `python scripts/tree_digest.py` recomputes it. A `dirty` build is
one made from a tree with uncommitted changes and is labelled so.

---

## Everyday commands

```bash
docker logs -f netforensiq            # watch it
docker stop netforensiq               # stop
docker start netforensiq              # start again, data intact
docker rm -f netforensiq              # remove the container; volumes survive
docker exec -it netforensiq python manage.py shell
```

Reset the case data but keep the sealed exhibits:

```bash
docker rm -f netforensiq
docker volume rm netforensiq_db
docker volume create netforensiq_db
# then repeat step 4
```

---

## Sign-in

All demonstration accounts share one password:

```
Netforensiq@2026
```

| Username | Role | Clearance | What they can do that others cannot |
|---|---|---|---|
| `investigator` | Investigator | Can act on evidence | Run detection, triage findings, seal exhibits, sign **Part A** of the certificate |
| `expert` | Investigator | Can act on evidence | The same permissions — but a *different person*, which is what lets them countersign **Part B**. BSA 2023 s.63(4) requires two people, not two permission levels, and the service layer refuses a certificate signed twice by one account |
| `commander` | Admin | Full | Everything above, plus approving who may hold an account at all |
| `viewer` | Viewer | Read-only | Reads the register and the findings. Never shown a control they cannot use, and **cannot read a reconstructed conversation** — message content is privileged even on a GET |
| `pending-applicant` | — | None | Exists to make the approval queue non-empty. **Sign-in fails on purpose**: an unapproved account cannot reach anything |

Start as **`investigator`**. Sign in as **`viewer`** to show the difference.

> Change these before the platform is near real evidence. The password is in
> `capture/management/commands/seed_demo.py`, in public, deliberately — it is a
> demonstration credential and must never be mistaken for a deployment one.

---

## Live monitoring

Detection while the capture is still running, alerting on findings as they
first appear:

```bash
sudo setcap cap_net_raw=eip "$(readlink -f backend/.venv/bin/python)"
python manage.py capture_live --iface eth0 --window 30 --home-net 10.0.0.0/8
```

In a container this needs `--network host`, because a bridged container sees
only its own traffic. `NET_RAW` is in Docker's default capability set, so no
`--cap-add` is needed, and `NET_ADMIN` is not needed at all — a non-root sniffer
with promiscuous mode on captured with `NET_RAW` alone (research/161). The image
used to demand `NET_ADMIN` and could not start without it.

Without the capability scapy captures **nothing and raises nothing** — the
capture would report zero packets, which looks exactly like a quiet network.
The command now refuses up front rather than letting that happen.
