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

## 3. Generate a key, once

Reuse the same value every run. A new key invalidates every existing session
and every issued token.

```bash
export NF_SECRET_KEY="$(openssl rand -base64 48)"
echo "$NF_SECRET_KEY" > ~/.netforensiq-secret && chmod 600 ~/.netforensiq-secret
```

## 4. Seed the demonstration dataset

```bash
docker run --rm --network none \
  -e SECRET_KEY="$NF_SECRET_KEY" \
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
> namespace. The container has one; what it does not have is a route to the
> internet when the host is in airplane mode. Step 4 is the proof that nothing
> in the platform needs one.

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
sudo setcap cap_net_raw,cap_net_admin=eip "$(readlink -f backend/.venv/bin/python)"
python manage.py capture_live --iface eth0 --window 30 --home-net 10.0.0.0/8
```

In a container this needs `--cap-add NET_RAW --cap-add NET_ADMIN --network host`,
because a bridged container sees only its own traffic.

Without the capability scapy captures **nothing and raises nothing** — the
capture would report zero packets, which looks exactly like a quiet network.
The command now refuses up front rather than letting that happen.
