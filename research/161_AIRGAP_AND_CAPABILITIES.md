# 161 — What "air-gapped" was resting on

**Question.** An independent review of the repository (see research/160's decision
record) found that the air-gap claims were stronger than the code and the
documents supported. This checks each claim by running the thing, and fixes what
turned out to be false.

Four defects were found. Three of them could not have been found by reading.

---

## 1. The image would not start under a plain `docker run`

```
$ docker run --rm --entrypoint python netforensiq:dev-base -c "print('ok')"
exec /usr/local/bin/python: operation not permitted
```

**Cause.** The Dockerfile granted the interpreter `cap_net_raw,cap_net_admin=eip`
so the web process could sniff packets as a non-root user. Python is a
"capability-dumb" binary. With the file's effective bit set, the kernel refuses
to exec it unless every permitted file capability can be granted
(capabilities(7)), and `CAP_NET_ADMIN` is not in Docker's default set
(`AUDIT_WRITE, CHOWN, DAC_OVERRIDE, FOWNER, FSETID, KILL, MKNOD, NET_BIND_SERVICE,
NET_RAW, SETFCAP, SETGID, SETPCAP, SETUID, SYS_CHROOT`, per Docker's runtime
privilege documentation). The README's quick start hid it by passing
`--cap-add=NET_ADMIN`; `docker-compose.yml` and every command in RUN_OFFLINE.md
did not.

The same kernel rule was already recorded for the analysis sandbox
(`scripts/analyse_untrusted.sh`, research/151). It had not been applied to the
main image.

**Was `NET_ADMIN` ever needed?** Measured, with controls that can fail. A
non-root scapy sniffer, promiscuous mode on (scapy's default), on `eth0`:

| Interpreter | Docker capabilities | Result |
|---|---|---|
| file capability `cap_net_raw=eip` | default | **26 packets captured** |
| current image (`net_raw,net_admin`) | default + `NET_ADMIN` | 28 packets captured |
| copy without file capabilities (control) | default | `PermissionError`, 0 packets |

**Fix.** `setcap cap_net_raw=eip`. A test pins the rule — every file capability
with the effective bit must be in Docker's default set — and was checked by
putting `cap_net_admin` back and watching it fail.

**What this does not cover.** Live capture still needs `--network host`, since a
bridged container sees only its own traffic, and I tested capture on the
container's own `eth0`, not on a host interface.

## 2. The printed air-gap run command published nothing

`scripts/load_airgap_images.sh` printed
`docker run --rm --network none -p 8000:8000 ...`. Run directly:

```
$ docker run -d --network none -p 127.0.0.1:8098:8000 alpine sleep 20   # exit 0, no output
$ docker port <container>                                              # (empty)
$ curl http://127.0.0.1:8098/                                          # connection failed
```

Docker accepts the combination without a warning. The command also mounted no
volume for `/app/data`, where the database and the evidence key live, and used
`--rm`, so stopping it would have deleted the custody chain with the key that
decrypts the exhibits. RUN_OFFLINE.md's own step 5 was correct (named volumes,
loopback bind, and an honest note that `--network none` cannot publish); only
the printed copy was wrong. It now prints the working commands.

## 3. Making "no route off the machine" a property of the network

README and the Dockerfile said the running container had been verified under
`--network none`. What had been run under it was the one-shot seeding command;
the server cannot be reached under it.

`docker-compose.airgap.yml` puts the application on an `internal` Docker network
and publishes the port through a 4 MB `socat` relay attached to both networks.
`scripts/verify_airgap.sh` checks Docker's own state (every attached network is
internal; no published port; not host-networked; not privileged; the relay binds
loopback only) and, as corroboration, tries an outbound connection from inside.

Measured 2 Oct 2026:

* structural checks: all pass;
* probe from the application container to `1.1.1.1:443`: failed;
* **control**, same probe from an ordinary container: succeeded, so the probe
  can detect egress on this host;
* a 10.2 MB capture uploaded through the relay: HTTP 202 in 0.2 s, imported in
  40.5 s to 118,105 packets, 107,035 conversations, 53 findings — identical to
  the direct measurement in research/155.

On a host with no network the probe passes whether or not the container is
isolated, so it is stated as corroboration and the structural checks decide the
exit code.

**A mistake of my own, kept because it is instructive.** The first version of the
compose file wrote the server command as a YAML folded block with deeper-indented
continuation lines. YAML keeps those newlines; the shell ended the command after
`application`; gunicorn started on its defaults — `127.0.0.1`, one worker, 30 s
timeout — with no error, and the container's healthcheck passed because it
connects from inside. The relay reported "connection refused". It is now one
line, and a test reads the parsed command back.

## 4. Claims the code supports, and the one it does not

Established by searching the backend for anything that initiates a connection:

* `capture/alerting.py` (syslog and webhook senders) — targets are empty by
  default, so nothing is sent unless an operator configures a sink;
* `apk_engine/refresh_data.py` — run by an operator on the connected build
  machine;
* everything else that imports `socket` formats addresses, reads the local
  hostname, or opens a local raw socket.

This is a search, not a network trace, and third-party libraries were not
audited. `scripts/build_offline_bundle.sh` additionally fails the build if a
built asset references an external host.

**Not supportable:** "no network at all". Live capture needs `--network host`;
SIEM export sends to a server; and the public certificate-verify endpoint exists
so that someone *else* can check a certificate, which a loopback-only machine
does not allow. The ATT&CK and source links in the interface are web links; the
interface now also prints each URL as text so a citation is readable and
printable where the link cannot open.

## 5. Also found

* The README read "Ran 447 tests" under a badge reading 631 and nothing caught
  it, because the docs checker had no pattern for that form. It has one now.
* The compose relay image is pinned by tag, not digest. On this machine's image
  store a digest survives `docker save`/`load`; on another it may not, and a
  digest reference that cannot be resolved offline would fail the deployment.
  Integrity of what is carried across is the archive checksum.

## What is still not shown

* That the host is offline.
* That the image works on a classic (non-containerd) Docker image store; it was
  run on one daemon.
* The compose file under Podman or Docker Swarm.

*Measured 2 Oct 2026. Tests: `backend/capture/tests_airgap_docs.py` (12), each
original defect restored in turn to confirm the matching test fails.*
