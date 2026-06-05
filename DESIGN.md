# Design notes

This document captures the architectural reasoning behind
`dsmr-checkpassword-dovecot`: what other approaches were considered, why they
were rejected, what the wire protocol looks like, and what the threat model
of the bridge is.

## Problem statement

A qmail submission daemon needs to authenticate two distinct populations from
one TLS endpoint:

1. vpopmail virtual users (`pw_name@pw_domain` rows in the `vpopmail` SQL
   table or `vpasswd` files).
2. A curated subset of Unix shell users on the host, for relaying outgoing
   mail in domains the host accepts via `rcpthosts` + `~user/.qmail-*`
   alias-extension delivery (i.e., domains that are **not** vpopmail
   virtual hosts).

The native qmail-smtpd checkpassword interface allows exactly one program to
adjudicate AUTH attempts. That program must be able to consult both
populations.

## Approaches considered

### A. Move the rcpthosts-only domain into vpopmail

Add `example.com` (or whatever domain hosts the system-user senders) to
vpopmail's `virtualdomains`, create a vpopmail account for each system
sender, and let `vchkpw` continue to do all the work.

**Rejected** because in the existing DSMR deployment, `~fade/.qmail-*` files
route ~150 sub-addressed extensions for `example.com` mail through system
delivery. Moving the domain into vpopmail collides with that delivery path:
either every extension must be migrated to a vpopmail alias (large surface
area, easy to lose mail in the migration), or the system aliases must be
duplicated in vpopmail's `.qmail-default`. Neither is small.

### B. Replace `vchkpw` with a checkpassword-pam binary

Use a published checkpassword that authenticates against PAM directly.
Configure `/etc/pam.d/smtp` to allow only an allow-listed group; let PAM do
the work for both system users and (via `pam_vpopmail` or similar) virtual
users.

**Considered, rejected** because:

- Two passdb chains (one for IMAP via dovecot, one for SMTP via PAM) drift.
  A new vpopmail account or a system-passwd change has to be reflected in
  both, and if they get out of sync, login behaviour silently differs by
  protocol.
- `pam_vpopmail` is not packaged for current Debian; bringing it in adds a
  build-from-source dependency that this stack already maintains via
  dovecot.

### C. Checkpassword multiplexer (chained at the qmail level)

A small wrapper that tries `vchkpw` first; on failure, tries
`checkpassword-pam`. Same end result as C without the dovecot dependency.

**Rejected** because of the same drift problem as B: the SMTP path's
allow-list (PAM stack) and the IMAP path's allow-list (dovecot's chained
passdbs) are separate. Adding an account requires touching both.

### D. Bridge through dovecot (this package)

`qmail-smtpd` calls a bridge that connects to dovecot's auth-client socket
and lets dovecot's already-chained passdbs (vpopmail SQL, system-passwd,
PAM) decide. One source of truth for both protocols.

**Chosen** because:

- The chained passdb already exists in this stack — no new policy machinery.
- Adding a new sender (vpopmail account or system-passwd row) immediately
  authenticates over both IMAP and SMTP-AUTH; never out of sync by
  construction.
- The bridge itself is small (~150 lines of C, libc-only) and the protocol
  it speaks is documented.

## Wire protocol — the qmail side (FD3)

`qmail-smtpd` exec()s the checkpassword program after STARTTLS+AUTH and
writes the credentials on file descriptor 3 in DJB's classic format:

```
<authcid>\0<password>\0<timestamp>\0
```

For AUTH LOGIN, qmail-smtpd has already base64-decoded the username and
password before composing this payload. For AUTH PLAIN, it splits the
client's `\0authzid\0authcid\0password` blob and forwards `authcid` and
`password`. CRAM-MD5 uses a different format (challenge/response) — the
DSMR stack does not advertise it, so the bridge does not implement it.

If the program exits 0, qmail-smtpd treats AUTH as accepted and the
program is expected to have exec()d its argv (typically `/bin/true`).
Any non-zero exit is treated as auth failure: 1 maps to a clean reject
(`535 authentication failed`), 111 maps to a transient error (`454
TLS not available due to temporary reason`).

## Wire protocol — the dovecot side (auth-client)

After connect, dovecot writes a greeting:

```
VERSION\t1\t2
MECH\tPLAIN\tplaintext
MECH\tLOGIN\tplaintext
SPID\t<server-pid>
CUID\t<connection-id>
COOKIE\t<cookie>
DONE
```

The bridge writes its handshake first (before reading the greeting, to
avoid any deadlock if dovecot blocks waiting for the client's
`VERSION`):

```
VERSION\t1\t2
CPID\t<bridge-pid>
```

After draining the server greeting up to `DONE`, the bridge sends:

```
AUTH\t1\tPLAIN\tservice=smtp\tresp=<base64(\0authcid\0password)>
```

Server response is one of:

- `OK\t1\tuser=<canonical-name>` → success
- `FAIL\t1\treason=...`         → bad credentials, or no passdb matched
- `CONT\t1\t<challenge>`        → not used for SASL PLAIN

The bridge maps `OK` to exec(argv+1) with exit 0, `FAIL` to exit 1, and
anything unexpected to exit 111.

The full dovecot auth-protocol spec lives at
<https://doc.dovecot.org/2.4/core/protocols/auth.html>.

## Why a separate listener (`auth-client-smtp`)

Dovecot's default `auth-client` socket is `mode 0600 dovecot:root`. The
bridge runs as the vpopmail UID (because qmail-smtpd does, and it
exec()s the bridge as a child); it cannot read the default socket.

Three options:

1. Loosen the default auth-client socket's mode — affects every other
   consumer of dovecot auth and is harder to reason about.
2. Run the bridge with extra capabilities — adds privilege rather than
   following least-privilege, and requires setuid/setgid plumbing.
3. Add a second listener with permissions matching the bridge's existing
   identity. **Chosen.**

The new listener at `/var/run/dovecot/auth-client-smtp` is mode 0660,
owner `vpopmail:vchkpw` — exactly the credentials qmail-smtpd already
runs under. No new privileges are introduced.

## Threat model

The bridge is invoked once per AUTH attempt, fork()ed as a child of
qmail-smtpd, and given a single short message on FD3. It does not
process untrusted network input directly. The protocol-parsing surface
is therefore:

- The FD3 payload from qmail-smtpd: trusted (qmail-smtpd has already
  rejected malformed AUTH framing).
- The dovecot auth-client socket: trusted (dovecot is on the same host,
  same trust boundary).

That said, the implementation includes:

- Bounds-checking on the FD3 payload (max 512 bytes, NUL-separator
  validation, reject control chars in the username so they cannot break
  the auth-client framing).
- Send-and-receive timeouts on the dovecot socket (10 seconds), so a
  hung dovecot does not tie up a qmail-smtpd worker indefinitely.
- Defensive responses: any unexpected line from dovecot exits the bridge
  with a transient error rather than treating it as success.

The bridge does not log credentials. Stderr is captured by qmail-smtpd's
multilog tree under `/var/log/qmail/submission/`; only error categories
land there, never user-supplied bytes.

## What was deliberately left out

- **CRAM-MD5 support.** The DSMR stack does not advertise it (`AUTH LOGIN
  PLAIN` only), and adding it requires the checkpassword/CRAM extension
  variant of the FD3 payload, plus dovecot's challenge/response auth-client
  flow. Out of scope.

- **Configurable socket path.** Compiled in. There is one socket path in
  this stack; making it tunable adds an attack-surface argument that is not
  needed.

- **Logging the authenticated user on success.** qmail-smtpd already logs
  `authuser=...` via `qlogenvelope`; duplicating it from the bridge would
  be redundant.

- **Async I/O.** A single short request/response per invocation, with a
  10-second timeout, does not justify the complexity.
