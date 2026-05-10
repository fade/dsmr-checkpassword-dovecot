# dsmr-checkpassword-dovecot

A small DJB-style checkpassword program that bridges qmail-smtpd's SMTP-AUTH
to dovecot's auth-client protocol over a Unix socket.

In a qmail + vpopmail + dovecot stack, this lets one chained dovecot passdb
(vpopmail SQL → `/etc/dovecot/system-passwd` → PAM) authenticate **both** IMAP
logins and SMTP submission, instead of having `qmail-submission` constrained to
vpopmail virtual accounts via `vchkpw`.

This package is part of the [DSMR mail-server stack](https://github.com/fade/dsmr-qmail).

## Why this exists

The DSMR submission daemon authenticates via `vchkpw`:

```
exec ... qmail-smtpd /home/vpopmail/bin/vchkpw /bin/true
```

`vchkpw` only knows about vpopmail virtual users — accounts under
`/home/vpopmail/domains/<domain>/`. That is fine for sites whose users live
exclusively in vpopmail, but it leaves a common case unhandled:

- The host has Unix shell users (`fade`, `marilyn`, ...).
- The host accepts mail for one or more domains via `rcpthosts` + qmail
  alias-extension files (`~/.qmail-foo`), **without** those domains being
  vpopmail virtual hosts.
- Those Unix users want to relay outgoing mail through the host's submission
  port, authenticated as `<user>@<rcpt-domain>`.

Without a checkpassword backend that knows about system users, those
authentications fail with `535 authentication failed` even when the password
is correct, because `vchkpw` cannot look the user up.

Meanwhile, dovecot in this stack already chains the right backends. Look at
`/etc/dovecot/conf.d/`:

```
passdb sql        { … vpopmail SQL passdb … }
passdb passwd-file { result_failure = continue
                     passwd_file_path = /etc/dovecot/system-passwd
                     auth_username_format = %{user|username} }
passdb pam        { }
```

`result_failure = continue` chains them: try vpopmail SQL, then the
passwd-file, then PAM. IMAP login already gets all three. Submission only
gets the first.

This bridge closes the gap. `qmail-submission` calls
`/var/qmail/bin/checkpassword-dovecot` instead of `vchkpw`; the bridge talks
to dovecot's auth-client socket; dovecot's existing chain decides who gets
in. One source of truth for authentication.

## How it works

```
   smtpd client (swaks, Thunderbird, …)
        │
        │ AUTH LOGIN/PLAIN over STARTTLS on :587
        ▼
   ┌─────────────────────────┐
   │   qmail-submission/run  │
   │   exec qmail-smtpd \    │
   │       checkpassword-... │
   └─────────────────────────┘
        │ fork+exec on each AUTH attempt
        │ FD3 carries: <user>\0<pass>\0<timestamp>\0
        ▼
   ┌─────────────────────────┐
   │  checkpassword-dovecot  │   (this package, runs as vpopmail UID)
   └─────────────────────────┘
        │ AUTH PLAIN over Unix socket
        ▼
   /var/run/dovecot/auth-client-smtp     (mode 0660, vpopmail:vchkpw)
        │
        ▼
   ┌─────────────────────────┐
   │       dovecot auth      │
   │  passdb sql (vpopmail)  │   tried first
   │  passdb passwd-file     │   /etc/dovecot/system-passwd, then
   │  passdb pam             │   then PAM
   └─────────────────────────┘
        │
        ▼
       OK / FAIL — propagated back to qmail-smtpd's 235 / 535.
```

The default dovecot `auth-client` socket is `mode 0600 dovecot:root`, which
qmail-smtpd (running as the vpopmail UID) cannot read. The conffile shipped
with this package adds a second listener at
`/var/run/dovecot/auth-client-smtp` with `mode 0660 vpopmail:vchkpw`.
qmail-smtpd already runs under those credentials, so no further privileges
are introduced.

## What's in the package

| Path                                                | Kind            | Notes                                  |
| --------------------------------------------------- | --------------- | -------------------------------------- |
| `/var/qmail/bin/checkpassword-dovecot`              | binary          | Runs as the calling UID (vpopmail).    |
| `/etc/dovecot/conf.d/99-dsmr-smtp-auth.conf`        | conffile        | Adds the auth-client-smtp listener.    |
| `/usr/share/doc/dsmr-checkpassword-dovecot/README.md` | documentation | This file.                             |
| `/usr/share/doc/dsmr-checkpassword-dovecot/DESIGN.md` | documentation | Architecture and protocol details.     |

## Install

```
sudo apt install dsmr-checkpassword-dovecot
```

The postinst:

1. reloads dovecot (so the new auth-client-smtp listener appears),
2. cycles `qmail-submission` (the run script in `dsmr-qmail-run >= 1.0-9`
   auto-detects the bridge),
3. prints next-steps on first install.

## Configure

### 1. Populate `/etc/dovecot/system-passwd`

This is the curated allow-list of system users permitted to SMTP-AUTH. It is
**not** populated automatically — there is no implicit "everyone in
`/etc/passwd` may relay" policy.

Use a credential **separate** from the user's Unix login. SMTP-relay and
shell-login have different blast radii; do not couple them.

```sh
# Generate a hash and append a row.
printf 'fade:%s::::\n' "$(doveadm pw -s SHA512-CRYPT)" \
  | sudo tee -a /etc/dovecot/system-passwd

sudo chown root:dovecot /etc/dovecot/system-passwd
sudo chmod 0640 /etc/dovecot/system-passwd
```

Format reminder (passwd-file with five trailing colons because we're not
storing uid/gid/gecos/home/shell here — userdb info comes from
`userdb passwd { }`):

```
<user>:{SHA512-CRYPT}<hash>::::
```

Dovecot's passwd-file passdb in this stack is configured with
`auth_username_format = %{user|username}`, which strips the domain before
looking up the file. That means clients can AUTH as either bare `fade` or
`fade@deepsky.com`; both resolve to the row keyed by `fade`.

### 2. Verify

After reload, the listener should be in place:

```sh
ls -l /var/run/dovecot/auth-client-smtp
# srw-rw---- 1 vpopmail vchkpw 0 ... auth-client-smtp
```

Submission should be running with the bridge wired in:

```sh
ps -ef | grep qmail-smtpd | grep checkpassword-dovecot
```

### 3. Test from a remote host

```sh
# vpopmail user (still works through the new bridge)
swaks --to ext@example.com --from fade@deepsky.ca \
      --server outrider.deepsky.com --port 587 --tls \
      --auth LOGIN --auth-user fade@deepsky.ca --auth-password '...'

# system user (newly authenticatable)
swaks --to ext@example.com --from fade@deepsky.com \
      --server outrider.deepsky.com --port 587 --tls \
      --auth LOGIN --auth-user fade@deepsky.com --auth-password '...'

# bad password — should still fail with 535
swaks ... --auth-password 'wrong'
```

In two parallel terminals, watch:

```sh
tail -f /var/log/qmail/submission/current | tai64nlocal
journalctl -fu dovecot
```

You should see, in dovecot's log:

```
auth: passdb(fade@deepsky.com): passwd-file(...): match
```

and in submission's:

```
qlogenvelope: ... authuser=fade@deepsky.com authtype=login encrypted=tls ...
```

## Interaction with other DSMR packages

The DSMR mail stack ships several inter-related source trees. Their
relationship to this package:

| Package                     | Relationship                                               |
| --------------------------- | ---------------------------------------------------------- |
| `qmail`                     | Provides `qmail-smtpd`. Hard `Depends`.                    |
| `dsmr-qmail-run`            | Owns `/etc/qmail/qmail-submission/run`. From 1.0-9 the script auto-detects this bridge; older versions need the run script edited by hand. `Recommends`. |
| `vpopmail`                  | Provides `vchkpw`, used as the fallback auth backend when this bridge is not installed. No direct dependency. |
| `dovecot-vpopmail`          | Provides the chained passdb config in `/etc/dovecot/conf.d/05-vpopmail-auth.conf`, `99-vpopmail-master.conf`. `Recommends`. |
| `dovecot-core`              | Provides the auth daemon this bridge speaks to. Hard `Depends`. |

### Why `dsmr-qmail-run` was bumped to 1.0-9

Previously, `/etc/qmail/qmail-submission/run` hard-coded `vchkpw`. To avoid
having `dsmr-checkpassword-dovecot.postinst` mutate a file owned by another
package (which would create reconciliation pain on every `dsmr-qmail-run`
upgrade), the run script in 1.0-9 selects its auth backend at exec time:

```sh
if [ -x /var/qmail/bin/checkpassword-dovecot ]; then
    AUTH_PROG=/var/qmail/bin/checkpassword-dovecot
else
    AUTH_PROG=/home/vpopmail/bin/vchkpw
fi
exec ... qmail-smtpd "$AUTH_PROG" /bin/true
```

So:

- Install **only** `dsmr-qmail-run >= 1.0-9` → vchkpw, status quo.
- Install **only** `dsmr-checkpassword-dovecot` (without bumping
  dsmr-qmail-run) → the bridge sits on disk but the run script does not
  call it. Postinst prints a notice if it detects this state.
- Install **both** `dsmr-qmail-run >= 1.0-9` and
  `dsmr-checkpassword-dovecot` → the bridge is used; vpopmail and system
  users authenticate from one passdb chain.

### What this package deliberately does **not** do

- It does **not** edit `/etc/qmail/qmail-submission/run` from postinst.
  The run script is owned by `dsmr-qmail-run`. Postinst-from-other-package
  edits would be silently overwritten on the next `dsmr-qmail-run` upgrade.
- It does **not** populate `/etc/dovecot/system-passwd`. That file is
  policy, not packaging — only the operator knows which Unix users should
  be allowed to relay.
- It does **not** change the inbound `qmail-smtpd` (port 25) run script.
  Inbound mail acceptance has nothing to do with SMTP-AUTH.
- It does **not** advertise CRAM-MD5 to clients. The bridge implements only
  AUTH PLAIN and AUTH LOGIN, which are what the DSMR stack already
  advertises today.

## `FORCEAUTHMAILFROM` and the username form

The submission run script sets `FORCEAUTHMAILFROM=1`, which requires
`MAIL FROM:<addr>` to match the SMTP-AUTH username exactly. Two notes:

- Encourage clients to AUTH with the full `user@domain` form, so the AUTH
  identity matches the From address. Bare-username AUTH is technically
  legal — dovecot's passwd-file passdb strips the domain before lookup —
  but the chkuser comparison sees the bare name and rejects MAIL FROM.

- A client that needs to send From multiple domains under a single account
  (e.g., `fade@deepsky.com` AND `fade@subdued.org`) is not served by
  `FORCEAUTHMAILFROM`. The conventional solution is to drop that constraint
  and add a qmail-spp envelope-checker plugin that consults an explicit
  authuser → permitted-From-domains allowlist. That is out of scope for
  this package.

## Build from source

```sh
# Native source package; native = source IS upstream.
cd dsmr-checkpassword-dovecot
sudo apt build-dep .
dpkg-buildpackage -us -uc -b
ls ../dsmr-checkpassword-dovecot_*.deb
```

The DSMR build environment is documented in the parent
[dsmr-qmail repo](https://github.com/fade/dsmr-qmail) — Debian builds run
on a dedicated VM, never on the production host.

## License

GPL-2 or later. See `debian/copyright`.

## See also

- `DESIGN.md` — protocol details, threat model, design alternatives that were rejected.
- [DSMR mail server stack](https://github.com/fade/dsmr-qmail) — the umbrella repo.
- [dovecot auth protocol](https://doc.dovecot.org/2.4/core/protocols/auth.html) — upstream documentation for the auth-client wire format.
