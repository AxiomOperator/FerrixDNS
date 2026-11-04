# Backup and restore

A backup holds policy revisions, downloaded lists, list status and the audit log. Query logs are left
out because they're disposable and sensitive, and sessions are never included.

## From the dashboard

**System → Backup and restore** downloads a backup and restores one. Restoring checks the file first
and shows what it contains, and accounts on the node are left alone.

## From the command line

```sh
ferrixdns backup create --state-dir /var/lib/ferrixdns --output backup.tar.gz
ferrixdns backup restore --state-dir /var/lib/ferrixdns --input backup.tar.gz --dry-run
sudo systemctl stop ferrixdns
ferrixdns backup restore --state-dir /var/lib/ferrixdns --input backup.tar.gz
sudo systemctl start ferrixdns
```

Stop the node before a command-line restore. Creating a backup is safe while it runs. With the packaged
service, `DynamicUser` stores state under `/var/lib/private/ferrixdns` and restricts it, so run these
commands as root, and after restoring as root, restart the service so systemd fixes its ownership.

## Moving accounts

Accounts are only included when encrypted, using a passphrase of at least 10 characters:

```sh
FERRIXDNS_BACKUP_PASSPHRASE='a long passphrase' ferrixdns backup create --include-credentials \
    --state-dir /var/lib/ferrixdns --output backup.tar.gz
FERRIXDNS_BACKUP_PASSPHRASE='a long passphrase' ferrixdns backup restore \
    --state-dir /var/lib/ferrixdns --input backup.tar.gz
```

Restoring accounts replaces every existing account and ends all sessions. Without the passphrase, a
restore skips them and leaves the node's accounts as they are. A wrong passphrase stops the restore
before anything changes.

## What's checked before a restore

Nothing changes until all of this passes:

- The format version, and every file against the manifest's checksums.
- Each revision's content against its name, and that every revision parses and compiles with the lists
  it refers to.
- Only expected file names, with no links or paths outside the backup, and at most 2 GiB when expanded.

Backups are plain text apart from the encrypted accounts. Store them somewhere private. They contain
your rules, client names and addresses, and who changed what.

## Test your backups

Spec section 7.4 asks for a restore test each quarter. `--dry-run` confirms a file is usable, and a full
test restores to a scratch directory, then starts a node on it:

```sh
ferrixdns backup restore --state-dir /tmp/restore-test --input backup.tar.gz
ferrixdns serve --listen 127.0.0.1:5399 --upstream 1.1.1.1 --state-dir /tmp/restore-test
dig @127.0.0.1 -p 5399 a-domain-you-block.example
```
