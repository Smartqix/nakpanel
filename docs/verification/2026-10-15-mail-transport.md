# Mail Transport Compatibility

The importer pins MIT-licensed `github.com/emersion/go-imap/v2`
`v2.0.0-beta.8`. Its prerelease status requires repeating these compatibility
checks before an upgrade. See the [upstream library](https://github.com/emersion/go-imap).

On October 15, the Linux test binary ran against the deployed Stalwart 0.11.8
using new mailbox ID 7, `import-qa-20261015@nakpanel.com`. Existing mailboxes
were not edited. The credential is held only in a mode-0600 QA file.

The native check passed for two distinct messages with identical MIME bytes:
attachment preservation, original internal date, seen/flagged/answered/deleted
flags, persistent receipt keywords, UIDPLUS receipts, and receipt searches.
All copied messages remain in their new QA folder. This was a transport check,
not a completed importer acceptance test.

The expanded test then exposed a Stalwart 0.11.8 account-cache problem:
CREATE updated the session's folder list, but a later APPEND child-state update
could advance an older cached list. The messages remained visible through
JMAP/storage while fresh IMAP connections omitted the folders. A controlled
service restart restored visibility without modifying data. Nakpanel now
renders `cache.account.size = 0` and `capacity = 0` for its pinned Stalwart
configuration. A new native test fails without this setting and passes with
it, including fresh-login receipt lookup and Sent-folder role discovery.
This is a compatibility safeguard, not a Stalwart version upgrade.

Import completion now requires independent verification through a fresh
destination connection. Empty source discovery is rejected before the import
can start; explicitly excluded source messages remain an intentional outcome.

Unit and race tests also cover an acknowledgement lost after the server
persisted the message: reconnecting finds its receipt instead of appending a
second copy. TLS trust failures, prohibited source addresses and changed
UIDVALIDITY fail closed.
