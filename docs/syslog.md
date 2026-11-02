# External syslog forwarding

Custos forwards local audit events using **RFC 5424** syslog messages: UTC timestamp,
host, `custos` application name, `AUDIT` message ID and UTF-8 JSON containing who,
what, target, outcome, source IP, correlation/operation ID and sanitized detail.
Unicode MSG starts with the UTF-8 BOM; JSON escaping prevents embedded newlines from
becoming forged log records. Facility is local0; ordinary events use informational,
denials warning, failures/unknown/unavailable error severity. Structured-data is NIL;
no unregistered enterprise number is invented.

TLS is the default transport on port 6514 (RFC 5425). TCP uses octet-counted framing
(RFC 6587); UDP is available for receivers requiring it, with one event per datagram.

Set these on the **worker** process, not in browser input:

```powershell
$env:CUSTOS_SYSLOG_HOST = 'logs.example.com'
$env:CUSTOS_SYSLOG_TRANSPORT = 'tls'
$env:CUSTOS_SYSLOG_PORT = '6514'
# Optional private CA; otherwise use server OS trust.
$env:CUSTOS_SYSLOG_CA_BUNDLE = 'C:\certificates\logging-ca.pem'
# Optional mutual TLS:
$env:CUSTOS_SYSLOG_CLIENT_CERT = 'C:\certificates\custos-client.pem'
$env:CUSTOS_SYSLOG_CLIENT_KEY = 'C:\secrets\custos-client.key'
.\.venv\Scripts\python -m custos.worker
```

Hostnames/certificates are validated and credentials/session tokens are not logged.
TCP/UDP do not provide TLS confidentiality; select them only for the appropriate
receiver/network. Configure the collector for RFC 5424 and octet counting on TCP/TLS.
Private keys and logger configuration belong to deployment secret/config management.

Each newly inserted audit record creates a `syslog_outbox` entry in the **same DB
transaction**. The single worker sends up to 100 pending records per cycle. Failed
transmissions remain queued with bounded exponential retry, up to one hour between
attempts. No configured host means records stay queued; local web audit remains
available. Admin Activity displays the pending outbox count. Run
`custos-directory init-db` to create the new outbox table before updated web/worker
processes start.

Successful send means bytes were handed to the socket, not an application-level
acknowledgement that the receiver stored them. Syslog itself provides no such receipt;
UDP can be lost, and a crash after transmission but before DB commit can duplicate
an event. Deduplicate at the collector using `event_id`. No local audit is deleted
when transmission succeeds. Historical audit rows created before the outbox feature
are not automatically backfilled; retention, replay/backfill and dead-letter UI are
future work. A database outage cannot produce a durable local audit; mutation dispatch
requires its initial audit/operation transaction to commit first.

This covers actions through Custos. It cannot capture activity performed directly in
vCenter/Prism or inside a console that has not been brokered. Correlate provider audits
and CyberArk session recordings for those activities.

Standards: [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424),
[RFC 5425](https://www.rfc-editor.org/rfc/rfc5425),
[RFC 6587](https://www.rfc-editor.org/rfc/rfc6587).
