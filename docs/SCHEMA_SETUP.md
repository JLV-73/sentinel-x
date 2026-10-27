# Pinned external schema setup

The runtime validation schema is intentionally **not redistributed in Git**.
The upstream notice explicitly covers the KEV database; scope for the ancillary
schema remains a narrowly documented licensing uncertainty. No project license
or third-party clearance is invented here.

After creating the project-local Python environment, run from the checkout root:

```powershell
.\.venv\Scripts\python.exe -I tools\bootstrap_schema.py
```

The helper uses verified HTTPS with no environment proxy or redirects, retrieves
only the immutable official schema revision in `config/kev-schema.source.json`,
checks size, JSON and SHA-256, then installs it locally at
`backend/app/kev_schema.json`. It is Git-ignored. Existing different bytes are
preserved, never overwritten. An already matching file needs no network.

Downloads have a 20-second cooperative monotonic budget, including response
opening, checked before and after each body read (including EOF). Reads use
`read1(4096)` when available, otherwise `read(1)`. The socket inactivity timeout
remains 20 seconds: a blocking operation may overrun the budget until it returns
or times out. DNS, TLS, headers and repeated lower-level operations can add delay;
this is not an absolute wall-clock cap. Expiry installs nothing.

Expected SHA-256:
`0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7`.

The installed bytes match the historical P0.1/P1-A validation resource exactly.
The application and its collectors are unchanged. This bootstrap is an explicit
installation prerequisite, not source collection at runtime or an automatic
update. If download or verification fails, stop; do not disable TLS or replace
the pinned hash to make a check green.

Bootstrap tests are offline and isolated:

```powershell
.\.venv\Scripts\python.exe -I -m unittest discover -s tools -p "test*.py" -v
```
