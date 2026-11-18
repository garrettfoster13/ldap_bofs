# ldap_bofs

BOFs I needed when proxying sucked or wasn't viable

## Installation

Requirements

```
uv
```

Install uv and the dependencies to use the helper python scripts in each directory

```
git clone https://github.com/garrettfoster13/ldap_bofs/
cd project-name
uv sync
```

## Cobalt Strike

Build the x64 objects and load `ldap_bofs.cna` from the repository root. The script registers:

```text
ldap_bofthedog <domain-or-dc> <target-dn> <security-descriptor-hex>
ldap_bofwhisker <domain-or-dc> <target-dn> <key-credential>
```

Distinguished names containing spaces must be quoted. Both commands use the current Beacon identity for LDAP negotiate authentication and modify the specified directory object; validate the target DN before execution.


## Code stolen from:

https://github.com/ndur0/bofs/tree/63eeb25977c6c0f0dc2749f56fd24d4388a43123/home_mod

https://github.com/fortra/impacket/blob/master/examples/rbcd.py

https://github.com/ShutdownRepo/pywhisker
