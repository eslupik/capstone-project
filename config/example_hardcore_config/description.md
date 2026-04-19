# Description

This directory contains an example configuration that can be used for heavy scanning.
For optimal results, the configuration needs to be adapted to the specific use case and hardware.

# Collected Data

- For all queries, DO (DNSSEC OK) bit is set
- It might get disabled if we receive a FORMERR response
- All records are requested from all NS over all IPs 
    - We may exclude some (or all) TLDs and request only from one NS (still over all IPs)
- We follow CNAMEs chains up to a depth of 15
- We request _dmarc and MX records but do not follow up on anything.
  - we also do not request IP of Mail Servers, even if they are in-bailiwick

## For every name

- Records requested for every name we encounter (zone name, name server name or original domain)

| RRType | Example    | Comment                     |
|--------|------------|-----------------------------|
| NS     | {name}     | At parent and authoritative |
| TXT    | {name}     |                             |

## For every zone

- Records requested for every zone we encounter

| RRType | Example       | Comment                                                                            |
|--------|---------------|------------------------------------------------------------------------------------|
| TXT    | _dmarc.{name} |                                                                                    |
| SOA    | {name}        |                                                                                    |
| MX     | {name}        |                                                                                    |
| TXT    | version.bind  | Chaos, we ask every ns of each zone                                                |
| DS     | {name}        | Has to be in parent zone, but we expect some entries mistakenly added to the child |
| DNSKEY | {name}        |                                                                                    |

- Additionally, we ask the NSes of the parent zone for these records (where name still is the zone name)

| RRType | Example       | Comment                                                      |
|--------|---------------|--------------------------------------------------------------|
| DS     | {name}        | Has to be asked to parent NSes                               |
| DNSKEY | {name}        | Should be in child zone, but is a potential misconfiguration |

## For every name server name

- Records requested for every name server name

| RRType | Example    |
|--------|------------|
| A      | {name}     |
| AAAA   | {name}     |

- Additionally, if glue is missing, we ask the NSes of the parent zone explicitly for these records.

## For the original name

| RRType | Example    |
|--------|------------|
| A      | www.{name} |
| AAAA   | www.{name} |
| A      | {name}     |
| AAAA   | {name}     |


# What is not included? Some examples

- www.{name} for name server or zones names
- A/AAAA for zone names (unless zone name == original name or name server name)
- IPs of Mail Server names
- ...