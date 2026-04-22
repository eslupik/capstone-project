# YoDNS Project Progress

## Project Goal

This project uses **YoDNS** to study DNS infrastructure issues, especially:

- **stale glue records**
- **bad / stale / dangling CNAMEs**

Our goal is not just to get final DNS answers such as `A`, `NS`, or `CNAME`, since ordinary `dig` can already do that. Instead, we use YoDNS to analyze DNS dependency structure and the query process at scale.

---

## Project Pipeline Overview

Our workflow currently has two major stages:

1. **Data preprocessing**
   - start from the **Tranco Top 10K**
   - use **Subfinder** to discover subdomains
   - filter and prepare candidate domains for later DNS analysis

2. **YoDNS analysis**
   - run YoDNS on the prepared candidate set
   - study `Zonedata` and `Messages`
   - extract glue-related information and identify stale-glue candidates

---

## What We Have Done So Far

### 1. Built the data preprocessing stage

Before using YoDNS, we first worked on building a candidate dataset from the **Tranco Top 10K**.

Our preprocessing pipeline is:

- take root domains from the Tranco 10K dataset
- sample or iterate through selected root domains
- use **Subfinder** to discover subdomains for each root domain
- use DNS queries to filter discovered names
- save usable candidates into output files for later YoDNS analysis

The goal of this stage is to avoid running YoDNS blindly on arbitrary names and instead prepare a cleaner and more relevant set of domains and subdomains. Since stale DNS issues, such as dangling CNAMEs and other stale dependencies, are more likely to appear in deeper operational subdomains, relying only on Tranco would likely cause us to miss many relevant cases.

---

### 2. Implemented subdomain collection with Subfinder

We wrote preprocessing code to automate the following steps:

- read root domains from input CSV files
- sample a subset of root domains when needed
- run **Subfinder** on each root domain
- collect discovered subdomains
- test whether each discovered name has meaningful DNS results

We also designed the code to distinguish between:

- **accepted candidates**: domains with usable DNS results, but some of them are very intertsing though, where its dns status is NOERROR but returned result is null.
- **excluded candidates**: domains with unhelpful, empty, or invalid results


---


### 3. Learn how to use YoDNS

We carefully learn how to use YoDNS by reading its instruction and doing lots of experiment:

- How to use different command to produce betetr result
- How to change the configuration to align YoDNS closely with our goal

---

### 4. Studied the structure of YoDNS output

We examined the JSON output and separated the main parts:

- `Domains`: the original target domains
- `Zonedata`: the DNS zone / nameserver dependency tree reconstructed by YoDNS
- `Messages`: the raw query-response log for the actual DNS lookups performed during the run

We also confirmed that `Messages` is not ordered like a simple human-readable recursive trace. Instead, it behaves more like a log of concurrent tasks, which explains why the message order may appear to jump between different zones and names.

---

### 5. Learned how to read `Messages`

We analyzed multiple examples and learned how to interpret:

- `OriginalQuestion`
- `NameServerIP`
- `ResponseAddr`
- `Metadata`
- `Message.Answer`
- `Message.Authority`
- `Message.Additional`
- `Error`

We also learned how to distinguish:

- authoritative `NODATA` responses
- infrastructure lookups
- referral-style responses
- timeout and retry behavior
---

### 6. Designing the stale glue workflow

Our current stale glue workflow is:

1. Extract domains with `NS` records from YoDNS `Zonedata`.
2. For each such domain, search YoDNS `Messages` for referral responses whose `Additional` section contains `A/AAAA` records for the delegated nameservers.
3. Treat those `Additional` `A/AAAA` records as raw glue.
4. Compare the raw glue with the nameserver IPs stored in `Zonedata`.
5. Resolve each nameserver hostname separately to obtain its current `A/AAAA` records.
6. If the parent-side glue differs from the current nameserver address, mark it as a **stale-glue candidate**.

---

### 7. Investigated how to handle YoDNS binary output

We also clarified that large-scale YoDNS analysis should ideally process the **binary protobuf output directly**, instead of converting everything to JSON first, since we already tried directly processing json data, and it is too large.

At this stage, we need to:

- learned the difference between YoDNS binary output and JSON output
- learned how to use protobuf to process binary data

---

## Current Results/Artifacts

### 1. run_scan and filter_results makefile functions
- Both present in the `makefile` within the main repository folder, in addition to earlier experiments, the makefile allows you to:
     A) Run YoDNS scans on any example dataset and place results in any output folder, with options to run commands for scan validation and scan statistics to ensure scan success.
     B) Filter binary YoDNS output file messages for authoritatative A and AAAA records, along with all NS records.

### 2. Output files for scans of varying sizes
- Present in subfolder the `YoDNS_output` folder, all raw YoDNS scan output is accessible in zipped binary (in `Output_#_DN/data`, `output_#.pb.zst` format) and json format (zipped or unzipped depending on file size, in `Output_#_DN/json`, `output_#.json.zst` or `output_#.json` format).
- Validation and stat output files are located in their respective subfolders.
- Filtered extracted messages from raw binary output files are present in the `Output_#_DN/filtered` subfolder.
   - So far, we have managed to filter all messages containing:
      A) Authoritative A record (Ipv4) answers.
      B) Authoritative AAAA record (Ipv6) answers.
      C) All NS record answers.
 
---

## Next Steps

Our next tasks are:

1. Continue improving the preprocessing pipeline and candidate quality, we still need more data.
3. Learn how to process binary output
2. Write code to automatically extract candidate domains with `NS` records from `Zonedata`.
3. Parse `Messages` to identify referral responses and collect raw glue from `Additional` sections.
4. Extend the pipeline later for bad or dangling CNAME analysis.

---
