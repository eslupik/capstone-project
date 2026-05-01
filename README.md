# Capstone Project: Utilizing YoDNS to Identify Dangling Records

## 1. Project Goal

This project uses **YoDNS**, a unique measurement toolchain, to study and identify the prevalence of DNS infrastructure issues, specifically:

- **Stale glue A and AAAA records**
- **Stale / dangling CNAME records**

Our goal is not just to measure final DNS answers for records such as `A`, `NS`, or `CNAME` records, since ordinary `dig` can already do that. However, typical resolvers utilize optimization strategies such as caching to reduce query load, and as such may not accurately capture the reality of DNS structure by not engaging in full DNS tree traversal [1]. Instead, we use YoDNS, designed by Steurer et al. [2025], to analyze DNS dependency structure and the query process at scale.

---

## 2. Project Pipeline

### Structural Overview:

Our methodology has three major stages:

1. **Data preprocessing**: Preparing an input database for efficient scanning by YoDNS
   - Start from the **Tranco Top 10K** list of domains.
   - Use **Subfinder** to discover subdomains from this list.
   - Filter and prepare candidate domains for later DNS analysis.

2. **YoDNS scanning**
   - Run a YoDNS scan on the prepared candidate set.
   - Store output efficiently.
   - Study the components of the output (in json format for visualization), namely its `Zonedata` and `Messages`.
  
3. **Dangling record extraction and analysis**
   - Extract glue-related information:
        - All NS response glue records containing IP addresses (`A`: `IPv4`, and `AAAA`: `IPv6`)
        - All authoritative `A` and `AAAA` records for those domains
   - Identify stale-glue candidates by comparing these records and quantify their prevalence/how frequently YoDNS encountered them.
   - Extract CNAME-related information and identify candidates for dangling CNAME records

---

## 3. Our Approach / What we Accomplished
_...and learning along the way_

### 3.1. We Built the Data Preprocessing Stage
_Task leader: Chenyun_

Before using YoDNS, we first worked on building a candidate dataset from the **Tranco Top 10K** to be used as an input `.csv` file for the scan.

**Our preprocessing pipeline is:**
   1. Take root domains from the Tranco 10K dataset
   2. Sample or iterate through selected root domains
   3. Use **Subfinder** to discover subdomains for each root domain
   4. Use DNS queries to filter discovered names
   5. Save usable candidates into output files for later YoDNS analysis

_The goal of this stage was to avoid running YoDNS blindly on arbitrary names and instead prepare a cleaner and more relevant set of domains and subdomains. Since stale DNS issues, such as dangling CNAMEs and other stale dependencies, are more likely to appear in deeper operational subdomains, relying solely on Tranco would likely cause us to miss many relevant cases._

---

### 3.2. We Implemented a Subdomain Collection with Subfinder
_Task leader: Chenyun_

**We wrote preprocessing code to automate the following steps:**
   1. Read root domains from input CSV files
   2. Sample a subset of root domains when needed
   3. Run **Subfinder** on each root domain
   4. Collect discovered subdomains
   5. Test whether each discovered name has meaningful DNS results

We also designed the code to distinguish between:

- **Accepted candidates**: Domains with usable DNS results.
   - Some of them are very interesting though, for example where a candidate's dns resolution status is `NOERROR` but  the returned result is `null`.
- **Excluded candidates**: Domains with unhelpful, empty, or invalid results.

---

### 3.3. We Learned How to Use YoDNS
_Task leader: Emma_

We carefully learned how to use the YoDNS measurement tool by analyzing its instructions, researching elements of its complex codebase, and doing lots of small-scale experiments:
   1. We began by reading all information provided in the [YoDNS GitHub repository](https://github.com/DNS-MSMT-INET/yodns) and descriptions of Struer et al. [2025]'s [published dataset](https://edmond.mpg.de/dataset.xhtml?persistentId=doi:10.17617/3.UBPZXP).
   2.  The GitHub repository, paper, along with other source materials on stale glue records and dangling CNAMEs were put into a NotebookLM notebook, which was used to help describe different functionalities of the codebase to help plan out small-scale experiments.
   3.  After installation of Go and YoDNS on two cs.colgate servers (Caspian and Malayan), an example makefile to run a simple resolution of one domain was identified and run, producing sample output in `.json` format.
   4.  We learned how to mimic 



- How to use different command to produce betetr result
- How to change the configuration to align YoDNS closely with our goal

---

### 3.4. Studied the structure of YoDNS output

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
## 4. Exact Procedure Replication
_Instructions for precisely replicating a YoDNS experiment to identify stale glue records and dangling CNAMEs_


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
