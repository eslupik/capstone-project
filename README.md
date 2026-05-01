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
   4.  We learned how to mimic the format of the makefile/write our own makefile to conduct configuration experiments on sample input DN lists and eventually the current largest `subfinder_candidates.csv` input list.
      - We created a capstone_test target to test variations of configuration changes to our modified `runconfig_capstone.json5` file (located in the `capstone-project/config/capstone_config` directory), which changed parameters of the example `runconfig.json5` file meant for large-scale scans (a copy is located in the `capstone-project/config/example_hardcore_config` directory) to match the description of parameters from the Steurer et al. [2025] paper, such as:
          -  Changing max `CNAM`E depth to 64
          -  Changing `MX`-followup to `true` to trace down `MX` records
          -  Ensuring all `NS` IPs are queried
          -  Changing input/output file directories
          -  Ensuring output files are in `.pb.zst` format to reduce space
   5.  Eventually, we created an efficient configuration for a large-scale scan that could be run using the makefile, and produced output in both `.pb.zst` and `.json` format using the `convertFormat` command to visually inspect the output format.     

---

### 3.4. Studied the Structure of YoDNS output
_Task leader: Emma_

We examined the `.json` output and identified the main components/objects containing the response:

- `Domains`: A list of the original target domains scanned
- `Zonedata`: the full DNS zone / nameserver dependency tree reconstructed by YoDNS
- `Messages`: the raw query-response log for the actual DNS lookups performed during the run, detailing all query, answer, and metadata information
   - _We also confirmed that `Messages` is not ordered like a simple human-readable recursive trace. Instead, it behaves more like a log of concurrent tasks, which explains why the message order may appear to jump between different zones and names._

---

### 3.5. Learned how to read `Messages`
_Task leader: Emma_

As the majority of information is contained in the `Messages` objects, including authoritative and glue records, we analyzed multiple examples and learned how to interpret its subsections:

- `OriginalQuestion`
- `NameServerIP`
- `ResponseAddr`
- `Metadata`
- `Message`
   - `RCode`
   - `IsAuthoritative`
   - `Question`
   - `Answer`
   - `Authority`
   - `Additional`
- `Error`
We identified that, in order to identify dangling records, we needed to get access to information within the `Message` itself:
- For example, to identify stale glue records, we wanted to find messages with `RCode`s of 1 (`A`) and 28 (`AAAA`) from authoritative name servers to compare all glue records for those domains to so that we may determine which are stale. However, how do we filter out all of the information less useful for our aims? Additionally, these `.json` files are HUGE; if we parsed the entirety of each output file via just looping in a python script, we wouldn't be able to scale our method up to a significantly larger number of input domains (10k or 1M). 

---

### 3.6. Extracting Relevant `Messages.Message` Components to ID Stale Glue Records

#### 3.6.a. Extracting messages and utilizing provided YoDNS code
As Steurer et al. [2025] scanned 812M domains over the course of 40 days, we positied that the large `yodns`codebase cloned from the GitHub repository would contain some built-in (efficient) methods for reading our binary output messages encoded using `protobuf` and filtering that output effectively. As such, we began to explore the provided yodns commands and their underlying code/data structures.

There are 20 commands listed on the `yodns/yodns --help` page, but most are very vaguely described, and, as they are written in Golang, they took significant research and experimentation to dissect. Commands of interest for our purposes included:
1. `scan`: We were already using it to conduct the YoDNS test scans
2. `convertFormat`: We had already used it to examine `.json` output format
3. `validate`: The sample makefile uses it, but its exact function was uncertain
4. `stats`: Seemed to provide some sort of statistics/metrics in regards to the scan's success
5. `bucketize`: Seemed to organize output files into zone "buckets" for file optimization and organization of future analysis
6. `mergeFiles`: Seemed to organize scan output files of various sizes to a standard size
7. `extractMessages` and `extractMessagesBinary`: These seemed like the most likely candidates for filtering for specfic record types, and as such were focused on.

**Commands we use:**
_We managed to run/ran these commands in our makefile_
1. `scan`
2. `convertFormat` (optional command we provide for viewable `.json` output files that are stored in a folder titled `YoDNS_output/Output_<#>_DN/json`)
3. `validate` _(optional command that allows us to check if YoDNS worked and see any errors that occured during resolution)_
4. `stats` _(optional command that allows us to see every target DN resolved in a specific output file, ending with a total number of DNs resolved, total messages and optional tagged DN counts)_
5. `extractMessages`: This command allowed us to filter YoDNS `json` output messages for specific `RCode` types and from only authoritative servers, which was our first step towards filtering the YoDNS output data for our specific goals.

_However, we did not feel like `extractMessages` was adequate, as large quantities of data we had no intention of using (Domain lists, Zonedata, and Message metadata) was still "clogging up" these large `.json` extracted output files. More importantly, there was no flag to specify only glue records; we could only extract every NS query message exchange. As a result, we looked into the underlying structure of the Go code for this command (located in `yodns/yodns/cmd/extractMessages.go` and a variety of other folders)..._

#### 3.6.b. Learn about the YoDNS struct system and using it to create our own modified message filtering command
Through tracing the `extractMessages.go` and `filters.go` files, we realized that numerous packages referencing files in other subfolders/directories, largely within the `yodns/resolver` directory, were imported and outline a complex system of structs that creates a somewhat object-oriented representation of the YoDNS scan components. The most important structs we identified for our purpose of filtering messages are mapped as follows:

   _*Note: not all the instance variables of each struct are provided, only the ones useful to our project_

```mermaid
graph TD;
A{package <b>model</b>} --> B([type <b>MessageExchange</b> <br> struct]);
B ----> C([<b>OriginalQuestion</b>: <br><i>model.Question struct]);
A ----> C;
B ----> D[ResponseAddr: <br><i>string];
B ----> E([<b>NameServerIP</b>:<br> <i>netip.Addr struct]);
B ----> F([<b>Metadata</b>: <br> <i>model.Metadata struct]);
A ----> F;
B ----> G([<b>Message</b>:<br> <i>*model.Message struct]);
A ----> G;
B ----> H([<b>Error</b>: <br> <i>model.SendError struct]);
A ----> H;
I{package <b>netip</b>} ----> E;
G ----> J[Id: <br> <i>uint16]
G ----> K[RCode: <br> <i>int]
G ----> L[Opcode: <br> <i>int]
G ----> M[IsAuthoritative: <br> <i>bool]
G ----> N(["`<b>Question</b>: <br><i> []ResourceRecord struct`"]);
G ----> O(["`<b>Answer</b>: <br> <i> []ResourceRecord struct`"]);
G ----> P(["`<b>Authority</b>: <br> <i>[]ResourceRecord struct`"]);
G ----> Q(["`<b>Additional</b>: <br> <i>[]ResourceRecord struct`"]);
G <----> R([type <b>*dns.Msg</b> <br> struct]);
S([type <b>ResourceRecord</b> <br> struct]) ----> N;
S ----> O;
S ----> P;
S ----> Q;
A ----> S;
T([type <b>dns.RR</b> <br> struct]) <----> S;
U{package <b>dns</b>} ----> T;
U ----> R;
S ----> V[Name: <br> <i>string];
S ----> W[Type: <br> <i>uint16];
S ----> X[Class: <br> <i>uint16];
S ----> Y[Value: <br> <i>string];
S ----> Z[TTL: <br> <i>uint32];
```
Utilization of this struct/package hierarchy enabled us the trace the filtering `msgLoop` in `extractMessages.go`, create additional glue filters in `filters.go`, and modify a `ResourceRecord` struct helper function (along with a few other small tweaks) for the purpose of creating a revised filtering command (`extractMessagesCapstone`) that is currently used in the makefile within the `filter_results` target to:
   - If the `--glue-only` flag is set to `true`, only the glue records (with flags to specify a DN, record type, or class of the glue record) will be extracted to a `.json.zst` file. We use this to extract `A` and `AAAA` glue records from NS queries. Relevant information (`File`: filename, `RespondingNS`: NS providing the glue records, `ProvidedWithAnswerTo`: the NS the glue record(s) are for, `GlueRecords`: the glue records) is presented in the following format:

```
{
   "File": "YoDNS_output/Output_1_DN/data/output_00000000_cda549f0.pb.zst",
   "RespondingNS": [
         "a2.info.afilias-nst.info."
   ],
   "ProvidedWithAnswerTo": "info.afilias-nst.org.",
   "GlueRecords": [
      {
               "Name": "b0.info.afilias-nst.org.",
               "Type": 1,
               "Class": 1,
               "TTL": 86400,
               "Value": "199.254.48.1"
      }
   ]
}
```
   - If glue records are not being searched for (such as when we extract `A` and `AAAA` authoritative records), only this information (`File`, `RespondingNS`, `Answer`) is provided in the following format:

```
{
   "File": "YoDNS_output/Output_1_DN/data/output_00000000_cda549f0.pb.zst",
   "RespondingNS": [
         "b0.info.afilias-nst.info."
   ],
   "Answer": [
      {
               "Name": "b0.info.afilias-nst.org.",
               "Type": 1,
               "Class": 1,
               "TTL": 86400,
               "Value": "199.254.48.1"
      }
   ]
}
```





---



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
