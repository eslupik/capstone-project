import csv
import random
import subprocess
from pathlib import Path

INPUT_FILE = "data_preprocess/root_domain.csv"
OUTPUT_ACCEPTED = "data_preprocess/subfinder_candidates.csv"
OUTPUT_EXCLUDED = "data_preprocess/excluded_candidates.csv"

NUM_ROOTS = 1000
MAX_ACCEPTED_PER_ROOT = 20
RANDOM_SEED = 67
MAX_CANDIDATES_PER_ROOT = 300

def load_root_domains(filepath: str):
    rows = []
    with open(filepath, "r", newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 2:
                continue
            rank = row[0].strip()
            domain = row[1].strip().lower().rstrip(".")
            if not rank or not domain:
                continue
            try:
                rank = int(rank)
            except ValueError:
                continue
            rows.append({
                "tranco_rank": rank,
                "root_domain": domain,
            })
    return rows

def sample_root_domains(rows, k: int, seed: int):
    random.seed(seed)
    if k >= len(rows):
        return rows
    return random.sample(rows, k)

def run_subfinder(domain: str):
    cmd = ["subfinder", "-silent", "-d", domain]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=200,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return []

    if result.returncode != 0:
        return []
    
    names = []
    seen = set()
    for line in result.stdout.splitlines():
        name = line.strip().lower().rstrip(".")
        if not name:
            continue
        if name in seen:
            continue
        seen.add(name)
        names.append(name)

    random.shuffle(names)
    return names[:MAX_CANDIDATES_PER_ROOT]

def dig_name(name: str):
    """
    return dict:
    {
        "dns_status": ...,
        "answer_type": ...,
        "resolved_value": ...
    }
    """
    cmd_short=["dig", "+short", name]
    try:
        result = subprocess.run(
            cmd_short,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "dns_status": "TIMEOUT",
            "answer_type": "NONE",
            "resolved_value": "",
        }
    cmd_complete = ["dig", name]
    try:
        status_result = subprocess.run(
            cmd_complete,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        full_output = status_result.stdout
    except subprocess.TimeoutExpired:
        return {
            "dns_status": "TIMEOUT",
            "answer_type": "NONE",
            "resolved_value": "",
        }
    dns_status = "OTHER"
    for line in full_output.splitlines():
        line = line.strip()
        if "status:" in line:
            part=line.split("status:")
            if len(part) >= 2:
                dns_status = part[1].split(",")[0].strip()
                break
    short_lines = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            short_lines.append(line)

    if dns_status != "NOERROR":
        return {
            "dns_status": dns_status,
            "answer_type": "NONE",
            "resolved_value": "",
        }
    if not short_lines:
        return {
            "dns_status": dns_status,
            "answer_type": "NOANSWER",
            "resolved_value": "",
        }
    first = short_lines[0]
    if first.endswith("."):
        answer_type = "CNAME"
    elif ":" in first:
        answer_type = "AAAA"
    else:
        answer_type = "A"
    
    return{
        "dns_status": dns_status,
        "answer_type": answer_type,
        "resolved_value": first,
    }

def is_candidate_accepted(dig_result: dict):
    result = False
    if dig_result["dns_status"]=="NOERROR":
        if dig_result["answer_type"] in {"A", "AAAA", "CNAME"}:
            result = True
    return result

def write_csv_header_if_needed(filepath: str, fieldnames):
    file_exists = Path(filepath).exists()
    if not file_exists:
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()

def append_row(filepath: str, fieldnames, row: dict):
    with open(filepath, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writerow(row)
    

    

    
        



def main():
    accepted = [
        "tranco_rank",
        "root_domain",
        "discovered_name",
        "dns_status",
        "answer_type",
        "resolved_value",
    ]
    excluded = [
        "tranco_rank",
        "root_domain",
        "discovered_name",
        "dns_status",
        "answer_type",
        "resolved_value",
    ]
    write_csv_header_if_needed(OUTPUT_ACCEPTED, accepted)
    write_csv_header_if_needed(OUTPUT_EXCLUDED, excluded)


    rows = load_root_domains(INPUT_FILE)
    sampled_roots = sample_root_domains(rows, NUM_ROOTS, RANDOM_SEED)

    for idx, item in enumerate(sampled_roots, start=1):
        rank = item["tranco_rank"]
        root_domain = item["root_domain"]
        candidates = run_subfinder(root_domain)
        accepted_count = 0
        for candidate in candidates:
            if accepted_count >= MAX_ACCEPTED_PER_ROOT:
                break
            dig_result = dig_name(candidate)
            base_row = {
                "tranco_rank": rank,
                "root_domain": root_domain,
                "discovered_name": candidate,
                "dns_status": dig_result["dns_status"],
                "answer_type": dig_result["answer_type"],
                "resolved_value": dig_result["resolved_value"],
            }
            if is_candidate_accepted(dig_result):
                append_row(OUTPUT_ACCEPTED, accepted, base_row)
                accepted_count += 1
            else:
                append_row(OUTPUT_EXCLUDED, excluded, base_row)
        print(f"[{idx}/{len(sampled_roots)}] {root_domain} | candidates={len(candidates)} | accepted={accepted_count}")
if __name__ == "__main__":
    main()