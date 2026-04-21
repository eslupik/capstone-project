import csv
import random
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

INPUT_FILE = "data_preprocess/root_domain.csv"
OUTPUT_ACCEPTED = "data_preprocess/subfinder_candidates_10k.csv"
OUTPUT_EXCLUDED = "data_preprocess/excluded_candidates_10k.csv"

NUM_ROOTS = 1800
MAX_ACCEPTED_PER_ROOT = 10
RANDOM_SEED = 13
MAX_CANDIDATES_PER_ROOT = 500
DIG_TIMEOUT = 20
SUBFINDER_TIMEOUT = 200
DIG_THREADS_PER_ROOT = 20
WAVE_SIZE = 60

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
            timeout=SUBFINDER_TIMEOUT,
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
    cmd = ["dig", name]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=DIG_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "dns_status": "TIMEOUT",
            "answer_type": "NONE",
            "resolved_value": "",
        }
    full_output = result.stdout
    dns_status = "OTHER"

    for line in full_output.splitlines():
        line = line.strip()
        if "status:" in line:
            part=line.split("status:")
            if len(part) >= 2:
                dns_status = part[1].split(",")[0].strip()
                break
    if dns_status != "NOERROR":
        return {
            "dns_status": dns_status,
            "answer_type": "NONE",
            "resolved_value": "",
        }
    in_answer_section = False
    answer_lines = []
    for line in full_output.splitlines():
        line = line.strip()
        if line.startswith(";; ANSWER SECTION:"):
            in_answer_section = True
            continue
        if in_answer_section:
            if line.startswith(";;") or not line:
                break
            answer_lines.append(line)

    if not answer_lines:
        return {
            "dns_status":dns_status,
            "answer_type": "NOANSWER",
            "resolved_value": "",
        }
    first_answer = answer_lines[0]
    parts = first_answer.split()
    if len(parts) < 5:
        return {
            "dns_status": dns_status,
            "answer_type": "UNKNOWN",
            "resolved_value": "",
        }
    rr_type = parts[3]
    resolved_value = parts[4].rstrip(".")
    return {
        "dns_status": dns_status,
        "answer_type": rr_type,
        "resolved_value": resolved_value,
    }

def resolve_candidate(rank, root_domain, candidate):
    dig_result = dig_name(candidate)
    return {
        "tranco_rank": rank,
        "root_domain": root_domain,
        "discovered_name": candidate,
        "dns_status": dig_result["dns_status"],
        "answer_type": dig_result["answer_type"],
        "resolved_value": dig_result["resolved_value"],
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

def write_rows(filepath: str, fieldnames, rows):
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


    
        



def main():
    fieldnames = [
        "tranco_rank",
        "root_domain",
        "discovered_name",
        "dns_status",
        "answer_type",
        "resolved_value",
    ]
    rows = load_root_domains(INPUT_FILE)
    sampled_roots = sample_root_domains(rows, NUM_ROOTS, RANDOM_SEED)

    all_accepted_rows = []
    all_excluded_rows = []

    for idx, item in enumerate(sampled_roots, start=1):
        rank = item["tranco_rank"]
        root_domain = item["root_domain"]
        candidates = run_subfinder(root_domain)
        accepted_count = 0
        accepted_rows_this_root = []
        excluded_rows_this_root = []
        for start in range(0, len(candidates), WAVE_SIZE):
            if accepted_count >= MAX_ACCEPTED_PER_ROOT:
                break
            batch = candidates[start:start + WAVE_SIZE]

            with ThreadPoolExecutor(max_workers=DIG_THREADS_PER_ROOT) as executor:
                futures = [
                    executor.submit(resolve_candidate, rank, root_domain, candidate)
                    for candidate in batch
                ]
                for future in as_completed(futures):
                    row = future.result()
                    dig_result = {
                        "dns_status": row["dns_status"],
                        "answer_type": row["answer_type"],
                        "resolved_value": row["resolved_value"],
                    }
                    if is_candidate_accepted(dig_result) and accepted_count < MAX_ACCEPTED_PER_ROOT:
                        accepted_rows_this_root.append(row)
                        accepted_count += 1
                    else:
                        excluded_rows_this_root.append(row)
        all_accepted_rows.extend(accepted_rows_this_root)
        all_excluded_rows.extend(excluded_rows_this_root)
        print(
            f"[{idx}/{len(sampled_roots)}] {root_domain} | "
            f"candidates={len(candidates)} | accepted={accepted_count}"
        )
    write_rows(OUTPUT_ACCEPTED, fieldnames, all_accepted_rows)
    write_rows(OUTPUT_EXCLUDED, fieldnames, all_excluded_rows)



if __name__ == "__main__":
    main()