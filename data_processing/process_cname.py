from pathlib import Path
import json
import concurrent.futures
import threading
import subprocess
import csv
import argparse

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--cname-dir", required=True)
    p.add_argument("--output-dir", required=True)
    return p.parse_args()

def save_results(results: dict, endpoints: dict, cname_chain: dict, cname_misconfig: dict,output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    all_results_path = output_dir / "all_results.csv"
    with open(all_results_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["start", "endpoint", "dig_status"])
        for start, status in results.items():
            endpoint = endpoints.get(start, "")
            writer.writerow([start, endpoint, status])
    dangling_statuses = {"NXDOMAIN", "SERVFAIL", "TIMEOUT", "UNKNOWN"}
    dangling_path = output_dir / "dangling_cname.csv"
    with open(dangling_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["start", "endpoint", "dig_status"])
        for start, status in results.items():
            if status in dangling_statuses:
                endpoint = endpoints.get(start, "")
                writer.writerow([start, endpoint, status])
    misconfig_path = output_dir / "misconfig.csv"
    with open(misconfig_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "conflicting_values"])
        for domain, values in cname_misconfig.items():
            writer.writerow([domain, " | ".join(sorted(values))])

    print(f"Misconfig cases: {misconfig_path}")
    print(f"Total misconfig: {len(cname_misconfig)}")

    print(f"All results: {all_results_path}")
    print(f"Dangling cases: {dangling_path}")
    print(f"Total: {len(results)} | Dangling: {sum(1 for s in results.values() if s in dangling_statuses)}")

def dig_endpoint(domain: str, start: str, results: dict, lock: threading.Lock):
    cmd_complete = ["dig", domain]
    try:
        full_output = subprocess.run(
            cmd_complete,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except subprocess.TimeoutExpired:
        with lock:
            results[start] = "TIMEOUT"
        print(f"Timeout while digging {domain}")
        return
    dns_status = "UNKNOWN"
    response = full_output.stdout.strip()
    for line in response.splitlines():
        line = line.strip()
        if "status:" in line:
            part=line.split("status:")
            if len(part) >= 2:
                dns_status = part[1].split(",")[0].strip()
                break
    with lock:
        results[start] = dns_status


def follow_chain(cname_chain: dict)-> dict:
    all_values = set(cname_chain.values())
    all_keys = set(cname_chain.keys())
    start_points = all_keys - all_values
    endpoints = {}
    for start in start_points:
        current = start
        visited = set()
        endpoint = follow_chain_recursive(cname_chain, current, visited)
        endpoints[current] = endpoint
    return endpoints


def follow_chain_recursive(cname_chain: dict, start: str, visited: set) -> str:
    current = start
    if current in visited:
        print(f"Cycle detected in CNAME chain at {current}")
        return current
    visited.add(current)
    if current not in cname_chain:
        return current
    return follow_chain_recursive(cname_chain, cname_chain[current], visited)

def process_file(file, cname_chain, cname_misconfig, lock):
    with open(file,"r",encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if not line:
                    continue
                message = json.loads(line)
                with lock:
                    handle_line(message,cname_chain,cname_misconfig)


def handle_line(line: dict, cname_chain: dict, cname_misconfig: dict):
    try:
        answer_list = line["Answer"]
        for answer in answer_list:
            if answer.get("Type") != 5:
                continue
            name = answer["Name"].lower().strip()
            value = answer["Value"].lower().strip()
            if name not in cname_chain:
                cname_chain[name] = value
            elif cname_chain[name] != value:
                if name not in cname_misconfig:
                    cname_misconfig[name] = set()
                cname_misconfig[name].add(cname_chain[name])
                cname_misconfig[name].add(value)
                print(f"Misconfiguration found for {name}: {cname_chain[name]} vs {value}")
    except KeyError:
        pass


def main():
    args = parse_args()
    directory = Path(args.cname_dir)
    output_dir = Path(args.output_dir)

    cname_misconfig={}
    cname_chain = {}
    results = {}
    lock = threading.Lock()

    files = list(directory.glob("*.json"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = []
        for f in files:
            future = executor.submit(process_file, f, cname_chain, cname_misconfig, lock)
            futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            future.result()
        endpoints = follow_chain(cname_chain)
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for start, endpoint in endpoints.items():
            future =executor.submit(dig_endpoint, endpoint, start, results, lock)
            futures.append(future)
        for future in concurrent.futures.as_completed(futures):
            future.result()
    save_results(results, endpoints, cname_chain, cname_misconfig, output_dir)


if __name__ == "__main__":
    main()