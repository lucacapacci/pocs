import json
import csv
import os
import re
from collections import defaultdict

def process_data():
    # 1. Setup Directories
    for folder in ['data_years', 'data_single']:
        if not os.path.exists(folder):
            os.makedirs(folder)

    # Dictionary structure: cve_map["CVE-XXXX-XXXX"]["source_name"] = [items]
    cve_map = defaultdict(lambda: {"metasploit": [], "exploitdb": [], "nuclei": []})

    # 2. Parse Metasploit JSON
    if os.path.exists('msf_metadata.json'):
        with open('msf_metadata.json', 'r') as f:
            msf_data = json.load(f)
            for mod_path, info in msf_data.items():
                if 'references' in info:
                    for ref in info['references']:
                        if ref.startswith('CVE-'):
                            cve_map[ref]["metasploit"].append({
                                "path": mod_path,
                                "name": info.get("name"),
                                "description": info.get("description")
                            })

    # 3. Parse Exploit-DB CSV
    if os.path.exists('edb_exploits.csv'):
        with open('edb_exploits.csv', 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                codes = row.get('codes', '')
                found_cves = re.findall(r'CVE-\d{4}-\d{3,10}', codes)
                for cve in found_cves:
                    cve_map[cve]["exploitdb"].append(row)

    # 4. Parse Nuclei JSONL
    if os.path.exists('nuclei_cves.json'):
        with open('nuclei_cves.json', 'r') as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    cve_id = entry.get("ID")
                    if cve_id and cve_id.startswith("CVE-"):
                        cve_map[cve_id]["nuclei"].append({
                            "info": entry.get("Info"),
                            "file_path": entry.get("file_path")
                        })

    # 5. Generate Organized Files
    years_data = defaultdict(dict)

    for cve, data in cve_map.items():
        parts = cve.split('-')
        if len(parts) < 3: continue
        year = parts[1]
        
        # Save individual CVE JSON
        year_dir = os.path.join('data_single', year)
        os.makedirs(year_dir, exist_ok=True)
        
        with open(os.path.join(year_dir, f"{cve}.json"), 'w') as f:
            json.dump({cve: data}, f, indent=2)
        
        # Add to yearly aggregation
        years_data[year][cve] = data

    # Save aggregated Year JSONs
    for year, data in years_data.items():
        with open(os.path.join('data_years', f"{year}.json"), 'w') as f:
            json.dump(data, f, indent=2)

if __name__ == "__main__":
    process_data()
