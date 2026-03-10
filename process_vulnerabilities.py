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

    cve_map = defaultdict(list)

    # 2. Parse Metasploit JSON
    if os.path.exists('msf_metadata.json'):
        with open('msf_metadata.json', 'r') as f:
            msf_data = json.load(f)
            for mod_path, info in msf_data.items():
                if 'references' in info:
                    for ref in info['references']:
                        if ref.startswith('CVE-'):
                            file_path = f'https://raw.githubusercontent.com/rapid7/metasploit-framework/refs/heads/master/modules{info.get("path")}'
                            cve_map[ref].append({
                                "source": "metasploit",
                                "file": file_path,
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
                    # Add Source tag to the CSV row data
                    row["source"] = "exploitdb"
                    row["file"] = f"https://gitlab.com/exploit-database/exploitdb/-/raw/main/{row['file']}"
                    cve_map[cve].append(row)

    # 4. Parse Nuclei JSONL
    if os.path.exists('nuclei_cves.json'):
        with open('nuclei_cves.json', 'r') as f:
            for line in f:
                if line.strip():
                    entry = json.loads(line)
                    cve_id = entry.get("ID")
                    if cve_id and cve_id.startswith("CVE-"):
                        # Inject Source into the 'Info' block as per your example
                        info_block = entry.get("Info", {})
                        info_block["source"] = "nuclei"
                        
                        cve_map[cve_id].append({
                            "info": info_block,
                            "file": f'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/refs/heads/main/{entry.get("file_path")}'
                        })

    # 5. Generate Organized Files
    years_data = defaultdict(dict)

    for cve, data_list in cve_map.items():
        parts = cve.split('-')
        if len(parts) < 3: continue
        year = parts[1]
        
        # Save individual CVE JSON
        year_dir = os.path.join('data_single', year)
        os.makedirs(year_dir, exist_ok=True)
        
        with open(os.path.join(year_dir, f"{cve}.json"), 'w') as f:
            json.dump({cve: data_list}, f, indent=2)
        
        # Add to yearly aggregation
        years_data[year][cve] = data_list

    # Save aggregated Year JSONs
    for year, data in years_data.items():
        with open(os.path.join('data_years', f"{year}.json"), 'w') as f:
            json.dump(data, f, indent=2)

if __name__ == "__main__":
    process_data()
