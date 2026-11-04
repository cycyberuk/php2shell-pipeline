import json
import os
import time

# Try to import the enricher from your existing modules
try:
    from modules.vt_enricher import precision_for_iocs
except ImportError:
    print("Error: Could not import 'precision_for_iocs' from modules.vt_enricher.")
    print("Please ensure you are running this script from the root 'php2shell-pipeline' folder.")
    exit(1)

INPUT_FILE = os.path.join("data", "advisory_iocs.json")
OUTPUT_FILE = os.path.join("data", "d3_results.json")

def main():
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Could not find {INPUT_FILE}.")
        print("Please run extract_d3_sample.py first to generate this file.")
        return

    with open(INPUT_FILE, "r") as f:
        advisory_iocs = json.load(f)

    results = {}
    
    print("Starting VirusTotal D3 Analysis...")
    print("NOTE: Due to free-tier rate limits, this will take about 15 seconds per IOC.")
    print("-" * 50)

    for advisory, iocs in advisory_iocs.items():
        print(f"Querying {advisory} ({len(iocs)} IOCs)...")
        
        # Call your existing enricher function
        res = precision_for_iocs(iocs)
        
        results[advisory] = res
        print(f"--> Precision for {advisory}: {res['precision']:.2f} ({res['malicious']}/{res['total']} confirmed malicious)")
        print("-" * 50)

    # Save the results
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nAnalysis complete!")
    print(f"Results saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()