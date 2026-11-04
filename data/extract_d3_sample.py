import json

# Load the huge verified dataset you downloaded
with open("php2shell_iocs.json", "r") as f:
    data = json.load(f)

# Filter for high-confidence IPs and Domains (ignore URLs and hashes for this test)
# We want 15 IPs and 15 Domains to make a balanced sample
ips = [item["indicator"] for item in data if item["type"] == "ip" and item["confidence"] == "high"][:15]
domains = [item["indicator"] for item in data if item["type"] == "domain" and item["confidence"] == "high"][:15]

# Create the format your pipeline expects
d3_sample = {
    "PHP2Shell_Verified_IPs": ips,
    "PHP2Shell_Verified_Domains": domains
}

# Save it to the file your pipeline uses
with open("advisory_iocs.json", "w") as f:
    json.dump(d3_sample, f, indent=2)

print(f"Extracted {len(ips)} IPs and {len(domains)} domains for D3 analysis.")