import pandas as pd
import sys
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------
# Classification functions
# ---------------------------------------------------------

# Determine which email provider a domain uses (Microsoft, Google, Local, etc.)
def classify_email_provider(mx: str, spf: str) -> str:
    mx = str(mx) if pd.notna(mx) else ""
    spf = str(spf) if pd.notna(spf) else ""
    text = f"{mx} {spf}".lower()

    if "protection.outlook.com" in text or "outlook.com" in text or "office365" in text or "microsoft" in text:
        return "Microsoft 365"

    if "aspmx.l.google.com" in text or "googlemail.com" in text or "spf.google.com" in text:
        return "Google Workspace"

    if ".is" in text:
        return "Local (.is)"

    if not mx and not spf:
        return "Unknown"

    return "Other"


# Categorize DNS provider (Cloudflare, AWS, Local Icelandic, etc.)
def classify_dns_category(ns: str) -> str:
    ns = str(ns) if pd.notna(ns) else ""
    ns_l = ns.lower()

    if not ns_l:
        return "Unknown"

    if "cloudflare.com" in ns_l:
        return "Cloudflare"

    if "awsdns" in ns_l:
        return "AWS"

    if "azure-dns" in ns_l or "microsoft" in ns_l:
        return "Azure"

    if any(part.strip().endswith(".is") for part in ns_l.split(";")):
        return "Local (.is)"

    return "Other"

# Categorize where the website is actually hosted based on ASN/organization data
def classify_hosting_category(asn: str, org: str) -> str:
    asn = str(asn) if pd.notna(asn) else ""
    org = str(org) if pd.notna(org) else ""
    asn_l, org_l = asn.lower(), org.lower()

    if not asn_l and not org_l:
        return "Unknown"

    # Local Icelandic hosting
    icelandic_markers = ["1984", "siminn", "simnet", "hysing", "rhnet", ".is"]
    if any(m in asn_l or m in org_l for m in icelandic_markers):
        return "Local (.is)"

    # US / big providers – simplified labels
    if "amazon" in asn_l or "amazon" in org_l or "aws" in org_l:
        return "AWS"

    if "msft" in asn_l or "microsoft" in org_l:
        return "Azure"

    if "google" in asn_l or "google" in org_l:
        return "Google"

    if "cloudflare" in asn_l or "cloudflare" in org_l:
        return "Cloudflare"

    if "vercel" in asn_l or "vercel" in org_l:
        return "Vercel"

    if "digitalocean" in asn_l or "digitalocean" in org_l:
        return "DigitalOcean"

    return "Other"


# ---------------------------------------------------------
# Run classification
# ---------------------------------------------------------

# Get input file path
data_dir = Path(__file__).parent.parent / "data"

if len(sys.argv) > 1:
    # Use file path provided as command line argument
    input_path = Path(sys.argv[1])
else:
    # Find the most recent timestamped dns scan file in data folder
    dns_files = sorted(data_dir.glob("dns_raw-*.csv"), reverse=True)
    if not dns_files:
        print("Error: No dns_raw-*.csv files found in data folder.")
        print("Run dns_lookup.py first to generate DNS data.")
        sys.exit(1)
    input_path = dns_files[0]
    print(f"Using most recent DNS data file: {input_path.name}")

# Read the raw DNS data
df = pd.read_csv(input_path)

# Replace any missing values with empty strings
df["mx"] = df["mx"].fillna("")
df["ns"] = df["ns"].fillna("")
df["spf"] = df["spf"].fillna("")
df["hosting_asn"] = df["hosting_asn"].fillna("")
df["hosting_org"] = df["hosting_org"].fillna("")
df["final_mx"] = df["final_mx"].fillna("")
df["final_ns"] = df["final_ns"].fillna("")
df["final_spf"] = df["final_spf"].fillna("")
df["final_hosting_asn"] = df["final_hosting_asn"].fillna("")
df["final_hosting_org"] = df["final_hosting_org"].fillna("")
df["final_domain"] = df["final_domain"].fillna("")
df["redirect_count"] = df["redirect_count"].fillna(0)

# Apply classifications
print("\nClassifying DNS data...")
df["email_provider"] = df.apply(
    lambda row: classify_email_provider(row["mx"], row["spf"]),
    axis=1,
)
df["dns_category"] = df["ns"].apply(classify_dns_category)
df["hosting_category"] = df.apply(
    lambda row: classify_hosting_category(row["hosting_asn"], row["hosting_org"]),
    axis=1,
)

# Classify final domain data (if redirect occurred)
df["final_email_provider"] = df.apply(
    lambda row: classify_email_provider(row["final_mx"], row["final_spf"]) if row.get("final_domain") and str(row.get("final_domain")).strip() else "",
    axis=1,
)
df["final_dns_category"] = df.apply(
    lambda row: classify_dns_category(row["final_ns"]) if row.get("final_domain") and str(row.get("final_domain")).strip() else "",
    axis=1,
)
df["final_hosting_category"] = df.apply(
    lambda row: classify_hosting_category(row["final_hosting_asn"], row["final_hosting_org"]) if row.get("final_domain") and str(row.get("final_domain")).strip() else "",
    axis=1,
)

# Add redirect status classification
def classify_redirect_status(row):
    redirect_count = row.get("redirect_count", 0)
    domain = str(row.get("domain", ""))
    final_domain = str(row.get("final_domain", ""))
    
    if redirect_count == 0 or not final_domain:
        return "No redirect"
    elif domain == final_domain:
        return "Internal redirect"
    elif final_domain.endswith(".is") and domain.endswith(".is"):
        return "Internal .is redirect"
    elif domain.endswith(".is") and not final_domain.endswith(".is"):
        return "Cross-border redirect"
    else:
        return "External redirect"

df["redirect_status"] = df.apply(classify_redirect_status, axis=1)

# Display summary of results in the console
print("\nClassification Summary:")
print(df[[
    "domain",
    "email_provider", "dns_category", "hosting_category",
    "redirect_status"
]].head(20))

print("\nRedirects Summary:")
redirects = df[df["redirect_count"] > 0]
if len(redirects) > 0:
    print(f"Total redirects: {len(redirects)}")
    print(redirects[[
        "domain", "final_domain", "redirect_status",
        "hosting_category", "final_hosting_category"
    ]].head(10))
else:
    print("No redirects found.")

# Save classified results to output folder with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_path = Path(__file__).parent.parent / "output" / f"dns_full_results-{timestamp}.csv"
df.to_csv(output_path, index=False)
print(f"\nSaved classified results to {output_path}")
