import pandas as pd
import sys
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------
# Classification functions
# ---------------------------------------------------------

# Determine which email provider a domain uses (Microsoft, Google, Local, etc.)
def classify_email_provider(mx: str, spf: str, mx_org: str = "", mx_country: str = "", spf_org: str = "", spf_country: str = "") -> str:
    mx = str(mx) if pd.notna(mx) else ""
    spf = str(spf) if pd.notna(spf) else ""
    mx_org = str(mx_org) if pd.notna(mx_org) else ""
    mx_country = str(mx_country) if pd.notna(mx_country) else ""
    spf_org = str(spf_org) if pd.notna(spf_org) else ""
    spf_country = str(spf_country) if pd.notna(spf_country) else ""
    
    # Prefer SPF org for classification (actual sending service)
    org_l = spf_org.lower() if spf_org else mx_org.lower()
    country_l = spf_country.lower() if spf_country else mx_country.lower()

    # 1. Check SPF for major email providers first (most reliable for actual sending)
    if "spf.protection.outlook.com" in spf.lower() or "microsoft" in spf_org.lower():
        return "Microsoft 365"
    
    if "spf.google.com" in spf.lower() or "google" in spf_org.lower():
        return "Google Workspace"

    # 2. Check MX records for direct hosting (if no SPF cloud provider)
    if "outlook.com" in mx.lower() or "office365" in mx.lower() or "microsoft" in mx_org.lower():
        return "Microsoft 365"
    
    if "google" in mx.lower() or "google" in mx_org.lower():
        return "Google Workspace"

    # 3. Check if email is in Iceland (using MX or SPF country)
    if country_l == "is" or ".is" in mx.lower():
        return "Local (.is)"

    # 4. Check if it's US-based email provider
    if country_l == "us":
        return "Other US"

    # Check for no email configuration or explicit rejection
    if not mx and (not spf or "v=spf1 -all" in spf.lower()):
        return "Unknown"

    return "Other"


# Categorize DNS provider (Cloudflare, AWS, Local Icelandic, etc.)
def classify_dns_category(ns: str, dns_org: str = "", dns_country: str = "") -> str:
    ns = str(ns) if pd.notna(ns) else ""
    dns_org = str(dns_org) if pd.notna(dns_org) else ""
    dns_country = str(dns_country) if pd.notna(dns_country) else ""
    ns_l = ns.lower()
    org_l = dns_org.lower()
    country_l = dns_country.lower()

    if not ns_l and not org_l and not country_l:
        return "Unknown"

    # 1. Check if DNS is hosted in Iceland
    if country_l == "is":
        return "Local (.is)"

    # 2. Check for major DNS providers
    if "cloudflare" in org_l or "cloudflare.com" in ns_l:
        return "Cloudflare"

    if "amazon" in org_l or "aws" in org_l or "awsdns" in ns_l:
        return "AWS"

    if "microsoft" in org_l or "azure-dns" in ns_l or "azure" in org_l:
        return "Azure"

    if "google" in org_l:
        return "Google"

    # 3. Check if it's US-based DNS provider
    if country_l == "us":
        return "Other US"

    # 4. Legacy check for .is nameservers (backup)
    if any(part.strip().endswith(".is") for part in ns_l.split(";")):
        return "Local (.is)"

    return "Other"

# Categorize where the website is actually hosted based on ASN/organization data
def classify_hosting_category(asn: str, org: str, country: str = "") -> str:
    asn = str(asn) if pd.notna(asn) else ""
    org = str(org) if pd.notna(org) else ""
    country = str(country) if pd.notna(country) else ""
    asn_l, org_l, country_l = asn.lower(), org.lower(), country.lower()

    if not asn_l and not org_l and not country_l:
        return "Unknown"

    # 1. Check if hosted in Iceland
    if country_l == "is":
        return "Local (.is)"

    # 2. Check for major cloud providers (the giants)
    if "amazon" in org_l or "aws" in org_l:
        return "AWS"

    if "microsoft" in org_l or "azure" in org_l:
        return "Azure"

    if "google" in org_l:
        return "Google"

    if "cloudflare" in org_l:
        return "Cloudflare"

    if "digitalocean" in org_l:
        return "DigitalOcean"

    # 3. Check if it's US-based (other US tech companies)
    if country_l == "us":
        return "Other US"

    # 4. Everything else
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
df["spf"] = df["spf"].fillna("")
df["mx_asn"] = df["mx_asn"].fillna("")
df["mx_org"] = df["mx_org"].fillna("")
df["mx_country"] = df["mx_country"].fillna("")
df["spf_asn"] = df["spf_asn"].fillna("")
df["spf_org"] = df["spf_org"].fillna("")
df["spf_country"] = df["spf_country"].fillna("")
df["ns"] = df["ns"].fillna("")
df["dns_asn"] = df["dns_asn"].fillna("")
df["dns_org"] = df["dns_org"].fillna("")
df["dns_country"] = df["dns_country"].fillna("")
df["a"] = df["a"].fillna("")
df["hosting_asn"] = df["hosting_asn"].fillna("")
df["hosting_org"] = df["hosting_org"].fillna("")
df["hosting_country"] = df["hosting_country"].fillna("")
df["final_mx"] = df["final_mx"].fillna("")
df["final_spf"] = df["final_spf"].fillna("")
df["final_mx_asn"] = df["final_mx_asn"].fillna("")
df["final_mx_org"] = df["final_mx_org"].fillna("")
df["final_mx_country"] = df["final_mx_country"].fillna("")
df["final_spf_asn"] = df["final_spf_asn"].fillna("")
df["final_spf_org"] = df["final_spf_org"].fillna("")
df["final_spf_country"] = df["final_spf_country"].fillna("")
df["final_ns"] = df["final_ns"].fillna("")
df["final_dns_asn"] = df["final_dns_asn"].fillna("")
df["final_dns_org"] = df["final_dns_org"].fillna("")
df["final_dns_country"] = df["final_dns_country"].fillna("")
df["final_a"] = df["final_a"].fillna("")
df["final_hosting_asn"] = df["final_hosting_asn"].fillna("")
df["final_hosting_org"] = df["final_hosting_org"].fillna("")
df["final_hosting_country"] = df["final_hosting_country"].fillna("")
df["final_domain"] = df["final_domain"].fillna("")
df["redirect_count"] = df["redirect_count"].fillna(0)

# Apply classifications
print("\nClassifying DNS data...")
df["email_provider"] = df.apply(
    lambda row: classify_email_provider(row["mx"], row["spf"], row["mx_org"], row["mx_country"], row["spf_org"], row["spf_country"]),
    axis=1,
)
df["dns_category"] = df.apply(
    lambda row: classify_dns_category(row["ns"], row["dns_org"], row["dns_country"]),
    axis=1,
)
df["hosting_category"] = df.apply(
    lambda row: classify_hosting_category(row["hosting_asn"], row["hosting_org"], row["hosting_country"]),
    axis=1,
)

# Classify final domain data (if redirect occurred)
df["final_email_provider"] = df.apply(
    lambda row: classify_email_provider(row["final_mx"], row["final_spf"], row["final_mx_org"], row["final_mx_country"], row["final_spf_org"], row["final_spf_country"]) if row.get("final_domain") and str(row.get("final_domain")).strip() else "",
    axis=1,
)
df["final_dns_category"] = df.apply(
    lambda row: classify_dns_category(row["final_ns"], row["final_dns_org"], row["final_dns_country"]) if row.get("final_domain") and str(row.get("final_domain")).strip() else "",
    axis=1,
)
df["final_hosting_category"] = df.apply(
    lambda row: classify_hosting_category(row["final_hosting_asn"], row["final_hosting_org"], row["final_hosting_country"]) if row.get("final_domain") and str(row.get("final_domain")).strip() else "",
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

# Save classified results to data folder with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
data_path_csv = Path(__file__).parent.parent / "data" / f"dns_classified-{timestamp}.csv"
data_path_json = Path(__file__).parent.parent / "data" / f"dns_classified-{timestamp}.json"

df.to_csv(data_path_csv, index=False)
print(f"\nSaved classified results to {data_path_csv}")

df.to_json(data_path_json, orient="records", indent=2, force_ascii=False)
print(f"Saved JSON results to {data_path_json}")
