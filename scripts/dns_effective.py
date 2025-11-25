import pandas as pd
import sys
from pathlib import Path
from datetime import datetime


# ---------------------------------------------------------
# Helper: Lowercase specific categories for mid-sentence usage
# ---------------------------------------------------------

def lowercase_category_for_sentence(category: str) -> str:
    """
    Lowercase only generic categories (Other, Other US, Local (.is), Unknown)
    when they appear mid-sentence. Company names remain capitalized.
    """
    if category == "Other":
        return "other"
    elif category == "Other US":
        return "other US"
    elif category == "Local (.is)":
        return "local (.is)"
    elif category == "Unknown":
        return "unknown"
    else:
        # Keep company/brand names capitalized (Microsoft 365, AWS, etc.)
        return category


# ---------------------------------------------------------
# Helper: Classify individual MX or SPF
# ---------------------------------------------------------

def classify_mx_or_spf(mx_or_spf: str, org: str, country: str) -> str:
    """Classify a single MX or SPF record to determine its category."""
    mx_or_spf = str(mx_or_spf).strip().lower() if pd.notna(mx_or_spf) else ""
    org = str(org).strip().lower() if pd.notna(org) else ""
    country = str(country).strip().lower() if pd.notna(country) else ""
    
    # Check for Microsoft
    if "microsoft" in org or "outlook.com" in mx_or_spf or "office365" in mx_or_spf or "protection.outlook.com" in mx_or_spf:
        return "Microsoft 365"
    
    # Check for Google
    if "google" in org or "google.com" in mx_or_spf:
        return "Google Workspace"
    
    # Check for Iceland
    if country == "is" or ".is" in mx_or_spf:
        return "Local (.is)"
    
    # Check for US
    if country == "us":
        return "Other US"
    
    # Check if unknown
    if not mx_or_spf and not org:
        return "Unknown"
    
    return "Other"


# ---------------------------------------------------------
# Part 1: Email Provider Determination (MX + SPF OR-logic)
# ---------------------------------------------------------

def determine_email_provider(email_provider: str, mx: str, mx_org: str, mx_country: str, spf: str, spf_org: str, spf_country: str):
    """
    Determine effective email provider with Microsoft 365 OR-logic and disclaimers.
    Uses the already-classified email_provider but adds Microsoft detection logic
    and generates appropriate disclaimer text.
    
    Email provider is ONLY based on original domain (never follows redirects).
    
    Args:
        email_provider: Already-classified email provider category
        mx: MX record value
        mx_org: Organization from MX record lookup
        mx_country: Country from MX record lookup
        spf: SPF record value
        spf_org: Organization from SPF record lookup
        spf_country: Country from SPF record lookup
    
    Returns:
        Tuple of (effective_provider, has_disclaimer, disclaimer_text)
    """
    email_provider = str(email_provider).strip() if pd.notna(email_provider) else "Unknown"
    mx_org = str(mx_org).strip() if pd.notna(mx_org) else ""
    spf_org = str(spf_org).strip() if pd.notna(spf_org) else ""
    
    # Classify MX and SPF individually to compare their categories
    mx_category = classify_mx_or_spf(mx, mx_org, mx_country)
    spf_category = classify_mx_or_spf(spf, spf_org, spf_country)
    
    mx_is_microsoft = "microsoft" in mx_org.lower()
    spf_is_microsoft = "microsoft" in spf_org.lower()
    
    # Email Rule A — Microsoft 365 OR-logic
    # If either MX or SPF is Microsoft, ensure it's classified as Microsoft 365
    if mx_is_microsoft and spf_is_microsoft:
        return (
            "Microsoft 365",
            True,
            "Microsoft 365 detected in both MX and SPF."
        )
    
    if mx_is_microsoft and not spf_is_microsoft:
        return (
            "Microsoft 365",
            True,
            "Microsoft 365 detected in MX. SPF does not clearly point to Microsoft 365."
        )
    
    if spf_is_microsoft and not mx_is_microsoft:
        return (
            "Microsoft 365",
            True,
            "SPF includes Microsoft 365 for sending. MX points elsewhere."
        )
    
    # Email Rule B — Non-Microsoft resolution
    # Use the already-classified provider category
    
    # If provider is Unknown, don't add a disclaimer
    if email_provider == "Unknown":
        return (email_provider, False, "")
    
    # For all other providers, add a disclaimer based on MX/SPF category comparison
    mx_known = mx_category != "Unknown"
    spf_known = spf_category != "Unknown"
    
    if mx_known and spf_known:
        # Compare CATEGORIES, not org names
        if mx_category == spf_category:
            return (
                email_provider,
                True,
                f"{email_provider} detected in both MX and SPF."
            )
        else:
            # Lowercase only generic categories in mid-sentence
            mx_cat_text = lowercase_category_for_sentence(mx_category)
            spf_cat_text = lowercase_category_for_sentence(spf_category)
            return (
                email_provider,
                True,
                f"{email_provider} detected. MX uses {mx_cat_text}, SPF uses {spf_cat_text}."
            )
    
    if mx_known and not spf_known:
        return (
            email_provider,
            True,
            f"{email_provider} detected in MX. SPF is unknown."
        )
    
    if spf_known and not mx_known:
        return (
            email_provider,
            True,
            f"{email_provider} detected in SPF. MX is unknown."
        )
    
    # No MX or SPF data
    return (email_provider, False, "")


# ---------------------------------------------------------
# Part 2: DNS & Hosting Redirect Logic
# ---------------------------------------------------------

def determine_effective_provider_with_redirect(
    original_provider: str,
    final_provider: str,
    service_type: str,
    final_domain: str = ""
):
    """
    Determine effective provider for DNS or Hosting based on redirect logic.
    
    Args:
        original_provider: Provider for original domain
        final_provider: Provider for final domain (empty if no redirect)
        service_type: "dns" or "hosting"
        final_domain: Final domain name (for tooltip)
    
    Returns:
        Tuple of (effective_provider, has_disclaimer, tooltip)
    """
    original_provider = str(original_provider).strip() if pd.notna(original_provider) else ""
    final_provider = str(final_provider).strip() if pd.notna(final_provider) else ""
    final_domain = str(final_domain).strip() if pd.notna(final_domain) else ""
    
    redirect_exists = bool(final_provider)
    
    # Rule 1a — No redirect
    if not redirect_exists:
        return (original_provider, False, "")
    
    # Rule 1b — Redirect exists AND final provider is Unknown
    if final_provider == "Unknown":
        return (
            original_provider,
            True,
            "Domain redirects but final provider is unknown. Showing original provider."
        )
    
    # Rule 2 — Original provider Unknown AND final provider known
    if original_provider == "Unknown" and final_provider != "Unknown":
        return (
            final_provider,
            True,
            f"Original provider unknown. Showing provider after redirect to {final_domain}."
        )
    
    # Rule 3 — Redirect exists AND both providers known AND providers differ
    if original_provider != final_provider:
        # Lowercase only generic categories in mid-sentence
        final_text = lowercase_category_for_sentence(final_provider)
        return (
            final_provider,
            True,
            f"Original domain used {original_provider}, but redirect target uses {final_text}."
        )
    
    # Rule 4 — Redirect exists AND both providers known AND providers are the same
    return (
        original_provider,
        True,
        f"{original_provider} is used on both domains."
    )



# ---------------------------------------------------------
# Run effective provider determination
# ---------------------------------------------------------

# Get input file path
data_dir = Path(__file__).parent.parent / "data"
output_dir = Path(__file__).parent.parent / "output"

if len(sys.argv) > 1:
    # Use file path provided as command line argument
    input_path = Path(sys.argv[1])
else:
    # Find the most recent classified results file in data folder
    result_files = sorted(data_dir.glob("dns_classified-*.csv"), reverse=True)
    if not result_files:
        print("Error: No dns_classified-*.csv files found in data folder.")
        print("Run dns_classify.py first to generate classified data.")
        sys.exit(1)
    input_path = result_files[0]
    print(f"Using most recent classified results: {input_path.name}")

# Read the classified data
df = pd.read_csv(input_path)

# Ensure all required columns exist and are filled
required_cols = [
    "email_provider", "mx", "mx_org", "mx_country", "spf", "spf_org", "spf_country",
    "dns_category", "hosting_category",
    "final_dns_category", "final_hosting_category",
    "final_domain"
]

for col in required_cols:
    if col not in df.columns:
        df[col] = ""
    df[col] = df[col].fillna("")

# Calculate effective providers
print("\nDetermining effective providers...")

# Part 1: Email Provider (MX + SPF OR-logic, never follows redirects)
print("Processing email providers...")
email_results = df.apply(
    lambda row: determine_email_provider(
        row["email_provider"],
        row["mx"],
        row["mx_org"],
        row["mx_country"],
        row["spf"],
        row["spf_org"],
        row["spf_country"]
    ),
    axis=1
)
df["effective_email_provider"] = email_results.apply(lambda x: x[0])
df["email_disclaimer"] = email_results.apply(lambda x: x[1])
df["email_disclaimer_text"] = email_results.apply(lambda x: x[2])

# Part 2: DNS Provider (with redirect logic)
print("Processing DNS providers...")
dns_results = df.apply(
    lambda row: determine_effective_provider_with_redirect(
        row["dns_category"],
        row["final_dns_category"],
        "dns",
        row["final_domain"]
    ),
    axis=1
)
df["effective_dns_category"] = dns_results.apply(lambda x: x[0])
df["dns_disclaimer"] = dns_results.apply(lambda x: x[1])
df["dns_disclaimer_text"] = dns_results.apply(lambda x: x[2])

# Part 2: Hosting Provider (with redirect logic)
print("Processing hosting providers...")
hosting_results = df.apply(
    lambda row: determine_effective_provider_with_redirect(
        row["hosting_category"],
        row["final_hosting_category"],
        "hosting",
        row["final_domain"]
    ),
    axis=1
)
df["effective_hosting_category"] = hosting_results.apply(lambda x: x[0])
df["hosting_disclaimer"] = hosting_results.apply(lambda x: x[1])
df["hosting_disclaimer_text"] = hosting_results.apply(lambda x: x[2])

# Display summary
print("\n" + "="*60)
print("EFFECTIVE PROVIDER SUMMARY")
print("="*60)

print("\nEmail Providers:")
print(df["effective_email_provider"].value_counts().to_string())

print("\nDNS Providers:")
print(df["effective_dns_category"].value_counts().to_string())

print("\nHosting Providers:")
print(df["effective_hosting_category"].value_counts().to_string())

print("\n" + "="*60)
print("DISCLAIMER STATISTICS")
print("="*60)
print(f"Email disclaimers: {df['email_disclaimer'].sum()} ({df['email_disclaimer'].sum() / len(df) * 100:.1f}%)")
print(f"DNS disclaimers: {df['dns_disclaimer'].sum()} ({df['dns_disclaimer'].sum() / len(df) * 100:.1f}%)")
print(f"Hosting disclaimers: {df['hosting_disclaimer'].sum()} ({df['hosting_disclaimer'].sum() / len(df) * 100:.1f}%)")

# Show sample tooltips
print("\n" + "="*60)
print("SAMPLE EMAIL TOOLTIPS (first 5 with disclaimers)")
print("="*60)
email_with_disclaimers = df[df["email_disclaimer"] == True].head(5)
for idx, row in email_with_disclaimers.iterrows():
    print(f"\n{row['domain']}:")
    print(f"  Provider: {row['effective_email_provider']}")
    print(f"  Disclaimer: {row['email_disclaimer_text']}")

# Save results with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_path_csv = output_dir / f"dns_full_results-{timestamp}.csv"
output_path_json = output_dir / f"dns_full_results-{timestamp}.json"

df.to_csv(output_path_csv, index=False)
print(f"\n" + "="*60)
print(f"Saved effective provider results to:")
print(f"  CSV:  {output_path_csv}")

df.to_json(output_path_json, orient="records", indent=2, force_ascii=False)
print(f"  JSON: {output_path_json}")
print("="*60)
