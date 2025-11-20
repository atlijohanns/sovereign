import dns.resolver
from ipwhois import IPWhois
import pandas as pd
import logging
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import requests
import urllib3


# Configure logging to show INFO level messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Disable SSL warnings for unverified HTTPS requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------
# DNS lookup helper functions
# ---------------------------------------------------------

# Helper to join multiple DNS records into a single string
def join_records(rrset):
    return "; ".join(sorted({r.to_text().rstrip('.') for r in rrset}))


# Follow HTTP redirects and return final URL and redirect info
def get_final_url(url, timeout=10):
    """
    Follow redirects and return the final URL.
    Returns: (final_url, redirect_count, redirect_codes)
    """
    if not url:
        return None, 0, ""
    
    try:
        # Make HEAD request to follow redirects
        response = requests.head(
            url,
            allow_redirects=True,
            timeout=timeout,
            verify=False  # Some .is sites have SSL issues
        )
        
        # Track redirect chain
        redirect_count = len(response.history)
        redirect_codes = "; ".join([str(r.status_code) for r in response.history]) if response.history else ""
        
        return response.url, redirect_count, redirect_codes
    except requests.exceptions.SSLError:
        # Try with http if https fails
        try:
            http_url = url.replace("https://", "http://")
            response = requests.head(
                http_url,
                allow_redirects=True,
                timeout=timeout
            )
            redirect_count = len(response.history)
            redirect_codes = "; ".join([str(r.status_code) for r in response.history]) if response.history else ""
            return response.url, redirect_count, redirect_codes
        except Exception as e:
            logging.warning(f"Failed to get final URL for {url}: {e}")
            return url, 0, ""
    except Exception as e:
        logging.warning(f"Failed to get final URL for {url}: {e}")
        return url, 0, ""


# Extract domain from URL
def extract_domain_from_url(url):
    """Extract the domain from a URL."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        # Remove www. prefix if present
        if domain.startswith("www."):
            domain = domain[4:]
        # Remove port number if present
        if ":" in domain:
            domain = domain.split(":")[0]
        # Remove trailing slashes and paths
        domain = domain.split('/')[0]
        return domain if domain else None
    except Exception as e:
        logging.warning(f"Failed to extract domain from {url}: {e}")
        return None


# Get mail server (MX) records for a domain
def get_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        hosts = [r.exchange.to_text().rstrip('.') for r in answers]
        return "; ".join(sorted(set(hosts)))
    except Exception as e:
        logging.warning(f"Failed to get MX records for {domain}: {e}")
        return ""


# Get nameserver (NS) records for a domain
def get_ns(domain):
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return join_records(answers)
    except Exception as e:
        logging.warning(f"Failed to get NS records for {domain}: {e}")
        return ""


# Get IP address (A) records for a domain
def get_a(domain):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return "; ".join(sorted({r.address for r in answers}))
    except Exception as e:
        logging.warning(f"Failed to get A records for {domain}: {e}")
        return ""


# Get SPF (email authentication) records from TXT records
def get_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        spf_records = [
            r.to_text().strip('"')
            for r in answers
            if r.to_text().strip('"').lower().startswith("v=spf1")
        ]
        return "; ".join(spf_records)
    except Exception as e:
        logging.warning(f"Failed to get SPF records for {domain}: {e}")
        return ""


# Look up ASN (Autonomous System Number) and organization info for an IP address
# This tells us who is hosting the website
def get_asn_info(ip):
    if not ip:
        return "", ""
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        asn = res.get("asn", "")
        network = res.get("network") or {}
        org = network.get("name", "") or res.get("asn_description", "")
        return asn, org
    except Exception as e:
        logging.warning(f"Failed to get ASN info for IP {ip}: {e}")
        return "", ""


# ---------------------------------------------------------
# Run DNS lookups
# ---------------------------------------------------------

# Read the most recent island.is organizations CSV
data_dir = Path(__file__).parent.parent / "data"
csv_files = sorted(data_dir.glob("island_is_government_agencies-*.csv"), reverse=True)
if not csv_files:
    print("Error: No island.is government agencies CSV found in data folder.")
    print("Run script/scrape_island_is.py first to scrape organizations.")
    exit(1)

csv_path = csv_files[0]
print(f"Using organizations file: {csv_path.name}")
orgs_df = pd.read_csv(csv_path)

rows = []
dns_cache = {}  # Cache to store DNS lookup results by domain

# Loop through each domain and collect DNS/hosting information
for _, row in orgs_df.iterrows():
    domain = row['domain']
    url = row['url']
    
    # Skip if domain is empty or NaN
    if pd.isna(domain) or not domain or str(domain).strip() == "":
        print(f"Skipping empty domain for {row.get('name_icelandic', 'unknown')}")
        continue
    
    # Check for redirects and get final URL
    print(f"Checking redirects for {url}...")
    final_url, redirect_count, redirect_codes = get_final_url(url)
    final_domain = extract_domain_from_url(final_url)
    
    # DNS lookup for ORIGINAL domain (for email, DNS, etc.)
    if domain not in dns_cache:
        print(f"Analyzing original domain {domain}...")
        a_record = get_a(domain)
        first_ip = a_record.split(";")[0].strip() if a_record else ""
        asn, hosting_org = get_asn_info(first_ip)

        dns_cache[domain] = {
            "mx": get_mx(domain),
            "ns": get_ns(domain),
            "a": a_record,
            "spf": get_spf(domain),
            "hosting_asn": asn,
            "hosting_org": hosting_org,
        }
    else:
        print(f"Using cached results for original domain {domain}")
    
    # DNS lookup for FINAL domain (if different from original)
    final_dns = None
    if redirect_count > 0 and final_domain and final_domain != domain:
        if final_domain not in dns_cache:
            print(f"Analyzing final domain {final_domain}...")
            a_record_final = get_a(final_domain)
            first_ip_final = a_record_final.split(";")[0].strip() if a_record_final else ""
            asn_final, hosting_org_final = get_asn_info(first_ip_final)

            dns_cache[final_domain] = {
                "mx": get_mx(final_domain),
                "ns": get_ns(final_domain),
                "a": a_record_final,
                "spf": get_spf(final_domain),
                "hosting_asn": asn_final,
                "hosting_org": hosting_org_final,
            }
        else:
            print(f"Using cached results for final domain {final_domain}")
        
        final_dns = dns_cache[final_domain]
    
    # Collect all the data for this domain
    data_row = {
        "name_icelandic": row['name_icelandic'],
        "name_english": row['name_english'],
        "tag_icelandic": row.get('tag_icelandic', ''),
        "tag_english": row.get('tag_english', ''),
        "url": url,
        "domain": domain,
        "final_url": final_url if redirect_count > 0 and final_domain != domain else "",
        "final_domain": final_domain if redirect_count > 0 and final_domain != domain else "",
        "redirect_count": redirect_count,
        "redirect_codes": redirect_codes,
        # Original domain DNS data
        "mx": dns_cache[domain]["mx"],
        "ns": dns_cache[domain]["ns"],
        "a": dns_cache[domain]["a"],
        "spf": dns_cache[domain]["spf"],
        "hosting_asn": dns_cache[domain]["hosting_asn"],
        "hosting_org": dns_cache[domain]["hosting_org"],
        # Final domain DNS data (only if redirect occurred and domain is different)
        "final_mx": final_dns["mx"] if final_dns else "",
        "final_ns": final_dns["ns"] if final_dns else "",
        "final_a": final_dns["a"] if final_dns else "",
        "final_spf": final_dns["spf"] if final_dns else "",
        "final_hosting_asn": final_dns["hosting_asn"] if final_dns else "",
        "final_hosting_org": final_dns["hosting_org"] if final_dns else "",
    }
    rows.append(data_row)

# Create a DataFrame (table) from all collected data
df = pd.DataFrame(rows)

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

# Save raw DNS data to data folder with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_path = Path(__file__).parent.parent / "data" / f"dns_raw-{timestamp}.csv"
df.to_csv(output_path, index=False)
print(f"\nSaved raw DNS data to {output_path}")
print(f"Total domains analyzed: {len(df)}")
print(f"Unique domains looked up: {len(dns_cache)}")
