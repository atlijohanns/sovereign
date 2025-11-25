import dns.resolver
from ipwhois import IPWhois
import pandas as pd
import logging
import sys
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


# Get email provider info by looking up the first mail server's IP (inbound mail)
def get_email_provider_info_mx(mx_records):
    """Look up ASN/org info for mail servers (inbound)."""
    if not mx_records:
        return "", "", ""
    
    try:
        # Get first mail server from the list
        first_mx = mx_records.split(";")[0].strip()
        if not first_mx:
            return "", "", ""
        
        # Resolve the mail server to an IP address
        mx_answers = dns.resolver.resolve(first_mx, "A")
        if not mx_answers:
            return "", "", ""
        
        mx_ip = str(mx_answers[0].address)  # type: ignore
        if not mx_ip:
            return "", "", ""
        
        # Get ASN info for the mail server IP
        asn, org, country = get_asn_info(mx_ip)
        return asn, org, country
        
    except Exception as e:
        logging.warning(f"Failed to get MX provider info for {mx_records}: {e}")
        return "", "", ""


# Get email sending provider info from SPF record (outbound mail)
def get_email_provider_info_spf(spf_record):
    """Determine email sending provider from SPF record (outbound)."""
    if not spf_record:
        return "", "", ""
    
    spf_lower = spf_record.lower()
    
    # Microsoft 365 - check first for cloud providers
    if "spf.protection.outlook.com" in spf_lower or "protection.outlook.com" in spf_lower:
        return "8075", "Microsoft Corporation", "US"
    
    # Google Workspace
    if "spf.google.com" in spf_lower or "_spf.google.com" in spf_lower:
        return "15169", "Google LLC", "US"
    
    # If no major cloud provider, try to resolve SPF includes or IP addresses
    # Parse SPF record for ip4:, ip6:, a:, mx:, include: directives
    parts = spf_record.split()
    
    # First, look for explicit IP addresses (ip4: or ip6:)
    for part in parts:
        if part.startswith("ip4:"):
            ip = part[4:].split("/")[0]  # Remove CIDR notation if present
            asn, org, country = get_asn_info(ip)
            if asn:
                return asn, org, country
        elif part.startswith("ip6:"):
            ip = part[4:].split("/")[0]
            asn, org, country = get_asn_info(ip)
            if asn:
                return asn, org, country
    
    # Second, look for a: or mx: directives (domain lookups)
    for part in parts:
        if part.startswith("a:"):
            domain = part[2:]
            try:
                answers = dns.resolver.resolve(domain, "A")
                if answers:
                    ip = str(answers[0].address)  # type: ignore
                    asn, org, country = get_asn_info(ip)
                    if asn:
                        return asn, org, country
            except:
                pass
        elif part == "mx" or part.startswith("mx:"):
            # Would need to look up MX for the domain, skip for now
            pass
    
    # Third, look for include: directives
    for part in parts:
        if part.startswith("include:"):
            include_domain = part[8:]
            try:
                # Try to get A record for the included domain
                answers = dns.resolver.resolve(include_domain, "A")
                if answers:
                    ip = str(answers[0].address)  # type: ignore
                    asn, org, country = get_asn_info(ip)
                    if asn:
                        return asn, org, country
            except:
                pass
    
    # If nothing found, return empty
    return "", "", ""


# Get nameserver (NS) records for a domain
def get_ns(domain):
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return join_records(answers)
    except Exception as e:
        logging.warning(f"Failed to get NS records for {domain}: {e}")
        return ""


# Get DNS provider info by looking up the first nameserver's IP
def get_dns_provider_info(ns_records):
    """Look up ASN/org info for DNS nameservers."""
    if not ns_records:
        return "", "", ""
    
    try:
        # Get first nameserver from the list
        first_ns = ns_records.split(";")[0].strip()
        if not first_ns:
            return "", "", ""
        
        # Resolve the nameserver to an IP address
        ns_answers = dns.resolver.resolve(first_ns, "A")
        if not ns_answers:
            return "", "", ""
        
        ns_ip = str(ns_answers[0].address)  # type: ignore
        if not ns_ip:
            return "", "", ""
        
        # Get ASN info for the nameserver IP
        asn, org, country = get_asn_info(ns_ip)
        return asn, org, country
        
    except Exception as e:
        logging.warning(f"Failed to get DNS provider info for {ns_records}: {e}")
        return "", "", ""


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
        return "", "", ""
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap()
        
        # Get ASN number
        asn = res.get("asn", "")
        
        # Get network information
        network = res.get("network") or {}
        
        # Get country code from multiple possible locations
        country = res.get("asn_country_code", "") or network.get("country", "")
        
        # Try to get organization info from objects array (most detailed and reliable)
        objects = res.get("objects", {})
        org_from_contact = ""
        
        if objects and isinstance(objects, dict):
            for obj_key, obj_data in objects.items():
                if isinstance(obj_data, dict):
                    # Check if this object is a registrant or has contact info
                    roles = obj_data.get("roles", [])
                    contact = obj_data.get("contact", {})
                    
                    if contact and isinstance(contact, dict):
                        # Get organization name from contact
                        name = contact.get("name", "")
                        if name and "registrant" in roles:
                            # Prioritize registrant role - this is the actual organization
                            org_from_contact = name
                            break
                        elif name and not org_from_contact:
                            # Use first available contact name if no registrant found
                            org_from_contact = name
        
        # Fallback chain: contact org > ASN description > network name
        final_org = (
            org_from_contact or 
            res.get("asn_description", "") or 
            network.get("name", "") or 
            ""
        )
        
        return asn, final_org, country
        
    except Exception as e:
        logging.warning(f"Failed to get ASN info for IP {ip}: {e}")
        return "", "", ""
    

# ---------------------------------------------------------
# Run DNS lookups
# ---------------------------------------------------------

# Get input file path
data_dir = Path(__file__).parent.parent / "data"

if len(sys.argv) > 1:
    # Use file path provided as command line argument
    input_path = Path(sys.argv[1])
    print(f"Using provided file: {input_path}")
else:
    # Find the most recent island.is government agencies file
    csv_files = sorted(data_dir.glob("island_is_government_agencies-*.csv"), reverse=True)
    if not csv_files:
        print("Error: No island.is government agencies CSV found in data folder.")
        print("Run script/scrape_island_is.py first to scrape organizations.")
        exit(1)
    
    input_path = csv_files[0]
    print(f"Using most recent organizations file: {input_path.name}")

# Read the CSV file
orgs_df = pd.read_csv(input_path)

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
        asn, hosting_org, hosting_country = get_asn_info(first_ip)
        
        # Get DNS provider info
        ns_records = get_ns(domain)
        dns_asn, dns_org, dns_country = get_dns_provider_info(ns_records)
        
        # Get email provider info - both inbound (MX) and outbound (SPF)
        mx_records = get_mx(domain)
        spf_record = get_spf(domain)
        mx_asn, mx_org, mx_country = get_email_provider_info_mx(mx_records)
        spf_asn, spf_org, spf_country = get_email_provider_info_spf(spf_record)

        dns_cache[domain] = {
            "mx": mx_records,
            "spf": spf_record,
            "ns": ns_records,
            "a": a_record,
            "hosting_asn": asn,
            "hosting_org": hosting_org,
            "hosting_country": hosting_country,
            "dns_asn": dns_asn,
            "dns_org": dns_org,
            "dns_country": dns_country,
            "mx_asn": mx_asn,
            "mx_org": mx_org,
            "mx_country": mx_country,
            "spf_asn": spf_asn,
            "spf_org": spf_org,
            "spf_country": spf_country,
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
            asn_final, hosting_org_final, hosting_country_final = get_asn_info(first_ip_final)
            
            # Get DNS provider info for final domain
            ns_records_final = get_ns(final_domain)
            dns_asn_final, dns_org_final, dns_country_final = get_dns_provider_info(ns_records_final)
            
            # Get email provider info for final domain - both inbound (MX) and outbound (SPF)
            mx_records_final = get_mx(final_domain)
            spf_record_final = get_spf(final_domain)
            mx_asn_final, mx_org_final, mx_country_final = get_email_provider_info_mx(mx_records_final)
            spf_asn_final, spf_org_final, spf_country_final = get_email_provider_info_spf(spf_record_final)

            dns_cache[final_domain] = {
                "mx": mx_records_final,
                "spf": spf_record_final,
                "ns": ns_records_final,
                "a": a_record_final,
                "hosting_asn": asn_final,
                "hosting_org": hosting_org_final,
                "hosting_country": hosting_country_final,
                "dns_asn": dns_asn_final,
                "dns_org": dns_org_final,
                "dns_country": dns_country_final,
                "mx_asn": mx_asn_final,
                "mx_org": mx_org_final,
                "mx_country": mx_country_final,
                "spf_asn": spf_asn_final,
                "spf_org": spf_org_final,
                "spf_country": spf_country_final,
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
        "spf": dns_cache[domain]["spf"],
        "mx_asn": dns_cache[domain]["mx_asn"],
        "mx_org": dns_cache[domain]["mx_org"],
        "mx_country": dns_cache[domain]["mx_country"],
        "spf_asn": dns_cache[domain]["spf_asn"],
        "spf_org": dns_cache[domain]["spf_org"],
        "spf_country": dns_cache[domain]["spf_country"],
        "ns": dns_cache[domain]["ns"],
        "dns_asn": dns_cache[domain]["dns_asn"],
        "dns_org": dns_cache[domain]["dns_org"],
        "dns_country": dns_cache[domain]["dns_country"],
        "a": dns_cache[domain]["a"],
        "hosting_asn": dns_cache[domain]["hosting_asn"],
        "hosting_org": dns_cache[domain]["hosting_org"],
        "hosting_country": dns_cache[domain]["hosting_country"],
        # Final domain DNS data (only if redirect occurred and domain is different)
        "final_mx": final_dns["mx"] if final_dns else "",
        "final_spf": final_dns["spf"] if final_dns else "",
        "final_mx_asn": final_dns["mx_asn"] if final_dns else "",
        "final_mx_org": final_dns["mx_org"] if final_dns else "",
        "final_mx_country": final_dns["mx_country"] if final_dns else "",
        "final_spf_asn": final_dns["spf_asn"] if final_dns else "",
        "final_spf_org": final_dns["spf_org"] if final_dns else "",
        "final_spf_country": final_dns["spf_country"] if final_dns else "",
        "final_ns": final_dns["ns"] if final_dns else "",
        "final_dns_asn": final_dns["dns_asn"] if final_dns else "",
        "final_dns_org": final_dns["dns_org"] if final_dns else "",
        "final_dns_country": final_dns["dns_country"] if final_dns else "",
        "final_a": final_dns["a"] if final_dns else "",
        "final_hosting_asn": final_dns["hosting_asn"] if final_dns else "",
        "final_hosting_org": final_dns["hosting_org"] if final_dns else "",
        "final_hosting_country": final_dns["hosting_country"] if final_dns else "",
    }
    rows.append(data_row)

# Create a DataFrame (table) from all collected data
df = pd.DataFrame(rows)

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

# Save raw DNS data to data folder with timestamp
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
output_path = Path(__file__).parent.parent / "data" / f"dns_raw-{timestamp}.csv"
df.to_csv(output_path, index=False)
print(f"\nSaved raw DNS data to {output_path}")
print(f"Total domains analyzed: {len(df)}")
print(f"Unique domains looked up: {len(dns_cache)}")
