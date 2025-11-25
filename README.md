# Digital Sovereignty Analysis of Icelandic Government Agencies

## What is this?

This project analyzes where Icelandic government agencies host their digital infrastructure - email, websites, and DNS - to understand Iceland's digital infrastructure in the public sector.

Inspired by [Proton's Europe Tech Watch](https://proton.me/business/europe-tech-watch), which analyzed publicly listed companies in Europe to determine their email service providers through DNS lookups, this project applies the same methodology to the public sector, with additional analysis of website hosting and DNS infrastructure.

### Why does this matter?

Email is the foundation of most business technology suites. When a government agency uses a US-based email provider like Microsoft 365, they likely also use their cloud storage, collaboration tools, and other services. This has implications for:

- **Data sovereignty**: Where is sensitive government data actually stored?
- **Digital independence**: Could Iceland continue operating if access to foreign services was disrupted?
- **Privacy and security**: Which jurisdictions have legal access to government communications and data?

By analyzing email (MX and SPF records), website hosting (A records), and DNS infrastructure (NS records), we can see the full picture of Iceland's digital infrastructure dependencies.

## How it works

The analysis pipeline consists of four stages:

1. **Scraping** (`scrape_island_is.py`): Collects all Icelandic government agency domains from [island.is](https://island.is/s)
2. **DNS Lookup** (`dns_lookup.py`): Performs DNS queries (MX, SPF, NS, A records) and resolves IP addresses to organizations and countries using WHOIS/RDAP data
3. **Classification** (`dns_classify.py`): Categorizes providers into groups (Local .is, Microsoft, AWS, Cloudflare, etc.)
4. **Effective Analysis** (`dns_effective.py`): Applies rules to determine the actual provider used, including:
   - **Email**: Based on MX and SPF records - if either points to a major provider (like Microsoft 365), that provider is identified with a disclaimer explaining which record indicates the connection
   - **Hosting**: Uses IP addresses and server signatures to identify where website content is served from, following redirects to the final destination
   - **DNS**: Analyzes nameserver records to determine who controls domain resolution and traffic routing
   - **Redirect Handling**: For hosting and DNS, follows redirects to show the actual infrastructure serving users; for email, keeps the original domain's provider since email infrastructure typically stays with the source domain
   - **Disclaimers**: Added when MX and SPF point to different providers, when redirects change infrastructure, or when detection is based on only one type of record

## Usage

### Full pipeline

```bash
python main.py
```

### Skip scraping (use existing data)

```bash
python main.py --skip-scrape
```

### Skip DNS lookup (use existing data)

```bash
python main.py --skip-dns
```

### Only classify existing DNS data

```bash
python main.py --classify-only
```

## Output Files

- `data/island_is_government_agencies-*.csv`: List of government domains scraped
- `data/dns_raw-*.csv`: Raw DNS lookup results with WHOIS data
- `data/dns_classified-*.csv`: Classified provider categories
- `output/dns_full_results-*.csv`: **Final analysis** with effective providers and disclaimers

The final results include:

- `effective_email_provider`: The actual email service being used
- `effective_dns_category`: Who controls the DNS infrastructure
- `effective_hosting_category`: Where the website is actually hosted
- Disclaimer fields explaining detection logic (e.g., "Microsoft 365 detected in SPF. MX points elsewhere.")

## Requirements

- Python 3.7+
- dnspython
- ipwhois
- pandas
- requests
