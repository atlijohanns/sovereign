import re
import json
import csv
from urllib.parse import urljoin, urlparse
from pathlib import Path
from datetime import datetime

import requests

PAGE_URL_is = "https://island.is/s"
PAGE_URL_en = "https://island.is/en/o"
BASE_URL = "https://island.is"


def get_next_data(url: str):
    html = requests.get(url).text

    # Grab the JSON inside <script id="__NEXT_DATA__" ...> ... </script>
    m = re.search(
        r'<script id="__NEXT_DATA__" type="application/json">(.+?)</script>',
        html,
        re.DOTALL,
    )
    if not m:
        raise RuntimeError("__NEXT_DATA__ not found in HTML")

    return json.loads(m.group(1))


def get_organizations_from_next_data(data: dict):
    """
    In your HAR the path was:
    props.pageProps.pageProps.pageProps.componentProps.organizations.items

    If this ever changes, you can print(data) or do a small tree-search.
    """
    orgs = (
        data["props"]["pageProps"]["pageProps"]["pageProps"]
        ["componentProps"]["organizations"]["items"]
    )

    return orgs


def build_island_url(org):
    """
    If hasALandingPage and link is a relative URL, prepend https://island.is.
    If link is an absolute URL (https://...), leave it.
    """
    link = org.get("link")

    if not link:
        return None

    if link.startswith("http://") or link.startswith("https://"):
        return link

    # internal island.is path
    return urljoin(BASE_URL, link)


def extract_root_domain(url):
    """
    Extract the root domain from a URL for DNS lookup.
    Returns None if URL is None or invalid.
    """
    if not url:
        return None
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path
        
        # Remove www. prefix if present
        if domain.startswith("www."):
            domain = domain[4:]
        
        # Remove trailing slashes and paths
        domain = domain.split('/')[0]
        
        return domain if domain else None
    except Exception:
        return None


def main():
    # Fetch Icelandic data
    print("Fetching Icelandic organizations...")
    data_is = get_next_data(PAGE_URL_is)
    orgs_is = get_organizations_from_next_data(data_is)
    print(f"Found {len(orgs_is)} Icelandic organizations")
    
  

    # Fetch English data
    print("Fetching English organizations...")
    data_en = get_next_data(PAGE_URL_en)
    orgs_en = get_organizations_from_next_data(data_en)
    print(f"Found {len(orgs_en)} English organizations")
    
  

    # Create lookup dictionary for English names by ID
    en_lookup = {o.get("id"): o.get("title") for o in orgs_en}
    # Create lookup dictionary for English tags by ID
    def extract_tag(org):
        tag = org.get("tag")
        if isinstance(tag, list) and len(tag) > 0:
            return tag[0].get("title", "")
        elif isinstance(tag, dict):
            return tag.get("title", "")
        return ""
    
    en_tag_lookup = {o.get("id"): extract_tag(o) for o in orgs_en}

    # Build combined rows
    rows = []
    for o in orgs_is:
        org_id = o.get("id")
        url = build_island_url(o)
        domain = extract_root_domain(url)
        tag_icelandic = extract_tag(o)
        tag_english = en_tag_lookup.get(org_id, "")
        
        rows.append(
            {
                "name_icelandic": o.get("title"),
                "name_english": en_lookup.get(org_id, ""),
                "tag_icelandic": tag_icelandic,
                "tag_english": tag_english,
                "url": url,
                "domain": domain,
            }
        )

    # Save to data directory with timestamp
    script_dir = Path(__file__).parent
    data_dir = script_dir.parent / "data"
    data_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_file = data_dir / f"island_is_government_agencies-{timestamp}.csv"
    
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "name_icelandic",
                "name_english",
                "tag_icelandic",
                "tag_english",
                "url",
                "domain",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Saved {len(rows)} organizations to {out_file}")


if __name__ == "__main__":
    main()
