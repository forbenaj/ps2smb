import argparse
import json
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def build_catalog(url: str) -> list[dict[str, str]]:
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    table = soup.select_one("table.directory-listing-table")

    if not table:
        raise RuntimeError("Could not find the directory listing table.")

    catalog = []
    base_url = url.rstrip("/") + "/"

    for row in table.select("tbody tr"):
        cells = row.find_all("td")
        if len(cells) < 3:
            continue

        link = cells[0].find("a", href=True)
        if not link:
            continue

        href = link["href"]

        # Ignore parent directory and "View Contents" links.
        if href.startswith("/details/") or href.endswith("/"):
            continue

        filename = unquote(href)

        # Only include ISO files.
        if not filename.lower().endswith(".iso"):
            continue

        name = unquote(link.get_text(strip=True))

        download_url = urljoin(base_url, href)

        catalog.append({
            "name": name[:-4] if name.lower().endswith(".iso") else name,
            "download_url": download_url,
        })

    return catalog


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build a JSON catalog from an Archive.org directory."
    )
    parser.add_argument(
        "url",
        help="Archive.org download URL, e.g. https://archive.org/download/ps2-games-collection_202501",
    )
    args = parser.parse_args()

    url = args.url.rstrip("/")

    # Use the last path component as the catalog name.
    page_name = unquote(urlparse(url).path.rstrip("/").split("/")[-1])

    if not page_name:
        raise ValueError("Could not determine the page name from the URL.")

    output_dir = Path("catalogs")
    output_dir.mkdir(parents=True, exist_ok=True)

    output_path = output_dir / f"{page_name}.json"

    catalog = build_catalog(url)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(catalog, f, ensure_ascii=False, indent=2)

    print(f"Saved {len(catalog)} games to {output_path}")


if __name__ == "__main__":
    main()
