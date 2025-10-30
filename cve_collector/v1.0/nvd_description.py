#!/usr/bin/env python3
"""
nvd_description.py

Input 1 or several CVE (or file), obtain Description from
https://nvd.nist.gov/vuln/detail/<CVE>, export to CSV file with 2 column: cve, description.

Usage:
  python3 nvd_description.py CVE-2023-50071
  python3 nvd_description.py CVE-2023-50071 CVE-2021-34527
  python3 nvd_description.py --input cve_list.txt --output out.csv
"""

import argparse
import csv
import time
import sys
import requests
from bs4 import BeautifulSoup
from typing import Optional, List

HEADERS = {"User-Agent": "Mozilla/5.0 (Linux) nvd-desc-simple/1.0"}

def fetch_description(cve_id: str, timeout: int = 12) -> Optional[str]:
	url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
	try:
		r = requests.get(url, headers=HEADERS, timeout=timeout)
		r.raise_for_status()
	except Exception as e:
		# Return None to indicate fetch error
		return None

	soup = BeautifulSoup(r.text, "html.parser")

	# Primary selector: element with data-testid="vuln-description"
	desc_elem = soup.find(attrs={"data-testid": "vuln-description"})
	if desc_elem and desc_elem.get_text(strip=True):
		return desc_elem.get_text(separator=" ", strip=True)

	# Fallback: meta description
	meta = soup.find("meta", {"name": "description"})
	if meta and meta.get("content"):
		return meta.get("content").strip()

	# Final fallback: try to find any element with class containing 'vuln-description'
	div = soup.find(class_=lambda c: c and "vuln-description" in c)
	if div and div.get_text(strip=True):
		return div.get_text(separator=" ", strip=True)

	# If nothing found, return empty string (not None)
	return ""

def write_csv(rows: List[dict], out_file: str):
	fieldnames = ["cve", "description", "error"]
	with open(out_file, "w", newline="", encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=fieldnames)
		writer.writeheader()
		for r in rows:
			# flatten newlines in description so CSV won't break
			desc = (r.get("description") or "").replace("\r", " ").replace("\n", " ")
			writer.writerow({"cve": r.get("cve",""), "description": desc, "error": r.get("error","")})

def main():
	parser = argparse.ArgumentParser(description="Simple NVD Description extractor")
	parser.add_argument("cves", nargs="*", help="CVE IDs (e.g. CVE-2023-50071)")
	parser.add_argument("--input", "-i", help="Text file with one CVE per line")
	parser.add_argument("--output", "-o", default="descriptions.csv", help="Output CSV file (default descriptions.csv)")
	parser.add_argument("--delay", "-d", type=float, default=1.0, help="Delay seconds between requests (default 1.0)")
	args = parser.parse_args()

	cve_list = []
	if args.input:
		try:
			with open(args.input, "r", encoding="utf-8") as fh:
				for ln in fh:
					ln = ln.strip()
					if ln:
						cve_list.append(ln)
		except Exception as e:
			print(f"Error reading input file: {e}", file=sys.stderr)
			sys.exit(1)
	if args.cves:
		cve_list.extend(args.cves)
	if not cve_list:
		print("No CVE IDs provided. Use arguments or --input file.", file=sys.stderr)
		sys.exit(1)

	rows = []
	for idx, cve in enumerate(cve_list, 1):
		print(f"[{idx}/{len(cve_list)}] Fetching {cve} ...")
		desc = fetch_description(cve)
		if desc is None:
			rows.append({"cve": cve, "description": "", "error": "fetch_error"})
		else:
			rows.append({"cve": cve, "description": desc, "error": ""})
		if idx < len(cve_list):
			time.sleep(args.delay)

	write_csv(rows, args.output)
	print(f"Done. Wrote {len(rows)} rows to {args.output}")

if __name__ == "__main__":
	main()
