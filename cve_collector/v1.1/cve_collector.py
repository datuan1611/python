#!/usr/bin/env python3
"""
cve_collector.py

Usage:
	python3 cve_collector.py CVE-2023-50071 CVE-2021-34527
	python3 cve_collector.py --input cve_list.txt --output results.csv

Requirements:
	pip install requests beautifulsoup4 python-dateutil
"""
import argparse
import csv
import os
import time
import requests
from bs4 import BeautifulSoup
from dateutil import parser as dateparser

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) cve-collector/1.0 (+https://example.local)"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional

HEADERS = {
	"User-Agent": USER_AGENT,
	"Accept": "text/html,application/json"
}

def check_exploitdb(cve_id, session):
	"""
	Search exploit-db for the CVE.
	Returns a dict:
	{
		"found": True/False,
		"records": [ {"title":..., "url":..., "date":..., "author":...}, ... ]
	}
	"""
	base_search = "https://www.exploit-db.com/search"
	params = {"cve": cve_id}
	try:
		r = session.get(base_search, params=params, timeout=15)
		r.raise_for_status()
	except Exception as e:
		return {"found": False, "records": [], "error": f"request_failed: {e}"}

	soup = BeautifulSoup(r.text, "html.parser")

	# Try to find a table of results
	table = soup.find("table")
	if not table:
		# maybe page has 'No results' text
		text = soup.get_text(separator=" ").strip().lower()
		if "no results found" in text or "no exploits found" in text:
			return {"found": False, "records": []}
		# fallback: try to detect direct exploit page (rare)
		# we'll consider not found
		return {"found": False, "records": []}

	records = []
	# table rows (skip header)
	for tr in table.find_all("tr"):
		cols = tr.find_all("td")
		if not cols:
			continue
		# typical columns: id, date, exploit title (with link), author, platform, type
		try:
			link_tag = cols[2].find("a")
			title = link_tag.get_text(strip=True) if link_tag else cols[2].get_text(strip=True)
			href = link_tag.get("href") if link_tag else None
			url = "https://www.exploit-db.com" + href if href and href.startswith("/") else href
			date_text = cols[1].get_text(strip=True) if len(cols) > 1 else ""
			author = cols[3].get_text(strip=True) if len(cols) > 3 else ""
			rec = {"title": title, "url": url, "date": date_text, "author": author}
			records.append(rec)
		except Exception:
			continue

	return {"found": len(records) > 0, "records": records}

def parse_cvss_versions_from_nvd(json_data):
	"""
	Extract available CVSS entries from NVD JSON (both v3 and v2 if present).
	Return list of dicts: [{"version":"3.1","baseScore":9.8, "vectorString":"..."}...]
	"""
	out = []
	# Impact object is under "result" -> "CVE_Items"[0] -> "impact"
	items = json_data.get("result", {}).get("CVE_Items", []) or json_data.get("result", {}).get("CVE", {}).get("CVE_Items", [])
	if not items:
		# Some responses might put data directly; try another pattern: top-level "CVE_Items"
		items = json_data.get("CVE_Items", [])

	for it in items:
		impact = it.get("impact", {}) or {}
		# v3
		v3 = impact.get("baseMetricV3")
		if v3:
			cvssV3 = v3.get("cvssV3")
			if cvssV3:
				version = cvssV3.get("version") or "3.x"
				score = cvssV3.get("baseScore")
				vector = cvssV3.get("vectorString")
				out.append({"version": str(version), "baseScore": float(score) if score is not None else None, "vector": vector})
		# v2
		v2 = impact.get("baseMetricV2")
		if v2:
			cvssV2 = v2.get("cvssV2")
			if cvssV2:
				version = cvssV2.get("version") or "2.0"
				score = cvssV2.get("baseScore")
				vector = cvssV2.get("vectorString")
				out.append({"version": str(version), "baseScore": float(score) if score is not None else None, "vector": vector})
	return out

def version_key(vstr):
	"""
	Convert version strings like "3.1", "3.0", "2.0" to tuple for comparison.
	Unknown formats -> (0,)
	"""
	try:
		parts = [int(p) for p in vstr.split(".") if p.isdigit() or p.replace(".","").isdigit()]
		return tuple(parts)
	except Exception:
		return (0,)

def check_nvd(cve_id, session):
	"""
	Query NVD REST API for the CVE.
	Returns dict:
	{
		"found": True/False,
		"cvss_entries": [ {"version":"3.1","baseScore":9.8,"vector":"..."}... ],
		"chosen_version": "3.1",
		"chosen_baseScore": 9.8,
		"raw": <json or None>,
		"error": None or text
	}
	"""
	#base = f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}"
	base = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
	headers = HEADERS.copy()
	#if NVD_API_KEY:
	#	headers["apiKey"] = NVD_API_KEY

	try:
		r = session.get(base, headers=headers, timeout=20)
		if r.status_code == 404:
			return {"found": False, "cvss_entries": [], "chosen_version": None, "chosen_baseScore": None, "raw": None}
		r.raise_for_status()
		j = r.json()
	except Exception as e:
		return {"found": False, "cvss_entries": [], "chosen_version": None, "chosen_baseScore": None, "raw": None, "error": str(e)}

	entries = parse_cvss_versions_from_nvd(j)
	if not entries:
		return {"found": False, "cvss_entries": [], "chosen_version": None, "chosen_baseScore": None, "raw": j}

	# Choose entry with largest version (compare numeric tuples), tie-breaker: larger baseScore
	entries_sorted = sorted(entries, key=lambda e: (version_key(e.get("version","0")), e.get("baseScore") or 0), reverse=True)
	chosen = entries_sorted[0]
	return {"found": True, "cvss_entries": entries, "chosen_version": chosen.get("version"), "chosen_baseScore": chosen.get("baseScore"), "raw": j}

def process_cve_list(cve_list, out_csv, delay=1.0):
	session = requests.Session()
	session.headers.update({"User-Agent": USER_AGENT})
	rows = []
	for idx, cve in enumerate(cve_list, 1):
		cve = cve.strip()
		if not cve:
			continue
		print(f"[{idx}/{len(cve_list)}] Processing {cve} ...")
		# Exploit-DB
		exp_res = check_exploitdb(cve, session)
		time.sleep(delay)

		# NVD
		nvd_res = check_nvd(cve, session)
		time.sleep(delay)

		exploitdb_found = exp_res.get("found", False)
		exploitdb_links = ";".join([rec.get("url","") for rec in exp_res.get("records",[])]) if exp_res.get("records") else ""
		exploitdb_titles = ";".join([rec.get("title","") for rec in exp_res.get("records",[])]) if exp_res.get("records") else ""

		nvd_found = nvd_res.get("found", False)
		chosen_ver = nvd_res.get("chosen_version")
		chosen_score = nvd_res.get("chosen_baseScore")
		# highest base score among entries
		cvss_entries = nvd_res.get("cvss_entries", [])
		highest_score = None
		if cvss_entries:
			scores = [e.get("baseScore") for e in cvss_entries if e.get("baseScore") is not None]
			highest_score = max(scores) if scores else None

		row = {
			"cve_id": cve,
			"exploitdb_found": "yes" if exploitdb_found else "no",
			"exploitdb_links": exploitdb_links,
			"exploitdb_titles": exploitdb_titles,
			"nvd_found": "yes" if nvd_found else "no",
			"nvd_chosen_cvss_version": chosen_ver or "",
			"nvd_chosen_baseScore": chosen_score if chosen_score is not None else "",
			"nvd_highest_baseScore": highest_score if highest_score is not None else "",
			"nvd_cvss_entries_count": len(cvss_entries),
		}
		rows.append(row)

	# Write CSV
	fieldnames = ["cve_id","exploitdb_found","exploitdb_links","exploitdb_titles","nvd_found","nvd_chosen_cvss_version","nvd_chosen_baseScore","nvd_highest_baseScore","nvd_cvss_entries_count"]
	with open(out_csv, "w", newline='', encoding="utf-8") as f:
		writer = csv.DictWriter(f, fieldnames=fieldnames)
		writer.writeheader()
		for r in rows:
			writer.writerow(r)

	print(f"Done. Results written to {out_csv}")

def main():
	parser = argparse.ArgumentParser(description="Collect CVE info from Exploit-DB and NVD, export CSV.")
	parser.add_argument("cves", nargs="*", help="One or more CVE IDs (e.g. CVE-2023-50071). If omitted, use --input file.")
	parser.add_argument("--input", "-i", help="File with CVE ids, one per line")
	parser.add_argument("--output", "-o", default="output.csv", help="Output CSV file (default: output.csv)")
	parser.add_argument("--delay", "-d", type=float, default=1.0, help="Seconds delay between requests (default 1.0)")
	args = parser.parse_args()

	cves = []
	if args.input:
		with open(args.input, "r", encoding="utf-8") as f:
			for ln in f:
				ln = ln.strip()
				if ln:
					cves.append(ln)
	if args.cves:
		cves.extend(args.cves)

	if not cves:
		parser.error("No CVE IDs provided. Provide as arguments or via --input file.")

	process_cve_list(cves, args.output, delay=args.delay)

if __name__ == "__main__":
	main()
