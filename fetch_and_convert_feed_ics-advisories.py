#!/usr/bin/env python3

import requests
import xml.etree.ElementTree as ET
from stix2 import Indicator, Bundle
import hashlib
import os

def fetch_and_parse_feed():
    # Fetch the XML feed
    url = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml"
    response = requests.get(url)
    response.raise_for_status()  # Raise an exception for HTTP errors
    root = ET.fromstring(response.content)

    # Parse the XML and extract advisories
    advisories = []
    for item in root.findall(".//item"):
        advisory = {
            "title": item.find("title").text,
            "link": item.find("link").text,
            "description": item.find("description").text
        }
        advisories.append(advisory)
    return advisories

def create_stix_objects(advisories):
    stix_objects = []
    for advisory in advisories:
        # Generate a SHA-256 hash based on the advisory link
        advisory_hash = hashlib.sha256(advisory["link"].encode()).hexdigest()

        indicator = Indicator(
            name=advisory["title"],
            pattern=f"[file:hashes.'SHA-256' = '{advisory_hash}']",
            pattern_type="stix",
            description=advisory["description"],
            external_references=[
                {
                    "source_name": "CISA",
                    "url": advisory["link"]
                }
            ]
        )
        stix_objects.append(indicator)
    return stix_objects

def main():
    # Fetch and parse the feed
    advisories = fetch_and_parse_feed()

    # Create STIX objects from the advisories
    stix_objects = create_stix_objects(advisories)

    # Bundle the STIX objects
    bundle = Bundle(objects=stix_objects)

    # Directory and file path for saving the JSON
    output_dir = "/var/www/MISP/app/files/feed/"
    os.makedirs(output_dir, exist_ok=True)
    stix_output_path = os.path.join(output_dir, "cisa_ics_advisories.json")

    # Serialize and save the bundle to a file
    with open(stix_output_path, "w") as stix_file:
        stix_file.write(bundle.serialize(pretty=True))

    print(f"STIX bundle saved to {stix_output_path}")

if __name__ == "__main__":
    main()
