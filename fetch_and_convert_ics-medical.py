#!/usr/bin/env python3

import requests
import xml.etree.ElementTree as ET
from stix2 import Indicator, Bundle
import hashlib

def fetch_and_parse_feed():
    # Fetch the XML feed
    url = "https://www.cisa.gov/cybersecurity-advisories/ics-medical-advisories.xml"
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

    # Serialize and save the bundle to a file
    stix_output_path = "/var/www/MISP/feed_output/cisa_ics_medical.json"
    with open(stix_output_path, "w") as stix_file:
        stix_file.write(bundle.serialize(pretty=True))

    print(f"STIX bundle saved to {stix_output_path}")

if __name__ == "__main__":
    main()
