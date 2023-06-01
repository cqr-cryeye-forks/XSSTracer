#!/usr/bin/python
# Cross-Site Tracer v1.3 by 1N3

# A python script to check remote web servers for Cross-Site Tracing, Cross-Frame Scripting/Clickjacking and Host
# Header Injection vulnerabilities. For more robust mass scanning, you can create a list of domains or IP addresses to
# iterate through by doing 'for a in `cat targets.txt`; do ./xsstracer.py $a 80; done;'

# USAGE: xsstracer.py <IP/host> <port>

# COMMENTS: this project is 8 years old. I changed everything about it. It's pretty damn simple.
# Forgive its functionality. Forgive me.

from __future__ import absolute_import
from __future__ import print_function

import json
import logging
import pathlib
import socket
import sys
from urllib.parse import urlparse

import requests


def main(argv):

    target_arg = argv[1]  # SET TARGET
    parsed_url = urlparse(target_arg)
    target = parsed_url.netloc if parsed_url.scheme else parsed_url.path
    scheme = parsed_url.scheme

    try:
        port = argv[2]  # SET PORT

    except IndexError:
        logging.info("IndexError. Port is not set in audit arguments. Attempting to set port...")

        if scheme == 'http':
            port = '80'
            logging.info("Port was set to: 80")

        elif scheme == 'https':
            port = '443'
            logging.info("Port was set to: 443")

        elif scheme == '':
            port = '80'
            logging.info("Schema not specified. Target is domain or IPv4. Moving to http schema : 80")

        else:
            logging.info("Can't define port at all. Problems in target and urlparse")
            port = None

    final_results = {}

    # SOCKET to establish connection with the target
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.0)
            result = s.connect_ex((target, int(port)))

            if result == 0:  # CONNECTION OK
                url = f"http://{target}:{port}/"

                try:
                    response = requests.request("TRACE", url, headers={"Test": "<script>alert(1);</script>"},
                                                timeout=1.0)

                    # Test for Cross-Site Tracing
                    if "<script>alert(1);</script>" in response.text:
                        final_results.update({"cross_site_tracing": True})
                        print("Site vulnerable to Cross-Site Tracing!")
                    else:
                        final_results.update({"cross_site_tracing": False})
                        print("Site not vulnerable to Cross-Site Tracing!")

                except requests.exceptions.RequestException as e:
                    if isinstance(e, requests.exceptions.ConnectionError):
                        print("An error occurred during the request: Connection error")
                    else:
                        print(f"An error occurred during the request: {e}")

                # Test for Host Header Injection
                frame_inject = "crowdshield"

                url = f"http://{target}:{port}/"

                try:
                    response = requests.get(url, headers={"Host": "http://crowdshield.com"}, timeout=1.0)

                    if frame_inject.lower() in response.text.lower():
                        final_results.update({"host_header_injection": True})
                        print("Site vulnerable to Host Header Injection!")
                    else:
                        final_results.update({"host_header_injection": False})
                        print("Site not vulnerable to Host Header Injection!")

                except requests.exceptions.RequestException as e:
                    print(f"An error occurred during the request: {e}")

                # Test for Clickjacking and CFS
                x_frame = "X-Frame-Options"

                url = f"http://{target}:{port}/"

                try:
                    response = requests.get(url, timeout=1.0)

                    if x_frame.lower() in response.headers.get("X-Frame-Options", "").lower():
                        final_results.update({"cross_frame_click_jack": False})
                        final_results.update({"click_jack": False})

                        print("Site not vulnerable to Cross-Frame Scripting!")
                        print("Site not vulnerable to Clickjacking!")
                    else:
                        final_results.update({"cross_frame_click_jack": True})
                        final_results.update({"click_jack": True})

                        print("Site vulnerable to Cross-Frame Scripting!")
                        print("Site vulnerable to Clickjacking!")

                except requests.exceptions.RequestException as e:
                    print(f"An error occurred during the request: {e}")

            else:
                print("Unable to establish a connection to the target.")

    except socket.error as e:
        print(f"An error occurred during the connection: {e}")


    root_path = pathlib.Path(__file__).parent
    file_path = root_path.joinpath('result.json')
    file_path.write_text(json.dumps(final_results))


main(sys.argv)
