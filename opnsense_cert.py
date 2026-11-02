#!/usr/bin/env python3

import argparse
import logging
import pathlib
import re
import requests
import subprocess
import urllib3

__version__ = "0.0.1"

def read_apikey(path: pathlib.Path) -> tuple[str, str]:
    """
    Reads an OPNsense API key from the provided file path.

    Given a file of the form:
        key=abc
        secret=def
    ... this returns the tuple (abc, def).
    """
    key = None
    secret = None
    with open(path, 'r') as f:
        for s in f:
            if s.startswith('key='):
                key = s[4:].strip()
            elif s.startswith('secret='):
                secret = s[7:].strip()
    assert key and secret
    return (key, secret)

def read_cert_bundle(path: pathlib.Path) -> list[str]:
    """
    Read a certificate bundle to a list of PEM certificates in file order.
    """
    certs = []
    cert = None

    with open(path, 'r') as f:
        for l in f:
            if l == "-----BEGIN CERTIFICATE-----\n":
                assert cert is None
                cert = l
            elif l == "-----END CERTIFICATE-----\n":
                assert cert is not None
                cert += l
                certs.append(cert)
                cert = None
            elif cert is not None:
                cert += l

    assert cert is None
    return certs

def get_cert_cn(cert_data: str) -> str:
    """
    Given a single PEM certificate, retrieve its common name using openssl.
    """
    output = subprocess.check_output(
        ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'multiline', '-nameopt', 'utf8'],
        input=cert_data, encoding='utf8')
    r = re.compile(r' +commonName += (.*)\n?')
    for line in output.splitlines():
        m = r.fullmatch(line)
        if m:
            return m.group(1)
    raise RuntimeError("Failed to parse CN from openssl output")

def search_one_cert(sess: requests.Session, api_url: str, commonname: str) -> str | None:
    """
    Query the OPNsense API, return the UUID of the first in-use certificate matching a given common name, otherwise None.
    """
    response = sess.get(f"{api_url}/trust/cert/search")
    response.raise_for_status()
    result = response.json()
    assert "rows" in result

    for row in result["rows"]:
        if row.get("commonname") == commonname and row.get("in_use", '0') != '0':
            return row["uuid"]
    return None

def import_ca(sess: requests.Session, api_url: str, ca_data: str) -> None:
    """
    Import a single CA certificate using the OPNsense API.
    """
    cn = get_cert_cn(ca_data)
    logging.info("Importing CA %s", cn)

    body = {"ca":
        {
            "action": "existing",
            "crt_payload": ca_data.strip(),
            "descr": cn,
        }
    }

    response = sess.post(f"{api_url}/trust/ca/add", json=body)
    response.raise_for_status()

def import_missing_cas(sess: requests.Session, api_url: str, ca_certs: list[str]) -> None:
    """
    Import each of the provided CA certificates not already present on the server using the OPNsense API.
    """
    response = sess.get(f"{api_url}/trust/ca/search")
    response.raise_for_status()

    server_ca_crts: set[str] = set()
    for row in response.json()["rows"]:
        crt = row.get("crt_payload")
        if crt:
            server_ca_crts.add(crt.strip())

    for ca in ca_certs:
        if not ca.strip() in server_ca_crts:
            import_ca(sess, api_url, ca)

def set_cert(sess: requests.Session, api_url: str, cert_uuid: str, descr: str, cert_data: str, key_data: str) -> None:
    """
    Update an existing certificate with the given UUID to a new payload and private key.
    """
    body = {"cert":
        {
            "action": "import",
            "descr": descr,
            "cert_type": "usr_cert",
            "private_key_location": "firewall",
            "crt_payload": cert_data,
            "prv_payload": key_data,
            "csr_payload": ""
        }
    }

    response = sess.post(f"{api_url}/trust/cert/set/{cert_uuid}", json=body)
    response.raise_for_status()

def update_cert_bundle(sess: requests.Session, api_url: str, cert_cn: str, certs: list[str], key_data: str) -> None:
    """
    Install an updated certificate and its CA bundle using the OPNsense API.
    """
    cert_uuid = search_one_cert(sess, api_url, cert_cn)
    if cert_uuid is None:
        raise RuntimeError("Failed to find existing in-use cert for %s" % cert_cn)
    import_missing_cas(sess, api_url, certs[1:])
    logging.info("Updating cert for %s with UUID %s", cert_cn, cert_uuid)
    set_cert(sess, api_url, cert_uuid, cert_cn, certs[0], key_data)

def restart_webgui(sess: requests.Session, api_url: str) -> None:
    logging.info("Restarting webgui service")
    try:
        response = sess.post(f"{api_url}/core/service/restart/webgui", json={})
    except requests.exceptions.ConnectionError:
        return # this is expected when the server restarts
    response.raise_for_status()

def main() -> None:
    parser = argparse.ArgumentParser(
                    description='Import a certificate bundle and private key to OPNsense')
    parser.add_argument('-u', dest='url', help='OPNsense URL, defaults to https://<CERT_COMMONNAME>')
    parser.add_argument('-k', '--insecure', dest='insecure', action='store_true',
                        help="Skip certificate verification on API endpoints")
    parser.add_argument('apikey', metavar='APIKEY', type=pathlib.Path, help='Path to OPNsense API key')
    parser.add_argument('cert', metavar='CERT', type=pathlib.Path, help='Path to certificate bundle')
    parser.add_argument('key', metavar='KEY', type=pathlib.Path, help='Path to private key')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(message)s')

    # the last cert in the bundle is (assumed to be) a self-signed root cert that we ignore
    certs = read_cert_bundle(args.cert)[:-1]

    cert_cn = get_cert_cn(certs[0])
    api_url = args.url or f"https://{cert_cn}"
    api_url += "/api"

    sess = requests.Session()
    sess.auth = read_apikey(args.apikey)

    if args.insecure:
        sess.verify = False
        urllib3.disable_warnings()

    key = open(args.key, 'r').read()
    update_cert_bundle(sess, api_url, cert_cn, certs, key)
    restart_webgui(sess, api_url)

if __name__ == "__main__":
    main()
