## opnsense-cert

This script automates installation of a certificate (e.g., fetched from Let's
Encrypt using an ACME client) to an OPNsense system using only its HTTP API.

### Setup / Requirements

**You must already have manually installed an SSL certificate on the target**
with the same *common name* using the web UI. This script will search for that
certificate and **replace it**, so keep a backup if necessary.

(Why? This is a limitation of the OPNsense API. It allows updating an existing
certificate, but not choosing/changing the certificate to be used by services
such as the web server. By overwriting the existing cert we achieve the desired
effect using solely the API.)

**You must have an *API key* for a user with permission to manage certificates.**
This need not be (and ideally isn't) the root user. To create such an account and key:
 1. Navigate to *System: Access: Users* and click the plus.
 2. Give the new user a suitable name.
 3. Select *Disabled* and *Scrambled Password*, so the user can't log in.
 4. Under *Privileges*, select *System: Trust: Authorities* and *System: Trust:
    Certificates*.
 5. Click *Save*.
 6. On the list of users, click the button to create and download API key for
    this user (just to the left of the user's edit button).
 7. Save the key file where this script will be run.

**You must have a PEM-encoded certificate bundle and the corresponding private key.**
The details of how to do this are out of scope for this document.

### Usage

Invoke the script with a command such as:
```
opnsense-cert myrouter_certadmin_apikey.txt myrouter.crt myrouter.key
```
See `opnsense-cert --help` for details.
