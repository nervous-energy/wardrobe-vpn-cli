# WardrobeVPN (free edition) - Assemble your own VPN

Wardrobe is the free and open source pre-cursor of Ceres VPN [https://cereslabs.org](https://cereslabs.org), a GUI tool that enables you to deploy your own WireGuard VPN server. 

## BLUF / TL;DR:
This is a CLI tool that lets you provision a WireGuard VPN server on DigitalOcean. 
- **DigitalOcean Droplet**: Ubuntu 24.04 server (1 vCPU, 1GB RAM) 
- **WireGuard VPN**: Running on UDP port 51820
- **Web Admin UI**: wg-easy interface on TCP port 51821 for managing VPN clients
- **Firewall Rules**: Secure access to SSH, VPN, and admin interface
- **SSH Key Setup**: Automatically configures your public key via DigitalOcean
- **Terraform:** Files are generated locally and cleaned up
- **DigitalOcean may change regions, pricing, droplet availability etc at any time. This tool contains hardcoded values that may be out of date**

> **Use at your own risk!** 

---

## Why 'Wardrobe'?
- To evoke CS Lewis' portal to another world!
- ...and also Ikea's self-assembly excellence


## Dependencies
- Python 3.10+
- Terraform 1.5+
- A DigitalOcean account + **Personal Access Token** (scopes: **read** and **write**)  
- `ssh-keygen` available on your machine (standard with OpenSSH)

Optional but recommended: a basic understanding of WireGuard and cloud firewalls.

---
## Installation
- Python 3.10+ is required. Terraform 1.5+ must be installed and on PATH.
- Recommended: use a virtual environment.

Steps:
- `python -m venv .venv`
- `source .venv/bin/activate`
- `pip install -r requirements.txt`
- Install Terraform from HashiCorp docs (v1.5+)

Run the wizard:
- `python cli/wardrobe-cli.py`

## Security Model (read this!)
- Admin UI is HTTP only (no TLS). Access is restricted by DigitalOcean Cloud Firewall to:
- - The public IP you used during setup, and
- - the VPN subnet once you’re connected (e.g., http://10.8.0.1:51821).
- SSH: keys-only from anywhere (port 22). Never share your private key.

## First-Run Setup (wg-easy)
On first visit to http://<droplet-ip>:51821/ you’ll see wg-easy’s setup screen:
  1. Create an Admin account/password.
  2. Add a client → scan the QR code in the WireGuard mobile app or download the .conf.
  3. Connect and verify you can reach http://10.8.0.1:51821/.
  4. see https://github.com/wg-easy/wg-easy

## Practical Notes
- This app is minimalist but has some guardrails to support you, such as checking for any existing wardrobeVPN droplets.
- You'll be asked to confirm before any paid infrastructure is deployed.
- Use DigitalOcean's webui to manage / delete droplets and firewalls created by this tool. (Note that firewalls are created and managed under the 'Networking tab' in DO)


## DigitalOcean Token Scopes
Create a Personal Access Token with following scopes:
- account -- READ
- actions -- READ
- droplet -- FULL
- firewall -- FULL
- image -- READ
- region -- READ
- project -- READ
- sizes -- READ
- snapshot -- READ
- ssh_key -- FULL
- tag -- FULL
- vpc -- READ

DigitalOceans's UI helps fill in any missing scopes.
Store it somewhere safe. The CLI only passes it to Terraform via environment variables.


## Troubleshooting
- **Deployments will fail if there are duplicate names** e.g. a duplicated firewall name. Delete these resources on DigitalOcean
- **Admin UI not up yet** → DO firewall can take ~1–2 minutes. Try: `curl -I http://<ip>:51821/`.
- **Admin UI browser warning** → There is NO HTTPS out of the box, your browser may warn you the site is 'insecure'.
- **Can’t SSH** → confirm the right key and IP: `terraform output vpn_server_ip` then `ssh -i <key> root@<ip>`.
- **UDP 51820 blocked** → some networks block VPN UDP; try another network or mobile hotspot.


## Platform Notes
- macOS and Linux supported. Windows users: run under WSL and ensure `ssh-keygen` is available.

## Security & Privacy Notes
- Public IP detection uses `https://ipv4.icanhazip.com` (fallback `https://api.ipify.org`).
- DO token is only passed to Terraform via environment variables during plan/apply; this tool does not write it to disk.
- Your SSH public key is uploaded to your DO account; remove it there if no longer needed.

## Third-Party Notices
- wg-easy container: `ghcr.io/wg-easy/wg-easy:15` (MIT License)
  - https://github.com/wg-easy/wg-easy
- Python libraries:
  - requests (Apache-2.0): https://github.com/psf/requests
  - inquirer (MIT): https://github.com/magmax/python-inquirer
- Tooling:
  - Terraform CLI (BUSL-1.1): https://github.com/hashicorp/terraform
  - DigitalOcean Terraform Provider (MPL-2.0): https://github.com/digitalocean/terraform-provider-digitalocean

This project does not redistribute third-party code; it invokes the components above. Refer to their licenses for details.


## License
MIT — see `LICENSE`.
