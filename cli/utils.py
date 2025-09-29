import os
import sys
import subprocess
import urllib.request
from pathlib import Path
import inquirer
import secrets
import string
import requests
import time
from typing import List, Dict, Any, Optional 
import base64
import hashlib

# =============================================================================
# Exceptions
# =============================================================================
class WardrobeError(Exception):
    """Base domain error (validation, infra, prompt)."""
    pass
class UserCancelled(Exception):
    """User intentionally aborted (exit code 0)."""
    pass
class InputError(Exception):
    """Issue with user input"""
    pass
class InfraError(Exception):
    """Problem with infrastructure / Terraform """
    pass


# =============================================================================
# Utility Functions
# =============================================================================

def ask_question(questions: List[Any], error_message: str = "Setup Cancelled"):    
    """
    Wrapper for inquirer prompt that handles user cancellations gracefully 
    Prompt the user. Returns dict of answers on success.
    Raises:
      UserCancelled  - user pressed Ctrl+C or provided no answer (esc / blank)
      WardrobeError  - unexpected prompt failure
    """
    try:
        answer = inquirer.prompt(questions)
        if not answer:
            raise UserCancelled(error_message)
        return answer
    except KeyboardInterrupt:
        raise UserCancelled("User interrupted")
    except UserCancelled:
        raise
    except Exception as e:
        raise WardrobeError(f"Prompt failed: {e}") from e


def generate_admin_password() -> str:
    """Generate a strong admin password"""
    # Generate 20 character password with letters and numbers (no special chars for easier typing)
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(20))


def get_user_ip():
    """Get user's current public IP address"""
    try:
        # Use a simple service to get public IP
        response = urllib.request.urlopen("https://ipv4.icanhazip.com", timeout=10)
        ip = response.read().decode().strip()
        return ip
    except Exception:
        # Fallback to a different service
        try:
            response = urllib.request.urlopen("https://api.ipify.org", timeout=10)
            ip = response.read().decode().strip()
            return ip
        except Exception:
            # Final fallback - use placeholder
            raise InfraError("⚠️  Could not detect your IP address.")


def wait_for_http(host: str, port: int = 51821, total_timeout: int = 180, interval: float = 5.0) -> bool:
    """Return True once http://host:port responds (<400), else False after timeout."""
    
    deadline = time.time() + total_timeout
    url = f"http://{host}:{port}/"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                if 200 <= getattr(resp, 'status', 200) < 400:
                    return True
        except Exception:
            pass
        time.sleep(interval)
    return False
        

# =============================================================================
# SSH Generation & Validation
# =============================================================================


def generate_ssh_key(filename: str = "id_ed25519", password="") -> Path:
    """
    Generate an ed25519 SSH key pair
    Returns Path to pub key
    """
    
    ssh_dir = Path.home() / ".ssh"
    private_key_path = ssh_dir / filename
    public_key_path  = ssh_dir / f"{filename}.pub"

    ssh_dir.mkdir(mode=0o700, exist_ok=True)

    # Check for duplication
    if private_key_path.exists() or public_key_path.exists():
        raise InputError(f"SSH key '{filename}' already exists at {ssh_dir}")
        
    #Generate Key
    cmd = [
        "ssh-keygen",
        "-t", "ed25519",
        "-C", "wardrobe-vpn", #comment
        "-N", password,  # can be empty
        "-f", str(private_key_path)
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)

    except FileNotFoundError as e:
        raise InputError("ssh-keygen tool not found in PATH. Ensure SSH tools are installed") from e
    except subprocess.CalledProcessError as e:
        raise WardrobeError(f"ssh-keygen failed: {e.stderr or e.stdout}") from e
    

    # Permissions for POSIX
    if os.name == "posix":
        os.chmod(ssh_dir, 0o700)
        os.chmod(private_key_path, 0o600)
        os.chmod(public_key_path, 0o644)

    # return public key path
    return public_key_path


def validate_ssh_key(ssh_key_path: Path) -> None:
    """
    Validate SSH public key exists and is properly formatted
    On success: returns None.
    On failure: raises InputError
    """
    if not ssh_key_path.exists():
        raise InputError(f"SSH key not found at: {ssh_key_path}")
    
    try:
        content = ssh_key_path.read_text().strip()
    except Exception as e:
        raise InputError(f"Error reading SSH key: {e}") from e
      
    if not content.startswith(('ssh-rsa', 'ssh-ed25519', 'ssh-dss', 'ecdsa-sha2')):
        raise InputError(f"File doesn't appear to be a valid SSH public key") 
        


# =============================================================================
# Cloud Provider API Calls
# =============================================================================

def find_existing_vpns(api_key: str) -> List:
    """Check for existing Wardrobe VPNs using DigitalOcean API"""
    
    try:
        headers = {"Authorization": f"Bearer {api_key}"}
        
        # Get all droplets
        response = requests.get(
            "https://api.digitalocean.com/v2/droplets",
            headers=headers,
            timeout=10
        )
    except Exception as e:
        raise InfraError(f"Could not check for existing VPN instances: {e}") from e

    if response.status_code != 200:
        raise InfraError(f"⚠️  Could not check for existing VPNs (API returned {response.status_code})")
        
    droplets = response.json().get("droplets", [])
    
    # Filter for Wardrobe VPNs (look for name pattern or tags)
    wardrobe_vpns = []
    for droplet in droplets:
        name = droplet.get("name", "").lower()
        tags = droplet.get("tags", [])
        
        # Check if this looks like a Wardrobe VPN
        if ("wardrobe" in name or 
            "vpn" in name and any("wardrobe" in tag for tag in tags) or
            any("wardrobe-vpn" in tag for tag in tags)):
            
            # Extract useful info
            wardrobe_vpns.append({
                "id": droplet["id"],
                "name": droplet["name"],
                "status": droplet["status"],
                "created": droplet["created_at"][:10],  # Just date
                "region": droplet["region"]["name"],
                "size": droplet["size_slug"],
                "ip": droplet["networks"]["v4"][0]["ip_address"] if droplet["networks"]["v4"] else "No IP",
            })      
    return wardrobe_vpns
    

def get_md5_fingerprint(pubkey_path:Path) -> str:
    "Returns MD5 coloned hex of a public key. Used by DO API to identify keys."
    try:
        content = pubkey_path.read_text().strip().split()
        if len(content) < 2:
            raise InputError(f"Invalid Key")
        key_bytes = base64.b64decode(content[1].encode())
    except Exception as e:
        raise InputError(f"failed to read/parse ssh key: {pubkey_path}: {e}") from e
    
    # Generate format aa:bb:cc ... etc
    md5_hex = hashlib.md5(key_bytes).hexdigest() #32 hex chars
    fingerprint = ":".join(md5_hex[i:i+2] for i in range(0,32,2))
    return fingerprint
    


def set_do_ssh_key(api_key, pubkey_path:Path, name) -> str:
    """ Ensure ssh key exists in digitalocean account. 
        
        Note fingerprint is a MD5 coloned hex.
    """
    
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    # Read local public key text (verbatim; DO must see the same string)
    try:
        public_key_text = pubkey_path.read_text().strip()
    except Exception as e:
        raise InputError(f"Failed to read SSH public key at {pubkey_path}: {e}") from e

    # 1) Compute fingerprint locally (identifier only; not a security primitive)
    fingerprint = get_md5_fingerprint(pubkey_path)  # returns "aa:bb:...:ff"
    
    # 2) Try to fetch by fingerprint
    # https://docs.digitalocean.com/reference/api/digitalocean/#tag/SSH-Keys/operation/sshKeys_get
    get_url = f"https://api.digitalocean.com/v2/account/keys/{fingerprint}"
    try:
        r = requests.get(get_url, headers=headers, timeout=10)
    except Exception as e:
        raise InfraError(f"DigitalOcean API error retrieving key by fingerprint: {e}") from e

    # Key Already exists on DO - return fingerprint to be used by terraform.
    if r.status_code == 200:
        return fingerprint

    if r.status_code not in (200, 404): #i.e. auth fail
        raise InfraError(f"DigitalOcean GET key failed: HTTP {r.status_code} — {r.text[:200]}")


    # 3) Key not registered -- Create it on DO + retrieve fingerprint
    payload = {"name": name, "public_key": public_key_text}
    try:
        c = requests.post(
            "https://api.digitalocean.com/v2/account/keys",
            headers=headers,
            json=payload,
            timeout=10,
        )

        # Get 'new' fingerprint from response
        if c.status_code in (200, 201, 202):
            new_fp = c.json()["ssh_key"]["fingerprint"]
            if not new_fp:
                raise InfraError("DigitalOcean create key succeeded but fingerprint missing in response.")
            return new_fp

        if c.status_code == 422:
            # 'New' key already exists in DigitalOcean... (e.g. race condition) use initially generated fingerprint
            return fingerprint

        # Any other non-2xx - raise error
        raise InfraError(f"DigitalOcean create key failed: HTTP {c.status_code} — {c.text[:200]}")

    except Exception as e:
        # Generic network/JSON/parse issues
        raise InfraError(f"DigitalOcean create key request failed: {e}") from e



# =============================================================================
# Print Functions
# =============================================================================
def print_welcome():
    """Display welcome banner"""
    print("=" * 60)
    print("|" + " " *58 + "|" )
    print("| ****   🔧 Wardrobe VPN - Assemble your own VPN 🔐   **** |")
    print("|" + " " *58 + "|" )
    print("=" * 60 )
    print("-" * 80)
    print(" This tool helps you setup a personal WireGuard VPN on DigitalOcean. ")
    print(" You will be asked for confirmation before any infrastructure is deployed. ") 
    print(" Use at own risk :)")
    print("-" * 80)
    print(" Last updated Sept 2025")
    print("=" * 80)
    print("SECURITY: Once deployed, your Admin UI runs over HTTP (no TLS) on port 51821. " \
        "\nThe Admin UI helps you configure your VPN, and access will be restricted to your *current* IP. " \
        "\nDo NOT open 51821 to the world. And do NOT run this setup process from a network you don't trust.")
    print("=" * 80)
    print("\n")

def print_review_configuration(config):
    """Display configuration summary for review"""
    print("\n" + "=" * 80)
    print("🔍 REVIEW INPUTS")
    print("=" * 80)
    print(f"Cloud Provider: {config['cloud']}")
    print(f"Server Size: 'Droplet': 1vCPU | 1GB Memory | 25GB Storage -- s-1vcpu-1gb")
    print(f"VPN Name: {config['vpn_name']}")
    print(f"VPN Region: {config['region']}")
    print(f"API Key: {'*' * (len(config['api_key'])-4) + config['api_key'][-4:]}")
    print(f"SSH Key: {config['ssh_key_path']}")
    print("=" * 80)
    print("\n")



def print_tf_plan_summary(plan: dict) -> None:
    """
    Human summary derived from the actual plan TF JSON.
    """
    
    changes = plan.get("resource_changes", [])

    droplet_after = {}
    firewall_after = {}

    for rc in changes:
        if rc.get("type") == "digitalocean_droplet" and rc.get("name") == "vpn_server":
            droplet_after = (rc.get("change") or {}).get("after") or {}
        elif rc.get("type") == "digitalocean_firewall" and rc.get("name") == "vpn_firewall":
            firewall_after = (rc.get("change") or {}).get("after") or {}

    print("=" * 80)
    print("=== TERRAFORM PLAN SUMMARY ===")
    print("=" * 80)
    # Droplet
    if droplet_after:
        print("VPN Server:")
        print(f"  name   : {droplet_after.get('name','—')}")
        print(f"  region : {droplet_after.get('region','—')}")
        print(f"  image  : {droplet_after.get('image','—')}")
        print(f"  size   : {droplet_after.get('size','—')}")
    else:
        print("Droplet: —")

    # Firewall (inbound)
    in_rules = (firewall_after or {}).get("inbound_rule") or []
    print("\nFirewall (inbound):")
    if in_rules:
        for r in in_rules:
            proto = r.get("protocol","—").upper()
            port  = r.get("port_range","—")
            srcs  = r.get("source_addresses") or []
            print(f"  {proto} {port:<7} from {', '.join(srcs) if isinstance(srcs, list) else srcs}")
    else:
        print("  —")
    print("=" * 80)
    print(" Wardrobe will configure your VPN server's firewall as follows:")
    print(" * TCP 22    : SSH (keys only) - allowed from any IP")
    print(" * TCP 51821 : Admin UI (HTTP only) — from your current IP OR via VPN subnet (10.8.0.0/24)")
    print(" * UDP 51820 : WireGuard - from anywhere (required for roaming)")
    print(" NOTE: Admin UI is HTTP (no TLS). To avoid MITM, prefer accessing it AFTER you connect to the VPN, or tunnel over SSH.")
    print(" These settings can be modified by logging into your DigitalOcean account")
    print("\n")
    print("\n")


# Print Results & Login info
def print_vpn_details(server_ip, admin_password, cloud_provider="digitalocean"):
    """Display final deployment results"""
    print("\n✅ VPN Setup Complete!")
    print("=" * 80)
    print("🌐 VPN DETAILS")
    print("=" * 80)
    print(f"Cloud Provider: {cloud_provider}")
    print(f"VPN IP Address: {server_ip}")
    print(f"Admin Login URL: http://{server_ip}:51821 -- see security notes")
    print(f"SECURITY: Admin Login is HTTP only! Once connected, the UI is also reachable via your VPN subnet (e.g., http://10.8.0.1:51821)")
    print("=" * 80)
    print("\n📝 Next Steps:")
    print("1. Open the login URL in your browser")
    print("2. Follow the WireGuard instructions to create an admin account and password ")
    print("3. Create your first WireGuard client configuration")
    print("4. Download the config file or scan the QR code with the WireGuard mobile app to connect to your VPN")
    print("\n💡 Keep this information secure!")
    print("=" * 80)
    print("  ")
    print("🔒 SECURITY NOTE:")
    print("   - The admin panel is only accessible from:")
    print("     • Your current IP address (used during setup)")
    print("     • Devices securely connected to the VPN")
    print(f"   - These firewall rules are defined at the infrastructure level, in your {cloud_provider} account")
    print(f"   - If your ISP changes your IP, you can update the firewall rules by logging into {cloud_provider}.") 
    print(f"     Take care when logging into the *Admin UI* as it is http only - do not use this method on an insecure network ")
    print("   - For full control over your VPN server, you can use SSH from anywhere.")
    print("\n💡 Keep this information secure!")