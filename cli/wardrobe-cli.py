#!/usr/bin/env python3
"""Wardrobe CLI - Assemble your own VPN; Using DigitalOcean & WireGuard"""
# =============================================================================
# IMPORTS
# =============================================================================

# Standard library
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
import time
import urllib.request

# Utils File
from utils import (
    UserCancelled,
    InputError,
    InfraError,
    WardrobeError,
    ask_question,
    get_user_ip,
    generate_admin_password,
    wait_for_http,
    generate_ssh_key,
    validate_ssh_key,
    set_do_ssh_key,
    find_existing_vpns,
    print_welcome,
    print_review_configuration,
    print_tf_plan_summary,
    print_vpn_details
)

from digitalocean import (
    DIGITALOCEAN_REGIONS,
)

# Third-party
try:
    import inquirer
except ImportError as e:
    print(f"❌ Missing dependency: inquirer lib not installed. Install with: pip install inquirer")
    sys.exit(1)


# =============================================================================
# CORE FUNCTIONALITY
# =============================================================================
def select_cloud_provider() -> str:
    """Confirm Cloud Provider"""

    cloud_providers = {
        "DigitalOcean" : "digitalocean",
        "I don't have a DigitalOcean account!" : "no account"
    }

    # Display question - uses inquirer package and ask_quesiton() wrapper util
    q = ask_question([
      inquirer.List(
        'cloud',  # Key name for the answer
        message="Confirm Cloud Provider",  # Prompt text shown to user
        choices= list(cloud_providers.keys()),  # Available options
        )], 
        "Cloud provider not selected" # Error message for question
    )
    if cloud_providers[q['cloud']] == "no account":
        print("A DigitalOcean account is required :) ")
        raise UserCancelled("No DigitalOcean account")
    
    return cloud_providers[q['cloud']]


def get_digitalocean_auth():
    """Get DigitalOcean API key from user"""
  
    print("🔑 A DigitalOcean API token is required to setup your VPN. (See docs for required scope / permissions)")
    q = ask_question([
        inquirer.Password(
            'api_key',
            message=f"Enter your DigitalOcean API Token",
        )], 
        "API Token is required"
    )
    
    # Validate Key Format
    do_api_key = q['api_key'].strip()
    pattern = r'^dop_v1_[a-f0-9]{64}$'
    if not bool(re.match(pattern, do_api_key)):
        raise InputError(
            "Invalid DigitalOcean API key format (expected dop_v1_ + 64 hex characters)", 
            )
        
    return do_api_key  


def set_vpn_region() -> str:
    """Set VPN Region"""
    cloud_regions = DIGITALOCEAN_REGIONS    
    q = ask_question([
        inquirer.List(
            'region',
              message="🌍 Select deployment region",
              choices=list(cloud_regions.keys()),
        )], 
        "Region not selected"
    )
    return cloud_regions[q['region']]


def confirm_droplet_size() -> None:
    """Confirm DigitalOcean droplet size """

    print(" ℹ️  's-1vcpu-1gb' is the smallest server available in all DigitalOcean regions.")
    print(" 💵  Pricing in Sept 2025 was listed at c.$6 USD per month for 1000GB traffic. ")
    print("     Please check DigitalOcean's website for up-to-date pricing information and region availability! \n")
    q = ask_question([
        inquirer.List(
            'droplet',
            message="Confirm server size",
            choices=["1vCPU | 1GB Memory | 25GB Storage -- 's-1vcpu-1gb'"]
        )]
    )
    return None


def set_vpn_name(region: str)-> str:
    """Set VPN server name with simple text input"""

    suggestion = f"wardrobe-vpn-{region}"

    q = ask_question([
        inquirer.Text(
            'vpn_name',
            message="Set name for your VPN server",
            default=suggestion
        )], "VPN name required"
    )
    if q["vpn_name"] == "":
        raise InputError("VPN name required")
    return q['vpn_name']


def set_ssh_key() -> Path:
    """Select or Generate Local SSH Key. Designed to be cross-platform"""
    
    dir = Path.home() / ".ssh"
    # Look up all public key files in the SSH directory
    ssh_options = []
    
    if dir.exists():
      for p in dir.glob("*.pub"):
        if Path(p).is_file():
          ssh_options.append(str(p))

    # Add option for creating a new key
    new_key_option = "Create new ssh key"
    ssh_options.append(new_key_option)
    
    q = ask_question([
        inquirer.List(
            'ssh_choice',
            message=(f"Select existing ssh key from {dir}, or create a new one"),
            choices= ssh_options
        )]
      )
    
    #Existing Key Selected
    if q['ssh_choice'] != new_key_option:
        validate_ssh_key(Path(q["ssh_choice"])) #returns none if successful... raises InputError on fail.
        print(f" ✅  SSH key verified: {q['ssh_choice']}") #single quote for fstr
        return Path(q["ssh_choice"])

    # Generate New Key
    if q['ssh_choice'] == new_key_option:
        q_new_ssh = ask_question([
          inquirer.Text(
            'key_name',
            message=(f"Name your new ssh key (must be unique)"),
            default = "wardrobe-vpn-key"
          )]
        )

        q_new_ssh_pw = ask_question([
          inquirer.Text(
            'password',
            message=(f"(Optional): set a password for this key. (Press return to skip)"),
            default = ""
          )]
        )

        # Generate new SSH key
        print(f"✅ Generating new SSH key...")
        new_key_path = generate_ssh_key(q_new_ssh['key_name'], q_new_ssh_pw['password'])
        validate_ssh_key(new_key_path)

        print(f"✅ SSH key verified: {str(new_key_path)}")
        return new_key_path





# =============================================================================
# Data Collection Wizard
# =============================================================================
def collect_user_inputs():
    """Collect all user inputs for VPN deployment"""
    
    # 1. Set Provider
    cloud = select_cloud_provider() # Cloud provider

    # 2. Enter API Token
    api_key = get_digitalocean_auth() # API Key with validation 
    
    # 3. Check for Existing VPNs 
    try:
      print(f"\n👀 Checking for any existing VPN servers...")
      existing_vpns = find_existing_vpns(api_key)
    except InfraError as e:
        # Check Failure: warns, but allows you to continue
        print(f" {str(e)}")
        print(f" ℹ️  Wizard will continue, but you should check your token is valid and has appropriate scope / permissions \n")
        existing_vpns = []
    
    # 4. List VPNs + Ask before continuing
    print(f"🔍 Found {len(existing_vpns)} existing VPN(s) \n")
    if len(existing_vpns) > 0:
        for vpn in existing_vpns:
          print(f"  - {vpn}")

        print("\n")
        q_continue = ask_question([
          inquirer.Confirm(
            'continue',
            message="Existing VPNs found on your DigitalOcean account, do you wish to continue? (Nothing will be deployed yet!)",
            default=True
        )]
      )
        if not q_continue['continue']:
            raise UserCancelled('Cancelled after reviewing existing VPNs')

    # 5. Set Region 
    region = set_vpn_region()

    # 6. Confirm Server Size
    confirm_droplet_size() # Set to Nano

    # 7. Set Name
    vpn_name = set_vpn_name(region) # Set VPN Name 

    # 8. Set Key
    ssh_key_path: Path = set_ssh_key() # SSH Key config
    
    # Wizard End/Output
    return {
        'cloud': cloud,
        'vpn_name': vpn_name,
        'region': region,
        'api_key': api_key,
        'ssh_key_path': ssh_key_path,
    }


# =============================================================================
# Terraform - Generate Files, Plan, Deploy
# =============================================================================

def generate_terraform_config(config, admin_password = "") -> Path:
    """
    Generate Terraform files
    Success: Returns Path
    Failure: Raises Exception
    """
  
    # Get Template Paths
    template_dir = Path(__file__).parent.parent / "templates"
    main_template = template_dir / f"{config['cloud']}-main.tf.template"
    cloud_init_template = template_dir / f"{config['cloud']}-cloud-init.yaml.template"
    if not main_template.exists():
        raise InfraError(f"Terraform template not found: {main_template}")

    # Prepare Output Directory
    output_dir = Path("tf_output")
    if output_dir.exists():
        shutil.rmtree(output_dir, ignore_errors=True)
    output_dir.mkdir(exist_ok=True)
    
    # Time    
    now = datetime.now(timezone.utc).replace(microsecond=0)

    try:
      user_ip = get_user_ip()  
      ssh_key_content = config['ssh_key_path'].read_text().strip()
    
      # Template substitutions
      substitutions = {
          "REGION": config['region'],
          "TIMESTAMP": now.isoformat().replace("+00:00", "Z"), #ISO 8601
          "CREATED_AT": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
          "DEPLOYMENT_NAME": config['vpn_name'],  # Use user-chosen VPN name
          "SSH_PUBLIC_KEY": ssh_key_content,
          "YOUR_IP": user_ip,
          "ADMIN_PASSWORD": admin_password
      }
    
      # Generate main.tf
      tf_content = main_template.read_text()
      for placeholder, value in substitutions.items():
          tf_content = tf_content.replace(f"${{{placeholder}}}", value)
      (output_dir / "main.tf").write_text(tf_content)
    
      # Generate cloud-init.yaml
      cloud_init_content = cloud_init_template.read_text()
      for placeholder, value in substitutions.items():
          cloud_init_content = cloud_init_content.replace(f"${{{placeholder}}}", value)
      (output_dir / "digitalocean-cloud-init.yaml").write_text(cloud_init_content)

      # Return Path to directory
      return output_dir.resolve()

    except Exception as e:
        raise InfraError(f"Failed to generate Terraform files: {e}") from e



def plan_terraform_deployment(config, tf_directory) -> Path:
    """Plan terraform deployment -> creates .tfplan file and prints"""
    
    # Pass sensitive tokens as env vars
    env = os.environ.copy()
    env['TF_VAR_do_token'] = config['api_key']
    env['TF_VAR_ssh_key_fingerprint'] = config['ssh_key_fingerprint']
    
    try:    
        # Initialize terraform
        subprocess.run(["terraform", "init", "-upgrade"], cwd=tf_directory, check=True, capture_output=True, text=True, env=env)

        # Run terraform 'plan' action with tf files in directory
        plan_file = tf_directory.resolve() / "terraform.tfplan"
        subprocess.run([
            "terraform", "plan", "-out" , str(plan_file)
        ], cwd=tf_directory, check=True, capture_output=True, text=True, env=env)
        
        # Run terraform show plan (human readable)
        show_plan = subprocess.run([
            "terraform", "show", "-no-color", str(plan_file)
        ], cwd=tf_directory, check=True, capture_output=True, text=True
        )
        print("Review Terraform Plan:")
        print(show_plan.stdout)
        return plan_file

    # subprocess for using TF will raise FileNotFound if terraform is not on the system
    except FileNotFoundError:
        raise InfraError(f"Terraform not found. Install it and ensure it's on PATH.")

    # subprocess.run(check=True) raises CalledProcessError on non-zero exit—catch it to surface Terraform stderr/stdout without masking unrelated bugs.
    except subprocess.CalledProcessError as e:
        # stderr / stdout from terraform for easier debugging
        msg = e.stderr or e.stdout or str(e)
        raise InfraError(f"Terraform plan fail: {msg}") from e
    


def deploy_terraform(config, tf_directory, plan_file):
    """ Deploy Terraform Function """
    
    # Use terraform with API token as environment variable
    env = os.environ.copy()
    env['TF_VAR_do_token'] = config['api_key']
    env['TF_VAR_ssh_key_fingerprint'] = config['ssh_key_fingerprint']

    try:
        # Apply plan_file (deploys)   
        subprocess.run([
            "terraform", "apply", "-input=false", str(plan_file)
        ], cwd=tf_directory, check=True, capture_output=True, text=True, env=env)
        
        # Clean up plan file after successful apply
        if plan_file.exists():
            plan_file.unlink()

        # Get output
        output_result = subprocess.run([
            "terraform", "output", "-json"
        ], cwd=tf_directory, check=True, capture_output=True, text=True, env=env)
        
        outputs = json.loads(output_result.stdout)
        return outputs
            
    # subprocess for using TF will raise FileNotFound if terraform is not on the system
    except FileNotFoundError:
        raise InfraError(f"Terraform not found. Install it and ensure it's on PATH.")

    # subprocess.run(check=True) raises CalledProcessError on non-zero exit—catch it to surface Terraform stderr/stdout without masking unrelated bugs.
    except subprocess.CalledProcessError as e:
        # stderr / stout from terraform for easier debugging
        msg = e.stderr or e.stdout or str(e)
        raise InfraError(f"Terraform deployment failed: {msg}") from e



# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Wardrobe VPN Management CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
          Examples:
            python wardrobe-cli.py
            python wardrobe-cli.py --help
              """
    )
    
    args = parser.parse_args()
    
    # Run interactive setup
    try:
        # === 0. Print Welcome + Health Warnings ===
        print_welcome()

        # === 1. Collect all user inputs + check existing infra ===
        config = collect_user_inputs()


        # === 2. Review Input + Confirm ===
        print_review_configuration(config)
        q_continue = ask_question([
            inquirer.Confirm(
                'confirm',
                message="Continue with Planning? " \
                        "\n  This step will create TF files locally and register your SSH key on DigitalOcean." \
                        "\n  This step will *NOT* deploy!",
                default=True
            )], 
            "Setup cancelled by user at review step"
        )
        if not q_continue['confirm']:
            raise UserCancelled("Cancelled at review step")
      

        # === 3. Generate Terraform files + Register SSH Key on Do ===
        print("📁  Preparing Terraform configuration...")
        
        # 3b Check / Register SSH key + Update Config for TF
        try:  
          key_name = Path(config['ssh_key_path']).stem
          fp = set_do_ssh_key(config['api_key'], config['ssh_key_path'], key_name)
          config['ssh_key_fingerprint'] = fp

        except Exception as e:
            raise InfraError(f"SSH key registration with DO failed: {e}") from e

        admin_password = generate_admin_password()
        terraform_dir = generate_terraform_config(config, admin_password) 
        

        # === 4. Plan terraform deployment - Generates .tfplan file and displays to user ===
        print("🖊️  Planning Terraform deployment...")
        plan_file = plan_terraform_deployment(config, terraform_dir)


        # 4b. Show TF plan summary
        print("*" * 50)
        print("\nFull Terraform Plan printed above. Summary below")
        show_json = subprocess.run(
            ["terraform", "show", "-json", str(plan_file)],
            cwd=terraform_dir,
            check=True,
            capture_output=True,
            text=True
        )
        plan_json = json.loads(show_json.stdout)
        print_tf_plan_summary(plan_json)


        # === 5. Confirm + Deploy ===
        q_deploy = ask_question([
            inquirer.Confirm(
            'deploy',
            message=(f"⚠️  Create VPN? \n "\
                     "   This will deploy the above resources on your DigitalOcean Account. "),
            default=False
        )], "Cancelled before deployment"
        )
        if q_deploy['deploy'] == False:
          print(f" Deployment Cancelled")
          sys.exit(0)
        
        # Deploy VPN with Terraform
        print("☁️  Deploying infrastructure... (this may take several minutes)")
        deploy_output = deploy_terraform(config, terraform_dir, plan_file)
        
        # === 6. Wait for Admin UI: DO firewall can take 1-2m to attach ===
        server_ip = deploy_output["vpn_server_ip"]["value"]
        print("🚀  Server running...")
        print("⏳  Installing VPN & Updates...")
        print("⌚︎  Waiting for Admin UI to respond (usually takes 1-2 min)... ")
        if wait_for_http(server_ip, port=51821, total_timeout=180, interval=3.0):
            print("✅  Admin UI is ready!")
        else:
            print("⚠️  Admin UI not reachable yet; it may appear shortly. You can retry: curl -I http://" + server_ip + ":51821/")

        # Extract IP address from terraform output
        print("📊  Retrieving deployment information...")
        print_vpn_details(server_ip, admin_password, config['cloud'])
        
        # === 7. Offer to clean up sensitive files ===
        q_cleanup = ask_question([
            inquirer.Confirm(
                'cleanup',
                message=f"Clean up terraform files? (Recommended!)",
                default=True
            )
        ])
        
        if q_cleanup['cleanup'] == True:
            try:
                shutil.rmtree(terraform_dir)
                print(f"✅ Cleaned up directory")
            except Exception as e:
                print(f"⚠️  Could not clean up: {e}")
        else:
            print(f"⚠️  Terraform files kept in dir - remember to delete manually!")
        
        sys.exit(0)
    

    # Display + handle Raised Exceptions
    except KeyboardInterrupt:
        print("\n ❌ Setup interrupted by user")
        sys.exit(0)

    except UserCancelled as e:
        print(f"\n ❌ User cancelled: {e}")
        sys.exit(0)

    except InputError as e:
        print(f"\n ❌ Error Invalid Input: \n {e}")
        sys.exit(2)

    except InfraError as e:
        print(f"\n ❌ Infrastructure / Terraform Error: \n {e}")
        sys.exit(3)

    except WardrobeError as e:
        print(f"\n ❌ WardrobeVPN Error: {e}")
        sys.exit(1)

    except Exception as e:
        print(f"\n ❌ Unexpected error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
