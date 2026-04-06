#!/usr/bin/env python3

# Usage: python3 NFR.py --yaml request.yaml --concurrency 20

import asyncio
import argparse
import sys
from typing import Dict, Any
import yaml
import httpx
from colorama import init, Fore, Style

init(autoreset=True)

def color_status(status_code: int) -> str:
    if 200 <= status_code < 300:
        return f"{Fore.GREEN}{status_code}{Style.RESET_ALL}"
    elif 300 <= status_code < 400:
        return f"{Fore.YELLOW}{status_code}{Style.RESET_ALL}"
    elif 400 <= status_code < 500:
        return f"{Fore.RED}{status_code}{Style.RESET_ALL}"
    else:
        return f"{Fore.MAGENTA}{status_code}{Style.RESET_ALL}"

async def send_req(client: httpx.AsyncClient, req: Dict[str, Any], idx: int):
    method = req["method"].upper()
    url = req["url"]
    headers = req.get("headers", {})
    headers = {k: str(v) for k, v in headers.items()} # Convert headers dict to plain dict
    body = req.get("body")
    
    kwargs = {
        "method": method,
        "url": url,
        "headers": headers,
        "timeout": 10.0
    }
    
    if body:
        if isinstance(body, (dict, list)):
            kwargs["json"] = body
        else:
            kwargs["content"] = body

    try:
        resp = await client.request(**kwargs)
        print(f"request {idx:3d} -> {color_status(resp.status_code)} {resp.reason_phrase or ''}")
    except Exception as e:
        print(f"request {idx:3d} -> {Fore.RED}ERROR: {e}{Style.RESET_ALL}")


async def race(req: Dict[str, Any], concurrency: int):
    async with httpx.AsyncClient(http2=False, verify=False) as client:
        tasks = [send_req(client, req, i+1) for i in range(concurrency)]
        await asyncio.gather(*tasks)

def load_yaml(yaml_path: str) -> Dict[str, Any]:
    with open(yaml_path, "r") as f:
        data = yaml.safe_load(f)
    if 'method' not in data or 'url' not in data:
        raise ValueError("YAML file must contain 'method' and 'url' keys")
    return data

def main():
    parser = argparse.ArgumentParser(description="NFR - NEED FOR RACE")
    parser.add_argument("--yaml", required=True, help="Path to YAML file")
    parser.add_argument("-c", "--concurrency", type=int, default=10, help="Concurrency level (default: 10)")
    args = parser.parse_args()

    if args.yaml.endswith(".yaml") or args.yaml.endswith(".yml"):
        req = load_yaml(args.yaml)
        print(f"{Fore.CYAN}Race {req['method']} {req['url']}{Style.RESET_ALL}")
        asyncio.run(race(req, args.concurrency))
    else:
        print(f"{Fore.RED}Error: YAML file must end with .yaml or .yml{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main()