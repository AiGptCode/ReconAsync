#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
recon_async.py v1.0.0 | Advanced Asynchronous Reconnaissance Tool
Usage: python recon_async.py <target-domain> [--url <example-url>] [--proxy <proxy-url>] [--format <txt|json|csv>] [--rate-limit <rps>]
Features: Subdomain enumeration, URL discovery, HTTP probing, parameter discovery, directory brute-forcing
Author: AIGPTCODE | License: MIT 
"""
 
import asyncio
import logging
import argparse
import os
import sys
import subprocess
import shutil
import platform
import json
import csv
from pathlib import Path
from datetime import datetime

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(), logging.FileHandler("recon.log")])
logger = logging.getLogger(__name__)

# Tool configurations
GO_TOOLS = {"subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest", "assetfinder": "github.com/tomnomnom/assetfinder@latest",
            "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest", "gobuster": "github.com/OJ/gobuster/v3@latest",
            "gau": "github.com/lc/gau/v2/cmd/gau@latest", "waybackurls": "github.com/tomnomnom/waybackurls@latest"}
PYPI_TOOLS = {"dirsearch": "dirsearch", "paramspider": "paramspider"}
OUTPUT_DIR = "output"
WORDLIST = "/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt" if platform.system().lower().startswith("linux") else r"C:\wordlists\directory-list-lowercase-2.3-medium.txt"
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")

def ensure_tools_installed():
    """Ensure all tools are installed and add Go binary paths to PATH."""
    if not shutil.which("go"): logger.error("Go not installed. Install manually."); sys.exit(1)
    # Add GOBIN and GOPATH/bin to PATH
    gobin = os.environ.get("GOBIN", os.path.join(os.environ.get("HOME", ""), "go", "bin"))
    gopath_bin = os.path.join(os.environ.get("GOPATH", os.path.join(os.environ.get("HOME", ""), "go")), "bin")
    for path in [gobin, gopath_bin]:
        if path and os.path.isdir(path) and path not in os.environ.get("PATH", ""):
            os.environ["PATH"] += os.pathsep + path
            logger.info(f"Added {path} to PATH.")
    # Install tools
    for tool, pkg in GO_TOOLS.items():
        if not shutil.which(tool):
            try:
                subprocess.run(["go", "install", pkg], check=True, capture_output=True)
                logger.info(f"{tool} installed.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install {tool}: {e.stderr.decode().strip()}"); sys.exit(1)
    for tool, pkg in PYPI_TOOLS.items():
        if not shutil.which(tool):
            try:
                subprocess.run(["pip3", "install", pkg], check=True, capture_output=True)
                logger.info(f"{tool} installed.")
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to install {tool}: {e.stderr.decode().strip()}"); sys.exit(1)

async def run_tool(cmd: list[str], outfile: str = None, proxy: str = None, rate_limiter: asyncio.Semaphore = None) -> None:
    """Run a tool asynchronously with rate limiting."""
    async with rate_limiter:
        if proxy: cmd.extend(["--proxy", proxy] if "gobuster" in cmd[0] else ["--http-proxy", proxy] if "httpx" in cmd[0] else [])
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0: logger.warning(f"{cmd[0]} failed: {stderr.decode().strip()}")
        elif outfile: Path(outfile).write_text(stdout.decode().strip() + "\n", encoding="utf-8"); logger.info(f"Output saved: {outfile}")

def save_output(data: list, outfile: str, format_type: str) -> None:
    """Save data in specified format."""
    with open(outfile, "w", encoding="utf-8") as f:
        if format_type == "txt": f.write("\n".join(data) + "\n")
        elif format_type == "json": json.dump(data, f, indent=2)
        elif format_type == "csv": csv.writer(f).writerows([d.split(",") if isinstance(d, str) else d for d in data])
    logger.info(f"Saved {format_type.upper()} output: {outfile}")

def merge_unique_lines(files: list[str], outfile: str, format_type: str) -> None:
    """Merge unique lines from files."""
    merged = set()
    for f in files:
        if Path(f).exists(): merged.update(line.strip() for line in Path(f).read_text(encoding="utf-8").splitlines() if line.strip())
    save_output(sorted(merged), outfile, format_type)

async def main(domain: str, url: str = None, proxy: str = None, format_type: str = "txt", rate_limit: int = 10):
    """Main reconnaissance workflow."""
    Path(OUTPUT_DIR).mkdir(exist_ok=True); ensure_tools_installed(); rate_limiter = asyncio.Semaphore(rate_limit)
    logger.info(f"Starting recon for {domain} at 2025-06-01 03:58 AM EEST")

    # Subdomain enumeration
    subfinder_file = f"{OUTPUT_DIR}/subfinder_{domain}_{TIMESTAMP}.{format_type}"
    assetfinder_file = f"{OUTPUT_DIR}/assetfinder_{domain}_{TIMESTAMP}.{format_type}"
    await asyncio.gather(
        run_tool(["subfinder", "-d", domain, "-o", subfinder_file], subfinder_file, proxy, rate_limiter),
        run_tool(["assetfinder", domain], assetfinder_file, proxy, rate_limiter)
    )
    merged_subdomains = f"{OUTPUT_DIR}/subdomains_{domain}_{TIMESTAMP}.{format_type}"
    merge_unique_lines([subfinder_file, assetfinder_file], merged_subdomains, format_type)

    # URL discovery
    gau_file = f"{OUTPUT_DIR}/gau_{domain}_{TIMESTAMP}.{format_type}"
    wayback_file = f"{OUTPUT_DIR}/waybackurls_{domain}_{TIMESTAMP}.{format_type}"
    await asyncio.gather(
        run_tool(["gau", domain], gau_file, proxy, rate_limiter),
        run_tool(["waybackurls", domain], wayback_file, proxy, rate_limiter)
    )
    merged_urls = f"{OUTPUT_DIR}/urls_{domain}_{TIMESTAMP}.{format_type}"
    merge_unique_lines([gau_file, wayback_file], merged_urls, format_type)

    # HTTP probing
    httpx_input = f"{OUTPUT_DIR}/httpx_input_{domain}_{TIMESTAMP}.{format_type}"
    httpx_output = f"{OUTPUT_DIR}/httpx_{domain}_{TIMESTAMP}.{format_type}"
    merge_unique_lines([merged_subdomains, merged_urls], httpx_input, format_type)
    await run_tool(["httpx", "-list", httpx_input, "-o", httpx_output, "-silent", "-json" if format_type == "json" else "-csv", "-sc", "-ip", "-location", "-title", "-tech-detect", "-threads", "50"], proxy=proxy, rate_limiter=rate_limiter)

    # Parameter discovery
    await run_tool(["paramspider", "-d", domain, "-o", f"{OUTPUT_DIR}/paramspider_{domain}_{TIMESTAMP}.{format_type}"], proxy=proxy, rate_limiter=rate_limiter)

    # Directory brute-forcing
    if url:
        if not os.path.isfile(WORDLIST): logger.warning(f"Wordlist missing: {WORDLIST}"); return
        await asyncio.gather(
            run_tool(["gobuster", "dir", "-u", url, "-w", WORDLIST, "-t", "30", "-x", "php,html,js,txt,json,asp,aspx,jsp", "-o", f"{OUTPUT_DIR}/gobuster_{url.replace('/', '_')}_{TIMESTAMP}.{format_type}"], proxy=proxy, rate_limiter=rate_limiter),
            run_tool(["python3", "-m", "dirsearch.dirsearch", "-u", url, "-w", WORDLIST, "-e", "php,html,js,txt,json,asp,aspx,jsp", "-t", "30", "-o", f"{OUTPUT_DIR}/dirsearch_{url.replace('/', '_')}_{TIMESTAMP}.{format_type}"], proxy=proxy, rate_limiter=rate_limiter)
        )
    logger.info("Recon completed. Ensure you have permission to scan the target.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reconnaissance Tool")
    parser.add_argument("domain", help="Target domain")
    parser.add_argument("--url", help="URL for dir brute-forcing")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://proxy:8080)")
    parser.add_argument("--format", choices=["txt", "json", "csv"], default="txt", help="Output format")
    parser.add_argument("--rate-limit", type=int, default=10, help="Requests per second")
    args = parser.parse_args()
    print("Recon Async v1.0.0 | Use responsibly with permission only.")
    try: asyncio.run(main(args.domain, args.url, args.proxy, args.format, args.rate_limit))
    except Exception as e: logger.error(f"Error: {e}"); sys.exit(1)
