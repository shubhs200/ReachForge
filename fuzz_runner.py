#!/usr/bin/env python3
"""
Fuzz runner that executes the compiled harness with generated seeds.
Converts seeds.json to corpus directory and runs the fuzzer.
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple


def decode_seed_content(content: str, encoding: str) -> bytes:
    """Decode seed content based on encoding type."""
    if encoding == "base64":
        return base64.b64decode(content)
    elif encoding == "hex":
        return bytes.fromhex(content)
    elif encoding == "utf8":
        return content.encode("utf-8")
    else:
        # Default to utf-8
        return content.encode("utf-8")


def validate_seed(seed: dict, index: int) -> tuple:
    """
    Validate a single seed entry.
    Returns (is_valid, decoded_content, error_message).
    """
    # Check required fields
    if not isinstance(seed, dict):
        return False, None, "Seed " + str(index) + " is not a dict"
    
    name = seed.get("name", "seed_" + str(index))
    content = seed.get("content")
    encoding = seed.get("encoding", "utf8")
    
    if not content:
        return False, None, "Seed '" + str(name) + "' missing 'content'"
    
    if encoding not in ("base64", "hex", "utf8"):
        return False, None, "Seed '" + str(name) + "' has invalid encoding: " + str(encoding)
    
    # Try to decode
    try:
        decoded = decode_seed_content(content, encoding)
        if len(decoded) == 0:
            return False, None, "Seed '" + str(name) + "' decoded to empty content"
        return True, decoded, None
    except Exception as e:
        return False, None, "Seed '" + str(name) + "' decode error: " + str(e)


def create_corpus_from_seeds(seeds_path: Path, corpus_dir: Path) -> int:
    """
    Create a corpus directory from seeds.json.
    Returns the number of seeds written.
    """
    corpus_dir.mkdir(parents=True, exist_ok=True)
    
    if not seeds_path.exists():
        print("No seeds file found at " + str(seeds_path) + ", using empty corpus")
        return 0
    
    # Try to read and parse JSON
    try:
        raw_content = seeds_path.read_text(encoding='utf-8')
        
        # Try to fix common JSON issues
        raw_content = raw_content.strip()
        if not raw_content.startswith('{'):
            print("Seeds file doesn't start with JSON object, trying to extract...")
            # Try to find JSON in the content
            import re
            match = re.search(r'\{[\s\S]*\}', raw_content)
            if match:
                raw_content = match.group(0)
        
        data = json.loads(raw_content)
    except json.JSONDecodeError as e:
        print("Error parsing seeds JSON: " + str(e))
        print("Creating default seed corpus...")
        return create_default_corpus(corpus_dir)
    except Exception as e:
        print("Error reading seeds file: " + str(e))
        return create_default_corpus(corpus_dir)
    
    seeds = data.get("seeds", [])
    if not isinstance(seeds, list):
        print("'seeds' is not a list, creating default corpus")
        return create_default_corpus(corpus_dir)
    
    count = 0
    for i, seed in enumerate(seeds):
        is_valid, decoded, error = validate_seed(seed, i)
        
        if not is_valid:
            print("  Skipping invalid seed: " + str(error))
            continue
        
        name = seed.get("name", "seed_" + str(i))
        safe_name = "".join(c if c.isalnum() or c in "_-" else "_" for c in name)
        
        seed_path = corpus_dir / (safe_name + "_" + str(i))
        seed_path.write_bytes(decoded)
        count += 1
        print("  Wrote seed: " + str(seed_path.name) + " (" + str(len(decoded)) + " bytes)")
    
    if count == 0:
        print("No valid seeds found, creating default corpus")
        return create_default_corpus(corpus_dir)
    
    return count


def create_default_corpus(corpus_dir: Path) -> int:
    """
    Create a minimal default corpus for JSON parsing.
    Returns number of seeds created.
    """
    corpus_dir.mkdir(parents=True, exist_ok=True)
    
    # Default JSON seeds for parsing
    default_seeds = [
        b'{}',
        b'[]',
        b'null',
        b'true',
        b'false',
        b'123',
        b'"hello"',
        b'{"key":"value"}',
        b'[1,2,3]',
        b'{"nested":{"key":1}}',
    ]
    
    for i, content in enumerate(default_seeds):
        seed_path = corpus_dir / ("default_" + str(i))
        seed_path.write_bytes(content)
        print("  Created default seed: " + str(seed_path.name) + " (" + str(len(content)) + " bytes)")
    
    return len(default_seeds)


def run_fuzzer(
    harness_binary: Path,
    corpus_dir: Path,
    output_dir: Path,
    runs: int = 0,  # 0 means unlimited
    max_time: int = 60,
    timeout: int = 10,
    max_len: Optional[int] = None,
    extra_args: Optional[List[str]] = None
) -> Tuple[int, str, Optional[Path]]:
    """
    Run the fuzzer with the given corpus.
    
    Returns:
        (return_code, output, crash_file_path)
    """
    # Simple command: just harness + corpus directory
    # LibFuzzer will run with defaults
    cmd = [str(harness_binary), str(corpus_dir)]
    
    # Add optional fuzzer flags if specified
    if runs > 0:
        cmd.append("-runs=" + str(runs))
    if max_time > 0:
        cmd.append("-max_total_time=" + str(max_time))
    cmd.append("-timeout=" + str(timeout))
    
    if max_len:
        cmd.append("-max_len=" + str(max_len))
    
    # Add extra arguments
    if extra_args:
        cmd.extend(extra_args)
    
    print("Running fuzzer: " + ' '.join(cmd))
    
    # Create crash output directory
    crash_dir = output_dir / "crashes"
    crash_dir.mkdir(parents=True, exist_ok=True)
    
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
    env["UBSAN_OPTIONS"] = "abort_on_error=1"
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=max_time + 30,  # Extra buffer for cleanup
            env=env,
            cwd=str(output_dir)
        )
        return_code = result.returncode
        output = result.stdout + "\n" + result.stderr
        
    except subprocess.TimeoutExpired as e:
        return_code = -1
        output = "Fuzzer timed out after " + str(max_time + 30) + " seconds"
    
    elapsed = time.time() - start_time
    print("Fuzzer finished in " + str(elapsed) + " seconds with return code " + str(return_code))
    
    # Check for crash files
    crash_file = None
    for f in output_dir.iterdir():
        if f.name.startswith("crash-") or f.name.startswith("timeout-"):
            crash_file = f
            print("Crash file found: " + str(f))
            break
    
    # Also check crash_dir
    if not crash_file:
        for f in crash_dir.iterdir():
            if f.name.startswith("crash-") or f.name.startswith("timeout-"):
                crash_file = f
                print("Crash file found: " + str(f))
                break
    
    return return_code, output, crash_file


def analyze_crash(crash_file: Path, harness_binary: Path) -> str:
    """Analyze a crash file to get stack trace."""
    try:
        # Run the harness with the crash input to get stack trace
        result = subprocess.run(
            [str(harness_binary), str(crash_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=30
        )
        return result.stderr or result.stdout
    except Exception as e:
        return "Could not analyze crash: " + str(e)


def main():
    parser = argparse.ArgumentParser(description="Run fuzzer with generated seeds")
    parser.add_argument("--harness", required=True, help="Path to compiled harness binary")
    parser.add_argument("--seeds", required=True, help="Path to seeds.json")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--runs", type=int, default=1000, help="Number of fuzzing runs")
    parser.add_argument("--max-time", type=int, default=60, help="Max fuzzing time in seconds")
    parser.add_argument("--timeout", type=int, default=10, help="Per-input timeout")
    parser.add_argument("--max-len", type=int, help="Max input length")
    args = parser.parse_args()
    
    harness_path = Path(args.harness).resolve()
    seeds_path = Path(args.seeds).resolve()
    output_dir = Path(args.out).resolve()
    
    if not harness_path.exists():
        print("Error: Harness not found at " + str(harness_path))
        sys.exit(1)
    
    # Create corpus from seeds
    print("Creating corpus from seeds...")
    corpus_dir = output_dir / "corpus"
    seed_count = create_corpus_from_seeds(seeds_path, corpus_dir)
    
    if seed_count == 0:
        print("Warning: No seeds created, using empty corpus")
    
    # Run fuzzer
    print("\nStarting fuzzer (runs=" + str(args.runs) + ", max_time=" + str(args.max_time) + "s)...")
    return_code, output, crash_file = run_fuzzer(
        harness_path,
        corpus_dir,
        output_dir,
        runs=args.runs,
        max_time=args.max_time,
        timeout=args.timeout,
        max_len=args.max_len
    )
    
    # Report results
    print("\n" + "=" * 60)
    print("FUZZING RESULTS")
    print("=" * 60)
    
    if crash_file:
        print("\nWARNING: CRASH DETECTED!")
        print("Crash file: " + str(crash_file))
        print("\nStack trace:")
        print(analyze_crash(crash_file, harness_path))
    elif return_code != 0:
        print("\nWARNING: Fuzzer exited with code " + str(return_code))
        print("\nOutput:")
        print(output[-2000:])  # Last 2000 chars
    else:
        print("\n✓ No crashes detected during fuzzing")
    
    # Save results
    results = {
        "return_code": return_code,
        "seed_count": seed_count,
        "crash_detected": crash_file is not None,
        "crash_file": str(crash_file) if crash_file else None,
        "runs": args.runs,
        "max_time": args.max_time
    }
    
    results_path = output_dir / "fuzz_results.json"
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)
    print("\nResults saved to " + str(results_path))
    
    return 1 if crash_file else 0


if __name__ == "__main__":
    sys.exit(main())