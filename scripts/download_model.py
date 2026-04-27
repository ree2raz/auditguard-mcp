#!/usr/bin/env python3
"""Download Privacy Filter model to a local directory.

Usage:
  python scripts/download_model.py                    # Download to ./models/
  python scripts/download_model.py /path/to/models  # Download to custom path

The downloaded model can then be mounted into Docker:
  docker run -v ./models:/app/model -e PRIVACY_FILTER_LOCAL_PATH=/app/model ...
"""

import argparse
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Download Privacy Filter model locally")
    parser.add_argument(
        "output_dir",
        nargs="?",
        default="models",
        help="Output directory for model files (default: ./models)",
    )
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_name = "openai/privacy-filter"

    print(f"Downloading {model_name} to {output_dir}...")
    print("This may take a few minutes (model is ~3GB)")

    try:
        from huggingface_hub import snapshot_download
    except ImportError:
        print("ERROR: huggingface-hub not installed.")
        print("Install with: pip install huggingface-hub")
        sys.exit(1)

    # Download all model files (config, tokenizer, weights)
    snapshot_download(
        repo_id=model_name,
        local_dir=output_dir,
        local_dir_use_symlinks=False,
    )

    print(f"\n✓ Model downloaded to {output_dir}/")
    print(f"\nTo use with Docker:")
    print(f"  docker run -v {output_dir.absolute()}:/app/model \\")
    print(f"    -e PRIVACY_FILTER_LOCAL_PATH=/app/model \\")
    print(f"    auditguard-mcp:local")
    print(f"\nTo use locally:")
    print(f"  export PRIVACY_FILTER_LOCAL_PATH={output_dir.absolute()}")


if __name__ == "__main__":
    main()
