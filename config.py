#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration Module for Metadata Extraction
Defines the Config class and utility function to create configuration from CLI arguments.
"""
from pathlib import Path
from typing import Optional

class Config:
    """Configuration class to hold analysis parameters."""
    def __init__(self):
        self.max_file_size_mb: int = 100  # Maximum file size to process (MB)
        self.chunk_size: int = 8192  # Buffer size for file reading
        self.max_workers: int = 4  # Number of threads for parallel processing
        self.timeout_seconds: int = 30  # Timeout per file analysis
        self.min_string_length: int = 4  # Minimum length for extracted strings
        self.max_strings: int = 1000  # Maximum number of strings to extract
        self.enable_steganography: bool = True  # Enable steganography detection
        self.max_memory_mb: int = 100  # Maximum memory for string extraction (MB)
        self.cache_dir: Path = Path.home() / ".metadata_extractor_cache"  # Cache directory
        self.deep_analysis: bool = False  # Enable deep analysis mode

def create_config_from_args(args) -> Config:
    """Create Config object from command-line arguments."""
    config = Config()
    config.max_workers = args.workers
    config.timeout_seconds = args.timeout
    config.min_string_length = args.min_string_length
    config.max_strings = args.max_strings
    config.enable_steganography = not args.no_stego
    config.deep_analysis = args.deep
    # Ensure cache directory exists
    if not config.cache_dir.exists():
        config.cache_dir.mkdir(parents=True, exist_ok=True)
    return config