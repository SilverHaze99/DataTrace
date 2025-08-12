#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utility Functions for Metadata Extraction
Provides helper functions for entropy calculation, file size formatting, and language detection.
"""
import math
import random
from pathlib import Path
try:
    import langdetect
    LANGDETECT_AVAILABLE = True
except ImportError:
    LANGDETECT_AVAILABLE = False

def calculate_entropy(filepath: Path, sample_size: int = 65536) -> float:
    """Calculate Shannon entropy with random sampling for large files.
    Forensic relevance: High entropy may indicate encrypted or hidden data."""
    try:
        byte_counts = [0] * 256
        total_bytes = 0
        file_size = filepath.stat().st_size
        if file_size > sample_size:
            sample_positions = random.sample(range(file_size), min(10, file_size // 4096))
            with open(filepath, 'rb') as f:
                for pos in sample_positions:
                    f.seek(pos)
                    chunk = f.read(min(4096, sample_size // len(sample_positions)))
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total_bytes += 1
        else:
            with open(filepath, 'rb') as f:
                while total_bytes < sample_size:
                    chunk = f.read(min(4096, sample_size - total_bytes))
                    if not chunk:
                        break
                    for byte in chunk:
                        byte_counts[byte] += 1
                        total_bytes += 1
        if total_bytes == 0:
            return 0.0
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        return entropy
    except Exception:
        return 0.0

def human_readable_size(size_bytes: int) -> str:
    """Convert bytes to human readable format."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"

def calculate_data_entropy(data: bytes) -> float:
    """Calculate entropy for a data chunk."""
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy

def get_jpeg_marker_name(marker_type: int) -> str:
    """Get human-readable JPEG marker names with extended APP markers."""
    markers = {
        0xd8: 'SOI (Start of Image)',
        0xd9: 'EOI (End of Image)',
        0xda: 'SOS (Start of Scan)',
        0xdb: 'DQT (Quantization Table)',
        0xc0: 'SOF0 (Baseline DCT)',
        0xc1: 'SOF1 (Extended Sequential DCT)',
        0xc2: 'SOF2 (Progressive DCT)',
        0xc4: 'DHT (Huffman Table)',
        0xe0: 'APP0 (JFIF)',
        0xe1: 'APP1 (EXIF/XMP)',
        0xe2: 'APP2 (ICC Profile)',
        0xe3: 'APP3 (Meta)',
        0xe4: 'APP4 (Extended Meta)',
        0xe5: 'APP5 (Custom)',
        0xe6: 'APP6 (NITF)',
        0xe7: 'APP7 (JPEG Extensions)',
        0xe8: 'APP8 (SPIFF)',
        0xe9: 'APP9 (SPIFF Directory)',
        0xea: 'APP10 (Custom)',
        0xeb: 'APP11 (Custom)',
        0xec: 'APP12 (Picture Info)',
        0xed: 'APP13 (Photoshop)',
        0xee: 'APP14 (Adobe)',
        0xef: 'APP15 (Graphic Technology)',
        0xfe: 'COM (Comment)',
    }
    return markers.get(marker_type, f'Unknown (0x{marker_type:02X})')

def detect_languages(text: str) -> list[str]:
    """Detect languages using langdetect or heuristic fallback."""
    if not text:
        return []
    if LANGDETECT_AVAILABLE:
        try:
            from langdetect import detect_langs
            langs = detect_langs(text[:1000])
            return [f"{lang.lang} ({lang.prob:.2f})" for lang in langs[:3]]
        except:
            pass
    languages = []
    if any(char in text for char in 'äöüßÄÖÜ'):
        languages.append('German')
    if any(word in text.lower() for word in ['the', 'and', 'or', 'but', 'with']):
        languages.append('English')
    if any(char in text for char in 'àâäéèêëïîôöùûüÿçÀÂÄÉÈÊËÏÎÔÖÙÛÜŸÇ'):
        languages.append('French')
    if any(char in text for char in 'áéíñóúüÁÉÍÑÓÚÜ'):
        languages.append('Spanish')
    if any(char in text for char in 'аеёиоуыэюяАЕЁИОУЫЭЮЯ'):
        languages.append('Russian')
    return languages[:3]