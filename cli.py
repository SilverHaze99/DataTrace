#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command Line Interface for Metadata Extraction
Handles user input, output formatting, and progress display.
"""
import argparse
import json
import csv
import logging
import sys
from pathlib import Path
from typing import Dict, List, Union, Any
try:
    from colorama import init, Fore, Style
    init()
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class MockColors:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
        RESET = BRIGHT = RESET_ALL = ""
    class MockFore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = ""
    class MockStyle:
        RESET_ALL = BRIGHT = ""
    Fore = MockFore()
    Style = MockStyle()

from metadata_extractor import MetadataExtractor
from config import Config, create_config_from_args

def setup_logging(level: int = logging.INFO, log_file: str = None) -> logging.Logger:
    """Setup structured logging with file and console output."""
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger('MetadataExtractor')
    logger.setLevel(level)
    logger.handlers = []  # Clear existing handlers
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger

class ProgressBar:
    """Simple progress bar for CLI with percentage display."""
    def __init__(self, total: int, width: int = 50):
        self.total = total
        self.width = width
        self.current = 0
    def update(self, increment: int = 1):
        self.current += increment
        self.display()
    def display(self):
        if not sys.stdout.isatty():
            return
        percent = min(100, (self.current / self.total) * 100)
        filled = int(self.width * percent / 100)
        bar = '█' * filled + '░' * (self.width - filled)
        color = Fore.GREEN if percent == 100 else Fore.CYAN
        print(f'\r{color}[{bar}] {percent:.1f}%{Style.RESET_ALL}', end='', flush=True)
        if percent == 100:
            print()

def print_banner():
    """Print cool ASCII banner."""
    banner = f"""
{Fore.CYAN}╔═════════════════════════════════════════════════════════════════════════════╗
║                                                                             ║
║  {Fore.YELLOW}██████╗  █████╗ ████████╗ █████╗ ████████╗██████╗  █████╗  ██████╗███████╗{Fore.CYAN} ║
║  {Fore.YELLOW}██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝{Fore.CYAN} ║
║  {Fore.YELLOW}██║  ██║███████║   ██║   ███████║   ██║   ██████╔╝███████║██║     █████╗  {Fore.CYAN} ║
║  {Fore.YELLOW}██║  ██║██╔══██║   ██║   ██╔══██║   ██║   ██╔══██╗██╔══██║██║     ██╔══╝  {Fore.CYAN} ║
║  {Fore.YELLOW}██████╔╝██║  ██║   ██║   ██║  ██║   ██║   ██║  ██║██║  ██║╚██████╗███████╗{Fore.CYAN} ║
║  {Fore.YELLOW}╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝{Fore.CYAN} ║
║                                                                             ║
║     {Fore.WHITE}Enhanced Metadata Extraction Tool v2.2{Fore.CYAN}                                  ║
║     {Fore.GREEN}Forensic Analysis • Steganography • Deep Inspection{Fore.CYAN}                     ║
║                                                                             ║
╚═════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def print_analysis_summary(results: Dict[str, Any], filepath: str, filter_types: List[str] = None):
    """Print colorized analysis summary with optional filtering."""
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"📁 ANALYSIS RESULTS: {Fore.YELLOW}{Path(filepath).name}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
    if (not filter_types or 'file_info' in filter_types) and 'file_info' in results:
        info = results['file_info']
        print(f"\n{Fore.CYAN}📋 File Information:{Style.RESET_ALL}")
        print(f"   Size: {info.get('size_human', 'Unknown')}")
        print(f"   Type: {info.get('mimetype', 'Unknown')}")
        print(f"   Modified: {info.get('modified', 'Unknown')}")
        if 'md5' in info:
            print(f"   MD5: {Fore.YELLOW}{info['md5']}{Style.RESET_ALL}")
        if 'crc32' in info:
            print(f"   CRC32: {Fore.YELLOW}{info['crc32']}{Style.RESET_ALL}")
    if (not filter_types or 'image_metadata' in filter_types) and 'image_metadata' in results:
        img_meta = results['image_metadata']
        print(f"\n{Fore.CYAN}🖼️ Image Metadata:{Style.RESET_ALL}")
        if 'image_info' in img_meta:
            img_info = img_meta['image_info']
            print(f"   📐 Dimensions: {img_info.get('width', 'Unknown')} x {img_info.get('height', 'Unknown')}")
            print(f"   🎨 Format: {img_info.get('format', 'Unknown')}")
            print(f"   🌈 Mode: {img_info.get('mode', 'Unknown')}")
            if img_info.get('has_transparency'):
                print(f"   ✨ Has transparency: {Fore.GREEN}Yes{Style.RESET_ALL}")
        exif_data = img_meta.get('exif_pil', {}) or img_meta.get('exif_detailed', {})
        if exif_data:
            print(f"   📷 EXIF Data found: {Fore.GREEN}{len(exif_data)} fields{Style.RESET_ALL}")
            key_fields = {
                'Make': '📱 Camera Brand',
                'Model': '📸 Camera Model',
                'DateTime': '📅 Date Taken',
                'GPS GPSLatitude': '🌍 GPS Latitude',
                'GPS GPSLongitude': '🌍 GPS Longitude',
                'Software': '💻 Software',
                'Artist': '👤 Artist/Author',
                'Copyright': '©️ Copyright',
                'FNumber': '🔍 Aperture',
                'ExposureTime': '⏱️ Shutter Speed',
                'ISOSpeedRatings': '📊 ISO',
            }
            shown_count = 0
            for field, description in key_fields.items():
                if field in exif_data and shown_count < 8:
                    value = str(exif_data[field])[:50]
                    print(f"      {description}: {Fore.YELLOW}{value}{Style.RESET_ALL}")
                    shown_count += 1
            if len(exif_data) > shown_count:
                print(f"      ... and {len(exif_data) - shown_count} more EXIF fields")
        else:
            print(f"   📷 EXIF Data: {Fore.RED}None found{Style.RESET_ALL}")
        if img_meta.get('icc_profile_present'):
            print(f"   🎨 ICC Profile: {Fore.GREEN}Present{Style.RESET_ALL} ({img_meta.get('icc_profile_size', 0)} bytes)")
        if 'color_analysis' in img_meta:
            color_info = img_meta['color_analysis']
            print(f"   🌈 Colors: {color_info.get('unique_colors', 'Unknown')} unique")
            if color_info.get('is_grayscale'):
                print(f"   ⚫ Grayscale: {Fore.YELLOW}Yes{Style.RESET_ALL}")
        if 'exiftool_metadata' in img_meta:
            exiftool_meta = img_meta['exiftool_metadata']
            print(f"   🛠️ ExifTool Metadata: {Fore.GREEN}Available{Style.RESET_ALL}")
            exiftool_keys = ['FileSize', 'FileModifyDate', 'FileType', 'MIMEType', 'ImageWidth', 'ImageHeight']
            for key in exiftool_keys:
                if key in exiftool_meta:
                    print(f"      {key}: {Fore.YELLOW}{exiftool_meta[key]}{Style.RESET_ALL}")
    if (not filter_types or 'audio_metadata' in filter_types) and 'audio_metadata' in results:
        audio_meta = results['audio_metadata']
        print(f"\n{Fore.BLUE}🎵 Audio Metadata:{Style.RESET_ALL}")
        if 'audio_info' in audio_meta:
            info = audio_meta['audio_info']
            length = info.get('length_seconds')
            if length:
                mins, secs = divmod(int(length), 60)
                print(f"   ⏱️ Duration: {mins}:{secs:02d}")
            print(f"   🔊 Bitrate: {info.get('bitrate', 'Unknown')} kbps")
            print(f"   📊 Sample Rate: {info.get('sample_rate', 'Unknown')} Hz")
            print(f"   🎵 Channels: {info.get('channels', 'Unknown')}")
        if 'common_tags' in audio_meta:
            tags = audio_meta['common_tags']
            for tag_name, value in tags.items():
                print(f"   {tag_name.title()}: {Fore.YELLOW}{str(value)[:50]}{Style.RESET_ALL}")
        if 'exiftool_metadata' in audio_meta:
            exiftool_meta = audio_meta['exiftool_metadata']
            print(f"   🛠️ ExifTool Metadata: {Fore.GREEN}Available{Style.RESET_ALL}")
            exiftool_keys = ['Duration', 'AudioBitrate', 'SampleRate', 'Channels', 'AudioFormat']
            for key in exiftool_keys:
                if key in exiftool_meta:
                    print(f"      {key}: {Fore.YELLOW}{exiftool_meta[key]}{Style.RESET_ALL}")
    if (not filter_types or 'pdf_metadata' in filter_types) and 'pdf_metadata' in results:
        pdf_meta = results['pdf_metadata']
        print(f"\n{Fore.RED}📄 PDF Metadata:{Style.RESET_ALL}")
        print(f"   📄 Pages: {pdf_meta.get('pages', 'Unknown')}")
        if pdf_meta.get('encrypted'):
            print(f"   🔒 Encrypted: {Fore.RED}Yes{Style.RESET_ALL}")
        if 'document_info' in pdf_meta:
            doc_info = pdf_meta['document_info']
            key_fields = ['Title', 'Author', 'Subject', 'Creator', 'Producer', 'CreationDate']
            for field in key_fields:
                if field in doc_info:
                    print(f"   {field}: {Fore.YELLOW}{str(doc_info[field])[:50]}{Style.RESET_ALL}")
        if 'exiftool_metadata' in pdf_meta:
            exiftool_meta = pdf_meta['exiftool_metadata']
            print(f"   🛠️ ExifTool Metadata: {Fore.GREEN}Available{Style.RESET_ALL}")
            exiftool_keys = ['Title', 'Author', 'Creator', 'Producer', 'CreateDate', 'ModifyDate']
            for key in exiftool_keys:
                if key in exiftool_meta:
                    print(f"      {key}: {Fore.YELLOW}{exiftool_meta[key]}{Style.RESET_ALL}")
    if (not filter_types or 'archive_metadata' in filter_types) and 'archive_metadata' in results:
        arch_meta = results['archive_metadata']
        print(f"\n{Fore.YELLOW}📦 Archive Metadata:{Style.RESET_ALL}")
        if 'archive_info' in arch_meta:
            info = arch_meta['archive_info']
            print(f"   📦 Type: {info.get('type', 'Unknown')}")
            print(f"   📁 Files: {info.get('total_files', 'Unknown')}")
            if 'compression_ratio' in info:
                ratio = info['compression_ratio']
                print(f"   🗜️ Compression: {ratio:.1f}x ({ratio*100-100:+.1f}%)")
        if 'security' in arch_meta:
            sec_info = arch_meta['security']
            if 'zip_bomb_warning' in sec_info:
                print(f"   {Fore.RED}⚠️ {sec_info['zip_bomb_warning']}{Style.RESET_ALL}")
            elif 'encrypted_files' in sec_info:
                print(f"   🔐 Encrypted files: {Fore.RED}{sec_info.get('encrypted_files', 0)}{Style.RESET_ALL}")
        if 'exiftool_metadata' in arch_meta:
            exiftool_meta = arch_meta['exiftool_metadata']
            print(f"   🛠️ ExifTool Metadata: {Fore.GREEN}Available{Style.RESET_ALL}")
            exiftool_keys = ['FileSize', 'FileType', 'MIMEType', 'ZipRequiredVersion', 'ZipBitFlag']
            for key in exiftool_keys:
                if key in exiftool_meta:
                    print(f"      {key}: {Fore.YELLOW}{exiftool_meta[key]}{Style.RESET_ALL}")
    if (not filter_types or 'office_metadata' in filter_types) and 'office_metadata' in results:
        office_meta = results['office_metadata']
        print(f"\n{Fore.MAGENTA}📊 Office Metadata:{Style.RESET_ALL}")
        if 'core_properties' in office_meta:
            props = office_meta['core_properties']
            key_fields = ['Title', 'Author', 'Subject', 'Created', 'Modified']
            for field in key_fields:
                if props.get(field.lower()):
                    print(f"   {field}: {Fore.YELLOW}{props.get(field.lower())}{Style.RESET_ALL}")
        elif 'workbook_properties' in office_meta:
            props = office_meta['workbook_properties']
            key_fields = ['Title', 'Creator', 'Created', 'Modified']
            for field in key_fields:
                if props.get(field.lower()):
                    print(f"   {field}: {Fore.YELLOW}{props.get(field.lower())}{Style.RESET_ALL}")
        if 'exiftool_metadata' in office_meta:
            exiftool_meta = office_meta['exiftool_metadata']
            print(f"   🛠️ ExifTool Metadata: {Fore.GREEN}Available{Style.RESET_ALL}")
            exiftool_keys = ['Title', 'Author', 'CreateDate', 'ModifyDate', 'Application', 'DocSecurity']
            for key in exiftool_keys:
                if key in exiftool_meta:
                    print(f"      {key}: {Fore.YELLOW}{exiftool_meta[key]}{Style.RESET_ALL}")
    if (not filter_types or 'steganography' in filter_types) and 'steganography' in results and results['steganography']:
        stego = results['steganography']
        print(f"\n{Fore.MAGENTA}🕵️ Steganography Analysis:{Style.RESET_ALL}")
        if stego.get('size_analysis', {}).get('suspicious'):
            print(f"   {Fore.RED}⚠️ Suspicious file size ratio{Style.RESET_ALL}")
        if stego.get('lsb_analysis', {}).get('suspicious'):
            print(f"   {Fore.RED}⚠️ Suspicious LSB distribution{Style.RESET_ALL}")
        if stego.get('embedded_signatures'):
            print(f"   {Fore.YELLOW}🔍 Found embedded signatures: {len(stego['embedded_signatures'])}{Style.RESET_ALL}")
            for sig in stego['embedded_signatures'][:3]:
                print(f"      • {sig.get('description', 'Unknown')} at offset {sig.get('offset', 0)}")
        entropy = stego.get('entropy', {})
        if entropy.get('value'):
            entropy_val = entropy.get('value', 0)
            status = f"{Fore.RED}High" if entropy.get('suspicious') else f"{Fore.GREEN}Normal"
            print(f"   📊 Entropy: {status} ({entropy_val:.2f}/8.0){Style.RESET_ALL}")
    if (not filter_types or 'strings' in filter_types) and 'strings' in results:
        strings_info = results['strings']
        print(f"\n{Fore.CYAN}🔤 String Analysis:{Style.RESET_ALL}")
        print(f"   Total strings: {strings_info.get('total_strings', 0)}")
        interesting = strings_info.get('interesting_strings', [])
        if interesting:
            print(f"   {Fore.YELLOW}⚡ Interesting strings: {len(interesting)}{Style.RESET_ALL}")
            for item in interesting[:5]:
                string_preview = item.get('string', '')[:60]
                string_type = item.get('type', 'unknown')
                print(f"      • {string_type}: {Fore.YELLOW}{string_preview}{Style.RESET_ALL}")
        if strings_info.get('truncated'):
            print(f"   {Fore.YELLOW}⚠️ Analysis truncated (large file){Style.RESET_ALL}")
    if (not filter_types or 'hex_header' in filter_types) and 'hex_header' in results:
        hex_info = results['hex_header']
        if hex_info.get('detected_type'):
            print(f"\n{Fore.CYAN}🔍 File Signature:{Style.RESET_ALL}")
            print(f"   Detected: {Fore.GREEN}{hex_info['detected_type']}{Style.RESET_ALL}")
        if hex_info.get('header_entropy'):
            entropy = hex_info['header_entropy']
            print(f"   Header entropy: {entropy:.2f}")
    print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}\n")

def save_to_csv(results: Dict[str, Dict[str, Any]], output_file: str):
    """Save analysis results to CSV format."""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Filepath', 'Type', 'Size', 'MD5', 'Modified', 'Key Metadata'])
            for filepath, result in results.items():
                file_info = result.get('file_info', {})
                row = [
                    filepath,
                    file_info.get('mimetype', 'Unknown'),
                    file_info.get('size_human', 'Unknown'),
                    file_info.get('md5', ''),
                    file_info.get('modified', ''),
                    ''
                ]
                if 'image_metadata' in result:
                    exif = result['image_metadata'].get('exif_pil', {}) or result['image_metadata'].get('exif_detailed', {})
                    key_fields = ['Make', 'Model', 'DateTime']
                    metadata = [f"{k}:{exif.get(k, '')}" for k in key_fields if k in exif]
                    row[5] = '; '.join(metadata)
                elif 'audio_metadata' in result:
                    tags = result['audio_metadata'].get('common_tags', {})
                    metadata = [f"{k}:{v}" for k, v in tags.items()]
                    row[5] = '; '.join(metadata)
                elif 'pdf_metadata' in result:
                    doc_info = result['pdf_metadata'].get('document_info', {})
                    key_fields = ['Title', 'Author', 'Creator']
                    metadata = [f"{k}:{doc_info.get(k, '')}" for k in key_fields if k in doc_info]
                    row[5] = '; '.join(metadata)
                elif 'office_metadata' in result:
                    props = result['office_metadata'].get('core_properties', {}) or result['office_metadata'].get('workbook_properties', {})
                    key_fields = ['Title', 'Author', 'Creator']
                    metadata = [f"{k}:{props.get(k.lower(), '')}" for k in key_fields if k.lower() in props]
                    row[5] = '; '.join(metadata)
                elif 'archive_metadata' in result:
                    info = result['archive_metadata'].get('archive_info', {})
                    metadata = [f"Type:{info.get('type', '')}", f"Files:{info.get('total_files', '')}"]
                    row[5] = '; '.join(metadata)
                writer.writerow(row)
        print(f"{Fore.GREEN}✅ Results saved to {output_file}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error saving CSV: {e}{Style.RESET_ALL}")
        logging.getLogger('MetadataExtractor').error(f"Error saving CSV: {e}")

def main():
    """Enhanced CLI interface for metadata extraction."""
    parser = argparse.ArgumentParser(
        description='🔍 Enhanced Metadata Extraction Tool - Deep file analysis and forensics',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s image.jpg                    # Basic analysis
  %(prog)s image.jpg --deep             # Deep analysis with all features
  %(prog)s *.pdf --batch                # Analyze multiple files
  %(prog)s file.zip --no-stego          # Skip steganography detection
  %(prog)s doc.docx -o results.json     # Save results to JSON
  %(prog)s suspicious.exe --verbose     # Verbose logging
  %(prog)s image.jpg --filter exif      # Filter specific metadata types
  %(prog)s files.zip --csv results.csv  # Save results to CSV
  %(prog)s dir/ --recursive             # Recursively analyze directory
        """
    )
    parser.add_argument('filepath', nargs='*', help='Path(s) to file(s) or directories for analysis')
    parser.add_argument('--batch', '-b', action='store_true',
                       help='Batch mode for multiple files')
    parser.add_argument('--recursive', '-r', action='store_true',
                       help='Recursively analyze directories')
    parser.add_argument('--no-strings', action='store_true',
                       help='Disable string extraction')
    parser.add_argument('--min-string-length', type=int, default=4,
                       help='Minimum string length to extract (default: 4)')
    parser.add_argument('--max-strings', type=int, default=1000,
                       help='Maximum number of strings to extract (default: 1000)')
    parser.add_argument('--no-stego', action='store_true',
                       help='Disable steganography detection')
    parser.add_argument('--deep', action='store_true',
                       help='Enable deep analysis (more thorough but slower)')
    parser.add_argument('--output', '-o', type=str,
                       help='Output file for results (JSON format)')
    parser.add_argument('--csv', type=str,
                       help='Output file for results (CSV format)')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--log-file', type=str,
                       help='Save logs to file')
    parser.add_argument('--workers', type=int, default=4,
                       help='Number of worker threads (default: 4)')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout per file in seconds (default: 30)')
    parser.add_argument('--filter', type=str,
                       help='Comma-separated metadata types to extract (e.g., file_info,strings,steganography)')
    args = parser.parse_args()

    print_banner()
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logger = setup_logging(log_level, args.log_file)
    config = create_config_from_args(args)

    if not args.filepath:
        print(f"{Fore.RED}❌ Error: At least one file path is required{Style.RESET_ALL}")
        parser.print_help()
        return 1

    extractor = MetadataExtractor(config, logger)
    filepaths = []
    filter_types = args.filter.split(',') if args.filter else None
    if filter_types:
        filter_types = [t.strip().lower() for t in filter_types]
        valid_filters = ['file_info', 'hex_header', 'strings', 'steganography', 'image_metadata',
                         'audio_metadata', 'pdf_metadata', 'office_metadata', 'archive_metadata']
        filter_types = [t for t in filter_types if t in valid_filters]
        if not filter_types:
            print(f"{Fore.RED}❌ Invalid filter types provided{Style.RESET_ALL}")
            return 1

    for path in args.filepath:
        path_obj = Path(path)
        if not path_obj.exists():
            logger.warning(f"Path does not exist: {path}")
            continue
        if args.recursive and path_obj.is_dir():
            for subpath in path_obj.rglob('*'):
                if subpath.is_file():
                    filepaths.append(subpath)
        elif path_obj.is_file():
            filepaths.append(path_obj)
        else:
            logger.warning(f"Skipping non-file path: {path}")

    if not filepaths:
        print(f"{Fore.RED}❌ No valid files found for analysis{Style.RESET_ALL}")
        return 1

    logger.info(f"Analyzing {len(filepaths)} file(s)")
    progress = ProgressBar(len(filepaths))
    def progress_callback():
        progress.update()

    results = extractor.analyze_multiple_files(
        filepaths,
        progress_callback=progress_callback if sys.stdout.isatty() else None,
        filter_types=filter_types
    )

    for filepath, result in results.items():
        if 'error' in result or 'critical_error' in result:
            error_key = 'critical_error' if 'critical_error' in result else 'error'
            print(f"{Fore.RED}❌ Analysis failed for {filepath}: {result[error_key]}{Style.RESET_ALL}")
            continue
        print_analysis_summary(result, filepath, filter_types)

    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}✅ Results saved to {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Error saving JSON: {e}{Style.RESET_ALL}")
            logger.error(f"Error saving JSON: {e}")

    if args.csv:
        save_to_csv(results, args.csv)

    return 0

if __name__ == '__main__':
    sys.exit(main())