**DataTrace** is a powerful command-line tool designed for forensic analysis and deep inspection of file metadata. It extracts comprehensive metadata from various file types, including images, audio files, PDFs, Office documents, and archives, with optional steganography detection and string analysis.

![Sample](/Sample.png)

## Features

- **Comprehensive Metadata Extraction**:
  - File information (size, hashes, timestamps, permissions)
  - Image metadata (EXIF, ICC profiles, color analysis)
  - Audio metadata (tags, bitrate, duration)
  - PDF metadata (document info, text analysis)
  - Office document metadata (Word, Excel, PowerPoint)
  - Archive analysis (ZIP, RAR, TAR.GZ, compression ratios)
- **Steganography Detection**:
  - Identifies suspicious file size ratios, LSB anomalies, and embedded signatures
  - Entropy analysis for detecting hidden data
- **String Extraction**:
  - Extracts printable strings with customizable length and limits
  - Identifies interesting strings (URLs, emails, paths, etc.)
- **Flexible Output**:
  - Console output with colorized formatting
  - Export results to JSON or CSV
- **Batch and Recursive Processing**:
  - Analyze multiple files or directories recursively
  - Parallel processing with configurable worker threads
- **Customizable Analysis**:
  - Filter specific metadata types (e.g., `file_info`, `image_metadata`)
  - Toggle deep analysis, steganography, or string extraction
- **Robust Error Handling**:
  - Graceful handling of large files, unsupported formats, and errors
  - Logging with configurable verbosity

## Installation

### Prerequisites
- Python 3.8 or higher
- [ExifTool](https://exiftool.org/) (optional, for enhanced metadata extraction)

### Dependencies
Install the required Python packages using `pip`:

```bash
pip install -r requirements.txt
```

The `requirements.txt` file includes:
```
Pillow>=9.0.0
exifread>=3.0.0
mutagen>=1.45.0
PyPDF2>=3.0.0
python-docx>=0.8.0
openpyxl>=3.0.0
rarfile>=4.0
colorama>=0.4.0
```

To create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### ExifTool Installation
For enhanced metadata extraction, install ExifTool:
- **Linux**: `sudo apt install exiftool`
- **macOS**: `brew install exiftool`
- **Windows**: Download and install from [exiftool.org](https://exiftool.org/)

## Usage

Run the tool using the `cli.py` script. The basic syntax is:
```bash
python cli.py <filepath> [options]
```

### Examples
1. **Basic Analysis**:
   Analyze a single file:
   ```bash
   python cli.py image.jpg
   ```

2. **Deep Analysis**:
   Enable thorough analysis (slower but more detailed):
   ```bash
   python cli.py image.jpg --deep
   ```

3. **Batch Processing**:
   Analyze multiple files:
   ```bash
   python cli.py *.pdf --batch
   ```

4. **Recursive Directory Analysis**:
   Analyze all files in a directory recursively:
   ```bash
   python cli.py ./folder/ --recursive
   ```

5. **Filter Specific Metadata**:
   Extract only specific metadata types:
   ```bash
   python cli.py image.jpg --filter image_metadata,steganography
   ```

6. **Output to JSON**:
   Save results to a JSON file:
   ```bash
   python cli.py document.docx -o results.json
   ```

7. **Output to CSV**:
   Save results to a CSV file:
   ```bash
   python cli.py files.zip --csv results.csv
   ```

8. **Disable Steganography Detection**:
   Skip steganography analysis:
   ```bash
   python cli.py image.png --no-stego
   ```

9. **Verbose Logging**:
   Enable detailed logging:
   ```bash
   python cli.py suspicious.exe --verbose --log-file analysis.log
   ```

### Command-Line Options
| Option | Description | Default |
|--------|-------------|---------|
| `--batch`, `-b` | Enable batch mode for multiple files | False |
| `--recursive`, `-r` | Analyze directories recursively | False |
| `--no-strings` | Disable string extraction | False |
| `--min-string-length` | Minimum string length to extract | 4 |
| `--max-strings` | Maximum number of strings to extract | 1000 |
| `--no-stego` | Disable steganography detection | False |
| `--deep` | Enable deep analysis (more thorough) | False |
| `--output`, `-o` | Output file for JSON results | None |
| `--csv` | Output file for CSV results | None |
| `--verbose`, `-v` | Enable verbose logging | False |
| `--log-file` | Save logs to a file | None |
| `--workers` | Number of worker threads | 4 |
| `--timeout` | Timeout per file in seconds | 30 |
| `--filter` | Comma-separated metadata types to extract | None |

### Supported File Types
- **Images**: JPEG, PNG, GIF
- **Audio**: MP3, WAV, FLAC, OGG
- **PDF**: PDF documents
- **Office**: DOCX, XLSX, PPTX
- **Archives**: ZIP, RAR, TAR.GZ

## Project Structure
```
metadata-extractor/
│
├── cli.py                # Command-line interface
├── config.py             # Configuration management
├── metadata_extractor.py # Core metadata extraction logic
├── utils.py              # Utility functions
├── requirements.txt      # Python dependencies
├── README.md             # This file
```

## Configuration
The `config.py` module defines default settings, which can be overridden via command-line arguments:
- `max_file_size_mb`: Maximum file size to process (default: 100 MB)
- `chunk_size`: Buffer size for file reading (default: 8192 bytes)
- `max_workers`: Number of threads for parallel processing (default: 4)
- `timeout_seconds`: Timeout per file (default: 30 seconds)
- `min_string_length`: Minimum string length (default: 4)
- `max_strings`: Maximum strings to extract (default: 1000)
- `enable_steganography`: Enable steganography detection (default: True)
- `cache_dir`: Directory for caching ExifTool results (default: `~/.metadata_extractor_cache`)

## Example Output
For an image file (`test.jpg`):
```
============================================================
📁 ANALYSIS RESULTS: test.jpg
============================================================

📋 File Information:
   Size: 3.8 MB
   Type: image/jpeg
   Modified: 2019-02-16T19:02:02
   MD5: d2575fda33f865f5039942b40bf41580
   CRC32: b6e73e62

🖼️ Image Metadata:
   📐 Dimensions: 4272 x 2848
   🎨 Format: JPEG
   🌈 Mode: RGB
   📷 EXIF Data found: 53 fields
      📱 Camera Brand: Canon
      📸 Camera Model: Canon EOS 1100D
      📅 Date Taken: 2019:02:16 19:02:01
      🔍 Aperture: 10.0
      ⏱️ Shutter Speed: 0.00125
      📊 ISO: 1600
      ... and 45 more EXIF fields

🕵️ Steganography Analysis:
   🔍 Found embedded signatures: 1
      • JPEG image at offset 9196
   📊 Entropy: High (7.96/8.0)

🔤 String Analysis:
   Total strings: 142
   ⚡ Interesting strings: 3
      • url: https://example.com/image
      • email: user@example.com
      • path: /DCIM/Camera
```

## Troubleshooting
- **Missing ExifTool**: Install ExifTool for complete metadata extraction.
- **Large Files**: Use `--no-strings` or `--no-stego` to reduce memory usage.
- **Unsupported Formats**: Ensure required libraries are installed (see `requirements.txt`).
- **Errors**: Check the log file (`--log-file`) or enable verbose mode (`--verbose`) for details.

## Contributing
Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/new-feature`).
3. Commit your changes (`git commit -m 'Add new feature'`).
4. Push to the branch (`git push origin feature/new-feature`).
5. Open a pull request.

## License
This project is licensed under the MIT License.
