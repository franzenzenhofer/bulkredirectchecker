# Bulk Redirect Checker README.md

## Introduction
The Bulk Redirect Checker is a comprehensive Python tool designed for URL redirect analysis. It offers detailed insights into redirect chains, canonical mismatches, and more.

## Features

- **Diverse Redirect Detection:** Identifies a range of redirects, including HTTP to HTTPS, WWW to Non-WWW, and several others.
- **Canonical URL Analysis:** Detects and reports canonical mismatches in URLs.
- **Redirect Chain Mapping:** Traces the complete redirect chain of a URL.
- **Checkpoint Functionality:** Allows processing to be paused and resumed, preventing data loss.
- **Logging Capability:** Maintains detailed logs for analysis and debugging.
- **Flowchart Visualization:** (In conjunction with `index.html`) Presents a graphical representation of redirect chains.
- **Command Line Flexibility:** Supports various command-line options for versatile operations.
- **Output Customization:** Generates detailed CSV reports of redirect analysis.

## Installation Instructions

1. Clone the Repository:
   ```bash
   git clone [repository-url]
   ```
2. Navigate to the Directory:
   ```bash
   cd path/to/bulkredirectchecker
   ```
3. Install Dependencies:
   ```bash
   pip install -e .
   ```

## Usage Guidelines

### Basic Usage
Process a list of URLs from a CSV file and generate a CSV output file.
```bash
bulkredirectchecker input_file.csv -o output_file.csv
```

### Single URL Analysis
Analyze a single URL.
```bash
bulkredirectchecker -u [single-url-to-check]
```

### Logging
Enable logging to record the process details.
```bash
bulkredirectchecker input_file.csv -o output_file.csv -l
```

### Checkpointing
Use checkpointing to resume processing from the last processed URL.
```bash
bulkredirectchecker input_file.csv --checkpoint
```

## Detailed Feature Explanation

### Checkpoint Functionality
The checkpoint feature is designed to save the progress of URL processing. It ensures that in case of an interruption, the tool can resume processing from the last saved state. This is particularly useful for large datasets where processing is time-consuming. The tool writes the state to a `checkpoint.json` file after processing each URL. When resumed, it skips URLs already processed, ensuring efficiency and saving time.

### Command Line Arguments
- `input_file`: Specifies the CSV file containing the list of URLs to process.
- `-o`, `--output_file`: Determines the name of the output CSV file.
- `--checkpoint`: Activates checkpointing functionality.
- `-u`, `--url`: Specifies a single URL for analysis.
- `-l`, `--log`: Enables logging of the process.

### Redirect Chain Analysis
Each URL is analyzed for its complete redirect path. This includes detection of the redirect type, status code, and the final URL after all redirects. The tool categorizes redirects into types like HTTP to HTTPS, WWW to Non-WWW, etc.

### Canonical URL Analysis
The tool checks the final URL of a redirect chain for canonical tags. It identifies any mismatches between the final URL and the canonical URL, highlighting potential SEO issues.

### Output File Structure
The generated CSV file contains detailed information about each URL, including:
- Redirect chain
- Final URL
- Status codes for each redirect
- Canonical URL
- Error messages (if any)

### Flowchart Visualization
Using `index.html`, the tool visualizes the redirect chain as a flowchart. This provides an intuitive graphical representation of the redirect path, making it easier to understand complex redirect chains.

## Contributing
Contributions to enhance the tool's functionality or to improve its efficiency are welcome.

## License
This tool is available under the MIT License.