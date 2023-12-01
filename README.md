# README.md for Bulk Redirect Checker

## About

Welcome to Bulk Redirect Checker, the digital sleuth for your URL mysteries! Crafted with the finesse of a British spy and the precision of a Swiss watch, this Python command-line tool delves into the labyrinthine world of URL redirects. It's like Sherlock Holmes, but for the internet.

## Features

- **Multifaceted Redirect Detection:** From the classic HTTP-to-HTTPS to the elusive WWW-to-Non-WWW, it uncovers all.
- **Canonical Mismatch Unearthing:** Like finding a needle in a haystack, but more fun.
- **Redirect Chain Chronicles:** It narrates the saga of your URL's journey with the gusto of a British historian.
- **Checkpointing:** For when tea time calls mid-audit.
- **Logging:** Because everyone loves a good paper trail.

## Installation (The British Butler Method)

1. **Fetch Your Top Hat:**
   
   Begin by cloning the repository or downloading the source like a true gentleman or lady.

   ```bash
   git clone [repository-url]
   ```

2. **Saunter to the Directory:**

   Stroll through the file system to your newly cloned repository.

   ```bash
   cd path/to/bulkredirectchecker
   ```

3. **Summon the Butler (a.k.a. Pip):**

   Command pip to install the package globally in editable mode, with the nonchalance of ringing a bell.

   ```bash
   pip install -e .
   ```

   This is the digital equivalent of "Jeeves, make this available everywhere, will you?"

4. **Ensure Everything is Tickety-Boo:**

   Run the following to ensure that the installation is spiffing.

   ```bash
   bulkredirectchecker --help
   ```

## Usage

1. **Prepare Your List of Suspects (URLs):**
   
   Jot down the URLs in a CSV file, as if you were drafting a guest list for high tea.

2. **Commence the Investigation:**

   Unleash the checker with a flourish:

   ```bash
   bulkredirectchecker input_file.csv -o output_file.csv
   ```

   Replace `input_file.csv` with your list, and `output_file.csv` with the name of your desired output file.

3. **Revel in the Findings:**

   The output file will reveal all, like the final chapter of an Agatha Christie novel.

## Contributing

Should you wish to contribute to this noble endeavour, your pull requests and issues will be received with the grace of a curtsy.

## License

Licensed under the [MIT License](LICENSE.txt) - because even we believe some things should be free as a bird.