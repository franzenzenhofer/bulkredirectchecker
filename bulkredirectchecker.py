#!/usr/bin/env python3
import requests
import csv
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import argparse
import configparser
import datetime
import os
from tqdm import tqdm
import time
import json
from urllib.parse import urlencode
import base64



# Constants
HTTP_TO_HTTPS = "HTTP to HTTPS"
NON_WWW_TO_WWW = "Non WWW to WWW"
SUBDOMAIN_TO_WWW = "Subdomain to WWW"
OTHER = "Other"
HTTPS_TO_HTTP = "HTTPS to HTTP"
WWW_TO_NON_WWW = "WWW to Non-WWW"
WWW_TO_SUBDOMAIN = "WWW to Subdomain"
PATH_REDIRECT = "Path Redirect"
DOMAIN_REDIRECT = "Domain Redirect"
PROTOCOL_AND_DOMAIN_REDIRECT = "Protocol and Domain Redirect"
PROTOCOL_AND_PATH_REDIRECT = "Protocol and Path Redirect"
DOMAIN_AND_PATH_REDIRECT = "Domain and Path Redirect"
PROTOCOL_DOMAIN_AND_PATH_REDIRECT = "Protocol, Domain, and Path Redirect"
CASE_CHANGE = "Case Change"
PORT_REMOVAL = "Port Removal"

# Load configuration
config = configparser.ConfigParser()
if os.path.exists('config.ini'):
    config.read('config.ini')

# Set up logging
log_filename = 'redirect_checker.log'  # default log filename
if config.has_section('Logging') and 'filename' in config['Logging']:
    log_filename = config.get('Logging', 'filename')
logging.basicConfig(filename=log_filename, level=logging.INFO)



CHECKPOINT_FILE = os.path.join(os.getcwd(), 'checkpoint.json')
def save_checkpoint(url, result):
    with open(CHECKPOINT_FILE, 'a') as f:
        f.write(json.dumps({'url': url, 'result': result}))
        f.write('\n')

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            for line in f:
                data = json.loads(line.strip())
                yield data['url'], data['result']

def get_redirect_type(resp, url):
    """Determines the type of redirect."""
    location = resp.headers.get('Location', '')
    if not location:
        return OTHER
    parsed_url = urlparse(url)
    parsed_location = urlparse(location)

    if parsed_url.scheme == 'http' and parsed_location.scheme == 'https':
        return HTTP_TO_HTTPS
    elif parsed_url.scheme == 'https' and parsed_location.scheme == 'http' and not parsed_url.netloc.startswith('https:') and parsed_location.netloc.startswith('http:'):
        return HTTPS_TO_HTTP
    elif 'www.' in parsed_location.netloc and 'www.' not in parsed_url.netloc:
        return NON_WWW_TO_WWW
    elif 'www.' not in parsed_location.netloc and 'www.' in parsed_url.netloc:
        return WWW_TO_NON_WWW
    elif parsed_location.netloc.startswith('www.') and not parsed_url.netloc.startswith('www.'):
        return SUBDOMAIN_TO_WWW
    elif not parsed_location.netloc.startswith('www.') and parsed_url.netloc.startswith('www.'):
        return WWW_TO_SUBDOMAIN
    elif parsed_location.path.lower() != parsed_url.path.lower():
        return CASE_CHANGE
    elif parsed_url.port and not parsed_location.port and parsed_url.netloc.replace(':{}'.format(parsed_url.port), '') == parsed_location.netloc:
        return PORT_REMOVAL
    elif parsed_location.path != parsed_url.path:
        return PATH_REDIRECT
    elif parsed_location.netloc != parsed_url.netloc:
        return DOMAIN_REDIRECT
    elif parsed_location.scheme != parsed_url.scheme and parsed_location.netloc != parsed_url.netloc:
        return PROTOCOL_AND_DOMAIN_REDIRECT
    elif parsed_location.scheme != parsed_url.scheme and parsed_location.path != parsed_url.path:
        return PROTOCOL_AND_PATH_REDIRECT
    elif parsed_location.netloc != parsed_url.netloc and parsed_location.path != parsed_url.path:
        return DOMAIN_AND_PATH_REDIRECT
    elif parsed_location.scheme != parsed_url.scheme and parsed_location.netloc != parsed_url.netloc and parsed_location.path != parsed_url.path:
        return PROTOCOL_DOMAIN_AND_PATH_REDIRECT
    else:
        return OTHER
    
session = requests.Session()

def process_url(url, session):
    # use the session object for requests
    try:
        response = session.head(url, allow_redirects=True)
    except (requests.TooManyRedirects, requests.ConnectionError, requests.Timeout,requests.RequestException) as e:
        return {"url": url, "error": str(e)}
    
    canonical_url = ''  # add this line


    redirect_chain = []
    prev_url = url
    for resp in response.history:
        redirect_chain.append({
            "initial_url": prev_url,
            "redirected_url": resp.headers.get('Location'),
            "redirect_type": get_redirect_type(resp, prev_url),
            "redirect_status_code": resp.status_code
        })
        prev_url = resp.headers.get('Location')

    final_url = response.url
    final_status_code = response.status_code
    content_type = response.headers.get('Content-Type', '').split(';')[0]
    canonical_mismatch = ''

    if final_status_code == 200 and 'text/html' in content_type:
        try:
            final_response = session.get(final_url)
        except (requests.TooManyRedirects, requests.ConnectionError, requests.Timeout) as e:
            return {"url": url, "error": str(e)}
        
        # Get canonical link from HTML
        soup = BeautifulSoup(final_response.text, 'html.parser')
        html_canonical_link = soup.find("link", {"rel": "canonical"})
        if html_canonical_link:
            html_canonical_link = html_canonical_link['href'].strip()
        
        # Get canonical link from HTTP header
        http_link_header = final_response.headers.get('Link')
        http_canonical_link = None

        if http_link_header:
            link_values = http_link_header.split(',')
            for link_value in link_values:
                if 'rel="canonical"' in link_value:
                    http_canonical_link = link_value[link_value.find('<')+1:link_value.find('>')]
                    break
        # If canonical link is in HTML but not in HTTP header 
        if html_canonical_link and not http_canonical_link:
            canonical_link = html_canonical_link
        # If canonical link is not in HTML but is in HTTP header
        elif not html_canonical_link and http_canonical_link:
            canonical_link = http_canonical_link
        # If canonical link is in both HTML and HTTP header
        elif html_canonical_link and http_canonical_link:
            canonical_link = 'HTTP-HTML-CANONICAL-COLLISION'
        # If canonical link is not in both HTML and HTTP header
        else:
            canonical_link = None

        if canonical_link:
            canonical_link = canonical_link.strip()  # trim whitespace
            canonical_url = urlparse(canonical_link)._replace(fragment='').geturl()  # remove fragment
            final_url_no_fragment = urlparse(final_url)._replace(fragment='').geturl()  # remove fragment from final_url
            canonical_mismatch = 'NO CANONICAL GIVEN' if canonical_link == '' else canonical_url != final_url_no_fragment
        else:
            canonical_mismatch = 'NO CANONICAL GIVEN'

    return {
        "final_url": final_url,
        "number_of_redirects": len(redirect_chain),
        "status_code": final_status_code,
        "content_type": content_type,
        "canonical_mismatch": canonical_mismatch,
        "canonical_url": canonical_url,  # add this line
        "redirect_chain": redirect_chain
    }

def check_redirects(urls, use_checkpoint):
    """Checks redirects for a list of URLs."""
    start_time = time.time()

    session = requests.Session()
    results = []

    for i, url in enumerate(tqdm(urls, desc="Processing URLs"), start=1):
        print(f"Checking URL: {url}")  # print the URL being checked
        result = {"url": url}  # initialize result with 'url' key
        try:
            result.update(process_url(url, session))
        except requests.RequestException as e:
            result["error"] = str(e)
        finally:
            results.append(result)
            save_checkpoint(url, result)  # save checkpoint after processing each URL

        elapsed_time = time.time() - start_time
        estimated_total_time = elapsed_time * len(urls) / i
        remaining_time = estimated_total_time - elapsed_time
        logging.info(f'Processed {i} of {len(urls)} URLs. Estimated time remaining: {remaining_time:.2f} seconds.')

    return results

def parse_arguments():
    parser = argparse.ArgumentParser(description='Check redirects for a list of URLs.')
    parser.add_argument('input_file', help='The input file containing the list of URLs.')
    parser.add_argument('-o', '--output_file', help='The output CSV file.', default=None)
    parser.add_argument('--checkpoint', action='store_true', help='Use checkpointing to resume from the last processed URL.')
    args = parser.parse_args()
    return args

def generate_output_filename(args):
    if args.output_file is None:
        base_name = os.path.splitext(os.path.basename(args.input_file))[0]
        date_time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args.output_file = f"{base_name}_{date_time}_output.csv"
    return args.output_file

def read_urls_from_file(input_file):
    with open(input_file, 'r') as f:
        urls = []
        reader = csv.DictReader(f)
        for row in reader:
            if any(row.values()):  # check if row is not empty
                for fieldname in ['URL', 'url', 'urls', 'URLS', 'Urls', 'Url']:
                    if fieldname in row:
                        url = row[fieldname].strip()
                        if url:  # check if url is not empty after stripping
                            urls.append(url)
                            break
    return sorted(urls, key=len)

def create_redirect_key(result):
    try:
        initial_url = urlparse(result['redirect_chain'][0]['initial_url']) #['redirect_chain'][0]['initial_url']
        final_url = urlparse(result.get('final_url', ''))
        number_of_redirects = len(result.get('redirect_chain', []))
        #if result['canonical_mismatch'] is true then canical status is CANONICAL_TRUE else CANONICAL_FALSE
        canonical_status = 'CANONICAL_AWAY' if result['canonical_mismatch'] else 'CANONICAL_OK'
    except Exception as e:
        logging.error(f'Error creating redirect key: {e}')
        return ''

    redirect_details = []
    for i in range(7):
        try:
            if i < number_of_redirects:
                redirect_status_code = result['redirect_chain'][i].get('redirect_status_code', '')
                redirect_type = result['redirect_chain'][i].get('redirect_type', '').replace(' ', '_')
                redirect_details.append(f"{redirect_status_code}-{redirect_type}-")
            else:
                redirect_details.append('')
        except Exception as e:
            logging.error(f'Error creating redirect details: {e}')
            redirect_details.append('')

    try:
        redirect_key = f"{initial_url.scheme}://{initial_url.netloc}-{final_url.scheme}://{final_url.netloc}-{number_of_redirects}-{'-'.join(redirect_details)}-{canonical_status}"
    except Exception as e:
        logging.error(f'Error creating redirect key: {e}')
        return ''

    return redirect_key

def create_url(result):
    params = {}
    for field in CSV_CONFIG:
        if field["header"] != "Visualize Link":
            try:
                params[field["header"]] = field["value"](result)
            except Exception as e:
                logging.error(f'Error creating URL parameter for field "{field["header"]}": {e}')
                params[field["header"]] = ''
    try:
        params_str = urlencode(params)
        params_base64 = base64.b64encode(params_str.encode())
        params_base64_str = params_base64.decode()
        return f"https://bulkredirectchecker.franzai.com/#{params_base64_str}"
    except Exception as e:
        logging.error(f'Error creating Visualize Link: {e}')
        return 'N/A'

CSV_CONFIG = [
    {"header": "Redirect Key", "value": create_redirect_key},
    {"header": "Initial URL", "value": lambda result: result['redirect_chain'][0]['initial_url'] if result['redirect_chain'] else ''},
    {"header": "Is Redirect", "value": lambda result: 'TRUE' if result['number_of_redirects'] > 0 else 'FALSE'},
    {"header": "Redirect Chain", "value": lambda result: 'TRUE' if len(result['redirect_chain']) > 1 else 'FALSE'},
    {"header": "Canonical Mismatch", "value": lambda result: result['canonical_mismatch']},
    {"header": "All 301", "value": lambda result: 'TRUE' if result['redirect_chain'] and all([redirect['redirect_status_code'] == 301 for redirect in result['redirect_chain']]) else ('FALSE' if result['redirect_chain'] else '')},
    {"header": "Multi Domain", "value": lambda result: 'TRUE' if result['redirect_chain'] and urlparse(result['redirect_chain'][0]['initial_url']).hostname != urlparse(result['final_url']).hostname else 'FALSE'},
    {"header": "Start Domain", "value": lambda result: urlparse(result['redirect_chain'][0]['initial_url']).netloc if result['redirect_chain'] else ''},
    {"header": "Final Domain", "value": lambda result: urlparse(result['final_url']).netloc},
    {"header": "Number of Redirects", "value": lambda result: result['number_of_redirects']},
    {"header": "Final Status Code", "value": lambda result: result['status_code']},
    {"header": "Final is AMP", "value": lambda result: 'TRUE' if result['content_type'] == 'text/html' and 'amp' in result['final_url'] else ('FALSE' if result['content_type'] == 'text/html' else '')},
    *[
        item for i in range(7) for item in [
            {"header": f"Redirect Status Code {i+1}", "value": lambda result, i=i: result['redirect_chain'][i]['redirect_status_code'] if i < len(result['redirect_chain']) else ''},
            {"header": f"Redirect Type {i+1}", "value": lambda result, i=i: result['redirect_chain'][i]['redirect_type'] if i < len(result['redirect_chain']) else ''},
            {"header": f"Redirected URL {i+1}", "value": lambda result, i=i: result['redirect_chain'][i]['redirected_url'] if i < len(result['redirect_chain']) else ''}
        ]
    ],
    {"header": "Final Status Code", "value": lambda result: result['status_code']},
    {"header": "Canonical URL", "value": lambda result: result['canonical_url']},
    {"header": "Content Type", "value": lambda result: result['content_type']},
    {"header": "Error", "value": lambda result: result['error'] if 'error' in result else ''},
    {"header": "Visualize Link", "value": create_url}

]

def create_header():
    return [field["header"] for field in CSV_CONFIG]

def create_csv_row(result):
    row = []
    for field in CSV_CONFIG:
        try:
            row.append(field["value"](result))
        except Exception as e:
            logging.error(f'Error creating CSV row: {e}')
            row.append('')
    return row

def write_results_to_file(output_file, redirect_results):
    with open(output_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        header = create_header()
        writer.writerow(header)
        for result in redirect_results:
            row = create_csv_row(result)
            initial_url = row[0].strip()  # "Initial URL" field
            if initial_url:  # check if "Initial URL" field is not empty after trimming
                writer.writerow(row)

def main():
    """Main function."""
    args = parse_arguments()
    output_file = generate_output_filename(args)
    urls = read_urls_from_file(args.input_file)

    # Load checkpoints and remove processed URLs from the list if --checkpoint is specified
    checkpoint_results = []
    if args.checkpoint:
        processed_urls = set()
        for url, result in load_checkpoint():
            processed_urls.add(url)
            checkpoint_results.append(result)
        urls = [url for url in urls if url not in processed_urls]

    results = check_redirects(urls, args.checkpoint)

    # Combine checkpoint results with current run results
    all_results = checkpoint_results + results

    # Remove duplicates from results
    seen_urls = set()
    unique_results = []
    for result in all_results:
        try:
            url = result['url']
            if url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(result)
        except KeyError:
            logging.error(f'Error: result dictionary does not contain url key: {result}')

    # Write results to output file
    write_results_to_file(output_file, unique_results)
    write_results_to_file(output_file, unique_results)

if __name__ == "__main__":
    main()