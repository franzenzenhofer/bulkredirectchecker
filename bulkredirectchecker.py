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
import webbrowser
import hashlib



# Constants
HTTP_TO_HTTPS = "HTTP to HTTPS"
HTTPS_TO_HTTP = "HTTPS to HTTP"
NON_WWW_TO_WWW = "Non WWW to WWW"
WWW_TO_NON_WWW = "WWW to Non-WWW"
SUBDOMAIN_TO_WWW = "Subdomain to WWW"
WWW_TO_SUBDOMAIN = "WWW to Subdomain"
TO_LOWERCASE = "To Lowercase"
CASE_CHANGE = "Case Change"
PORT_REMOVAL = "Port Removal"
ADDING_ENDING_SLASH = "Adding Ending Slash"
REMOVING_ENDING_SLASH = "Removing Ending Slash"
ADDING_QUERY_PARAM = "Adding Query Param"
REMOVING_QUERY_PARAM = "Removing Query Param"
CHANGING_QUERY_PARAM = "Changing Query Param"
PATH_REDIRECT = "Path Redirect"
DOMAIN_REDIRECT = "Domain Redirect"
DOMAIN_AND_PATH_REDIRECT = "Domain and Path Redirect"
PROTOCOL_REDIRECT = "Protocol Redirect"
PORT_ADDED = "Port Added"
HTTP_TO_HTTPS_PLUS_PORT = "HTTP to HTTPS with Port"
ADDING_URL_PARAM = "Adding URL Param"
REMOVING_URL_PARAM = "Removing URL Param"
PARAM_CHANGE = "Param Change"
FRAGMENT_ADDED = "Fragment Added"
FRAGMENT_REMOVED = "Fragment Removed"
FRAGMENT_CHANGED = "Fragment Changed"
AUTH_CHANGE = "Auth Change"
PORT_CHANGED = "Port Changed"
SUBDOMAIN_TO_SUBDOMAIN = "Subdomain to Subdomain"
SUBDOMAIN_TO_MAIN_DOMAIN = "Subdomain to Main Domain"
MAIN_DOMAIN_TO_SUBDOMAIN = "Main Domain to Subdomain"
PATH_ADDED = "Path Added"
OTHER = "Other"

# Load configuration
config = configparser.ConfigParser()
if os.path.exists('config.ini'):
    config.read('config.ini')




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
        return OTHER  # No location header, so it's not a redirect

    parsed_url = urlparse(url)
    parsed_location = urlparse(location)

    redirect_types = []

    # Check for scheme changes
    if parsed_url.scheme == 'http' and parsed_location.scheme == 'https':
        redirect_types.append(HTTP_TO_HTTPS)  # Redirect from HTTP to HTTPS
    elif parsed_url.scheme == 'https' and parsed_location.scheme == 'http':
        redirect_types.append(HTTPS_TO_HTTP)  # Redirect from HTTPS to HTTP

    # Check for netloc changes
    if parsed_location.netloc != parsed_url.netloc:
        if 'www.' in parsed_location.netloc and 'www.' not in parsed_url.netloc:
            redirect_types.append(NON_WWW_TO_WWW)  # Redirect from non-www to www
        elif 'www.' not in parsed_location.netloc and 'www.' in parsed_url.netloc:
            redirect_types.append(WWW_TO_NON_WWW)  # Redirect from www to non-www
        elif parsed_location.netloc.startswith('www.') and not parsed_url.netloc.startswith('www.'):
            redirect_types.append(SUBDOMAIN_TO_WWW)  # Redirect from a subdomain to www
        elif not parsed_location.netloc.startswith('www.') and parsed_url.netloc.startswith('www.'):
            redirect_types.append(WWW_TO_SUBDOMAIN)  # Redirect from www to a subdomain
        elif parsed_location.scheme == parsed_url.scheme and parsed_location.netloc != parsed_url.netloc and parsed_location.path == parsed_url.path:
            redirect_types.append(DOMAIN_REDIRECT)  # Redirect where only the domain changes

        # Check for subdomain changes
        parsed_location_subdomain = parsed_location.netloc.split('.')[0]
        parsed_url_subdomain = parsed_url.netloc.split('.')[0]

        if parsed_location_subdomain != 'www' and parsed_url_subdomain != 'www' and parsed_location_subdomain != parsed_url_subdomain:
            redirect_types.append(SUBDOMAIN_TO_SUBDOMAIN)  # Redirect from one subdomain to another
        elif parsed_location_subdomain != 'www' and parsed_url_subdomain == parsed_url.netloc.split('.')[-2]:
            redirect_types.append(SUBDOMAIN_TO_MAIN_DOMAIN)  # Redirect from a subdomain to the main domain
        elif parsed_location_subdomain == parsed_location.netloc.split('.')[-2] and parsed_url_subdomain != 'www':
            redirect_types.append(MAIN_DOMAIN_TO_SUBDOMAIN)  # Redirect from the main domain to a subdomain

    # Check for port changes
    if not parsed_url.port and parsed_location.port and parsed_location.netloc and parsed_url.netloc and parsed_location.netloc.replace(':{}'.format(parsed_location.port), '') == parsed_url.netloc:
        redirect_types.append(PORT_ADDED)  # Redirect where a port is added to the URL
    elif parsed_url.port and not parsed_location.port and parsed_location.netloc and parsed_url.netloc and parsed_url.netloc.replace(':{}'.format(parsed_url.port), '') == parsed_location.netloc:
        redirect_types.append(PORT_REMOVAL)  # Redirect where the port is removed from the URL
    elif parsed_url.port and parsed_location.port and parsed_url.port != parsed_location.port:
        redirect_types.append(PORT_CHANGED)  # Redirect where the port is changed

    # Check for path changes
    if parsed_location.path != parsed_url.path:
        #log
        #print(f"parsed_url.path: {parsed_url.path}")
        #print(f"parsed_location.path: {parsed_location.path}")
        # Check for path changes
        if parsed_location.path.lower() == parsed_url.path.lower() and parsed_url.path != parsed_url.path.lower():
            redirect_types.append(TO_LOWERCASE)  # Redirect where the path changes to all lowercase
        elif parsed_location.path.lower() == parsed_url.path.lower() and parsed_location.path != parsed_url.path:
            redirect_types.append(CASE_CHANGE)  # Redirect where the path changes case but remains the same otherwise
        elif parsed_location.path != parsed_url.path and parsed_location.path == parsed_url.path + '/':
            redirect_types.append(ADDING_ENDING_SLASH)  # Redirect where a trailing slash is added
        elif parsed_location.path != parsed_url.path and parsed_location.path + '/' == parsed_url.path:
            redirect_types.append(REMOVING_ENDING_SLASH)  # Redirect where a trailing slash is removed
        elif parsed_location.path != parsed_url.path and parsed_location.path.startswith(parsed_url.path):
            redirect_types.append(PATH_ADDED)  # Redirect where a path is added
        elif parsed_location.path != parsed_url.path:
            redirect_types.append(PATH_REDIRECT)  # Redirect where only the path changes
       

    # Check for query changes
    if parsed_location.query != parsed_url.query:
        if parsed_location.query and not parsed_url.query:
            redirect_types.append(ADDING_QUERY_PARAM)  # Redirect where a query parameter is added
        elif not parsed_location.query and parsed_url.query:
            redirect_types.append(REMOVING_QUERY_PARAM)  # Redirect where a query parameter is removed
        elif parsed_location.query != parsed_url.query:
            redirect_types.append(CHANGING_QUERY_PARAM)  # Redirect where a query parameter value is changed

    # Check for params changes
    if parsed_location.params != parsed_url.params:
        if parsed_location.params and not parsed_url.params:
            redirect_types.append(ADDING_URL_PARAM)  # Redirect where a URL parameter is added
        elif not parsed_location.params and parsed_url.params:
            redirect_types.append(REMOVING_URL_PARAM)  # Redirect where a URL parameter is removed
        elif parsed_location.params != parsed_url.params:
            redirect_types.append(PARAM_CHANGE)  # Redirect where a URL parameter value is changed

    # Check for fragment changes
    if parsed_location.fragment and not parsed_url.fragment:
        redirect_types.append(FRAGMENT_ADDED)  # Redirect where a fragment identifier is added
    elif not parsed_location.fragment and parsed_url.fragment:
        redirect_types.append(FRAGMENT_REMOVED)  # Redirect where the fragment identifier is removed
    elif parsed_location.fragment != parsed_url.fragment:
        redirect_types.append(FRAGMENT_CHANGED)  # Redirect where the fragment identifier changes

    # Check for auth changes
    if parsed_location.username != parsed_url.username or parsed_location.password != parsed_url.password:
        redirect_types.append(AUTH_CHANGE)  # Redirect where the username or password changes

    #print(f"redirect_types: {redirect_types}")
    if redirect_types:
        if len(redirect_types) > 1:
            return ' and '.join(redirect_types)
        else:
            return redirect_types[0]
    else:
        return OTHER  # Some other type of redirect
    
session = requests.Session()

headers = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
}

def process_url(url, session):
    try:
        response = session.head(url, headers=headers, allow_redirects=True)
    except (requests.TooManyRedirects, requests.ConnectionError, requests.Timeout, requests.RequestException) as e:
        return {"url": url, "error": str(e)}
    
    redirect_chain = []
    prev_url = url
    initial_url_is_200 = False
    # If there are no redirects, handle the initial URL as the final URL
    if not response.history:
        initial_url_is_200 = True
        redirect_chain.append({
            "initial_url": url,
            "redirected_url": response.url,
            "redirect_type": "No Redirect",
            "redirect_status_code": response.status_code
        })
    else:
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
        
        # Determine the canonical URL and if there is a mismatch
        canonical_url = None
        if html_canonical_link:
            canonical_url = urlparse(html_canonical_link)._replace(fragment='').geturl()  # remove fragment
        elif http_canonical_link:
            canonical_url = urlparse(http_canonical_link)._replace(fragment='').geturl()  # remove fragment
        
        if canonical_url:
            final_url_no_fragment = urlparse(final_url)._replace(fragment='').geturl()  # remove fragment from final_url
            canonical_mismatch = canonical_url != final_url_no_fragment
        else:
            canonical_mismatch = 'NO CANONICAL GIVEN'

    return {
        "final_url": final_url,
        "number_of_redirects": len(redirect_chain) if not initial_url_is_200 else 0,
        "status_code": final_status_code,
        "content_type": content_type,
        "canonical_mismatch": canonical_mismatch,
        "canonical_url": canonical_url if canonical_url else '',
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
    parser = argparse.ArgumentParser(description='Check redirects for a URL.')
    parser.add_argument('input_file', help='The input file containing the list of URLs.', nargs='?', default=None)
    parser.add_argument('-o', '--output_file', help='The output CSV file.', default=None)
    parser.add_argument('--checkpoint', action='store_true', help='Use checkpointing to resume from the last processed URL.')
    parser.add_argument('-u', '--url', help='The URL to check.')
    parser.add_argument('-l', '--log', action='store_true', help='Write a log file.')
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
        canonical_status = 'CANONICAL_AWAY' if result['canonical_mismatch'] else 'CANONICAL_OK'
    except Exception as e:
        logging.error(f'Error creating redirect key: {e}')
        return ''

    redirect_details = []
    for i in range(7):
        try:
            if i < number_of_redirects:
                redirect = result['redirect_chain'][i]
                redirect_status_code = redirect.get('redirect_status_code', '')
                redirect_type = redirect.get('redirect_type', '')
                if redirect_type:  # Ensure redirect_type is not None
                    redirect_type = redirect_type.replace(' ', '_')
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

    return "RK_" + str(redirect_key)


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
    
def base36encode(number):
    """Converts an integer to a base36 string."""
    alphabet = '0123456789abcdefghijklmnopqrstuvwxyz'
    base36 = ''
    while number:
        number, i = divmod(number, 36)
        base36 = alphabet[i] + base36
    return base36 or alphabet[0]
    
def generate_ruid(redirect_key):
    """Generates a unique identifier for the given redirect key."""
    md5_hash = hashlib.md5(redirect_key.encode()).hexdigest()
    ruid = int(md5_hash, 16)
    return base36encode(ruid)

CSV_CONFIG = [
    {"header": "RUID", "value": lambda result: generate_ruid(create_redirect_key(result))},
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

def process_args():
    args = parse_arguments()
    output_file = generate_output_filename(args)
    return args, output_file

def get_urls(args):
    urls = []
    if args.url or args.ur:
        urls.append(args.url)
    else:
        urls = read_urls_from_file(args.input_file)
    return urls

def load_checkpoints(args, urls):
    checkpoint_results = []
    if args.checkpoint:
        processed_urls = set()
        for url, result in load_checkpoint():
            processed_urls.add(url)
            checkpoint_results.append(result)
        urls = [url for url in urls if url not in processed_urls]
    return checkpoint_results, urls

def remove_duplicates(all_results):
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
    return unique_results

def redirect_to_result(args, unique_results):
    if args.redirect or args.ur:
        result = unique_results[0]  # get the first result
        visualize_link = create_url(result)  # create the visualize link
        print(f"Redirecting to: {visualize_link}")
        webbrowser.open(visualize_link)  # open the visualize link in a web browser

def delete_checkpoint_file():
    if os.path.exists(CHECKPOINT_FILE):
        os.remove(CHECKPOINT_FILE)

#this functions reuses most of the funcitonality alreadu in the code, but just for one URL, do not duplicate functionality
def check_redirect(url):
    result = check_redirects([url], False)
    return result[0]  # return the first result (there should only be one)



def main():
    """Main function."""
    args = parse_arguments()

    if args.log:
        log_filename = 'redirect_checker.log'  # default log filename
        if config.has_section('Logging') and 'filename' in config['Logging']:
            log_filename = config.get('Logging', 'filename')
        logging.basicConfig(filename=log_filename, level=logging.INFO)
    
    if args.url:
        result = check_redirect(args.url)
        visualize_link = create_url(result)  # create the visualize link
        print(f"Redirecting to: {visualize_link}")
        webbrowser.open(visualize_link)  # open the visualize link in a web browser
    else:
        output_file = generate_output_filename(args)
        urls = read_urls_from_file(args.input_file)
        checkpoint_results, urls = load_checkpoints(args, urls)
        results = check_redirects(urls, args.checkpoint)
        all_results = checkpoint_results + results
        unique_results = remove_duplicates(all_results)
        write_results_to_file(output_file, unique_results)
        delete_checkpoint_file()

if __name__ == "__main__":
    main()