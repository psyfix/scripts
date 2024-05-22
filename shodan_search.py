import shodan

# API key from Shodan.io
API_KEY = "INSERT API KEY HERE"

def search_domains(api_key, file_path):
    # Initialize Shodan API client
    api = shodan.Shodan(api_key)

    try:
        with open('domains.txt', 'r') as file:
            for line in file:
                domain = line.strip()

                try:
                    # Perform Shodan search for the given domain
                    results = api.search(domain)

                    # Print the search results
                    print(f"Results for {domain}:")
                    for result in results['matches']:
                        print(f"- IP: {result['ip_str']}")
                        print(f"  Port: {result['port']}")
                        print(f"  Organization: {result.get('org', 'N/A')}")
                        print()

                except shodan.APIError as e:
                    print(f"Error: {e}")

    except FileNotFoundError:
        print(f"File '{file_path}' not found.")

# Call the function to search the domains
search_domains(API_KEY, 'domains.txt')
