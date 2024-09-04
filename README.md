![Untitled](https://github.com/user-attachments/assets/f718acf6-5a1c-4c8e-a69a-7dfeeb6a1a42)


# ABHIMANYU - Fetching and displaying URLs 
This script is a tool for fetching and displaying URLs related to a given domain using several online sources such as Wayback Machine, Common Crawl, and VirusTotal. Here’s a breakdown of the key features and functionality

# Overview
## 1.Fetching URLs:

   > Wayback Machine: Retrieves archived URLs of a domain.
   > Common Crawl: Retrieves URLs from Common Crawl's index.
   > VirusTotal: Retrieves detected URLs associated with a domain from VirusTotal (requires an API key).

## 2.Handling Subdomains:

   > The script can either include or exclude subdomains based on the --no-subs flag.

## 3.Fetching Versions:

   > The script can list versions of a specific URL from the Wayback Machine using the --get-versions flag.

## 4.Multi-threading:

   > The script uses a ThreadPoolExecutor for concurrent execution, speeding up the fetching process.

## How It Works:

   > Banner: Displays an ASCII art banner when the script is executed.
   > Argument Parsing: Uses argparse to handle command-line arguments.
   > Fetching Data: Each fetch function makes HTTP requests to the respective service, parses the response, and extracts relevant URLs.
      --Output--:
        > URLs can be printed with or without their fetch dates based on the --dates flag.
        > If the --get-versions flag is used, the script lists different versions of a specific URL from the Wayback Machine.

## Example Usage:
1.Fetch URLs for a domain including subdomains:
```
python abhimanyu.py example.com
```
2.Fetch URLs for a domain excluding subdomains:
```
python abhimanyu.py example.com --no-subs
```
3.List URLs with their fetch dates:
```
python abhimanyu.py example.com --dates
```
4.Get versions of a specific URL:
```
python abhimanyu.py https://example.com/some-page --get-versions
```
5. use -h for help
```
python abhimanyu.py -h
```

# INSPIRED BY 
@tomnomnom waybackurls
