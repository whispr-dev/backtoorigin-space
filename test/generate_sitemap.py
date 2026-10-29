# generate_sitemap.py
import os
from datetime import datetime

def generate_sitemap(base_url, output_file='sitemap.xml', html_dir='.'):
    """
    Generates a sitemap.xml file by scanning for HTML files.

    Args:
        base_url (str): The base URL of your website (e.g., "https://fastping.it.com/").
        output_file (str): The name of the sitemap file to generate.
        html_dir (str): The directory to scan for HTML files. Defaults to current directory.
    """
    if not base_url.endswith('/'):
        base_url += '/'

    # XML header for sitemap
    sitemap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
"""

    # List to hold URLs found
    urls = []

    # Walk through the specified directory
    for root, _, files in os.walk(html_dir):
        for file in files:
            if file.endswith('.html'):
                # Construct the full path to the HTML file
                full_path = os.path.join(root, file)
                
                # Calculate the relative path from html_dir
                # This assumes html_dir is the root of your web content
                relative_path = os.path.relpath(full_path, html_dir)
                
                # Replace backslashes with forward slashes for URLs on Windows
                url_path = relative_path.replace('\\', '/')

                # Set priority based on file (index.html is highest)
                priority = '1.0' if file == 'pricing.html' and root == html_dir else '0.8'
                
                # Construct the full URL
                full_url = f"{base_url}{url_path}"

                # Add to URLs list
                urls.append({
                    'loc': full_url,
                    'lastmod': datetime.now().isoformat(timespec='seconds') + '+00:00', # Current time in UTC
                    'priority': priority
                })

    # Add URLs to the sitemap XML
    for url_data in urls:
        sitemap_xml += f"""  <url>
    <loc>{url_data['loc']}</loc>
    <lastmod>{url_data['lastmod']}</lastmod>
    <priority>{url_data['priority']}</priority>
  </url>
"""

    sitemap_xml += "</urlset>"

    # Write to file
    with open(output_file, 'w') as f:
        f.write(sitemap_xml)

    print(f"Sitemap generated successfully at {output_file} with {len(urls)} URLs.")
    print("Remember to place sitemap.xml and robots.txt in your website's root directory.")
    print(f"Also, update your robots.txt to point to the sitemap: Sitemap: {base_url}sitemap.xml")

if __name__ == "__main__":
    # IMPORTANT: Replace with your actual base URL
    YOUR_BASE_URL = "https://fastping.it.com/"

    # Assuming your HTML files are in the same directory as this script, or in subdirectories
    # If your HTML files are in a 'public' or 'site' folder, adjust html_dir accordingly:
    # Example: generate_sitemap(YOUR_BASE_URL, html_dir='path/to/your/html/files')
    
    # For your setup (HTML files directly in D:\code\fastping-deploy or its subfolders):
    # If you run this script from D:\code\fastping-deploy\, use '.' for html_dir
    # If your HTML files are in D:\code\fastping-deploy\public, use 'public'
    
    # Assuming your HTML files are within 'D:\code\fastping-deploy\code'
    # and you will run this script from 'D:\code\fastping-deploy\code'
    generate_sitemap(YOUR_BASE_URL, html_dir='.')
