import requests
import json
import os

access_token = "ory_at_dw8EP2WnSYP9ptVjLSrP-i7mmAkQJLMOGX2EFgFibBw.kwJ3VVzFNsv6X2DsKjJMVMplBRE0tjT4f6GSya3RxZY"
headers = {"Authorization": f"Bearer {access_token}"}
all_products = []

# Load existing products if the file exists
file_path = 'mesaky_salla_products.json'
if os.path.exists(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        try:
            all_products = json.load(f)
        except json.JSONDecodeError:
            all_products = []

# Collect product URLs from existing list to prevent duplicates
existing_urls = {p['product_url'] for p in all_products}

page = 660

try:
    while True:
        url = f"https://api.salla.dev/admin/v2/products?page={page}"
        print(f"Fetching: {url}")
        resp = requests.get(url, headers=headers)

        if resp.status_code != 200:
            print(f"Request failed with status code {resp.status_code}. Exiting...")
            break

        data = resp.json()
        for product in data.get('data', []):
            if product['is_available']:
                if product['url'] not in existing_urls:
                    all_products.append({
                        "product_name": product['name'],
                        "image_url": product['main_image'],
                        "product_url": product['url'],
                        "price_amount": product['price']['amount'],
                        "price_unit": product['price']['currency'],
                        "category": product['categories'][0]['name'] if len(product['categories']) >= 1 else None
                    })
                    existing_urls.add(product['url'])

        if page >= data['pagination']['totalPages']:
            break
        page += 1

except Exception as e:
    print(f"An error occurred: {e}")

finally:
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(all_products, f, ensure_ascii=False, indent=2)
    print(f"Saved {len(all_products)} total unique products to file.")
