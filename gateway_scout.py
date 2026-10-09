#!/usr/bin/env python3
"""
gateway_scout.py v2.1 — payment gateway intelligence tool
fixed: uses duckduckgo-search library for reliable results
"""

import argparse
import json
import random
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, unquote, parse_qs

import requests
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS

# ─── constants ─────────────────────────────────────────────────────────────

VERSION = "2.1"
TOOL_NAME = "gateway_scout"

USER_AGENTS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
]

REQUEST_HEADERS_BASE = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "identity",
    "Connection": "keep-alive",
}

CHECKOUT_PATHS = [
    "/checkout", "/cart", "/payment", "/shop/checkout",
    "/store/checkout", "/billing", "/pay", "/checkout.html",
    "/order", "/shop/cart", "/purchase", "/payments",
]

CRAWL_KEYWORDS = [
    "checkout", "cart", "payment", "pay", "billing", "purchase",
    "order", "shop", "store", "subscribe", "pricing", "upgrade",
]

# ─── gateway fingerprint database ──────────────────────────────────────────

GATEWAY_SIGNATURES = {
    "Stripe": {
        "script_domains": ["js.stripe.com", "checkout.stripe.com", "api.stripe.com", "m.stripe.com", "m.stripe.network", "hooks.stripe.com", "stripe.network"],
        "inline_patterns": [
            r"js\.stripe\.com/v\d+", r"pk_live_[a-zA-Z0-9]{20,}",
            r"pk_test_[a-zA-Z0-9]{20,}", r"rk_live_[a-zA-Z0-9]{20,}",
            r"rk_test_[a-zA-Z0-9]{20,}", r"checkout\.stripe\.com",
            r"StripeElements", r"stripe\.js",
            r"stripe.*payment.*element", r"expressCheckoutElement",
        ],
    },
    "Adyen": {
        "script_domains": ["checkoutshopper-live.adyen.com", "checkoutshopper-test.adyen.com", "live.adyen.com", "checkout.adyen.com", "adyen.com"],
        "inline_patterns": [
            r"checkoutshopper-(live|test)\.adyen\.com", r"adyen\.com/checkout",
            r"adyen-checkout__", r"data-adyen", r"AdyenCheckout",
            r"adyenCustomElement", r"adyen.*web.*sdk",
        ],
    },
    "PayPal": {
        "script_domains": ["paypal.com", "paypalobjects.com", "checkout.paypal.com"],
        "inline_patterns": [
            r"paypal\.com/sdk/js", r"paypalobjects\.com", r"paypal-button",
            r"PAYPAL.*BUTTON", r"smart-payment-buttons",
            r"paypal\.com/checkoutnow", r"paypal\.com/webapps/hermes",
        ],
    },
    "Braintree": {
        "script_domains": ["js.braintreegateway.com", "assets.braintreegateway.com", "braintreegateway.com"],
        "inline_patterns": [
            r"js\.braintreegateway\.com", r"braintree\.hostedFields",
            r"braintree\.client", r"clientToken.*braintree",
            r"braintree\.web", r"braintree.*datacollector",
        ],
    },
    "Square": {
        "script_domains": ["js.squareup.com", "web.squarecdn.com", "squareup.com"],
        "inline_patterns": [
            r"SqPaymentForm", r"js\.squareup\.com/v\d",
            r"squareup\.com/frontend", r"square.*web.*payments",
        ],
    },
    "Checkout.com": {
        "script_domains": ["cdn.checkout.com", "api2.checkout.com", "checkout.com"],
        "inline_patterns": [
            r"cdn\.checkout\.com/js", r"Frames\(\{",
            r"checkout\.com/js/frames", r"Checkout\.com.*iframe",
        ],
    },
    "Klarna": {
        "script_domains": ["x.klarnacdn.net", "js.klarna.com", "klarna.com", "klarna.ai"],
        "inline_patterns": [
            r"klarnacdn\.net", r"Klarna\.Payments",
            r"klarna-checkout", r"klarna.*payment.*method",
            r"klarna.*banner", r"klarna.*widget",
        ],
    },
    "Razorpay": {
        "script_domains": ["checkout.razorpay.com", "razorpay.com", "api.razorpay.com", "rzp.io"],
        "inline_patterns": [
            r"checkout\.razorpay\.com/v\d+", r"rzp_live_[a-zA-Z0-9]+",
            r"rzp_test_[a-zA-Z0-9]+", r"razorpay.*checkout",
            r"razorpay.*payment.*button", r"razorpaycheckout",
            r"razorpay.*payment.*form", r"rzp\.io",
        ],
    },
    "PayU": {
        "script_domains": ["payu.in", "secure.payu.in", "js.payu.co.in", "merch-prod.s3.amazonaws.com"],
        "inline_patterns": [
            r"payu\.in", r"secure\.payu\.in",
            r"js\.payu\.co\.in", r"payu\.buzz", r"payu.*checkout",
        ],
    },
    "2Checkout (Verifone)": {
        "script_domains": ["2checkout.com", "2co.com", "avangate.com"],
        "inline_patterns": [
            r"2checkout\.com", r"avangate\.com", r"2co\.com", r"2checkout.*inline",
        ],
    },
    "Mercado Pago": {
        "script_domains": ["mercadopago.com", "sdk.mercadopago.com", "mercadolibre.com"],
        "inline_patterns": [
            r"mercadopago\.com", r"mercadolibre\.com/checkout", r"mercadopago.*web.*payment",
        ],
    },
    "Apple Pay": {
        "script_domains": ["apple.com/apple-pay"],
        "inline_patterns": [
            r"ApplePaySession", r"apple-pay", r"apple_pay_button", r"applePayButton",
        ],
    },
    "Google Pay": {
        "script_domains": ["pay.google.com", "payments.google.com"],
        "inline_patterns": [
            r"pay\.google\.com", r"googlePayButton", r"google.*payment.*button.*container",
        ],
    },
    "Shopify Payments": {
        "script_domains": ["shopify.com", "shopifycs.com", "cdn.shopify.com"],
        "inline_patterns": [
            r"shopify\.com/s/", r"shopifycs\.com",
            r"shopify.*payments", r"shopify.*checkout", r"Shopify.*Buy.*Button",
        ],
    },
    "Amazon Pay": {
        "script_domains": ["payments.amazon.com", "static-na.payments-amazon.com"],
        "inline_patterns": [
            r"payments\.amazon\.com", r"OffAmazonPayments", r"amazon.*pay.*button",
        ],
    },
    "Worldpay": {
        "script_domains": ["worldpay.com", "cdn.worldpay.com"],
        "inline_patterns": [
            r"worldpay\.com", r"worldpay.*checkout", r"worldpay.*hosted",
        ],
    },
    "GoCardless": {
        "script_domains": ["gocardless.com", "js.gocardless.com"],
        "inline_patterns": [
            r"gocardless\.com", r"GoCardless.*checkout", r"gocardless.*dropin",
        ],
    },
    "BitPay": {
        "script_domains": ["bitpay.com", "cdn.bitpay.com"],
        "inline_patterns": [
            r"bitpay\.com", r"bitpay.*invoice", r"bitpay.*checkout",
        ],
    },
    "Coinbase Commerce": {
        "script_domains": ["commerce.coinbase.com", "cdn.coinbase.com"],
        "inline_patterns": [
            r"commerce\.coinbase\.com", r"coinbase.*commerce", r"coinbase.*checkout",
        ],
    },
    "Cybersource": {
        "script_domains": ["cybersource.com"],
        "inline_patterns": [
            r"cybersource\.com", r"secureAcceptance", r"cybersource.*flex",
        ],
    },
    "Authorize.net": {
        "script_domains": ["authorize.net", "js.authorize.net", "accept.authorize.net"],
        "inline_patterns": [
            r"authorize\.net", r"accept.*js.*authorize", r"AcceptJS", r"authorizenet",
        ],
    },
}

# ─── tech stack fingerprints ───────────────────────────────────────────────

TECH_SIGNATURES = {
    "WordPress": [r"wp-content", r"wp-includes", r"WordPress \d+\.\d+"],
    "Shopify": [r"cdn\.shopify\.com", r"shopify\.theme", r"Shopify\.theme"],
    "Magento": [r"Magento", r"mage/"],
    "WooCommerce": [r"woocommerce", r"woo-commerce"],
    "React": [r"__NEXT_DATA__", r"react-root", r"_reactListening", r"react.*dom"],
    "Vue.js": [r"vue-app", r"v-bind", r"__VUE__", r"vue\.js", r"nuxt"],
    "Angular": [r"ng-app", r"angular\.js", r"ng-controller", r"zone\.js"],
    "Next.js": [r"__NEXT_DATA__", r"_next/"],
    "Wix": [r"wix\.com", r"wixstatic", r"wix.*apps"],
    "Squarespace": [r"squarespace\.com", r"squarespace", r"static1\.squarespace\.com"],
    "Webflow": [r"webflow\.com", r"webflow", r"wf-page"],
    "BigCommerce": [r"bigcommerce", r"bc-sf-filter"],
    "Salesforce Commerce": [r"demandware", r"salesforce.*commerce"],
    "Drupal": [r"drupal", r"sites/default/files"],
    "Cloudflare": [r"cdn-cgi", r"cloudflare", r"cf-ray"],
    "Google Analytics": [r"googletagmanager\.com", r"google-analytics\.com", r"gtag\("],
    "Meta Pixel": [r"connect\.facebook\.net", r"fbq\(", r"facebook.*pixel"],
    "Hotjar": [r"hotjar", r"static\.hotjar\.com"],
    "Intercom": [r"intercom", r"intercomcdn"],
    "HubSpot": [r"hs-scripts\.com", r"hubspot", r"hs-analytics"],
}

# ─── dork templates (expanded) ─────────────────────────────────────────────

DORK_TEMPLATES = {
    "stripe": [
        '"js.stripe.com/v3" -site:stripe.com -site:github.com',
        '"pk_live_" -site:github.com -site:stripe.com -site:docs.stripe.com',
        'inurl:checkout.stripe.com -site:stripe.com',
        'intext:"powered by stripe"',
        '"stripe-payment-element" -site:github.com -site:stripe.com',
        '"stripe checkout" -site:stripe.com -site:github.com -site:docs.stripe.com',
        '"pay with stripe" -site:stripe.com -site:github.com',
    ],
    "adyen": [
        '"checkoutshopper-live.adyen.com" -site:adyen.com -site:github.com',
        'inurl:checkoutshopper-live -site:adyen.com',
        'intext:"powered by adyen"',
        '"adyen-checkout__" -site:github.com -site:adyen.com',
        '"AdyenCheckout" -site:github.com -site:adyen.com',
        '"adyen web sdk" -site:adyen.com -site:github.com',
    ],
    "paypal": [
        'inurl:paypal.com/sdk/js -site:paypal.com',
        '"paypal-button-container" -site:paypal.com -site:github.com',
        'intext:"powered by paypal"',
        '"smart-payment-buttons" -site:paypal.com -site:github.com',
        '"paypal checkout" -site:paypal.com -site:github.com -site:developer.paypal.com',
    ],
    "braintree": [
        '"js.braintreegateway.com" -site:braintreegateway.com -site:github.com',
        'intext:"powered by braintree"',
        '"braintree.hostedFields" -site:github.com -site:braintreegateway.com',
        '"braintree checkout" -site:braintreegateway.com -site:github.com',
    ],
    "razorpay": [
        '"checkout.razorpay.com/v1" -site:razorpay.com -site:github.com',
        '"razorpay.com/payment-button" -site:razorpay.com -site:github.com',
        'inurl:checkout.razorpay.com -site:razorpay.com',
        'intext:"powered by razorpay"',
        '"rzp_live_" -site:github.com -site:razorpay.com',
        '"razorpaycheckout" -site:github.com -site:razorpay.com',
        'inurl:rzp.io -site:razorpay.com',
        '"pay with razorpay" OR "pay via razorpay"',
        '"razorpay-button" -site:razorpay.com -site:github.com',
        '"razorpay.*payment.*form" -site:razorpay.com -site:github.com',
        'intext:"razorpay payment" -site:razorpay.com -site:github.com',
        '"razorpay_client" -site:razorpay.com -site:github.com',
    ],
    "klarna": [
        '"klarnacdn.net" -site:klarna.com -site:github.com',
        'intext:"pay later with klarna" OR intext:"klarna checkout"',
        '"klarna-pay-later" -site:klarna.com -site:github.com',
        '"klarna payments" -site:klarna.com -site:github.com',
    ],
    "square": [
        '"js.squareup.com" -site:squareup.com -site:github.com',
        '"SqPaymentForm" -site:github.com -site:squareup.com',
        'intext:"powered by square" -site:squareup.com',
        '"square checkout" -site:squareup.com -site:github.com',
    ],
    "checkout.com": [
        '"cdn.checkout.com/js" -site:checkout.com -site:github.com',
        'intext:"powered by checkout.com"',
        '"checkout.com/frames" -site:checkout.com -site:github.com',
    ],
    "mercadopago": [
        '"sdk.mercadopago.com" -site:mercadopago.com -site:github.com',
        'intext:"powered by mercadopago"',
        '"mercadopago checkout" -site:mercadopago.com -site:github.com',
    ],
    "gocardless": [
        '"js.gocardless.com" -site:gocardless.com -site:github.com',
        'intext:"powered by gocardless"',
    ],
    "authorize.net": [
        '"accept.authorize.net" -site:authorize.net -site:github.com',
        '"AcceptJS" -site:github.com -site:authorize.net',
        'intext:"powered by authorize.net"',
        '"authorize.net payment" -site:authorize.net -site:github.com',
    ],
    "2checkout": [
        '"2checkout.com/checkout" -site:2checkout.com -site:github.com',
        'intext:"powered by 2checkout" OR intext:"powered by verifone"',
    ],
}

INDUSTRY_FILTERS = {
    "saas": [' "pricing" OR "subscription" OR "plans"'],
    "ecommerce": [' "cart" OR "add to cart" OR "checkout"'],
    "fintech": [' "fintech" OR "financial" OR "banking"'],
    "travel": [' "booking" OR "reservation" OR "flight"'],
    "gaming": [' "game" OR "gaming" OR "esports"'],
    "india": [' "india" OR "bharat" OR "desi"'],
}

# ─── search engine (FIXED) ─────────────────────────────────────────────────

class SearchEngine:
    """
    uses duckduckgo-search library for reliable results
    falls back to bing scrape if ddg fails
    """

    def __init__(self, timeout=15, proxy=None, max_retries=3):
        self.timeout = timeout
        self.max_retries = max_retries
        self.session = requests.Session()
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})

    def search_ddg(self, query, max_results=25):
        """search via duckduckgo-search library — handles rate limits internally"""
        for attempt in range(self.max_retries):
            try:
                with DDGS(timeout=self.timeout) as ddgs:
                    results = list(ddgs.text(query, max_results=max_results))
                    urls = [r["href"] for r in results if r and "href" in r]
                    if urls:
                        return urls
            except Exception as e:
                if attempt < self.max_retries - 1:
                    wait = random.uniform(2, 5) * (attempt + 1)
                    time.sleep(wait)
            else:
                break
        return []

    def search_bing(self, query, max_results=25):
        """bing fallback scrape"""
        try:
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml",
            }
            url = f"https://www.bing.com/search?q={query}&count={max_results}"
            resp = self.session.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for item in soup.find_all("li", class_="b_algo"):
                link = item.find("a")
                if link and link.get("href", "").startswith("http"):
                    results.append(link["href"])
            return results[:max_results]
        except Exception:
            return []

    def search(self, query, max_results=25):
        """primary: ddg library → fallback: bing scrape"""
        results = self.search_ddg(query, max_results)
        if not results:
            results = self.search_bing(query, max_results)
        return results


# ─── scanner engine ────────────────────────────────────────────────────────

class Scanner:
    def __init__(self, timeout=10, deep=False, crawl=False, tech_stack=False,
                 stealth=False, proxy=None):
        self.timeout = timeout
        self.deep = deep
        self.crawl = crawl
        self.tech_stack = tech_stack
        self.stealth = stealth
        self.session = requests.Session()
        if proxy:
            self.session.proxies.update({"http": proxy, "https": proxy})
        self._ua = random.choice(USER_AGENTS)

    def _delay(self):
        if self.stealth:
            time.sleep(random.uniform(0.5, 2.0))

    def _headers(self):
        h = dict(REQUEST_HEADERS_BASE)
        h["User-Agent"] = random.choice(USER_AGENTS) if self.stealth else self._ua
        return h

    def fetch(self, url):
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True, headers=self._headers())
            if resp.status_code == 200:
                return resp.text
        except requests.RequestException:
            pass
        return None

    def extract_refs(self, html):
        soup = BeautifulSoup(html, "html.parser")
        scripts = [s.get("src", "") for s in soup.find_all("script", src=True)]
        links = [l.get("href", "") for l in soup.find_all("link", href=True)]
        iframes = [i.get("src", "") for i in soup.find_all("iframe", src=True)]
        forms = str(soup.find_all("form"))
        inline_scripts = " ".join([s.string for s in soup.find_all("script") if s.string])
        return scripts, links, iframes, forms, inline_scripts, soup

    def scan_page(self, url):
        self._delay()
        html = self.fetch(url)
        if not html:
            return {}, {}

        scripts, links, iframes, forms, inline_js, soup = self.extract_refs(html)
        all_refs = scripts + links + iframes
        all_text = html + " " + forms + " " + inline_js

        gateways = {}
        for gw, sigs in GATEWAY_SIGNATURES.items():
            evidence = []
            confidence = 0
            for ref in all_refs:
                for domain in sigs["script_domains"]:
                    if domain in ref:
                        evidence.append(f"ref: {ref[:120]}")
                        confidence = max(confidence, 90)
                        break
            for pattern in sigs["inline_patterns"]:
                matches = re.findall(pattern, all_text)
                if matches:
                    evidence.append(f"pattern: {pattern} ({len(matches)}x)")
                    confidence = max(confidence, 75)
            if evidence:
                gateways[gw] = {"confidence": confidence, "evidence": evidence[:5]}

        tech = {}
        if self.tech_stack:
            for name, patterns in TECH_SIGNATURES.items():
                for p in patterns:
                    if re.search(p, all_text):
                        tech[name] = True
                        break

        return gateways, tech

    def discover_checkout_links(self, url, soup):
        checkout_urls = set()
        base = urljoin(url, "/")
        for a in soup.find_all("a", href=True):
            href = a["href"].lower()
            text = a.get_text().lower().strip()
            if any(kw in href or kw in text for kw in CRAWL_KEYWORDS):
                full_url = urljoin(base, a["href"])
                if full_url.startswith("http"):
                    checkout_urls.add(full_url)
        return list(checkout_urls)[:15]

    def scan(self, url):
        if not url.startswith("http"):
            url = "https://" + url

        result = {"url": url, "gateways": {}, "tech_stack": {}, "pages_scanned": [url]}

        gateways, tech = self.scan_page(url)
        result["gateways"].update(gateways)
        result["tech_stack"].update(tech)

        html = self.fetch(url)
        if html:
            soup = BeautifulSoup(html, "html.parser")
            checkout_links = self.discover_checkout_links(url, soup)
        else:
            checkout_links = []

        scan_targets = []
        if self.deep:
            parsed = urlparse(url)
            base = f"{parsed.scheme}://{parsed.netloc}"
            for path in CHECKOUT_PATHS:
                scan_targets.append(base + path)

        if self.crawl and checkout_links:
            scan_targets.extend(checkout_links)

        scan_targets = list(set(scan_targets))
        scan_targets = [t for t in scan_targets if t != url]

        for target in scan_targets:
            self._delay()
            gws, tech = self.scan_page(target)
            for gw, data in gws.items():
                if gw not in result["gateways"]:
                    data["found_on"] = urlparse(target).path or target
                    result["gateways"][gw] = data
            result["tech_stack"].update(tech)
            result["pages_scanned"].append(target)

        return result


# ─── dork engine ───────────────────────────────────────────────────────────

class DorkEngine:
    def __init__(self, search_engine, scanner, gateway_name, industry=None, max_results_per_dork=25):
        self.search_engine = search_engine
        self.scanner = scanner
        self.gateway_key = self._resolve_gateway(gateway_name)
        self.industry = industry
        self.max_results = max_results_per_dork

    def _resolve_gateway(self, name):
        name_lower = name.lower().replace(" ", "").replace(".", "").replace("-", "")
        for key in GATEWAY_SIGNATURES:
            key_normalized = key.lower().replace(" ", "").replace(".", "").replace("-", "").replace("(", "").replace(")", "")
            if name_lower in key_normalized or key_normalized in name_lower:
                return key
        for key in DORK_TEMPLATES:
            if name_lower in key:
                return key
        return None

    def get_dorks(self):
        if self.gateway_key not in DORK_TEMPLATES:
            return []
        dorks = list(DORK_TEMPLATES[self.gateway_key])
        if self.industry and self.industry in INDUSTRY_FILTERS:
            filters = INDUSTRY_FILTERS[self.industry]
            enhanced = []
            for dork in dorks:
                for f in filters:
                    enhanced.append(dork + f)
            dorks = enhanced[:15]
        return dorks

    def extract_domains(self, urls):
        domains = {}
        for url in urls:
            parsed = urlparse(url)
            domain = parsed.netloc
            if domain:
                domain = domain.replace("www.", "")
                if domain and domain not in domains:
                    domains[domain] = f"https://{domain}"
        return domains

    def discover(self):
        dorks = self.get_dorks()
        if not dorks:
            return [], f"no dorks found for gateway: {self.gateway_key}"

        all_urls = []
        print(f"  executing {len(dorks)} dorks for: {self.gateway_key}", file=sys.stderr)

        for i, dork in enumerate(dorks):
            print(f"  [{i+1}/{len(dorks)}] {dork[:80]}", file=sys.stderr)
            results = self.search_engine.search(dork, self.max_results)
            all_urls.extend(results)
            print(f"    → {len(results)} results", file=sys.stderr)
            time.sleep(random.uniform(1, 2.5))

        domains = self.extract_domains(all_urls)
        print(f"  deduped: {len(domains)} unique domains from {len(all_urls)} results", file=sys.stderr)
        return list(domains.values()), None

    def run(self):
        urls, error = self.discover()
        if error:
            return None, error
        if not urls:
            return None, "no results found — try different gateway"

        print(f"\n  verifying {len(urls)} candidates...", file=sys.stderr)
        confirmed = []
        for i, url in enumerate(urls):
            print(f"  [{i+1}/{len(urls)}] scanning {url}", file=sys.stderr)
            result = self.scanner.scan(url)

            if self.gateway_key in result["gateways"]:
                result["verified"] = True
                confirmed.append(result)
                conf = result["gateways"][self.gateway_key]["confidence"]
                print(f"    ✓ CONFIRMED ({conf}% conf)", file=sys.stderr)
            else:
                result["verified"] = False
                if result["gateways"]:
                    other_gws = ", ".join(result["gateways"].keys())
                    print(f"    ✗ not {self.gateway_key} (found: {other_gws})", file=sys.stderr)
                else:
                    print("    ✗ no gateway detected", file=sys.stderr)

        return {
            "gateway": self.gateway_key,
            "total_candidates": len(urls),
            "confirmed": len(confirmed),
            "results": confirmed,
        }, None


# ─── output formatting ─────────────────────────────────────────────────────

def format_single_result(result):
    lines = []
    lines.append(f"\n  TARGET: {result['url']}")
    lines.append(f"  {'═' * 60}")

    if result.get("tech_stack"):
        stack = ", ".join(result["tech_stack"].keys())
        lines.append(f"  Tech stack: {stack}")
        lines.append(f"  {'─' * 60}")

    if not result["gateways"]:
        lines.append("  No gateways detected.")
        lines.append("  (may need --deep or --crawl for JS-rendered sites)")
        return "\n".join(lines)

    for gw, data in sorted(result["gateways"].items(), key=lambda x: -x[1]["confidence"]):
        conf = data["confidence"]
        bar = "█" * (conf // 10) + "░" * (10 - conf // 10)
        lines.append(f"  {gw}")
        lines.append(f"  [{bar}] {conf}% confidence")
        for ev in data["evidence"][:3]:
            lines.append(f"    → {ev}")
        if "found_on" in data:
            lines.append(f"    found on: {data['found_on']}")
        lines.append("")

    lines.append(f"  pages scanned: {len(result.get('pages_scanned', []))}")
    return "\n".join(lines)


def format_discovery_report(report):
    lines = []
    lines.append(f"\n  {'═' * 60}")
    lines.append("  GATEWAY SCOUT — DISCOVERY REPORT")
    lines.append(f"  Target gateway: {report['gateway'].upper()}")
    lines.append(f"  {'═' * 60}")
    lines.append(f"  Candidates scanned: {report['total_candidates']}")
    lines.append(f"  Confirmed users:    {report['confirmed']}")
    lines.append(f"  {'─' * 60}")

    for r in report["results"]:
        conf = r["gateways"][report["gateway"]]["confidence"]
        lines.append(f"  ✓ {r['url']} ({conf}% conf)")
        other_gws = [g for g in r["gateways"].keys() if g != report["gateway"]]
        if other_gws:
            lines.append(f"    also uses: {', '.join(other_gws)}")
        if r.get("tech_stack"):
            stack = ", ".join(list(r["tech_stack"].keys())[:8])
            lines.append(f"    tech: {stack}")

    lines.append(f"\n  {'═' * 60}")
    lines.append(f"  {report['confirmed']} confirmed {report['gateway']} users discovered")
    return "\n".join(lines)


def format_batch(results, gateway_filter=None):
    lines = []
    lines.append("\n  GATEWAY SCOUT — BATCH REPORT")
    lines.append(f"  {'═' * 60}")

    if gateway_filter:
        gw_lower = gateway_filter.lower()
        matched = [r for r in results if any(gw_lower in gw.lower() for gw in r["gateways"])]
        lines.append(f"  filter: {gateway_filter}")
        lines.append(f"  matched: {len(matched)}/{len(results)}")
        lines.append(f"  {'─' * 60}")
        for r in matched:
            gws = {k: v for k, v in r["gateways"].items() if gw_lower in k.lower()}
            for gw, data in gws.items():
                lines.append(f"  ✓ {r['url']} ({data['confidence']}% conf)")
    else:
        lines.append(f"  scanned: {len(results)} URLs")
        lines.append(f"  {'─' * 60}")
        for r in results:
            gws = ", ".join(r["gateways"].keys()) if r["gateways"] else "—"
            lines.append(f"  {r['url']}")
            lines.append(f"    → {gws}")

    return "\n".join(lines)


# ─── CLI ───────────────────────────────────────────────────────────────────

def load_urls(source):
    if source.startswith("http"):
        return [source]
    try:
        with open(source, "r") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"  [!] file not found: {source}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{VERSION} — payment gateway intelligence tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("source", nargs="?", help="URL or file of URLs")
    parser.add_argument("--find", type=str, help="discover sites using this gateway via dorks")
    parser.add_argument("--industry", type=str, help="industry filter")
    parser.add_argument("--deep", action="store_true", help="also scan known checkout paths")
    parser.add_argument("--crawl", action="store_true", help="crawl checkout-related links")
    parser.add_argument("--tech-stack", action="store_true", dest="tech_stack", help="detect tech stack")
    parser.add_argument("--stealth", action="store_true", help="random delays + UA rotation")
    parser.add_argument("--proxy", type=str, help="proxy URL")
    parser.add_argument("--gateway", type=str, help="filter batch results by gateway")
    parser.add_argument("--json", action="store_true", dest="output_json", help="JSON output")
    parser.add_argument("--out", type=str, help="save output to file")
    parser.add_argument("--timeout", type=int, default=10, help="request timeout")
    parser.add_argument("--threads", type=int, default=5, help="concurrent threads")
    parser.add_argument("--max-dork-results", type=int, default=25, dest="max_dork_results")
    args = parser.parse_args()

    if not args.source and not args.find:
        parser.print_help()
        sys.exit(1)

    scanner = Scanner(
        timeout=args.timeout, deep=args.deep, crawl=args.crawl,
        tech_stack=args.tech_stack, stealth=args.stealth, proxy=args.proxy
    )

    if args.find:
        print(f"\n  {TOOL_NAME} v{VERSION} — discovering {args.find} users", file=sys.stderr)
        if args.industry:
            print(f"  industry filter: {args.industry}", file=sys.stderr)
        print(f"  {'═' * 60}", file=sys.stderr)

        search_engine = SearchEngine(timeout=15, proxy=args.proxy)
        engine = DorkEngine(
            search_engine, scanner, args.find,
            industry=args.industry, max_results_per_dork=args.max_dork_results
        )

        if not engine.gateway_key:
            available = ", ".join(list(DORK_TEMPLATES.keys()))
            print(f"  [!] unknown gateway: {args.find}", file=sys.stderr)
            print(f"  available: {available}", file=sys.stderr)
            sys.exit(1)

        report, error = engine.run()

        if error:
            print(f"  [!] {error}", file=sys.stderr)
            sys.exit(1)

        if args.output_json:
            output = json.dumps(report, indent=2)
        else:
            output = format_discovery_report(report)

        if args.out:
            with open(args.out, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"  saved to: {args.out}", file=sys.stderr)
        print(output)
        return

    urls = load_urls(args.source)

    if len(urls) == 1:
        result = scanner.scan(urls[0])
        if args.output_json:
            output = json.dumps(result, indent=2)
        else:
            output = format_single_result(result)
    else:
        results = []
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {executor.submit(scanner.scan, url): url for url in urls}
            for future in as_completed(futures):
                url = futures[future]
                try:
                    r = future.result()
                    results.append(r)
                    gws = ", ".join(r["gateways"].keys()) if r["gateways"] else "—"
                    print(f"  [✓] {url} → {gws}", file=sys.stderr)
                except Exception as e:
                    print(f"  [✗] {url} → error: {e}", file=sys.stderr)

        if args.output_json:
            output = json.dumps(results, indent=2)
        else:
            output = format_batch(results, args.gateway)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"  saved to: {args.out}", file=sys.stderr)
    print(output)


if __name__ == "__main__":
    main()
