"""
HTML / Webpage Metadata Analysis Module.
Statically parses HTML metadata safely without executing JavaScript,
detecting password inputs, foreign form actions, hidden iframes, and external asset ratios.
"""

from typing import Dict, Any, Optional
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract


class HTMLMetadataAnalyzer:
    """Safe HTML metadata analyzer for phishing indicator extraction."""

    def analyze(self, html_content: Optional[str], page_url: str) -> Dict[str, Any]:
        """
        Parses HTML statically and extracts phishing-indicative structural features.
        If html_content is None (e.g. unreachable, blocked, or timed out), returns safe defaults.
        """
        defaults = {
            "html_retrieved": False,
            "has_password_input": 0,
            "has_login_form": 0,
            "form_count": 0,
            "external_form_action": 0,
            "iframe_count": 0,
            "has_hidden_iframe": 0,
            "script_count": 0,
            "external_resources_ratio": 0.0,
            "page_title": "",
            "page_title_domain_mismatch": 0,
            "suspicious_html_indicators": [],
        }

        if not html_content or not isinstance(html_content, str):
            return defaults

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception:
            return defaults

        parsed_page = urlparse(page_url)
        extracted_page = tldextract.extract(page_url)
        base_domain = f"{extracted_page.domain}.{extracted_page.suffix}".lower()

        # 1. Page Title
        title_tag = soup.find("title")
        title_text = title_tag.get_text().strip() if title_tag else ""

        # Check title domain mismatch (e.g. Title says "PayPal Login" but domain is "xyz-update.com")
        title_lower = title_text.lower()
        title_mismatch = 0
        common_brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "chase", "bank of america"]
        for brand in common_brands:
            if brand in title_lower and brand.replace(" ", "") not in extracted_page.domain.lower():
                title_mismatch = 1
                break

        # 2. Forms and Inputs
        forms = soup.find_all("form")
        form_count = len(forms)
        has_password = 0
        has_login = 0
        external_form_action = 0

        # Password inputs
        password_inputs = soup.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"})
        if len(password_inputs) > 0:
            has_password = 1

        for form in forms:
            action = form.get("action", "").strip()
            # Check if form has password input
            if form.find("input", attrs={"type": lambda t: t and t.lower() == "password"}):
                has_login = 1

            if action and not action.startswith("#") and not action.startswith("javascript:"):
                action_parsed = urlparse(action)
                if action_parsed.netloc:
                    act_extracted = tldextract.extract(action)
                    act_domain = f"{act_extracted.domain}.{act_extracted.suffix}".lower()
                    if act_domain and act_domain != base_domain:
                        external_form_action = 1

        # 3. iFrames
        iframes = soup.find_all("iframe")
        iframe_count = len(iframes)
        has_hidden_iframe = 0
        for iframe in iframes:
            style = iframe.get("style", "").lower()
            width = str(iframe.get("width", "")).strip()
            height = str(iframe.get("height", "")).strip()
            if "display:none" in style or "visibility:hidden" in style or width in ("0", "1") or height in ("0", "1"):
                has_hidden_iframe = 1
                break

        # 4. Scripts
        scripts = soup.find_all("script")
        script_count = len(scripts)

        # 5. External Resources Ratio (scripts, images, stylesheets)
        total_resources = 0
        external_resources = 0

        # Check script src, img src, link href
        resource_tags = [
            (soup.find_all("script", src=True), "src"),
            (soup.find_all("img", src=True), "src"),
            (soup.find_all("link", rel=lambda r: r and "stylesheet" in r, href=True), "href"),
        ]

        for tag_list, attr_name in resource_tags:
            for tag in tag_list:
                src = tag.get(attr_name, "")
                if src:
                    total_resources += 1
                    src_parsed = urlparse(src)
                    if src_parsed.netloc:
                        src_extracted = tldextract.extract(src)
                        src_domain = f"{src_extracted.domain}.{src_extracted.suffix}".lower()
                        if src_domain and src_domain != base_domain:
                            external_resources += 1

        ext_ratio = round(external_resources / total_resources, 3) if total_resources > 0 else 0.0

        # Collect suspicious indicators
        indicators = []
        if has_password and external_form_action:
            indicators.append("Password input transmits credentials to foreign domain.")
        elif has_password:
            indicators.append("Credential password input field detected.")
        if has_hidden_iframe:
            indicators.append("Hidden iframe embedded on webpage.")
        if title_mismatch:
            indicators.append(f"Webpage title '{title_text[:40]}' references brand not matching hosting domain.")
        if ext_ratio > 0.70 and total_resources >= 5:
            indicators.append(f"High external asset dependency ({int(ext_ratio*100)}% foreign hosted).")

        return {
            "html_retrieved": True,
            "has_password_input": has_password,
            "has_login_form": has_login,
            "form_count": form_count,
            "external_form_action": external_form_action,
            "iframe_count": iframe_count,
            "has_hidden_iframe": has_hidden_iframe,
            "script_count": script_count,
            "external_resources_ratio": ext_ratio,
            "page_title": title_text[:120],
            "page_title_domain_mismatch": title_mismatch,
            "suspicious_html_indicators": indicators,
        }
