"""Check the offline diagram's navigation, accessible SVGs and text containment."""
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import unquote, urlsplit

from playwright.sync_api import expect, sync_playwright

root = Path(__file__).resolve().parent.parent
counts = json.loads((root / "analysis/reusability-coverage.json").read_text())["counts"]["core"]
results = []
with sync_playwright() as playwright:
    browser = playwright.chromium.launch(headless=True, executable_path=os.environ.get("CHROMIUM_EXECUTABLE"))
    for name, width, height in [("desktop", 1440, 900), ("mobile", 390, 844)]:
        page = browser.new_page(viewport={"width": width, "height": height})
        page.goto((root / "ARCHITECTURE.html").as_uri())
        expect(page.get_by_role("heading", level=1)).to_have_text("The Go runner, at a glance")
        expect(page.get_by_role("img")).to_have_count(3)
        expect(page.get_by_role("region")).to_have_count(3)
        expect(page.locator(".caveat")).to_contain_text(f"{counts['full']}/{counts['total']} full family contracts")
        assert page.locator("input, select, textarea, form").count() == 0
        expect(page.locator("svg").nth(2)).to_contain_text("controls / encode: shared text")
        expect(page.get_by_role("link", name="canonical audit example", exact=True)).to_have_count(1)
        expect(page.locator("body")).to_contain_text("Headerless setup is supported")
        assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
        for index in range(3):
            svg = page.get_by_role("img").nth(index)
            ids = svg.get_attribute("aria-labelledby").split()
            assert len(ids) == 2
            for element_id in ids:
                assert page.locator("#" + element_id).text_content().strip()
        for owner in ["authorRegistry", "Draft additions / field policy", "authorTexture / indexTextures", "manifestTextures → cmbIndex", "inspectRaster: discovery leads", "contactSheets → textMasks", "decodePNG", "Textures / specs / comparisons", "previewFit / wrapPages / controls", "composeCells → renderRuns", "snapshotArtifacts", "Shared publisher: writeNewFile"]:
            expect(page.locator("svg").first).to_contain_text(owner)
        for index in range(page.locator("a").count()):
            reference = urlsplit(page.locator("a").nth(index).get_attribute("href"))
            assert not reference.scheme and not reference.netloc
            if reference.path:
                assert (root / unquote(reference.path)).is_file()
            elif reference.fragment:
                expect(page.locator("#" + reference.fragment)).to_have_count(1)
        for index in range(page.locator("svg g.logic, svg g.data, svg g.note").count()):
            selector = f"document.querySelectorAll('svg g.logic, svg g.data, svg g.note')[{index}]"
            rect = {key: page.evaluate(selector + ".querySelector('rect').getBBox()." + key) for key in ["x", "y", "width", "height"]}
            text = {key: page.evaluate(selector + ".querySelector('text').getBBox()." + key) for key in ["x", "y", "width", "height"]}
            assert text["x"] >= rect["x"] and text["y"] >= rect["y"], (name, index, rect, text)
            assert text["x"] + text["width"] <= rect["x"] + rect["width"], (name, index, rect, text)
            assert text["y"] + text["height"] <= rect["y"] + rect["height"], (name, index, rect, text)
        page.get_by_role("link", name="Components", exact=True).focus()
        for _ in range(4):
            page.keyboard.press("Tab")
        expect(page.get_by_role("region").first).to_be_focused()
        assert page.evaluate("getComputedStyle(document.activeElement).outlineStyle") != "none"
        if name == "mobile":
            page.keyboard.press("ArrowRight")
            page.wait_for_function("document.querySelector('.diagram').scrollLeft > 0")
        page.evaluate("document.querySelector('.diagram').scrollLeft = 0")
        page.screenshot(path=str(root / "test-results" / f"architecture-{name}.png"), full_page=True)
        results.append({"viewport": [width, height], "status": "PASS", "svg_count": 3, "keyboard_focus": True, "horizontal_scroll": name == "mobile"})
        page.close()
    browser.close()
receipt = {"status": "PASS", "source_sha256": hashlib.sha256((root / "ARCHITECTURE.html").read_bytes()).hexdigest(), "checks": results, "limits": "Static documentation only; no form behavior applies. No gameplay or Go behavior claim."}
(root / "test-results" / "architecture-checks.json").write_text(json.dumps(receipt, indent=2) + "\n")
print(json.dumps(receipt))
