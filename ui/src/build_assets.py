"""Builds ui/net.html = ui/src/net.src.html + the shared base CSS from ui/health.html.
Run after editing either file:  python3 ui/src/build_assets.py"""
import re, os
here = os.path.dirname(os.path.abspath(__file__)); ui = os.path.join(here, '..')
idx = open(os.path.join(ui, 'health.html'), encoding='utf-8').read()
base = re.search(r'<style id="css">\n(.*?)</style>', idx, re.S).group(1)
src = open(os.path.join(here, 'net.src.html'), encoding='utf-8').read()
open(os.path.join(ui, 'net.html'), 'w', encoding='utf-8', newline='').write(src.replace('/*BASE_CSS*/', base))
print('ui/net.html built')
