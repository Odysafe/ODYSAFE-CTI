#!/usr/bin/env python3
"""
Fix SyntaxWarnings in iocsearcher by converting regex strings to raw strings.
This script is called automatically during installation.
"""
import os
import sys

def fix_file(filepath, replacements):
    """Apply replacements to a file."""
    if not os.path.exists(filepath):
        return False
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original = content
    for old, new in replacements:
        content = content.replace(old, new)
    
    if content != original:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    iocsearcher_dir = os.path.join(base_dir, 'iocsearcher')
    
    # Fix searcher.py
    searcher_file = os.path.join(iocsearcher_dir, 'searcher.py')
    if os.path.exists(searcher_file):
        with open(searcher_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Line 271
        content = content.replace(
            "if not re.match('^(\\*\\.)?[a-zA-Z0-9_\\-\\.]+$', s):",
            "if not re.match(r'^(\\*\\.)?[a-zA-Z0-9_\\-\\.]+$', s):"
        )
        
        # Line 325
        content = content.replace(
            "if re.match('^([xX\\.]+|[\\-]+|[_]+)$', tokens[0]):",
            "if re.match(r'^([xX\\.]+|[\\-]+|[_]+)$', tokens[0]):"
        )
        
        # Line 922
        content = content.replace(
            "ioc_name = re.sub('\\-[0-9]+$','', sec)",
            "ioc_name = re.sub(r'\\-[0-9]+$','', sec)"
        )
        
        # Copyright regex (lines 485-492) - convert each string to raw
        lines = content.split('\n')
        new_lines = []
        in_copyright_regex = False
        for i, line in enumerate(lines):
            if 'regexp = re.compile(' in line:
                in_copyright_regex = True
                new_lines.append(line)
            elif in_copyright_regex and line.strip().startswith('"') and '|' in line:
                # Convert string to raw string
                if line.strip().startswith('"') and not line.strip().startswith('r"'):
                    line = line.replace('"', 'r"', 1)
                new_lines.append(line)
                if 're.UNICODE' in line or 're.I)' in line:
                    in_copyright_regex = False
            else:
                new_lines.append(line)
        
        content = '\n'.join(new_lines)
        
        with open(searcher_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed: {searcher_file}")
    
    # Fix doc_common.py
    doc_common_file = os.path.join(iocsearcher_dir, 'doc_common.py')
    if os.path.exists(doc_common_file):
        with open(doc_common_file, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace(
            'html_regex = (b"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br \\/>"',
            'html_regex = (br"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br />"'
        )
        with open(doc_common_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed: {doc_common_file}")
    
    # Fix doc_ehtml.py
    doc_ehtml_file = os.path.join(iocsearcher_dir, 'doc_ehtml.py')
    if os.path.exists(doc_ehtml_file):
        with open(doc_ehtml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace(
            'match = re.search("(?:app-id=|id)?(\\d+)", value)',
            'match = re.search(r"(?:app-id=|id)?(\\d+)", value)'
        )
        content = content.replace(
            'match = re.search("(?:app-id=)?([A-Za-z][A-Za-z0-9_\\.]+)", value)',
            'match = re.search(r"(?:app-id=)?([A-Za-z][A-Za-z0-9_\\.]+)", value)'
        )
        content = content.replace(
            "s = re.sub('\\s*\\n\\s*', ', ', s)",
            "s = re.sub(r'\\s*\\n\\s*', ', ', s)"
        )
        content = content.replace(
            "s = re.sub('\\s+,', ',', s)",
            "s = re.sub(r'\\s+,', ',', s)"
        )
        content = content.replace(
            "s = re.sub('\\s+', ' ', s)",
            "s = re.sub(r'\\s+', ' ', s)"
        )
        with open(doc_ehtml_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed: {doc_ehtml_file}")
    
    # Fix doc_html.py
    doc_html_file = os.path.join(iocsearcher_dir, 'doc_html.py')
    if os.path.exists(doc_html_file):
        with open(doc_html_file, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace(
            'replace_regex = (b"<span[^>]*>|</span>|<pre[^>]*>|</pre>|"',
            'replace_regex = (br"<span[^>]*>|</span>|<pre[^>]*>|</pre>|"'
        )
        content = content.replace(
            'b"<em>|</em>|<i>|</i>|"',
            'br"<em>|</em>|<i>|</i>|"'
        )
        content = content.replace(
            'b"<b>|</b>|<strong[^>]*>|</strong>|<wbr \\/>"',
            'br"<b>|</b>|<strong[^>]*>|</strong>|<wbr />"'
        )
        with open(doc_html_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed: {doc_html_file}")
    
    # Fix doc_word.py
    doc_word_file = os.path.join(iocsearcher_dir, 'doc_word.py')
    if os.path.exists(doc_word_file):
        with open(doc_word_file, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace(
            "text = re.sub('----media\\/[a-zA-Z0-9]+\\.[a-z]{3,}----',",
            "text = re.sub(r'----media/[a-zA-Z0-9]+\\.[a-z]{3,}----',"
        )
        with open(doc_word_file, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed: {doc_word_file}")
    
    print("All SyntaxWarnings fixes applied successfully!")
    return 0

if __name__ == "__main__":
    sys.exit(main())

