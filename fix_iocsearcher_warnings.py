#!/usr/bin/env python3
"""
Script to fix SyntaxWarnings in iocsearcher by converting regex strings to raw strings.
This fixes invalid escape sequence warnings in Python 3.8+.
"""

import re
import os

IOCSEARCHER_DIR = "dependencies/repos/iocsearcher-main"

def fix_file(filepath, fixes):
    """Apply fixes to a file."""
    if not os.path.exists(filepath):
        print(f"Warning: File not found: {filepath}")
        return False
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    original_content = content
    for pattern, replacement in fixes:
        content = re.sub(pattern, replacement, content)
    
    if content != original_content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

def main():
    print("Fixing SyntaxWarnings in iocsearcher...")
    
    # Fix searcher.py line 271
    searcher_fixes = [
        # Line 271: '^(\*\.)?[a-zA-Z0-9_\-\.]+$'
        (r"if not re\.match\('^\(\\\*\\\.\)\?\[a-zA-Z0-9_\\-\\\.\]\+'\$', s\):", 
         r"if not re.match(r'^(\*\.)?[a-zA-Z0-9_\-\.]+$', s):"),
        
        # Line 325: '^([xX\.]+|[\-]+|[_]+)$'
        (r"if re\.match\('^\(\[xX\\\.\]\+|\[\\-\]\+|\[_\]\+\)'\$', tokens\[0\]\):", 
         r"if re.match(r'^([xX\.]+|[\-]+|[_]+)$', tokens[0]):"),
        
        # Line 922: '\-[0-9]+$'
        (r"ioc_name = re\.sub\('\\-\[0-9\]\+'\$','', sec\)", 
         r"ioc_name = re.sub(r'\-[0-9]+$','', sec)"),
    ]
    
    # Fix copyright regex (lines 485-492) - need to handle multi-line
    searcher_file = os.path.join(IOCSEARCHER_DIR, "iocsearcher/searcher.py")
    if os.path.exists(searcher_file):
        with open(searcher_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix copyright regex - convert to raw string
        copyright_pattern = r're\.compile\(\s*"\(\(?:\?\[\.\\-,\u2013;\]\+\)\?\(?:\?\[ \]\+\)\?All Right\[s\]\? Reserved\( to\|\\\.\)\?\)\|\s*"\(\(?:\?©\|\\\(C\\\)\|&copy;\|\\xA9\)\(?:\?\\s\+\)\?\[\.\\-,\\\-\]\+\)\?\|\s*"\(@\)\|\s*"\(\[12\]\[0-9\]\{3\}\\s\?\[--\u2013\u2014\]\\s\?\(?:\?\[12\]\[0-9\]\{3\}\|present\)\s*"\(?:\?\\s\+by\)\?\(?:\?\[\\s\.\\-\\/\]\+\)\?\|\s*"\(\[12\]\[0-9\]\{3\}\(?:\\s\+by\)\?\(?:\?\[\\s\.\\-\\/\]\+\)\?\|\s*"\(CopyRight\)"'
        
        # Simpler approach: find and replace the re.compile line
        new_content = content
        # Replace re.compile( with re.compile(r
        new_content = re.sub(
            r're\.compile\(\s*"\(\(?:\?\[\.\\-,\u2013;\]\+\)\?\(?:\?\[ \]\+\)\?All Right',
            r're.compile(r"((?:[.\-,–;]+)?(?:[ ]+)?All Right',
            new_content
        )
        
        # Fix other parts of the copyright regex
        new_content = re.sub(
            r'"\(\(?:\?©\|\\\(C\\\)\|&copy;\|\\xA9\)\(?:\?\\s\+\)\?\[\.\\-,\\\-\]\+\)\?\|\|',
            r'r"((?:©|\(C\)|&copy;|\\xA9)(?:\s+)?[.,\-]?)|\|',
            new_content
        )
        
        new_content = re.sub(
            r'"\(\[12\]\[0-9\]\{3\}\\s\?\[--\u2013\u2014\]\\s\?\(?:\?\[12\]\[0-9\]\{3\}\|present\)',
            r'r"([12][0-9]{3}\s?[--–—]\s?(?:[12][0-9]{3}|present)',
            new_content
        )
        
        new_content = re.sub(
            r'\(?:\?\\s\+by\)\?\(?:\?\[\\s\.\\-\\/\]\+\)\?\|\|',
            r'(?:\s+by)?(?:[\s.,\-\/]+)?)|\|',
            new_content
        )
        
        new_content = re.sub(
            r'"\(\[12\]\[0-9\]\{3\}\(?:\\s\+by\)\?\(?:\?\[\\s\.\\-\\/\]\+\)\?\|\|',
            r'r"([12][0-9]{3}(?:\s+by)?(?:[\s.,\-\/]+)?)|\|',
            new_content
        )
        
        if new_content != content:
            with open(searcher_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed: {searcher_file}")
        
        # Apply other fixes
        for pattern, replacement in searcher_fixes:
            if re.search(pattern, new_content):
                new_content = re.sub(pattern, replacement, new_content)
                with open(searcher_file, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"Applied fix in {searcher_file}")
    
    # Fix doc_common.py
    doc_common_file = os.path.join(IOCSEARCHER_DIR, "iocsearcher/doc_common.py")
    if os.path.exists(doc_common_file):
        with open(doc_common_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Fix line 48: html_regex = (b"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br \/>"
        new_content = re.sub(
            r'html_regex = \(b"<h1>\|<h2>\|<h3>\|<p>\|<em>\|<i>\|<br>\|<br \\/>"',
            r'html_regex = (br"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br />"',
            content
        )
        
        if new_content != content:
            with open(doc_common_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed: {doc_common_file}")
    
    # Fix doc_ehtml.py
    doc_ehtml_file = os.path.join(IOCSEARCHER_DIR, "iocsearcher/doc_ehtml.py")
    if os.path.exists(doc_ehtml_file):
        with open(doc_ehtml_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_content = content
        # Line 92: match = re.search("(?:app-id=|id)?(\d+)", value)
        new_content = re.sub(
            r'match = re\.search\("\(?:\?app-id=\|id\)\?\(\\d\+\)", value\)',
            r'match = re.search(r"(?:app-id=|id)?(\d+)", value)',
            new_content
        )
        
        # Line 97: match = re.search("(?:app-id=)?([A-Za-z][A-Za-z0-9_\.]+)", value)
        new_content = re.sub(
            r'match = re\.search\("\(?:\?app-id=\)\?\(\[A-Za-z\]\[A-Za-z0-9_\\\.\]\+\)", value\)',
            r'match = re.search(r"(?:app-id=)?([A-Za-z][A-Za-z0-9_\.]+)", value)',
            new_content
        )
        
        # Lines 606-609
        new_content = re.sub(
            r"s = re\.sub\('\\s\*\\n\\s\*', ', ', s\)",
            r"s = re.sub(r'\s*\n\s*', ', ', s)",
            new_content
        )
        new_content = re.sub(
            r"s = re\.sub\('\\s\+,', ',', s\)",
            r"s = re.sub(r'\s+,', ',', s)",
            new_content
        )
        new_content = re.sub(
            r"s = re\.sub\('\\s\+', ' ', s\)",
            r"s = re.sub(r'\s+', ' ', s)",
            new_content
        )
        
        if new_content != content:
            with open(doc_ehtml_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed: {doc_ehtml_file}")
    
    # Fix doc_html.py
    doc_html_file = os.path.join(IOCSEARCHER_DIR, "iocsearcher/doc_html.py")
    if os.path.exists(doc_html_file):
        with open(doc_html_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        new_content = content
        # Lines 102-104: replace_regex
        new_content = re.sub(
            r'replace_regex = \(b"<span\[^>\]\*>\|</span>\|<pre\[^>\]\*>\|</pre>\|"',
            r'replace_regex = (br"<span[^>]*>|</span>|<pre[^>]*>|</pre>|"',
            new_content
        )
        new_content = re.sub(
            r'b"<em>\|</em>\|<i>\|</i>\|"',
            r'br"<em>|</em>|<i>|</i>|"',
            new_content
        )
        new_content = re.sub(
            r'b"<b>\|</b>\|<strong\[^>\]\*>\|</strong>\|<wbr \\/>"',
            r'br"<b>|</b>|<strong[^>]*>|</strong>|<wbr />"',
            new_content
        )
        
        if new_content != content:
            with open(doc_html_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed: {doc_html_file}")
    
    # Fix doc_word.py
    doc_word_file = os.path.join(IOCSEARCHER_DIR, "iocsearcher/doc_word.py")
    if os.path.exists(doc_word_file):
        with open(doc_word_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Line 65: text = re.sub('----media\/[a-zA-Z0-9]+\.[a-z]{3,}----',
        new_content = re.sub(
            r"text = re\.sub\('----media\\/\[a-zA-Z0-9\]\+\\\.\[a-z\]\{3,\}----',",
            r"text = re.sub(r'----media/[a-zA-Z0-9]+\.[a-z]{3,}----',",
            content
        )
        
        if new_content != content:
            with open(doc_word_file, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f"Fixed: {doc_word_file}")
    
    print("Done! SyntaxWarnings should be fixed.")

if __name__ == "__main__":
    main()

