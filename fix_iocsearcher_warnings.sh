#!/bin/bash
# Script to fix SyntaxWarnings in iocsearcher by converting regex strings to raw strings

IOCSEARCHER_DIR="dependencies/repos/iocsearcher-main"

if [ ! -d "$IOCSEARCHER_DIR" ]; then
    echo "Error: iocsearcher directory not found at $IOCSEARCHER_DIR"
    exit 1
fi

echo "Fixing SyntaxWarnings in iocsearcher..."

# Fix searcher.py line 271
sed -i "s|if not re.match('^(\*\.)?\[a-zA-Z0-9_\\-\.\]+$', s):|if not re.match(r'^(\*\.)?[a-zA-Z0-9_\-\.]+$', s):|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"

# Fix searcher.py line 325
sed -i "s|if re.match('^(\[xX\.\]+|\[\\-\]+|\[_\]+)$', tokens\[0\]):|if re.match(r'^([xX\.]+|[\-]+|[_]+)$', tokens[0]):|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"

# Fix searcher.py lines 486-492 (copyright regex)
sed -i "s|regexp = re.compile(|regexp = re.compile(r|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"
# Fix the specific copyright regex lines
sed -i "s|              \"((?:\[.\\-,–;\]\+)?(?:\[ \]\+)?All Right\[s\]? Reserved( to|\.)?)|\||              r\"((?:[.\-,–;]+)?(?:[ ]+)?All Right[s]? Reserved( to|\.)?)|\||g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"
sed -i "s|              \"((?:©|\(C\)|&copy;|\\xA9)(?:\\s\+)?\[.,\\-\]?)\||              r\"((?:©|\(C\)|&copy;|\\xA9)(?:\s+)?[.,\-]?)|\||g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"
sed -i "s|              \"(\[12\]\[0-9\]\{3\}\\s?\[--–—\]\\s?(?:\[12\]\[0-9\]\{3\}|present)\"|              r\"([12][0-9]{3}\s?[--–—]\s?(?:[12][0-9]{3}|present)\"|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"
sed -i "s|                    \"(?:\s+by)?(?:\[\\s.,\\-\\/\]\+)?)\"|\"|                    r\"(?:\s+by)?(?:[\s.,\-\/]+)?)\"|\"|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"
sed -i "s|              \"(\[12\]\[0-9\]\{3\}(?:\\s\+by)?(?:\[\\s.,\\-\\/\]\+)?)\"|\"|              r\"([12][0-9]{3}(?:\s+by)?(?:[\s.,\-\/]+)?)\"|\"|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"

# Fix searcher.py line 922
sed -i "s|ioc_name = re.sub('\\-\[0-9\]\+$','', sec)|ioc_name = re.sub(r'\-[0-9]+$','', sec)|g" "$IOCSEARCHER_DIR/iocsearcher/searcher.py"

# Fix doc_common.py line 48
sed -i "s|html_regex = (b\"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br \\/>\"|html_regex = (br\"<h1>|<h2>|<h3>|<p>|<em>|<i>|<br>|<br />\"|g" "$IOCSEARCHER_DIR/iocsearcher/doc_common.py"

# Fix doc_ehtml.py line 92
sed -i "s|match = re.search(\"(?:app-id=|id)?(\\d+)\", value)|match = re.search(r\"(?:app-id=|id)?(\d+)\", value)|g" "$IOCSEARCHER_DIR/iocsearcher/doc_ehtml.py"

# Fix doc_ehtml.py line 97
sed -i "s|match = re.search(\"(?:app-id=)?(\[A-Za-z\]\[A-Za-z0-9_\.\]\+)\", value)|match = re.search(r\"(?:app-id=)?([A-Za-z][A-Za-z0-9_\.]+)\", value)|g" "$IOCSEARCHER_DIR/iocsearcher/doc_ehtml.py"

# Fix doc_ehtml.py lines 606-609
sed -i "s|s = re.sub('\\s\*\\n\\s\*', ', ', s)|s = re.sub(r'\s*\n\s*', ', ', s)|g" "$IOCSEARCHER_DIR/iocsearcher/doc_ehtml.py"
sed -i "s|s = re.sub('\\s\+,', ',', s)|s = re.sub(r'\s+,', ',', s)|g" "$IOCSEARCHER_DIR/iocsearcher/doc_ehtml.py"
sed -i "s|s = re.sub('\\s\+', ' ', s)|s = re.sub(r'\s+', ' ', s)|g" "$IOCSEARCHER_DIR/iocsearcher/doc_ehtml.py"

# Fix doc_html.py lines 102-104
sed -i "s|replace_regex = (b\"<span\[^>\]\*>|<\/span>|<pre\[^>\]\*>|<\/pre>|\"|replace_regex = (br\"<span[^>]*>|</span>|<pre[^>]*>|</pre>|\"|g" "$IOCSEARCHER_DIR/iocsearcher/doc_html.py"
sed -i "s|b\"<em>|<\/em>|<i>|<\/i>|\"|br\"<em>|</em>|<i>|</i>|\"|g" "$IOCSEARCHER_DIR/iocsearcher/doc_html.py"
sed -i "s|b\"<b>|<\/b>|<strong\[^>\]\*>|<\/strong>|<wbr \\/>\"|br\"<b>|</b>|<strong[^>]*>|</strong>|<wbr />\"|g" "$IOCSEARCHER_DIR/iocsearcher/doc_html.py"

# Fix doc_word.py line 65
sed -i "s|text = re.sub('----media\\/[a-zA-Z0-9\]\+\\.[a-z\]\{3,\}----',|text = re.sub(r'----media/[a-zA-Z0-9]+\.[a-z]{3,}----',|g" "$IOCSEARCHER_DIR/iocsearcher/doc_word.py"

echo "SyntaxWarnings fixes applied. Note: Some complex regex patterns may need manual review."

