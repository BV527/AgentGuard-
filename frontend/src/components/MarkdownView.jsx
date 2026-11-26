function inlineMarkdown(value, keyPrefix) {
  const tokens = String(value).split(/(\*\*[^*]+\*\*|`[^`]+`|\*[^*]+\*)/g).filter(Boolean);
  return tokens.map((token, index) => {
    const key = `${keyPrefix}-${index}`;
    if (token.startsWith('**') && token.endsWith('**')) return <strong key={key}>{token.slice(2, -2)}</strong>;
    if (token.startsWith('`') && token.endsWith('`')) return <code key={key}>{token.slice(1, -1)}</code>;
    if (token.startsWith('*') && token.endsWith('*')) return <em key={key}>{token.slice(1, -1)}</em>;
    return token;
  });
}

export default function MarkdownView({ content }) {
  const lines = (content || '').split('\n');
  const blocks = [];
  let i = 0;
  const isBlockStart = (line) => /^(#{1,6} |\s*\||[-*] |\d+\. )/.test(line);
  while (i < lines.length) {
    const line = lines[i].trim();
    if (!line) { i++; continue; }
    if (/^\|/.test(line)) {
      const rows = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) {
        const cells = lines[i].trim().replace(/^\|/, '').replace(/\|$/, '').split('|').map(c => c.trim());
        if (!cells.every(c => /^:?-{3,}:?$/.test(c))) rows.push(cells);
        i++;
      }
      if (rows.length) blocks.push(
        <div className="markdown-table-wrap" key={`table-${i}`}>
          <table>
            <thead><tr>{rows[0].map((c, col) => <th key={col}>{inlineMarkdown(c, `th-${i}-${col}`)}</th>)}</tr></thead>
            <tbody>{rows.slice(1).map((row, ri) => <tr key={ri}>{rows[0].map((_, col) => <td key={col}>{inlineMarkdown(row[col] || '', `td-${i}-${ri}-${col}`)}</td>)}</tr>)}</tbody>
          </table>
        </div>
      );
      continue;
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      const Tag = heading[1].length <= 2 ? 'h2' : 'h3';
      blocks.push(<Tag key={`h-${i}`}>{inlineMarkdown(heading[2], `h-${i}`)}</Tag>);
      i++; continue;
    }
    if (/^[-*] /.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*[-*] /.test(lines[i])) { items.push(lines[i].trim().slice(2)); i++; }
      blocks.push(<ul key={`ul-${i}`}>{items.map((item, j) => <li key={j}>{inlineMarkdown(item, `ul-${i}-${j}`)}</li>)}</ul>);
      continue;
    }
    if (/^\d+\. /.test(line)) {
      const items = [];
      while (i < lines.length && /^\s*\d+\. /.test(lines[i])) { items.push(lines[i].replace(/^\s*\d+\. /, '')); i++; }
      blocks.push(<ol key={`ol-${i}`}>{items.map((item, j) => <li key={j}>{inlineMarkdown(item, `ol-${i}-${j}`)}</li>)}</ol>);
      continue;
    }
    const para = [line]; i++;
    while (i < lines.length && lines[i].trim() && !isBlockStart(lines[i].trim())) { para.push(lines[i].trim()); i++; }
    blocks.push(<p key={`p-${i}`}>{inlineMarkdown(para.join(' '), `p-${i}`)}</p>);
  }
  return <div className="markdown-view">{blocks}</div>;
}
