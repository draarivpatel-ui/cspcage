import { diffCsp, intersectCsp, mergeCsp } from '../src/index.mjs';

const before = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const addition = "script-src 'self' https://cdn.example.com/app.js; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const merged = mergeCsp([before, addition]);
const intersection = intersectCsp([before, addition]);
const diff = diffCsp(before, merged);

console.log('merged', merged);
console.log('intersection', intersection);
console.log('diff', JSON.stringify(diff.summary));
