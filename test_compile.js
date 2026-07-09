const fs = require('fs');
const Babel = require('@babel/standalone');

const code = fs.readFileSync('app/frontend/index.html', 'utf8');
const scriptMatch = code.match(/<script type="text\/babel">([\s\S]*?)<\/script>/);
if (scriptMatch) {
  try {
    const transpiled = Babel.transform(scriptMatch[1], { presets: ['react'] });
    console.log("Success!");
  } catch (err) {
    console.error("Syntax Error:", err.message);
  }
}
