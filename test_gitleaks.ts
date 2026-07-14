import toml from 'toml';

async function test() {
  const response = await fetch(
    'https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml'
  );
  const text = await response.text();
  const config = toml.parse(text);

  let regexCompiled = 0;
  for (const rule of config.rules) {
    if (rule.id && rule.regex) {
      try {
        new RegExp(rule.regex, 'g');
        regexCompiled++;
      } catch (e) {}
    }
  }
  console.log(
    'Compiled',
    regexCompiled,
    'regexes from',
    config.rules.length,
    'rules.'
  );

  // Test if it catches an AWS key
  const patterns: Record<string, RegExp> = {};
  for (const rule of config.rules) {
    if (rule.id && rule.regex) {
      try {
        patterns[rule.id] = new RegExp(rule.regex, 'g');
      } catch (e) {}
    }
  }
  const textContent = 'AKIA1234567890ABCDEF';
  for (const [id, regex] of Object.entries(patterns)) {
    if (regex.test(textContent)) {
      console.log('Matched!', id);
    }
  }
}
test();
