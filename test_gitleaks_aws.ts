import toml from 'toml';

async function test() {
  const response = await fetch(
    'https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml'
  );
  const text = await response.text();
  const config = toml.parse(text);

  const awsRule = config.rules.find((r: any) => r.id === 'aws-access-token');
  console.log('AWS Rule Regex:', awsRule?.regex);
  if (awsRule) {
    try {
      const r = new RegExp(awsRule.regex, 'g');
      console.log('Compiles?', true);
      console.log('Matches AKIA?', r.test('AKIA1234567890ABCDEF'));
    } catch (e) {
      console.error('Compile error', e);
    }
  }
}
test();
