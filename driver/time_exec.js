const readline = require('readline');
const rl = readline.createInterface({
    input: process.stdin
});

function pumpIndex(s, pos, len, times)
{
    // end is exclusive
    const substr = s.substr(pos, len);
    const pumped = (new Array(times)).fill(substr).join('');
    const before = s.substring(0, pos);
    const after = s.substring(pos + len);
    return before + pumped + after;
}

rl.on('line', (line) => {
    const parsed = JSON.parse(line);
    const pattern = Buffer.from(parsed.pattern, 'base64').toString('utf-8');
    const flags = Buffer.from(parsed.flags, 'base64').toString('utf-8');
    const charEncoding = parsed.char_encoding;
    const witness = Buffer.from(parsed.witness, 'base64').toString(charEncoding);
    const pump_pos = parsed.pump_pos;
    const pump_len = parsed.pump_len;
    const num_pumps = parsed.num_pumps;
    const times = parsed.times;
    const regexp = new RegExp(pattern, flags);
    console.log(regexp);
    
    console.log('WARMING_UP');
    // warm-up the regex
    for (let i=0; i < 10; i++)
    {
        regexp.test('a' + i + 'b');
    }

    const pumped_string = pumpIndex(witness, pump_pos, pump_len, num_pumps);

    console.log('BEGIN_TEST(' + (+new Date()) + ')');
    const start = +new Date();
    for (let i=0; i < times; i++)
    {
        regexp.test(pumped_string);
    }

    const elapsed = (+new Date() - start) / times;

    console.log('RESULT(' + elapsed + ')ENDRESULT');
});

console.log('READY')
