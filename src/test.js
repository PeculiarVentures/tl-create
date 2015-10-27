/*var needle = require('needle');

var options = {
 json:true

};
needle.get('http://ec.europa.eu/information_society/newsroom/cf/dae/document.cfm?doc_id=1789', options, function(error, response) {
  if (!error && response.statusCode == 200)
    console.log(response.body);
});*/
/*
var HttpClient = new require('httpclient').HttpClient;

console.log( HttpClient({
	url: 'http://google.com'
}).finish().body.read(null).decodeToString());
*/
var request = require('sync-request');
var res = request('GET', 'http://www.tscheme.org/UK_TSL/TSL-UKsigned.xml');
console.log(res.body.toString('utf-8'));