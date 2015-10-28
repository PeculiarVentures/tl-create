/*
 * 
 * Mozilla parisng functions
 * 
 */


function certMozilla(codeFilter) {
	this.attributes=[];
	this.certTxt=null;
	this.curIndex=0;
	
	for( var i in codeFilter) {
		codeFilter[i] = "CKA_TRUST_"+ codeFilter[i];
	}
	this.codeFilterList= codeFilter;
	
}

certMozilla.prototype.parse = function(body,fws,outputFormat) {
	//console.log("parsing started "+ this.codeFilterList);
	this.certText = body.toString().split("\n");
	this.findObjectDefinitionsSegment();
	this.findTrustSegment();
	this.findBeginDataSegment();
	while( this.curIndex < this.certText.length) {
		this.parseOneCertificate();
		this.printCertificte(fws,outputFormat);
	}
};

certMozilla.prototype.findObjectDefinitionsSegment = function() {
	while( this.curIndex < this.certText.length ) {
		var patt = /(Certificates)/g;
		var res = this.certText[this.curIndex].match(patt);
		if( res == 'Certificates') {
			return;
		}
		
		this.curIndex++;
	}
};

certMozilla.prototype.findTrustSegment = function() {
	while( this.curIndex < this.certText.length )
	{
		var patt = /(Trust)/g;
		var res = this.certText[ this.curIndex].match(patt);
		if( res == "Trust"){
		 	return ;
		}
		
		this.curIndex++;
	}
	
};
certMozilla.prototype.findBeginDataSegment = function() {
	
	while( this.curIndex < this.certText.length )
	{
		var patt = /(BEGINDATA)/g;
		var res = this.certText[ this.curIndex].match(patt);
		if( res == "BEGINDATA"){
			while(1) {
				res = this.certText[this.curIndex++].split(/[ ,]+/);
				if( res[0] == "CKA_CLASS"){
			 		return;	
				}
			}
			
		}
		
		this.curIndex++;
	}
};
countLbl =0 ;
certMozilla.prototype.parseOneCertificate = function() {
	while( this.curIndex < this.certText.length ) {
		var isPushed = 0 ;
		var curObj =  {} ;
		var res = this.certText[this.curIndex++].split(/[ ,]+/);
		if (res[0].match(/^#|^\s*$/)) continue;
		
		if( res[0] == "CKA_CLASS") {	
		 	curObj[res[0]] = {
		 		attrType: res[1],
		 		value:    res[2]
			};
		 	while(this.curIndex < this.certText.length) {
		 		
		 		res = this.certText[this.curIndex].split(/[ ,]+/);
		 		if( res.length == 3 &&  res[0] == "CKA_CLASS" && res[2].match(/(CKO_NSS_TRUST)/g) !="CKO_NSS_TRUST"  ) {
					isPushed = 1 ;
					this.attributes.push(curObj);
					break;
				}
				if(res[0] == "CKA_LABEL" ) {
					
					var lblValue = this.certText[this.curIndex].split(/CKA_LABEL UTF8 \"(.*)\"/);
					res = [] ;
					res[0] = "CKA_LABEL";
					res[1] = "UTF8";
					res[2] = lblValue[1];
				}
				
				if( res.length == 3 ) {
					
					var trust = res[0].match(/(CKA_TRUST)/g);
					if(  trust == "CKA_TRUST") {
						if ( this.codeFilterList.indexOf( res[0] ) > -1 || this.codeFilterList.indexOf( "CKA_TRUST_ALL" ) > -1) {
							
							if(typeof curObj[trust] !== "undefined") {
								curObj[trust].value += "," + res[0];  
							
							}
							else {
								curObj[trust] =  {
									attrType: "String",
									value:    res[0]
								};	
							}
						}
					}
					
					curObj[res[0]] =  {
						attrType: res[1],
						value:    res[2]
					};
						
				}			
				else if(res.length == 2 && res[1].match(/(MULTILINE_OCTAL)/g) == "MULTILINE_OCTAL") {
					 
					
					var data="";
					while( this.certText[++this.curIndex].match(/(END)/g) != "END")
					{
						data += this.certText[this.curIndex] ;
					}
					var offset = 0;
					var bytes = data.split('\\');
					bytes.shift();
					var converted = new Buffer(bytes.length);
					while(bytes.length > 0) {
   						converted.writeUInt8(parseInt(bytes.shift(), 8), offset++);
  					}
					curObj[res[0]] =  {
						attrType: res[1],
						value:  
						{
							js:	converted.toString('base64').replace(/(.{1,*})/g, '$1'),
							pem: converted.toString('base64').replace(/(.{1,76})/g, '$1\n')
						} 
					};
					
					
				}
				this.curIndex++;		
		 	}
		}
		
		if(!isPushed) {
			this.attributes[0]= curObj;
		}
		
	} 
	
};

certMozilla.prototype.printCertificte = function(fws,outputFormat) {
	
	
	for(var attrib in this.attributes ) {
		if( outputFormat == "pem"){
			fws.write( "Operator: "+ this.attributes[attrib].CKA_LABEL.value +"\n");
			fws.write("For: "+ this.attributes[attrib].CKA_TRUST.value +"\n");
			fws.write("Source: Mozilla"+"\n");
			fws.write("-----BEGIN CERTIFICATE-----"+"\n");
			fws.write( ( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value.pem :"" );
			fws.write("-----END CERTIFICATE-----\n");
		}
		else if( outputFormat == "js"){
			
			if(isFirstOutput)
			{
				isFirstOutput = false;
				//fws.write('var MozillaTrustedRoots = [\n');
				//fws.write('var MozillaTrustedRoots =[\''); 
				//fws.write('"-----BEGIN CERTIFICATE-----" + \n');
				//fws.write('\n');
				fws.write('\''+(( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value.js  :'' ) );
				
			}
			else {
				//fws.write('"-----BEGIN CERTIFICATE-----" + \n');
				fws.write(',\n\'');
				fws.write( ( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value.js :'' );
			}
			fws.write('\'');
			//fws.write('"-----END CERTIFICATE-----",\n' );
		}
	}
	
	//if(outputFormat == "js")
		//fws.write( '\n];\n\n' ) ;
};

/*
 * 
 * EUTL parsing functions
 * 
 */

function certEutl () {
    
}



certEutl.prototype.parseTL = function (data,fws,outputFormat)
{

	if( typeof data[prepareTagName('TrustServiceStatusList')]== 'undefined') {
		return ;
	}
	if( typeof data[prepareTagName('TrustServiceStatusList')][prepareTagName('TrustServiceProviderList')] == 'undefined') {
		console.log("TrustServiceProviderList not found");
		return ;
	}
		
	var totlaCertFound =0 ;
	
	data[ prepareTagName('TrustServiceStatusList') ][prepareTagName('TrustServiceProviderList')].forEach(function (trustServiceProviderList) {
	
		trustServiceProviderList[prepareTagName('TrustServiceProvider')].forEach(function(trustServiceProvider) {
			totlaCertFound ++;		
			tspInfo = trustServiceProvider[ prepareTagName('TSPInformation')];
			var addInfo = parseAdditionalInformation( tspInfo[0] );
			
			tspServiceList = trustServiceProvider[ prepareTagName('TSPServices')];
			
			for( var tspServiceInd in tspServiceList) {
				tspService = tspServiceList[tspServiceInd ];
				//console.log(tspService[prepareTagName('TSPService')][0][prepareTagName('ServiceInformation')][0][prepareTagName('ServiceTypeIdentifier')]);
				serviceInfo = tspService[prepareTagName('TSPService')][0][prepareTagName('ServiceInformation')][0];
				serviceTypeIdentifier = serviceInfo[prepareTagName('ServiceTypeIdentifier')][0];
				
				matchedStrCAQC = serviceTypeIdentifier.toString().match(/.*(CA\/QC)/g);
				NationalRootCAQC = serviceTypeIdentifier.toString().match(/.*(NationalRootCA-QC)/g);
				matchedStrCAPKC = serviceTypeIdentifier.toString().match(/.*(CA\/PKC)/g);
				if( matchedStrCAQC !== null  || NationalRootCAQC !== null || matchedStrCAPKC !== null ) {
					//console.log(serviceInfo[prepareTagName('ServiceStatus')]);
					serviceStatus = serviceInfo[prepareTagName('ServiceStatus')][0].toString().match(/.*(TrustedList\/Svcstatus\/accredited)/g);
					//console.log(serviceStatus );
					if( serviceStatus !== null ) {
						for( var ind in serviceInfo[prepareTagName('ServiceDigitalIdentity')] ) {
								serviceIdent = serviceInfo[prepareTagName('ServiceDigitalIdentity')][ind];							
								serviceIdent[prepareTagName('DigitalId')].forEach(function(digitalId) {
									if( typeof digitalId[prepareTagName('X509Certificate')] !== 'undefined' ) {
										if(outputFormat == "pem" ) {
											fws.write("Country: " + addInfo.country+"\n");
											fws.write("Operator: " + addInfo.serviceProviderName+"\n");
											fws.write("Source: EUTL\n");
											fws.write("-----BEGIN CERTIFICATE-----"+"\n");
											fws.write(digitalId[prepareTagName('X509Certificate')][0].replace(/(.{1,64})/g, '$1\n'));	
											fws.write("-----END CERTIFICATE-----\n\n");
										}
										else if( outputFormat =="js"){
											if( isFirstOutput ) {
												isFirstOutput = false ;
												//fws.write('var EUTrustedRoots = [\''); 
												//fws.write('"-----BEGIN CERTIFICATE-----" + \n');
												fws.write('\''+digitalId[prepareTagName('X509Certificate')][0].replace(/(.{1,*})/g, '$1'));
												
											}
											else {
												//fws.write(',"-----BEGIN CERTIFICATE-----" + \n');
												fws.write(',\n\'');
												fws.write(digitalId[prepareTagName('X509Certificate')][0].replace(/(.{1,*})/g, '$1'));
												//fws.write('\"');
											}
											fws.write('\'');
											//fws.write('"-----END CERTIFICATE-----"\n' );
										
										}
									}
								});
								
						}
					}
				} 
			}
		});	
	});
	
	console.log( totlaCertFound + " Certificate Found" );
	
};


certEutl.prototype.parsePointToOtherTsl = function (data,fws,outputFormat) {
		
	if( typeof data[ ('TrustServiceStatusList') ] == 'undefined')
		return ;

	var otherTslList = data[ ('TrustServiceStatusList') ][('SchemeInformation')][0][('PointersToOtherTSL')][0][('OtherTSLPointer')];
	//####
	//for nodejs required. if not set generate error for some https link. mostlikely nodejs's trust list not updated
	//###
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";	
	
	for(var i in otherTslList ) {
		
		var tlLocation = otherTslList[i][('TSLLocation')][0] ;
		
		totalRootCount++;
		if( tlLocation.match(/.*\.xml$/g) ){
			
			var territory;
			otherTslList[i]['AdditionalInformation'][0]['OtherInformation'].forEach( function (addOtherInfo){
				if( typeof addOtherInfo['SchemeTerritory'] !== 'undefined' ) {
					console.log("\n");
					console.log("### Processing : " +addOtherInfo['SchemeTerritory']);
					console.log("Started : " + getDateTime() ) ;
				}
			});
			
			
		
			var res;
			try{
				res = request('GET', tlLocation, {'timeout':10000,'retry':true,'headers': {'user-agent': 'nodejs'}} ) ;	
				var tslBody = res.body.toString('utf-8') ;
				var parser = new xml2js.Parser();
				var parsedObj ;
				parsedRootCount++;
				parser.parseString(tslBody ,function (err, result) {
					 
					if( typeof result[('TrustServiceStatusList')] !=='undefined' ) {
				 			prefix = "";	
				 	}
				 	else {
				 		prefix = "tsl:";
				 	}
				 	parsedObj = result ;	
				});
				this.parseTL(parsedObj,fws,outputFormat);
				
			}catch(e){
				errorParsedRootCount++;
				console.log(e.toString());
			}
			console.log("Ended : " + getDateTime() ) ;
		}
		else {
			totalRootsSkip++;
		}
							
	}
	
	
	
};

function prepareTagName (name) {
	return prefix+name ;
}

function parseAdditionalInformation (tspInfo)
{
	var parsedInfo =  {country: "" , serviceProviderName:"" };
	tspInfo[prepareTagName('TSPName')][0][ prepareTagName('Name')].forEach(function(name) {
		 if( name.$['xml:lang'] == "en") {
		 	parsedInfo.serviceProviderName =  name._ ;
		 }
	});
	parsedInfo.country = tspInfo[prepareTagName('TSPAddress')][0][ prepareTagName('PostalAddresses')][0][ prepareTagName('PostalAddress')][0][prepareTagName('CountryName')][0];
	return parsedInfo ;
}

/*
 * Utility functions 
 * 
 */
function getDateTime() {

    var date = new Date();

    var hour = date.getHours();
    hour = (hour < 10 ? "0" : "") + hour;

    var min  = date.getMinutes();
    min = (min < 10 ? "0" : "") + min;

    var sec  = date.getSeconds();
    sec = (sec < 10 ? "0" : "") + sec;

    var year = date.getFullYear();

    var month = date.getMonth() + 1;
    month = (month < 10 ? "0" : "") + month;

    var day  = date.getDate();
    day = (day < 10 ? "0" : "") + day;

    return year + ":" + month + ":" + day + ":" + hour + ":" + min + ":" + sec;

}



/**
 * Module dependencies.
 */

var program = require('commander');
var util = require('util');
var xml2js = require('xml2js');
var request = require('sync-request');
var fs = require('fs');
var prefix = "tsl:";//user by eutil 
var euLocalUrl = "/../data/EUTrustedListsofCertificationServiceProvidersXML.xml";
var euUrl = "http://ec.europa.eu/information_society/newsroom/cf/dae/document.cfm?doc_id=1789";
var mozillaUrl = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";
var mozillaLocalUrl = "/../data/certdata.txt";
var isFirstOutput = true ;
var totalRootCount =0 ;
var parsedRootCount = 0;
var errorParsedRootCount = 0;
var totalRootsSkip = 0;

program
  .version('0.0.1')
  .option('-e, --eutl', 'EU Trust List Parse')
  .option('-m, --mozilla', 'Mozilla Trust List Parse')
  .option('-f, --for [type]', 'Add the specified type for parse', 'ALL')
  .option('-o, --format [format]', 'Add the specified type for output format', 'pem');
  
  
program.on('--help', function(){
  console.log('  Examples:');
  console.log('');
  console.log('    $ node tl-create --mozilla --format pem roots.pem');
  console.log('    $ node tl-create --mozilla --for "EMAIL_PROTECTION,CODE_SIGNING" --format pem roots.pem');
  console.log('    $ node tl-create --eutil --format pem roots.pem');
  console.log('    $ node tl-create --eutil --format js roots.js');
  console.log('');
});
  
program.on('--help', function(){
  console.log('  Types:');
  console.log('');
  console.log('    DIGITAL_SIGNATURE');
  console.log('    NON_REPUDIATION');
  console.log('    KEY_ENCIPHERMENT');
  console.log('    DATA_ENCIPHERMENT');
  console.log('    KEY_AGREEMENT');
  console.log('    KEY_CERT_SIGN');
  console.log('    CRL_SIGN');
  console.log('    SERVER_AUTH');
  console.log('    CLIENT_AUTH');
  console.log('    CODE_SIGNING');
  console.log('    EMAIL_PROTECTION');
  console.log('    IPSEC_END_SYSTEM');
  console.log('    IPSEC_TUNNEL');
  console.log('    IPSEC_USER');
  console.log('    TIME_STAMPING');
  console.log('    STEP_UP_APPROVED');
  console.log('');
}); 

program.parse(process.argv);
 
  

if (!program.args.length) program.help();

else if(program.args[0]) {
	
	console.log('Parsing started: '+ getDateTime());
	var writableStream = fs.createWriteStream(program.args[0]);
	
	if(program.format=='js')
		writableStream.write('var TrustedRoots = [ ') ;
	
	if (program.eutl) {	
		console.log('Trust Lists: EUTIL');
		console.log('Started parsing  - EUTIL '+getDateTime());
		try {
			var res = request('GET', euUrl, {'timeout':10000,'retry':true, 'headers': {'user-agent': 'nodejs'}} ) ;
			var data = res.body.toString('utf-8') ;
			//var data =  fs.readFileSync(__dirname + euLocalUrl, {encoding: 'utf-8'});
			var parser = new xml2js.Parser();
			parser.parseString(data ,function (err, result) {
		 		var euCertParser = new certEutl();
		 		//if( typeof result[prepareTagName('TrustServiceStatusList')] ==='undefined' ) {
			 	//	prefix = "";	
			 	//}
		 		euCertParser.parsePointToOtherTsl(result,writableStream,program.format);
	    	});
	    	console.log('\n\nFinished parsing  - EUTL '+getDateTime());	
	    	console.log("Total Roots Found :" + totalRootCount);
			console.log("Total Roots Parse Success :" + parsedRootCount);
			console.log("Total Roots Parse Error :" + errorParsedRootCount);
			console.log("Total Roots Skips :" + totalRootsSkip);
		}catch(e){
			console.log(e.toString());
		}	
		
	}
	if (program.mozilla) {
		
		console.log('Trust Lists: Mozilla');
		console.log('Started parsing  - Mozilla ' + getDateTime());
		try {
			var res = request('GET', mozillaUrl, {'timeout':10000,'retry':true,'headers': {'user-agent': 'nodejs'}} ) ;
			var codeFilter = program.for.split(",");
			//var data = fs.readFileSync(__dirname + mozillaLocalUrl, {encoding: 'utf-8'});
			var data = res.body.toString('utf-8') ;
			var mozillaCertParser = new certMozilla(codeFilter);
			mozillaCertParser.parse(data,writableStream,program.format);	
		}catch(e){
			console.log(e.toString());
		}
		console.log('Finished parsing  - Mozilla '+getDateTime());
	}
	if(program.format=='js')
		writableStream.write(" ];");
	writableStream.end();
}
