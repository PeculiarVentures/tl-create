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
	
	var isFirstOutput = true ;
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
				fws.write('var MozillaTrustedRoots =[\''); 
				//fws.write('"-----BEGIN CERTIFICATE-----" + \n');
				//fws.write('\n');
				fws.write(( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value.js  :""  );
				
			}
			else {
				//fws.write('"-----BEGIN CERTIFICATE-----" + \n');
				fws.write(',\n\'');
				fws.write( ( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value.js :"" );
			}
			fws.write('\'');
			//fws.write('"-----END CERTIFICATE-----",\n' );
		}
	}
	
	if(outputFormat == "js")
		fws.write( '\n];\n\n' ) ;
};

/*
 * 
 * EUTL parsing functions
 * 
 */

function certEutl () {
    
}



certEutl.prototype.parse = function parse(data,fws,outputFormat)
{
	var isFirstOutput = true ;
	data[ prepareTagName('TrustServiceStatusList') ][prepareTagName('TrustServiceProviderList')].forEach(function (trustServiceProviderList) {
	
		trustServiceProviderList[prepareTagName('TrustServiceProvider')].forEach(function(trustServiceProvider) {
			
			tspInfo = trustServiceProvider[ prepareTagName('TSPInformation')];
			var addInfo = parseAdditionalInformation( tspInfo[0] );
			
			tspServiceList = trustServiceProvider[ prepareTagName('TSPServices')];
			//console.dir(tspServiceList );
			for( var tspServiceInd in tspServiceList) {
				tspService = tspServiceList[tspServiceInd ];
				//console.log(tspService[prepareTagName('TSPService')][0][prepareTagName('ServiceInformation')][0][prepareTagName('ServiceTypeIdentifier')]);
				serviceInfo = tspService[prepareTagName('TSPService')][0][prepareTagName('ServiceInformation')][0];
				serviceTypeIdentifier = serviceInfo[prepareTagName('ServiceTypeIdentifier')][0];
				
				matchedStrCAQC = serviceTypeIdentifier.toString().match(/.*(CA\/QC)/g);
				NationalRootCAQC = serviceTypeIdentifier.toString().match(/.*(NationalRootCA-QC)/g);
				matchedStrCAPKC = serviceTypeIdentifier.toString().match(/.*(CA\/PKC)/g);
				if( matchedStrCAQC != null  || NationalRootCAQC !=null || matchedStrCAPKC != null ) {
					//console.log(serviceInfo[prepareTagName('ServiceStatus')]);
					serviceStatus = serviceInfo[prepareTagName('ServiceStatus')][0].toString().match(/.*(TrustedList\/Svcstatus\/accredited)/g);
					//console.log(serviceStatus );
					if( serviceStatus != null ) {
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
												fws.write('var EUTrustedRoots = [\''); 
												//fws.write('"-----BEGIN CERTIFICATE-----" + \n');
												fws.write(digitalId[prepareTagName('X509Certificate')][0].replace(/(.{1,*})/g, '$1'));
												
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
			};
		});	
	});
	if( outputFormat == "js" ) 
		fws.write("\n];\n\n");
	
};

function prepareTagName (name) {
	return prefix+name ;
};

function parseAdditionalInformation  (tspInfo)
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

/**
 * Module dependencies.
 */

var program = require('commander');
var util = require('util');
var xml2js = require('xml2js');
var fs = require('fs');
var prefix = "tsl:";//user by eutil 
var euLocalUrl = "/../data/currenttl.xml";
var euUrl = "";
var mozillaUrl = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";
var mozillaLocalUrl = "/../data/certdata.txt";

program
  .version('0.0.1')
  .option('-e, --eutil', 'EU Trust List Parse')
  .option('-m, --mozilla', 'Mozilla Trust List Parse')
  .option('-f, --for [type]', 'Add the specified type for parse', 'ALL')
  .option('-o, --format [type]', 'Add the specified type for output format', 'pem')
  .parse(process.argv);
  
console.log('Parsing started:');
if(program.args[0]) {
	var writableStream = fs.createWriteStream(program.args[0]);
	if (program.eutil) {	
		console.log('Started parsing  - eutil');
		var data = fs.readFileSync(__dirname + euLocalUrl, {encoding: 'utf-8'});
		var parser = new xml2js.Parser();
		parser.parseString(data ,function (err, result) {
		 	var euCertParser = new certEutl();
		 	
		 	if( typeof result['TrustServiceStatusList'] !=='undefined' ) {
		 			prefix = "";	
		 	}
		 		
		 	euCertParser.parse(result,writableStream,program.format);
	    });
	}
	if (program.mozilla) {
		console.log('Started parsing  - mozilla');
		var data = fs.readFileSync(__dirname + mozillaLocalUrl, {encoding: 'utf-8'});
		var codeFilter = program.for.split(",");
		
		var mozillaCertParser = new certMozilla(codeFilter);
		mozillaCertParser.parse(data,writableStream,program.format);
	}
	
	writableStream.end();
}
else {
	console.log("output <filename> argument missing");
	console.log("EX: node tl-create --eutil -mozilla --for 'EMAIL_PROTECTION,CODE_SIGNING' <roots.pem>");
}