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

certMozilla.prototype.parse = function(body,fws) {
	//console.log("parsing started "+ this.codeFilterList);
	this.certText = body.toString().split("\n");
	this.findObjectDefinitionsSegment();
	this.findTrustSegment();
	this.findBeginDataSegment();
	while( this.curIndex < this.certText.length) {
		this.parseOneCertificate();
		this.printCertificte(fws);
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

certMozilla.prototype.parseOneCertificate = function() {
	while( this.curIndex < this.certText.length ) {
		var isPushed = 0 ;
		var curObj =  {} ;
		var res = this.certText[this.curIndex++].split(/[ ,]+/);
		if( res[0] == "CKA_CLASS") {	
		 	curObj[res[0]] = {
		 		attrType: res[1],
		 		value:    res[2]
			};
		 	while(this.curIndex < this.certText.length) {
		 		
		 		res = this.certText[this.curIndex].split(/[ ,]+/);
		 		if( res.length == 3 &&  res[0] == "CKA_CLASS" && res[2] !="CKO_NSS_TRUST"  ) {
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
						if ( this.codeFilterList.indexOf( res[0] ) > -1 ) {
							//console.log(res[0] + "  " +this.codeFilterList.indexOf( res[0] ));
							if(typeof curObj[trust] !== "undefined") {
								curObj[trust].value += "," + res[0];  
								//console.log(curObj[trust].value );
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
				else if(res.length == 2 && res[1] == "MULTILINE_OCTAL")
				{
					 
					
					var data="";
					while( this.certText[++this.curIndex] != "END")
					{
						var octArr = this.certText[this.curIndex].split('\\'); 
						for( var i=1; i < octArr.length ; i++ ) {
							data+= String.fromCharCode( parseInt(octArr[i].toString(),8) ) ;
						}
						this.curIndex++;
					}
					curObj[res[0]] =  {
						attrType: res[1],
						value:   data.toString('base64') 
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

certMozilla.prototype.printCertificte = function(fws) {
	
	for(var attrib in this.attributes ) {
		fws.write( "Operator: "+ this.attributes[attrib].CKA_LABEL.value +"\n");
		fws.write("For: "+ this.attributes[attrib].CKA_TRUST.value +"\n");
		fws.write("Source: Mozilla"+"\n");
		fws.write("-----BEGIN CERTIFICATE-----"+"\n");
		fws.write( ( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value :"" );
		fws.write("\n-----END CERTIFICATE-----\n");
			
	}
};

/*
 * 
 * EUTL parsing functions
 * 
 */

function certEutl () {
    
}



certEutl.prototype.parse = function parse(data,fws)
{
	
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
					
					for( var ind in serviceInfo[prepareTagName('ServiceDigitalIdentity')] ) {
							serviceIdent = serviceInfo[prepareTagName('ServiceDigitalIdentity')][ind];							
							serviceIdent[prepareTagName('DigitalId')].forEach(function(digitalId) {
								if( typeof digitalId[prepareTagName('X509Certificate')] !== 'undefined' ){
									fws.write("Country: " + addInfo.country+"\n");
									fws.write("Operator: " + addInfo.serviceProviderName+"\n");
									fws.write("Source: EUTL\n");
									fws.write("-----BEGIN CERTIFICATE-----"+"\n");
									for( var i =0 ; i< Math.ceil(digitalId[prepareTagName('X509Certificate')][0].length/64);i++) {
										fws.write(digitalId[prepareTagName('X509Certificate')][0].slice(i*64 , i*64+64 )+"\n");	
									}
										
									fws.write("-----END CERTIFICATE-----\n\n");
								}
							});
							
					}	
				} 
			};
		});	
	});
	
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
//var mozillaUrl = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";
var mozillaLocalUrl = "/../data/certdata.txt";

program
  .version('0.0.1')
  .option('-e, --eutil', 'EU Trust List Parse')
  .option('-m, --mozilla', 'Mozilla Trust List Parse')
  .option('-f, --for [type]', 'Add the specified type for parse', 'EMAIL_PROTECTION,CODE_SIGNING')
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
		 			//console.log("prefix "+ prefix);	
		 	}
		 		
		 	euCertParser.parse(result,writableStream);
	    });
	}
	if (program.mozilla) {
		console.log('Started parsing  - mozilla');
		var data = fs.readFileSync(__dirname + mozillaLocalUrl, {encoding: 'utf-8'});
		var codeFilter = program.for.split(",");
		
		var mozillaCertParser = new certMozilla(codeFilter);
		mozillaCertParser.parse(data,writableStream);
	}
	
	writableStream.end();
}
else {
	console.log("output <filename> argument missing");
	console.log("EX: node tl-create --eutil -mozilla --for 'EMAIL_PROTECTION,CODE_SIGNING' <roots.pem>");	
}

