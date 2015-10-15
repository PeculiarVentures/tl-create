/*
 * 
 * Mozilla parisng functions
 * 
 */


function certMozilla() {
	this.attributes=[];
	this.certTxt=null;
	this.curIndex=0;
}

certMozilla.prototype.parse = function(body) {
	console.log("parsing started ");
	this.certText = body.toString().split("\n");
	this.findObjectDefinitionsSegment();
	this.findTrustSegment();
	this.findBeginDataSegment();
	while( this.curIndex < this.certText.length) {
		this.parseOneCertificate();
		this.printCertificte();
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
	while( this.curIndex < this.certText.length )
	{
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
						if(typeof curObj[trust] !== "undefined") {
							curObj[trust].value += "," + res[2];  
						}
						else {
							curObj[trust] =  {
								attrType: "String",
								value:    res[2]
							};	
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

certMozilla.prototype.printCertificte = function() {
	
	for(var attrib in this.attributes ) {
		console.log("Country: ");
		console.log( "Operator: "+ this.attributes[attrib].CKA_LABEL.value );
		console.log("For: "+ this.attributes[attrib].CKA_TRUST.value );
		console.log("Source: Mozilla");
		console.log("-----BEGIN CERTIFICATE-----");
		console.log( ( typeof this.attributes[attrib].CKA_VALUE !== 'undefined'  )?  this.attributes[attrib].CKA_VALUE.value :"" );
		console.log("-----END CERTIFICATE-----\n\n");
			
	}
};

/*
 * 
 * EUTL parsing functions
 * 
 */

function certEutl () {
    
}

certEutl.prototype.parse = function parse(body)
{
	
	body.TrustServiceStatusList.SchemeInformation[0].PointersToOtherTSL.forEach(function (pointToOtherTsl) {
			pointToOtherTsl.OtherTSLPointer.forEach(function(otherTslPointer) {
				
				var addInfo = parseAdditionalInformation(otherTslPointer.AdditionalInformation);
				for( var i in otherTslPointer.ServiceDigitalIdentities ){
					console.log("Country: " + addInfo.country);
					console.log("Operator: " + addInfo.operatorName);
					console.log("Operator: " + addInfo.operatorName);
					console.log("-----BEGIN CERTIFICATE-----");
					console.dir(otherTslPointer.ServiceDigitalIdentities[i].ServiceDigitalIdentity[0].DigitalId[0].X509Certificate[0]);
					console.log("-----END CERTIFICATE-----\n\n");
				}
			} );
	});
	
};

function parseAdditionalInformation  (additionalInfoObj)
{
	var parsedInfo =  {country: "" , operatorName:"" };
	for( var i in additionalInfoObj[0].OtherInformation ) {
		if( typeof additionalInfoObj[0].OtherInformation[i].SchemeOperatorName  !== "undefined" ) {
			var operatorNames = additionalInfoObj[0].OtherInformation[i].SchemeOperatorName ;
			for(var ind in operatorNames) {
				if( operatorNames[ind].Name[0].$['xml:lang'] == "en") {
					parsedInfo.operatorName = operatorNames[ind].Name[0]._;
				}
			} 
				
		}
		if( typeof additionalInfoObj[0].OtherInformation[i].SchemeTerritory  !== "undefined" ) {
			parsedInfo.country= additionalInfoObj[0].OtherInformation[i].SchemeTerritory[0]; 
		}	
	}
	return parsedInfo ;
}

/**
 * Module dependencies.
 */

var program = require('commander');
var util = require('util');
var xml4js = require('xml4js');
var xml2js = require('xml2js');
var fs = require('fs');

var euLocalUrl = "/../data/EUTrustedListsofCertificationServiceProvidersXML.xml";
var mozillaUrl = "http://mxr.mozilla.org/mozilla/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1";
var mozillaLocalUrl = "/../data/certdata.txt";

program
  .version('0.0.1')
  .option('-e, --eutil', 'EU Trust List Parse')
  .option('-m, --mozilla', 'Mozilla Trust List Parse')
  .option('-f, --for [type]', 'Add the specified type for parse', 'email,code,www,roots.pem')
  .parse(process.argv);
  
console.log('Parsing started:');

if (program.eutil) {

	console.log('Started parsing  - eutil');
	
	var data = fs.readFileSync(__dirname + euLocalUrl, {encoding: 'utf-8'});
	var parser = new xml2js.Parser();
	 parser.parseString(data ,function (err, result) {
	 	var euCertParser = new certEutl();
	 	euCertParser.parse(result);
    });
}

if (program.mozilla) 
{
	console.log('Started parsing  - mozilla');
	var request = require('request');
	console.log("Data received from url....");
	var data = fs.readFileSync(__dirname + mozillaLocalUrl, {encoding: 'utf-8'});
	var mozillaCertParser = new certMozilla();
	mozillaCertParser.parse(data);
}
