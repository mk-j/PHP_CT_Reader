<?php
include_once("ctreader.class.php");

//quick example
$ct = new CTReader('https://ct.googleapis.com/pilot/');
$ct->downloadNextRange();//grab first 2000
$ct->parseFileList();//parse first 2000
exit(0);

//download all
$ct = new CTReader('https://ct.googleapis.com/pilot/');
$ct->downloadAll();//loop and fetch 2000 at a time
exit(0);

//customize the parser
class CTParser extends CTReader
{
	public function parseCert($cert_pem)
	{
		$parsed = openssl_x509_parse($cert_pem);
		echo json_encode($parsed['subject']['CN'])."\n";
		//$file = new ASN1X509();
		//$file->loadPEM($pem);
		//$details = array();
		//$details['version'] = $file->getVersion();
		//$details['serial'] = $file->getSerialNumber();
		//$details['signatureType'] = $file->getSignatureType();
		//$details['issuer'] = $file->getIssuer();
		//$details['validDates'] = $file->getValidDates();
		//$details['subject'] = $file->getSubject();
		//$details['publicKey'] = $file->getPublicKeyInfo();
		//$details['extensionInfo'] = $file->getExtensionInfo();
		//$details['signatureInfo'] = $file->getSignatureInfo();
		//print_r($details);
	}
}

$ct = new CTParser('https://ct.googleapis.com/pilot/');
$ct->parseFileList();
exit(0);
