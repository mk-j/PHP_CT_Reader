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
	}
}

$ct = new CTParser('https://ct.googleapis.com/pilot/');
$ct->parseFileList();
exit(0);
