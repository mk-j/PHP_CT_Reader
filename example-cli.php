<?php
include_once("ctreader.class.php");

$ct = new CTReader('https://ct.googleapis.com/pilot/');
$ct->downloadNextRange($i=0);//grab another 2000
$ct->parseFileList();
exit(0);

//or with inheritance
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
