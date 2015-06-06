PHP_CT_Reader
=============

Simple, lightweight certificate transparency log parser for PHP.

This code will allow to one to download and parse SSL certificates from a public CT log.

Stores CT log entries in groups in .gz files

Quick PHP CLI example:
```php
class CTParser extends CTReader
{
	public function parseCert($cert_pem)
	{
		$parsed = openssl_x509_parse($cert_pem);
		echo json_encode($parsed['subject']['CN'])."\n";
	}
}

$ct = new CTParser('https://ct.googleapis.com/pilot/');
$ct->downloadNextRange($i=0);//grab next batch
$ct->parseFileList();
exit(0);
```

More on certificate transparency:
* http://en.wikipedia.org/wiki/Certificate_transparency
* http://www.certificate-transparency.org/
* http://tools.ietf.org/html/rfc6962
* https://www.digicert.com/certificate-transparency.htm
* https://github.com/google/certificate-transparency

