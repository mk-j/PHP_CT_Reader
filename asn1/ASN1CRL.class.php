<?php
include_once("asn1/ASN1File.class.php");
include_once("asn1/ASN1Node.class.php");
include_once("asn1/ASN1Parser.class.php");
include_once("asn1/ASN1Utils.class.php");

//A CRL
//http://www.ietf.org/rfc/rfc3280.txt
//http://www.ietf.org/rfc/rfc5280.txt
//-----------------------------------
//Parse Cert for CRL URL
//    openssl x509 -in cert.pem -noout -text
//Get CRL
//    wget http://crl3.digicert.com/evca1-g1.crl
//Parse CRL with openssl asn1parse:
//    openssl asn1parse -in evca1-g1.crl -inform DER
//Parse
//    openssl crl -in evca1-g1.crl -inform DER -noout -text
//-----------------------------------
class ASN1CRL extends ASN1File
{

	protected function tbsCertificateNode($which)
	{
		if ($this->root && $this->root->child(0))
		{
			$children = $this->root->child(0)->children();
			return isset($children[$which]) ? $children[$which] : null;
		}
		return null;
	}

	public function getVersion()
	{
		$node = $this->tbsCertificateNode(0);
		if ($node)
		{
			return $node->toString()+1;
		}
		return 2;
	}

	public function getSignatureType()
	{
		$node = $this->tbsCertificateNode(1);
		if ($node && $node->child(0))
		{
			$oid = $node->child(0)->toString();//no value
			return ASN1Utils::oid($oid);//TODO: test sha2
		}
		return null;
	}

	public function getIssuer()
	{
		$node = $this->tbsCertificateNode(2);
		return $node ? $this->subjectOIDValues($node) : null;
	}

	public function getUpdateTimes()
	{
		$dates = array();
		if ($node = $this->tbsCertificateNode(3))
		{
			$dates['lastUpdate'] = $node->toString();
		}
		if ($node = $this->tbsCertificateNode(4))
		{
			$dates['nextUpdate'] = $node->toString();
		}
		return $dates;
	}

	public function getRevokedCerts($with_reasons=false)
	{
		$certs = array();
		if ($node = $this->tbsCertificateNode(5))
		{
			foreach($node->children() as $child)
			{
				$cert = array();
				$cert['serial'] = $child->child(0)->toHexString();
				
				$date_raw = $child->child(1)->contentBytes();
				$cert['date'] = ASN1Parser::parseTime($date_raw,0,strlen($date_raw));

				if ($with_reasons && ($base = $child->child(2)))
				{
					if ($base->child("0-0") && $base->child("0-1"))
					{
						$oid = $base->child("0-0")->toString();
						if ($oid=='2.5.29.21')//ASN1Utils::oid('2.5.29.21') = 'reasonCode';
						{
							$parsed_node = ASN1Parser::parseDERBytes($base->child("0-1")->contentBytes(),$pos=0);
							$byte_array = $parsed_node->contentBytes();
							$cert['reasonCode'] = ASN1Utils::reasonCode($byte_array[0]);
						}
					}
				}
				$certs[] = $cert;
			}
		}
		return $certs;
	}

	public function containsSerial($serial_number)
	{
		$certs = $this->getRevokedCerts();
		foreach($certs as $cert)
		{
			if (strtolower($cert['serial']) == strtolower($serial_number))//both should already be lower, but just in case
			{
				return true;
			}
		}
		return false;
	}

	public function getExtensionInfo()
	{
		$extensions_node = $this->tbsCertificateNode(6);

		if ($extensions_node && $extensions_node->tag()==0xa0 && $extensions_node->child(0) && $extensions_node->child(0)->tag()==0x30)
		{
			return $this->extensionInfo($extensions_node->child(0));//calls extensionParser()
		}
		return array();
	}

	protected function extensionParser($oid,$parsed_node,$critical_flag)
	{
		$info = is_null($critical_flag) ? array() : array('critical'=>$critical_flag);

		//custom parsers for some oids
		if ($oid=='2.5.29.35')//auth key identifier
		{
			if ($ak_node = $parsed_node->child("0"))
			{
				$info = $ak_node->toHexString();
			}
		}
		else if ($oid=='2.5.29.20')//crlNumber
		{
			$info = hexdec($parsed_node->toHexString());
		}
		else //
		{
		}
		return $info;
	}

	public function getSignatureInfo()
	{
		return self::signatureInfo($this->root);
	}

}

/*
if(0 && basename($_SERVER['PHP_SELF'])==basename(__FILE__) && php_sapi_name()=='cli')
{
	$cert_filename = dirname(__FILE__)."/www_digicert_com.pem";
	if (!file_exists($cert_filename)) //fetch cert
	{
		$host='www.digicert.com';
		$ssloptions = array(
			"capture_peer_cert" => true, 
			"capture_peer_cert_chain" => false,
			"allow_self_signed"=>true, 
			"CN_match"=>$host, 
			"verify_peer"=>true, 
			"SNI_enabled"=>true,
			"SNI_server_name"=>$host,
			"cafile"=>'/etc/ssl/certs/ca-certificates.crt'
		);

		$g = stream_context_create( array("ssl" => $ssloptions) );
		$r = @stream_socket_client("ssl://$host:443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $g);
		if ($r)
		{
			$cont = stream_context_get_params($r);
			$cert_res = $cont["options"]["ssl"]["peer_certificate"];
			openssl_x509_export($cert_res, $pem_encoded);
		}
		file_put_contents($cert_filename, $pem_encoded);
	}
	$cert = file_get_contents($cert_filename);

	set_include_path(dirname(__FILE__)."/.." );
	include_once("asn1/ASN1X509.class.php");

	//extract CRL url
	$file = new ASN1X509();
	$file->loadPEM($cert);
	$serial = $file->getSerialNumber();
	$v3_info = $file->getExtensionInfo();
	$crls = explode(", ", $v3_info['crlDistributionPoints']);
	$crl = $crls[0];

	$crl_filename = dirname(__FILE__)."/crl.der";
	if (!file_exists( $crl_filename ))
	{
		file_put_contents($crl_filename, file_get_contents($crl));
	}
	$serial = '0c89ee2a5677d7b57f78f999f6a1a1e9';

	$file = new ASN1CRL();
	$file->loadFile($crl_filename); //openssl x509 -in www_digicert_com.pem -inform PEM -outform DER > www_digicert_com.der
	//$file->loadPEM($pem);

	$details = array();
	$details['version'] = $file->getVersion();
	$details['signatureType'] = $file->getSignatureType();
	$details['issuer'] = $file->getIssuer();
	$details['updateTimes'] = $file->getUpdateTimes();
	//$details['revokedCerts'] = array_slice( $file->getRevokedCerts(true) , 0, 10);
	$details['revokedCerts'] = $file->getRevokedCerts();
	$details['extensionInfo'] = $file->getExtensionInfo();
	$details['signatureInfo'] = $file->getSignatureInfo();

	//$file->echoNodes();
	print_r($details);
	//has high memory usage for large CRLs

	echo (memory_get_peak_usage()/1024)."KB"."\n";
	exit(0);
}

if(0 && basename($_SERVER['PHP_SELF'])==basename(__FILE__) && php_sapi_name()=='cli')
{
	set_include_path(dirname(__FILE__)."/.." );
	include_once("asn1/ASN1File.class.php");
	//time php -d include_path="..:." -d xdebug.profiler_enable=1 ASN1CRL.class.php
	//output /tmp
	$file = new ASN1CRL();
	$file->loadFile('file0.crl');
	$r = $file->getRevokedCerts();
	echo (memory_get_peak_usage()/1024)."KB"."\n";
	exit(0);

}

*/