<?php

include_once("asn1/ASN1File.class.php");
include_once("asn1/ASN1Node.class.php");
include_once("asn1/ASN1Parser.class.php");
include_once("asn1/ASN1Utils.class.php");

//A CSR - Certificate Signing Request is ASN1 DER encoded PKCS10
//http://tools.ietf.org/html/rfc2986
class ASN1CSR extends ASN1File
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
			return hexdec($node->toString());
		}
		return null;
	}
	
	public function getSubject()
	{
		$node = $this->tbsCertificateNode(1);
		$key_value_pairs = $this->subjectOIDValues($node);
		return $key_value_pairs;
	}

	public function getPublicKeyInfo()
	{
		$node = $this->tbsCertificateNode(2);
		return $node ? $this->publicKeyInfo($node) : null;
	}

	public function getExtensions()
	{
		$details = array();
		$extensions_node = $this->tbsCertificateNode(3);
		if ($extensions_node && $extensions_node->tag()==0xa0 && $extensions_node->child(0) && $extensions_node->child(0)->tag()==0x30)//seq
		{
			foreach($extensions_node->children() as $main_node)
			{
				$oid = $main_node->child(0)->toString();
				$data_node = $main_node->child(1);
				if ($oid=='1.2.840.113549.1.9.14')//Requested Extensions
				{
					if ($data_node && $data_node->tag()==0x31 && $data_node->child(0) && $data_node->child(0)->tag()==0x30)
					{
						$details = $this->extensionInfo($data_node->child(0));//ASN1Parse the extensions... then pass them onto $this->extensionParser()
					}
				}
				else //attributes
				{
					/*
					$info = array();
					if ($data_node->tag()==0x31 && $data_node->child(0))//31=SET
					{
						if ($data_node->child(0)->hasChildren())
						{
							foreach($data_node->child(0)->children() as $c)
							{
								$i = $c->hasChildren() ? '' : $c->toString();
								if ($c->hasChildren())
								{
									foreach($c->children() as $cc)
									{
										$i.=', '.$cc->toString();
									}
								}
								$info[] = ltrim($i, ", ");
							}
						}
						else //if (!$data_node->child(0)->hasChildren())
						{
							$info = $data_node->child(0)->toString();
						}
					}
					$details[ASN1Utils::oid($oid)] = $info;
					**/
				}
			}
		}
		return $details;
	}

	protected function extensionParser($oid,$parsed_node,$critical_flag)
	{
		$info = is_null($critical_flag) ? array() : array('critical'=>$critical_flag);

		if ($oid=='2.5.29.17')//SANs
		{
			unset($info['critical']);//ignore, its implied
			foreach($parsed_node->children() as $child)
			{
				$info[] = $child->toString();
			}
		}
		else if ($parsed_node->hasChildren())//if ($oid=='1.3.6.1.4.1.311.13.2.3')
		{
			foreach($parsed_node->children() as $child)
			{
				$info[] = $child->toString();
			}
			$info = implode(", ", $info);
		}
		else //no children
		{
			$str = $parsed_node->toString();
			if (empty($info))
			{
				$info = $str;
			}
			else if (!empty($str))
			{
				$info[] = $str;
			}
		}
		return $info;
	}

	//--
	public function getSignatureInfo()
	{
		return self::signatureInfo($this->root);
	}

	public function isSelfSigned()
	{
		if ($this->root)
		{
			$data='';
			if ($node = $this->root->child(0))
			{
				$start = $node->cstart() - $node->header();
				$leng = $node->clength() + $node->header();
				$data = ASN1Parser::parseStringISO($this->bytes, $start, $leng);
				//file_put_contents('z_body.txt', chunk_split(implode(":",str_split(bin2hex($data),2)),63));
			}
			
			$signature='';
			if ($node = $this->root->child(2))
			{
				$start = $node->cstart();
				$leng = $node->clength();
				$signature = ASN1Parser::parseStringISO($this->bytes, $start, $leng);
				$signature = $signature[0]=="\x0" ? substr($signature,1) : $signature;
				//file_put_contents('z_sig.txt', chunk_split(implode(":",str_split(bin2hex($signature),2)),63));
			}

			$public_key_info = $this->getPublicKeyInfo();
			$public_key_pem = $public_key_info['key'];
			
			if ($node = $this->root->child("1-0"))
			{
				$algs = array();
				if (defined('OPENSSL_ALGO_MD4')) { $algs['md4WithRSAEncryption']=OPENSSL_ALGO_MD4; }
				if (defined('OPENSSL_ALGO_MD5')) { $algs['md5WithRSAEncryption']=OPENSSL_ALGO_MD5; }
				if (defined('OPENSSL_ALGO_SHA1')) { $algs['sha1WithRSA'          ]=OPENSSL_ALGO_SHA1; }
				if (defined('OPENSSL_ALGO_SHA1')) { $algs['sha1WithRSAEncryption']=OPENSSL_ALGO_SHA1; }

				//PHP >=5.4.8
				if (defined('OPENSSL_ALGO_SHA224')) { $algs['sha224WithRSAEncryption']=OPENSSL_ALGO_SHA224; }
				if (defined('OPENSSL_ALGO_SHA256')) { $algs['sha256WithRSAEncryption']=OPENSSL_ALGO_SHA256; }
				if (defined('OPENSSL_ALGO_SHA384')) { $algs['sha384WithRSAEncryption']=OPENSSL_ALGO_SHA384; }
				if (defined('OPENSSL_ALGO_SHA512')) { $algs['sha512WithRSAEncryption']=OPENSSL_ALGO_SHA512; }

				//PHP compile php src with md2 enabled patch:
				if (defined('OPENSSL_ALGO_MD2'))    { $algs['md2WithRSAEncryption']=OPENSSL_ALGO_MD2; }

				$sig_alg = ASN1Utils::oid($node->toString());
				if (isset($algs[$sig_alg]))
				{
					return @openssl_verify($data, $signature, $public_key_pem, $algs[$sig_alg]);
				}
				syslog(LOG_INFO, "[CERTTOOLS] ASN1 Unable to verify alg $sig_alg, returning true");
				return true;
			}
		}
		return false;
	}


}

/*
if(0 && basename($_SERVER['PHP_SELF'])==basename(__FILE__) && php_sapi_name()=='cli')
{
//has sans and other extensions
$csr='-----BEGIN NEW CERTIFICATE REQUEST-----
MIIETTCCA7YCAQAwgdsxCzAJBgNVBAYTAlVTMQ4wDAYDVQQIEwVUZXhhczEUMBIG
A1UEBxMLU2FuIEFudG9uaW8xZzBlBgNVBAoeXgBIAG8AcgBuAGIAZQByAGcAZQBy
ACAAUwBoAGUAZQBoAGEAbgAgAEYAdQBsAGwAZQByACAAJgAgAEIAZQBpAHQAZQBy
ACAASQBuAGMAbwByAHAAbwByAGEAdABlAGQxHjAcBgNVBAsTFUluZm9ybWF0aW9u
IFRlY2hvbG9neTEdMBsGA1UEAxMUZXhjaDIwMDcuaHNmYmxhdy5jb20wgZ8wDQYJ
KoZIhvcNAQEBBQADgY0AMIGJAoGBALzNyqhqnU0NO2SEoRfl5sx0BbeCsZvxA0LI
4slzUR3qpROQXIqxFq7ZvGl5kbQH8DE+59D2zIgzc4tK/AhqtAAA0/MprCV8UuhQ
0kiQ83vMdLHba/y6LWf1vPxIUXr3oTMTqTfQ0fbjEppmKy9Uc651fgBiSae6WPWj
3VKLStw7AgMBAAGgggIvMBoGCisGAQQBgjcNAgMxDBYKNS4yLjM3OTAuMjBLBgkr
BgEEAYI3FRQxPjA8AgEBDBNFWENIMjAwNy5oc2ZiLmxvY2FsDBJIU0ZCXGFkbWlu
aXN0cmF0b3IMDlBvd2VyU2hlbGwuZXhlMIHDBgkqhkiG9w0BCQ4xgbUwgbIwHQYD
VR0OBBYEFFQ1vWag7pAMc7L69OwqLzRaOAyZMBMGA1UdJQQMMAoGCCsGAQUFBwMB
MAwGA1UdEwEB/wQCMAAwXgYDVR0RAQH/BFQwUoIYYXV0b2Rpc2NvdmVyLmhzZmJs
YXcuY29tghNleGNoMjAwNy5oc2ZiLmxvY2FsghdhdXRvZGlzY292ZXIuaHNmYi5s
b2NhbIIIZXhjaDIwMDcwDgYDVR0PAQH/BAQDAgWgMIH9BgorBgEEAYI3DQICMYHu
MIHrAgEBHloATQBpAGMAcgBvAHMAbwBmAHQAIABSAFMAQQAgAFMAQwBoAGEAbgBu
AGUAbAAgAEMAcgB5AHAAdABvAGcAcgBhAHAAaABpAGMAIABQAHIAbwB2AGkAZABl
AHIDgYkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAN
BgkqhkiG9w0BAQUFAAOBgQCw0BiyM8GQb4FccGRYpLYwoJhtSqrsYOpiSpb7jp4o
eexnfVf8z9M4CGpxnxWtIlkOBCtqlMS0DcrNmARGAFWCHIG/4T25DSVhV3B9FVIS
3VdJDEv9ZcCVFnVsee3EuA2ErLMafRNc1DwZzeWI6RxCrZYQWt7Y1v5mMhHvpdFA
7w==
-----END NEW CERTIFICATE REQUEST-----';

	$file = new ASN1CSR();
	$file->loadPEM($csr);
	//$file->loadFile('sans.csr');
	//$file->echoNodes();
	$details = array();
	$details['version'] = $file->getVersion();
	$details['subject'] = $file->getSubject();
	$details['publicKey'] = $file->getPublicKeyInfo();
	$details['extensions'] = $file->getExtensions();
	$details['signature'] = $file->getSignatureInfo();
	print_r($details);
	
	echo $file->isSelfSigned() ? '[verified]' : '[invalid signature]';
	echo "\n";

	echo (memory_get_peak_usage()/1024)."KB"."\n";
	exit(0);
}
*/
