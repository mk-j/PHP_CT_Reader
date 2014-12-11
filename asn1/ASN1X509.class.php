<?php
include_once("asn1/ASN1File.class.php");
include_once("asn1/ASN1Node.class.php");
include_once("asn1/ASN1Parser.class.php");
include_once("asn1/ASN1Utils.class.php");

//also test:
//* code signing
//* email cert
//* client only
 
//http://tools.ietf.org/html/rfc2459
//http://tools.ietf.org/html/rfc5280
class ASN1X509 extends ASN1File
{
	protected function tbsCertificateNode($which)
	{
		if ($this->root)
		{
			if ($child = $this->root->child(0))
			{
				$nodes = $child->children();
				$offset = ($nodes[0] && $nodes[0]->tag()==0xa0) ? 0 : -1;
				return isset($nodes[$which+$offset]) ? $nodes[$which+$offset] : null;
			}
		}
		return null;
	}
	
	public function getVersion()
	{
		$node = $this->tbsCertificateNode(0);
		if ($node)
		{
			if ($child = $node->child(0))
			{
				return $child->toString()+1;
			}
		}
		return 1; 
	}
	
	public function getSerialNumber()
	{
		$node = $this->tbsCertificateNode(1);
		return $node ? $node->toString() : null;
	}

	public function getSignatureType()
	{
		$node = $this->tbsCertificateNode(2);
		if ($node && $node->child(0))
		{
			$oid = $node->child(0)->toString();//no value
			return ASN1Utils::oid($oid);//TODO: test sha2
		}
		return null;
	}

	public function getIssuer()
	{
		$node = $this->tbsCertificateNode(3);
		return $node ? $this->subjectOIDValues($node) : null;
	}

	public function getValidDates()
	{
		$node = $this->tbsCertificateNode(4);
		$valid_dates = array();
		if ($node)
		{
			if ($not_before_node = $node->child(0))
			{
				$valid_dates['validFrom'] = $not_before_node->toString();//TODO gradually deprecate this
				$valid_dates['notBefore'] = $not_before_node->toString();
			}
			if ($not_after_node = $node->child(1))
			{
				$valid_dates['validTill'] = $not_after_node->toString();//TODO gradually deprecate this
				$valid_dates['notAfter']  = $not_after_node->toString();
			}
		}
		return $valid_dates;
	}
	
	public function getSubject()
	{
		$node = $this->tbsCertificateNode(5);
		return $node ? $this->subjectOIDValues($node) : null;
	}
	
	public function getPublicKeyInfo()
	{
		$node = $this->tbsCertificateNode(6);
		return $node ? $this->publicKeyInfo($node) : null;
	}
	
	public function getThumbprint($thumbprint_type='sha1')
	{
		//need to call loadPEM or loadFile first
		if (empty($this->bytes))
		{
			return '';
		}
		$allowed_types = hash_algos();//md5,sha1,sha256...etc
		$thumbprint_type = in_array($thumbprint_type,$allowed_types) ? $thumbprint_type : 'sha1';
		

		$hash_value = strtoupper(hash($thumbprint_type,$this->bytes));
		return $hash_value;
	}

	public function getExtensionInfo()
	{
		$extensions_node = $this->tbsCertificateNode(7);
        //    self::echoNode($extensions_node);
        if ($this->getVersion()!=3)
        {
		    return array();
        }
		if ($extensions_node && $extensions_node->tag()==0xa3 && $extensions_node->child(0) && $extensions_node->child(0)->tag()==0x30)
		{
			$info = $this->extensionInfo($extensions_node->child(0));//calls extensionParser()
            if (isset($info['basicConstraints']['CA']))//see v3_purp.c, check_ca()
            {
                //must contain keyCertSign
                if (isset($info['keyUsage']) && strpos($info['keyUsage'],"Certificate Sign")===false)
                {            
                    $info['basicConstraints']['CA']='FALSE';
                }
            }
            return $info;
		}
		return array();
	}
	
	protected function extensionParser($oid,$parsed_node,$critical_flag)
	{
		$info = is_null($critical_flag) ? array() : array('critical'=>$critical_flag);

		//custom parsers for some oids
		if ($oid=='2.5.29.35')//auth key identifier
		{
			//ASSUMPTIONS: only 1 authority KEY, spec implies 1+
			if ($ak_node = $parsed_node->child("0"))
			{
				$info = $ak_node->toString();
			}
		}
		else if ($oid=='2.5.29.14')//subject key identifier
		{
			$info = $parsed_node->toString();
		}
		else if ($oid=='2.5.29.31')//crlDistributionPoints
		{
			foreach($parsed_node->children() as $child)
			{
				if ($crl_node = $child->child("0-0-0"))
				{
					$info[] = $crl_node->toString();
				}
			}
			$info = implode(", ", $info);
		}
		else if ($oid=="2.5.29.19")//basicConstraints
		{
            //self::echoNode($parsed_node);
			$info['CA'] = 'FALSE';
            $first_node = $parsed_node->child("0");
            if ($first_node && $first_node->tag()==ASN1Parser::U_BOOLEAN && $first_node->toString())
            {
				$info['CA'] = 'TRUE';
            }
            else if ($first_node && $first_node->tag()==ASN1Parser::U_INTEGER)
            {
		        $info['pathlen'] = hexdec($first_node->toString());
            }
			if (!isset($info['pathlen']) && $pathlen_node = $parsed_node->child("1"))
			{
		        $info['pathlen'] = hexdec($pathlen_node->toString());
            }
		}
		else if ($oid=='2.5.29.32')//certificatePolicies
		{
			//tested on digicert.com, ASSUMING layout will be pretty much the same for other certs
			foreach($parsed_node->children() as $child)
			{
				foreach($child->children() as $grandchild)
				{
					if ($grandchild->tag()==ASN1Parser::U_OID)
					{
						$info['policy'][] = $grandchild->toString();
					}
					else if ($grandchild->hasChildren())
					{
						foreach($grandchild->children() as $ggc)
						{
							$data = array();
							$nodes = $ggc->child(1) ? array($ggc->child(1)) : array();
							while(!empty($nodes))
							{
								$node = array_shift($nodes);
								if ($node->hasChildren())
								{
									foreach($node->children() as $c)
									{
										$nodes[] = $c;
									}
								}
								else if ($node->tag()!=0x02)//if not integer
								{
									$data[] = $node->toString();
								}
							}
							$info[ ASN1Utils::oid($ggc->child(0)->toString()) ][] = implode(",", $data);
						}
					}
				}
			}
			foreach($info as $i=>$r)
			{
				$info[$i] = is_array($r) ? implode(", ", $r) : $r;
			}
		}
		else if ($oid=="1.3.6.1.5.5.7.1.1")//authorityInfoAccess
		{
			//ASSUMPTIONS: only 1 OCSP, or only1 CAIssuer per cert
			foreach($parsed_node->children() as $child)
			{
				if ($child->tag()==0x30 && $child->hasChildren())
				{
					$info[ ASN1Utils::oid($child->child(0)->toString()) ] = $child->child(1)->toString();
				}
			}
		}
		else if ($oid=='2.16.840.1.113730.1.1')//nsCertType
		{
			//see: http://www.mozilla.org/projects/security/pki/nss/tech-notes/tn3.html
			//see: openssl-1.0.1c/crypto/x509v3/v3_bitst.c
			$cert_type = array();
			$types = $parsed_node->toString();
			$value = hexdec($types);
			if ($value & 0x80) { $cert_type[] = 'SSL Client';        }//client
			if ($value & 0x40) { $cert_type[] = 'SSL Server';        }//server
			if ($value & 0x20) { $cert_type[] = 'S/MIME';            }//email
			if ($value & 0x10) { $cert_type[] = 'Object Signing';    }//objsign
			if ($value & 0x08) { $cert_type[] = 'Unused';            }//reserved
			if ($value & 0x04) { $cert_type[] = 'SSL CA';            }//sslCA
			if ($value & 0x02) { $cert_type[] = 'S/MIME CA';         }//emailCA
			if ($value & 0x01) { $cert_type[] = 'Object Signing CA'; }//objCA
			if ($critical_flag)  { $cert_type[] = 'critical'; }
			$info = implode(", ", $cert_type);
		}
		else if ($oid=="2.5.29.15")//keyUsage
		{
			static $masks = array(7=>0x80, 6=>0xc0, 5=>0xe0, 4=>0xf0, 3=>0xf8, 2=>0xfc, 1=>0xfe, 0=>0xff);
			//BIT STRING, first byte shows number of unused bits in the last byte
			//http://luca.ntop.org/Teaching/Appunti/asn1.html

			$bytes = $parsed_node->contentBytes();
			$b0 = isset($bytes[0]) ? ord($bytes[0]) : 0;
			$b1 = isset($bytes[1]) ? ord($bytes[1]) : 0;
			$b2 = isset($bytes[2]) ? ord($bytes[2]) : 0;
			$mask = isset($masks[$b0]) ? $masks[$b0] : 0xff;
			$byte_count = strlen($bytes);
			$b1 = $byte_count==2 ? ($b1 & $mask) : $b1;
			$b2 = $byte_count==3 ? ($b2 & $mask) : $b2;

			//see: openssl-1.0.1c/crypto/x509v3/v3_bitst.c
			$key_usage = array();
			if ($b1 & 0x80) { $key_usage[] = 'Digital Signature'; }//"digitalSignature",
			if ($b1 & 0x40) { $key_usage[] = 'Non Repudiation';   }//"nonRepudiation",
			if ($b1 & 0x20) { $key_usage[] = 'Key Encipherment';  }//"keyEncipherment",
			if ($b1 & 0x10) { $key_usage[] = 'Data Encipherment'; }//"dataEncipherment",
			if ($b1 & 0x08) { $key_usage[] = 'Key Agreement';     }//"keyAgreement",
			if ($b1 & 0x04) { $key_usage[] = 'Certificate Sign';  }//"keyCertSign",
			if ($b1 & 0x02) { $key_usage[] = 'CRL Sign';          }//"cRLSign",
			if ($b1 & 0x01) { $key_usage[] = 'Encipher Only';     }//"encipherOnly",
			if ($b2 & 0x80) { $key_usage[] = 'Decipher Only';     }//"decipherOnly",
			if ($critical_flag)  { $key_usage[] = 'critical'; }
			$info = implode(", ", $key_usage);
		}
		else if ($oid=="2.5.29.37")//extendedKeyUsage
		{
			$eku_lookup = array(
				'serverAuth'         =>'TLS Web Server Authentication',
				'clientAuth'         =>'TLS Web Client Authentication',
				'codeSigning'        =>'Code Signing',
				'emailProtection'    =>'E-mail Protection',
				'anyExtendedKeyUsage'=>'Any Extended Key Usage',
				'timeStamping'       =>'Time Stamping',
				'ocspSigning'        =>'OCSP Signing',
				'ipsecEndSystem'     =>'IPSec End System',
				'ipsecTunnel'        =>'IPSec Tunnel',
				'ipsecUser'          =>'IPSec User',
				'ipsecProtection'    =>'IPSec Protection',
			);
			$eku = array();
			foreach($parsed_node->children() as $child)
			{
				if ($child->tag()==0x06)
				{
					$oid = ASN1Utils::oid($child->toString());
					$eku[] = isset($eku_lookup[$oid]) ? $eku_lookup[$oid] : $oid;
				}
			}
			if ($critical_flag)  { $eku[] = 'critical'; }
			$info = implode(", ", $eku);
		}
		else if ($oid=='2.5.29.17')//SANs
		{
			foreach($parsed_node->children() as $child)
			{
				$info[] = $child->toString();
			}
		}//2.5.29.18
		else if (!empty($parsed_node))
		{
			//self::echoNode($parsed_node);
			if (!$parsed_node->hasChildren())//used by nsComment
			{
				$info[] = $parsed_node->tag()==0x06 ? ASN1Utils::oid($parsed_node->toString()) : $parsed_node->toString();
			}

			//1.3.6.1.5.5.7.1.12(id-pe-logotype), issuerAltName
			foreach($parsed_node->children() as $child)
			{
				$info[] = $child->tag()==0x06 ? ASN1Utils::oid($child->toString()) : $child->toString() ;
			}
			$info = implode(",", $info);
		}
		return $info;
	}

	public function getSignatureInfo()
	{
		return self::signatureInfo($this->root);
	}//if we want to have signature checking, then we are saying we want a function isSignedBy() 
}

/*
if(0 && basename($_SERVER['PHP_SELF'])==basename(__FILE__) && php_sapi_name()=='cli')
{
	$pem='-----BEGIN CERTIFICATE-----
MIIDPzCCAqigAwIBAgICNTUwDQYJKoZIhvcNAQEFBQAwgbsxCzAJBgNVBAYTAi0t
MRIwEAYDVQQIDAlTb21lU3RhdGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQK
DBBTb21lT3JnYW5pemF0aW9uMR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxV
bml0MR4wHAYDVQQDDBV0ZXN0aW5nLmFhY3JlYS5vcmcuYXIxKTAnBgkqhkiG9w0B
CQEWGnJvb3RAdGVzdGluZy5hYWNyZWEub3JnLmFyMB4XDTEyMDQyMzIzMDcwM1oX
DTEzMDQyMzIzMDcwM1owgbsxCzAJBgNVBAYTAi0tMRIwEAYDVQQIDAlTb21lU3Rh
dGUxETAPBgNVBAcMCFNvbWVDaXR5MRkwFwYDVQQKDBBTb21lT3JnYW5pemF0aW9u
MR8wHQYDVQQLDBZTb21lT3JnYW5pemF0aW9uYWxVbml0MR4wHAYDVQQDDBV0ZXN0
aW5nLmFhY3JlYS5vcmcuYXIxKTAnBgkqhkiG9w0BCQEWGnJvb3RAdGVzdGluZy5h
YWNyZWEub3JnLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCyUT7tH8C4
s4E1BG09T0vEi+ekqCO2HC79a96h6FSdZUdofIFnNo9s/jUYXCOnLhZ8r/z0aT7x
/095B8CZVxBChqKDMAekABZIgDvZkCn32qbe7Ph1E+DMmmaHKjpgazK3vdLqBLt8
kTiWVDsYen3abyfD/cMcijAaj0TK5s/tywIDAQABo1AwTjAdBgNVHQ4EFgQUJ7ZM
vA7pHguoSAsQBLe9zh8ZEeIwHwYDVR0jBBgwFoAUJ7ZMvA7pHguoSAsQBLe9zh8Z
EeIwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOBgQCLcnCxPfsHQvbbv9sz
cjX0zaEW3nkMaEFSh9ZjTC9/nQYRo85KZWBHTyw1eAPTC3DfSHFAVUPDVUGOkf9Q
E7uqazArayjTI+f6nb5lf+6v5PW1uSJSBtVPKt/sJcuMgwqZi/bpm2Jx7Ehj5h/P
UI5xI5WROf3M7hJeJk3c4y/hRg==
-----END CERTIFICATE-----';
	$file = new ASN1X509();
	$file->loadPEM($pem);
	//$file->loadFile('www_digicert_com.pem');
	//$file->loadFile('www_digicert_com.der'); //openssl x509 -in www_digicert_com.pem -inform PEM -outform DER > www_digicert_com.der

	$details = array();
	$details['version'] = $file->getVersion();
	$details['serial'] = $file->getSerialNumber();
	$details['signatureType'] = $file->getSignatureType();
	$details['issuer'] = $file->getIssuer();
	$details['validDates'] = $file->getValidDates();
	$details['subject'] = $file->getSubject();
	$details['publicKey'] = $file->getPublicKeyInfo();
	$details['extensionInfo'] = $file->getExtensionInfo();
	$details['signatureInfo'] = $file->getSignatureInfo();
	print_r($details);

	echo (memory_get_peak_usage()/1024)."KB"."\n";
	exit(0);
}*/

