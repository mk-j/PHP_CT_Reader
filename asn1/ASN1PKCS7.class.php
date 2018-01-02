<?php
include_once("asn1/ASN1File.class.php");
include_once("asn1/ASN1Parser.class.php");
include_once("asn1/ASN1Utils.class.php");

class ASN1PKCS7 extends ASN1File
{
	private function isPKCS7()
	{
		$good_so_far = 0;
		if ($this->root)
		{
			if (($child = $this->root->child(0)) && $child->tag()==ASN1Parser::U_OID && $child->toString()=='1.2.840.113549.1.7.2')
			{
				$good_so_far++;
			}
			if (($child = $this->root->child(1)->child(0)->child(1)) && $child->tag()==ASN1Parser::U_Set)
			{
				$good_so_far++;
			}
			if (($child = $this->root->child(1)->child(0)->child(2)->child(0)) && $child->tag()==ASN1Parser::U_OID && $child->toString()=='1.2.840.113549.1.7.1')
			{
				$good_so_far++;
			}
		}
		return ($good_so_far==3) ? true : false;
	}
	
	public function getVersion()
	{
		if ($this->root && $this->isPKCS7())
		{
			if (($child = $this->root->child(1)->child(0)->child(0)) && $child->tag()==ASN1Parser::U_INTEGER && $child->toString()=='01')
			{
				return intval($child->toString());
			}
		}
		return null;
	}

	public function getCerts()
	{
		$certs = array();
		if ($this->root && $this->isPKCS7())
		{
			$children = $this->root->child(1)->child(0)->child(3)->children();
			foreach($children as $child)
			{
				$bytes = $child->contentBytes();
				$certs[] = '-----BEGIN CERTIFICATE-----'."\r\n".chunk_split(base64_encode($bytes),64,"\r\n").'-----END CERTIFICATE-----'."\r\n";
			}
		}
		return $certs;
	}

	public static function build($certs = array())
	{
		$binary_certs='';
		foreach($certs as $x509_pem_encoded_string)
		{
			$str = $x509_pem_encoded_string;
			$str = preg_replace('/\-+BEGIN CERTIFICATE\-+/','',$str);
			$str = preg_replace('/\-+END CERTIFICATE\-+/','',$str);
			$str = trim($str);
			$str = preg_replace('/[^A-Za-z0-9=+\/]/m','',$str);//strip off all non base64 chars
			$bytes = base64_decode($str);
			$binary_certs.= $bytes;
		}

		$inner='';
		{
			{
				{
					{
						$bin_version = chr($version=1);
						$inner.= "\x02";//tag=int
						$inner.= ASN1Utils::encodeLength(strlen($bin_version));
						$inner.= $bin_version;
					}
					{
						$inner.= "\x31";//tag=set
						$inner.= "\x00";//len=0
					}
					{
						$pkcs7_data_oid = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01";
						$inner.= "\x30";//tag=seq
						$inner.= ASN1Utils::encodeLength(strlen($pkcs7_data_oid));//seq for oid
						$inner.= $pkcs7_data_oid;//oid: pkcs7-data
					}
					{
						$inner.= "\xA0";//tag=constructed(context specific)
						$inner.= ASN1Utils::encodeLength(strlen($binary_certs));//length
						$inner.= $binary_certs;//length
					}
					{
						$inner.= "\x31";//tag=set
						$inner.= "\x00";//len=0
					}
					$inner= "\x30".ASN1Utils::encodeLength(strlen($inner)).$inner;
				}
				$inner= "\xA0".ASN1Utils::encodeLength(strlen($inner)).$inner;
			}
			$pkcs7_signed_data_oid = "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02";
			$inner = $pkcs7_signed_data_oid.$inner;
		}
		$output = "\x30". ASN1Utils::encodeLength(strlen($inner)).$inner;
		
		return '-----BEGIN PKCS7-----'."\r\n".chunk_split(base64_encode($output),64,"\r\n").'-----END PKCS7-----'."\r\n";
	}
}

