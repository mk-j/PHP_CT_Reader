<?php
include_once("asn1/ASN1Parser.class.php");
include_once("asn1/ASN1Utils.class.php");

class ASN1File
{
	protected $root = null;//root node
	protected $bytes = array();
	public function __construct($config=array())
	{
		if (isset($config['file']))
		{
			$this->loadFile($config['file']);
		}
		else if (isset($config['pem']))
		{
			$this->loadPEM($config['pem']);
		}
	}

	public function loadFile($filepath)
	{
		if (file_exists($filepath))
		{
			$file_as_string = file_get_contents($filepath);
			if (!empty($file_as_string))
            {
				$byte0 = ord($file_as_string[0]);
				$byte1 = ord($file_as_string[1]);
                if($byte0==48 && ($byte1==130 || $byte1==131))
				{
					$this->loadDER($file_as_string);
				}
				else //can start with  MII,MIJ,MIK,MIL,MIM,MIN,MIO,MIP.. or -----BEGIN...
				{
					$this->loadPEM($file_as_string);
				}
			}
		}
	}

	public function loadDER($bytes_str)
	{
		$initpos = 0;
		$this->bytes = $bytes_str;
		try
		{
			$node = ASN1Parser::parseDERBytes($this->bytes,$initpos);
		}
		catch(Exception $e)
		{
			syslog(LOG_INFO, "[CERTPARSER] Invalid cert format, Exception thrown ".$e->getMessage() ."");
			$node = null;//unable to parse
		}
		$this->root = $node;
	}

	public function loadPEM($pem_encoded_string)
	{
		$str = $pem_encoded_string;
		$str = preg_replace('/\-+BEGIN [A-Z0-9_ ]+\-+/','',$str);
		$str = preg_replace('/\-+END [A-Z0-9_ ]+\-+/','',$str);
		$str = trim($str);
		$str = str_replace( array("\n","\r"), '', $str);
		$this->bytes = base64_decode($str);
		$initpos=0;
		try
		{
			$node = ASN1Parser::parseDERBytes($this->bytes,$initpos);
		}
		catch(Exception $e)
		{
			syslog(LOG_INFO, "[CERTPARSER] Invalid cert format, Exception thrown ".$e->getMessage() ."");
			$node = null;//unable to parse
		}
		$this->root = $node;

		//$unpacked = unpack("H*", base64_decode($str));
		//$bytes = array_map('hexdec',str_split(array_pop($unpacked), 2));
		//$struct = self::parseDERBytes($bytes,$pos=0);//unpack leaves a '0' indexed array
	}
	
	public function hasLoaded()
	{
		return !is_null($this->root);
	}
	
	public function echoNodes()
	{
		self::echoNode($this->root);
	}

	protected static function echoNode($node,$depth=0)
	{
		if (!$node) return;
		$tabs = str_repeat(" ", $depth);
		
		
		$taginfo = $node->taginfo();
		$has_children = $node->hasChildren();
		$content = !$has_children ? $node->toString() : '';

		$l = "\xe2\x94\x94";
		echo $tabs."[".$taginfo."]"."\n";
		echo !empty($content) ? $tabs.$l."[".$content."]"."\n" : '';
		
		foreach($node->children() as $child)
		{
			self::echoNode($child,$depth+1);
		}
	}

	protected function subjectOIDValues($node)//used by ASN1CSR and ASN1X509
	{
		$key_value_pairs = array();
		if ($node)
		{
			foreach($node->children() as $child)
			{
				if ($child && $child->child("0-0"))
				{
					$oid_node = $child->child("0-0");
					if ($oid_node && $child->child("0-1"))
					{
						$key = ASN1Utils::oid($oid_node->toString());
                        $key = ($key=='street1' && isset($key_value_pairs[$key])) ? 'street2' : $key;
                        $key = ($key=='street2' && isset($key_value_pairs[$key])) ? 'street3' : $key;
						$val = $child->child("0-1")->toString();
						$key_value_pairs[$key] = $val;
					}
				}
			}
		}
		return $key_value_pairs;
	}
	
	protected function publicKeyInfo($node)
	{
		$details = array();
		if ($node)
		{
			$start = $node->cstart() - $node->header();
			$leng = $node->clength() + $node->header();
			$public_key = ASN1Parser::parseStringISO($this->bytes, $start, $leng);
			$details['key']='-----BEGIN PUBLIC KEY-----'."\n".chunk_split(base64_encode($public_key),64,"\n").'-----END PUBLIC KEY-----'."\n";

			//if (($oid_node = $node->child("0")) && !$oid_node->hasChildren())
			//{
			//	$oid = $oid_node->toString();
			//	$details['publicKeyAlgorithm'] = ASN1Utils::oid($oid);
			//}
			//else 
			if ($oid_node = $node->child("0-0"))
			{
				$oid = $oid_node->toString();
				$details['publicKeyAlgorithm'] = ASN1Utils::oid($oid);
			}
			//if ($oid=='1.2.840.10040.4.3' && ($alg_node = $node->child("0-1")))//DSA not really supported yet
			//{
            //    $details['type'] = 'dsa';
			//}
			if ($oid=='1.2.840.10045.2.1' && ($alg_node = $node->child("0-1")))//EC
			{
				$details['type'] = 'ec';
				$details['algorithmCurve'] = ASN1Utils::oid($alg_node->toString());
				if (preg_match("/([0-9]+)[^0-9]/", $details['algorithmCurve'], $matches))
				{
					$details['keySize'] = $matches[1];//the first positive integer in the string of ASN1Utils::oid() is keysize of the curve
				}
			}
			if ($oid=='1.2.840.113549.1.1.1' && ($bit_node = $node->child("1")))//RSA
			{
                $details['type'] = 'rsa';
				$bytes = $bit_node->contentBytes();
				$pos=1;//for some reason we skip a byte, otherwise we woulds start at $pos=0
				$parsed_node = ASN1Parser::parseDERBytes($bytes,$pos);

				if ($mod_node = $parsed_node->child(0))
				{
					$a = substr($bytes,$mod_node->cstart(),$mod_node->clength());
					for($i=0; ord($a[$i])==0; $i++);//find first non-zero byte
					//$details['keySize'] = strlen(decbin(ord($a[$i]))) + strlen(substr($a,$i+1))*8;
					$details['modulus'] = bin2hex(substr($a, $i));
					$details['keySize'] = strlen(decbin(ord($a[$i]))) + (strlen($a)-$i-1)*8;
				}
				if ($exp_node = $parsed_node->child(1))
				{
					$details['exponent'] = $exp_node->toString();
				}
			}
		}
		return $details;
	}

	//protected function extensionInfo($node,$tag)
	protected function extensionInfo($extension_data_node)
	{
		$details = array();
		//$extensions_node = $this->tbsCertificateNode($node);

		//if ($extensions_node && $extensions_node->tag()==0xa0 && $extensions_node->child(0) && $extensions_node->child(0)->tag()==0x30)//seq
		if ($extension_data_node && $extension_data_node->tag()==0x30)//seq
		{
			foreach($extension_data_node->children() as $main_node)
			{
				if ($main_node && $main_node->tag()==0x30 && $main_node->child(0) && $main_node->child(1) && $main_node->child(0)->tag()==0x06)//0x06=oid
				{
					$critical_flag = null;
					$oid_node = $main_node->child(0);
					$oid = $oid_node->toString();
					$data_node = $main_node->child(1);
					if ($data_node->tag()==0x01)
					{
						$critical_flag=$data_node->toString();
						$data_node = $main_node->child(2);
					}
					if (!empty($data_node))
					{
						$content = $data_node->contentBytes();
						$pos =0;
						$parsed_node = ASN1Parser::parseDERBytes($content,$pos);
						$details[ASN1Utils::oid($oid)] = $this->extensionParser($oid,$parsed_node,$critical_flag);
					}
				}
			}
		}
		return $details;
	}
	
	protected function extensionParser($oid, $parsed_node, $critical_flag)
	{
		//will be overridden
	}

	protected function signatureInfo()
	{
		$details = array();
		if ($this->root)
		{
			if ($oid_node = $this->root->child("1-0"))
			{
				$oid_string = ASN1Utils::oid($oid_node->toString());
				$details['signatureAlgorithm'] = $oid_string;
			}
			if ($sig_node = $this->root->child("2"))
			{
				$details['signature'] = $sig_node->toString();
			}
			//$details['signatureIsValid'] = $this->hasValidSignature() ? true : false;
		}
		return $details;
	}
	
	//abstract protected function tbsCertificateNode($which);
	//public function hasValidSignature()


}

/*
if(0 && basename($_SERVER['PHP_SELF'])==basename(__FILE__) && php_sapi_name()=='cli')
{
	$file = new ASN1File();
	$file->loadFile('certificate.pem');
	$file->echoNodes();

	echo (memory_get_peak_usage()/1024)."KB"."\n";
	exit(0);
}
*/
