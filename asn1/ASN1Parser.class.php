<?php

class ASN1Parser
{
	//Univeral Tags
    const U_EOC             =0x00;
    const U_BOOLEAN         =0x01;
    const U_INTEGER         =0x02;
    const U_BIT_STRING      =0x03;
    const U_OCTET_STRING    =0x04;
    const U_NULL            =0x05;
    const U_OID             =0x06;
    const U_ObjectDescriptor=0x07;
    const U_External        =0x08;
    const U_Real            =0x09;
    const U_Enumerated      =0x0A;
    const U_EmbeddedPDV     =0x0B;
    const U_UTF8String      =0x0C;
    const U_Sequence        =0x10;
    const U_Set             =0x11;
    const U_NumericString   =0x12;
    const U_PrintableString =0x13; //ASCII subset A, B, ..., Z a, b, ..., z 0, 1, ..., 9 (space) ' ( ) + , - . / : = ?  EXCLUDES & and @
    const U_T61String       =0x14; //TeletexString //an arbitrary string of T.61 (eight-bit) characters.
    const U_VideoTexString  =0x15;                           
    const U_IA5String       =0x16; //ASCII                         
    const U_UTCTime         =0x17;                           
    const U_GeneralizedTime =0x18;                           
    const U_GraphicString   =0x19;                           
    const U_VisibleString   =0x1A; //ASCII subset              
    const U_GeneralString   =0x1B;                           
    const U_UniversalString =0x1C;                           
    const U_BMPString       =0x1E;

    public static function parseDERBytes(&$bytes,&$pos)
	{
		if (empty($bytes)){ return; }
        $startpos = $pos;
    	$tag = self::readByte($bytes,$pos);
		$clength = self::readLength($bytes,$pos);
    	$header = $pos - $startpos;
    	$cstart = $pos;
		//echo json_encode(array($tag,$clength,$pos))."\n";

		$node = new ASN1Node($bytes, $tag, $cstart, $clength, $header);
//        echo json_encode(array($startpos,$header,$cstart,$clength,"t$tag"))."\n";
		//$node = array();
		//$node['tag'] = $tag;
		//$node['cstart'] = $cstart;
		//$node['clength'] = $clength;//content length
		//$node['header'] = $header;
		//$node['startpos'] = $startpos;

		if ($tag & 0x20) //if hasChildren() // constructed
		{
			//$node['children'] = array();
			if ($tag==0x03){ self::readByte($bytes, $pos); } // skip BitString unused bits, must be in [0, 7]
			
			if ($clength>=0)
			{
				$end = $cstart + $clength;
				while($pos < $end)
				{
					$child = self::parseDERBytes($bytes,$pos);
					$node->addChild($child);
					//$node['children'][] = $parsed;
					//$pos+= $parsed['header'];
					//$pos+= $parsed['clength'];
				}
			}
			else if ($tag & 0x21)// and $clength==-1
			{
				//indefinite length asn1
				$byte_count=strlen($bytes);
				$child = self::parseDERBytes($bytes,$pos);
				$lastpos = array();
				$i=0;
				while($child->tag()!=0 && $pos<$byte_count)
				{
					$node->addChild($child);
					$lastpos[] = $pos;
					
					$child = self::parseDERBytes($bytes,$pos);//get next...
					if ($i++>10000) throw new Exception("Encountered Invalid ASN1 Format Line ".__LINE__);//infinite loop detection
				}
				$clength = $pos - $cstart;
				$node->ulength($clength);//set indefinite length asn1 to a real length value
			}
			else
			{
				throw new Exception("Encountered Invalid ASN1 Format Line ".__LINE__);
			}
		}
		else
		{
			//$content = self::parseContent($bytes,$cstart, $clength, $tag, $has_children=false);
			//$node->setContent($content);
		}
		
		$pos = $cstart + $clength;//$pos is by reference... so we are setting it before we return
		//$node->setPositionInfo($tag,$cstart,$clength,$header,$startpos,$pos);
		return $node;
	}
	
	public static function readByte($bytes,&$pos)
	{
	    $byte = isset($bytes[$pos]) ? $bytes[$pos] : null;
		$pos++;
		return ord($byte);
	}

	public static function readLength($bytes,&$pos)
	{
		$buf = self::readByte($bytes, $pos);
		$len = $buf & 0x7F;
		if ($len == $buf)
			return $len;
		if ($len > 3)
			throw new Exception("ASN1Parser: Length ($len) over 24 bits not supported at position " . ($pos - 1));
		if ($len == 0)
			return -1; // undefined
		$buf = 0;
		for ($i = 0; $i < $len; ++$i)
			$buf = ($buf << 8) | self::readByte($bytes, $pos);
		return $buf;
	}
	
	public static function parseContent($bytes,$cstart, $clength, $tag, $hasChildren)
	{
		if (!empty($tag))
		{
			$tagClass = $tag >> 6;
			//$tagConstructed = ($tag >> 5) & 1;
			//$hasChildren = ($tag & 0x20);

			if ($tagClass==0)
			{
				$tagNumber = $tag & 0x1F;
				switch ($tagNumber)
				{
					case 0x01: // BOOLEAN
						return self::parseBool($bytes,$cstart,$clength);
					case 0x02: // INTEGER
					case 0x03: // BIT_STRING
					case 0x04: // OCTET_STRING
						return $hasChildren ? "" : self::parseHexString($bytes,$cstart,$clength);
					//case 0x05: // NULL
					case 0x06: // OID/OBJECT_IDENTIFIER
						return self::parseOID($bytes,$cstart,$clength);
					//case 0x07: // ObjectDescriptor
					//case 0x08: // EXTERNAL
					//case 0x09: // REAL
					//case 0x0A: // ENUMERATED
					//case 0x0B: // EMBEDDED_PDV
					case 0x10: // SEQUENCE
					case 0x11: // SET
						return $hasChildren ? "" : "";
					case 0x0C: // UTF8String
						return self::parseStringUTF8($bytes,$cstart,$clength);
					case 0x13: // PrintableString
						//return self::parseStringPrintable($bytes,$cstart,$clength);
					case 0x14: // TeletexString
						return self::parseStringTeletext($bytes,$cstart,$clength);
					case 0x12: // NumericString
					case 0x15: // VideotexString
					case 0x16: // IA5String
					case 0x19: // GraphicString
					case 0x1A: // VisibleString
					case 0x1B: // GeneralString
						return self::parseStringISO($bytes,$cstart,$clength);
					case 0x1C: // UniversalString //UCS4 UTF-32
						return self::parseStringUniversal($bytes,$cstart,$clength);
					case 0x1E: // BMPString //UCS2 http://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/asn1/BMPString.html
						return self::parseStringBMP($bytes,$cstart,$clength);
					case 0x17: // UTCTime
					case 0x18: // GeneralizedTime
						return self::parseTime($bytes,$cstart,$clength);
				}
			}
			else if ($tagClass==1)//Application
			{
			}
			else if ($tagClass==2)//Context Specific
			{
				//if ($tagConstructed==1 && $tagNumber==0)
				//{
					//$sub = array_slice($bytes,$cstart,$clength);
					//return implode(":",array_map('dechex',$sub));
				//}
				return self::parseStringISO($bytes,$cstart,$clength);
				//return $has_children ? "" : self::parseStringISO($bytes,$cstart,$clength);
			}
			else if ($tagClass==3)//Private
			{
			}
		}
		return null;
	}
	
    //return json_encode(array_map("dechex",array_slice($bytes,$node['cstart'],$node['clength'])));
	
	public static function parseBool($bytes,$cstart,$clength)
	{
		$pos = $cstart;
		return $bytes[$pos] ? true : false;
	}
	
	public static function parseHexString($bytes,$cstart,$clength)
	{
    	$start = $cstart;
		$end = $cstart+$clength;

		$str='';
		for($i = $start; $i < $end; $i++)
		{
			$str.= sprintf("%02x", ord($bytes[$i]));
		}
		return $str;
	}

	public static function parseStringTeletext($bytes,$cstart,$clength)
	{
		$str=self::parseStringISO($bytes,$cstart,$clength);
		if (ASN1Utils::isValidUTF8($str)) { return $str; }

		$iso = mb_convert_encoding($str,'UTF-8','ISO-8859-1');
		if (ASN1Utils::isValidUTF8($iso)) { return $iso; }
		return $str;
	}

	public static function parseStringPrintable($bytes,$cstart,$clength)
	{
		$str=self::parseStringISO($bytes,$cstart,$clength);
		return mb_convert_encoding($str,'UTF-8','ISO-8859-1');
	}

	public static function parseStringISO($bytes,$cstart,$clength)
	{
		return substr($bytes,$cstart,$clength);
	}
	
	public static function parseStringUTF8($bytes,$cstart,$clength)
	{
		return self::parseStringISO($bytes,$cstart,$clength);
	}
	
	public static function parseStringBMP($bytes,$cstart,$clength)
	{
		$str=self::parseStringISO($bytes,$cstart,$clength);
		return mb_convert_encoding($str,'UTF-8','UCS2');//UCS2 = UTF-16BE
 	}
	
	public static function parseStringUniversal($bytes,$cstart,$clength)
	{
		$str=self::parseStringISO($bytes,$cstart,$clength);
		return mb_convert_encoding($str,'UTF-8','UCS4');//UCS4 = UTF-32
	}

	public static function parseTime($bytes,$cstart,$clength)
	{
		//YYMMDDhhmmZ (test) (YY below 50, 1949... YY>=50 2050)
		//YYYYMMDDhhmmZ (test)
		$str = self::parseStringISO($bytes,$cstart,$clength);
		$p = str_split($str,2);
		if (preg_match("/^[0-9]{12}Z$/", $str))
		{
			$prefix = $p[0] > 50 ? '19' : '20';
		}
		else if (preg_match("/^[0-9]{14}Z$/", $str))
		{
			$prefix = $p[0];
			array_shift($p);//remove p[0], shift
		}
		if (!empty($prefix))
		{
			$p[6] = $p[5]=='Z' ? 'Z' : $p[6]; //move Z to 6... if on 5
			$p[5] = $p[5]=='Z' ? '00' : $p[5];//replace Z on 5 with 00
			$tz = $p[6][0]=='Z' ? 'GMT' : $p[6];//replace Z with GMT
			return $prefix.$p[0]."-".$p[1]."-".$p[2]." ".$p[3].":".$p[4].":".$p[5]." ".$tz;//6 expects 'Z'
		}
		syslog(LOG_INFO, "[CERTTOOLS] ASN1 Unable to parse date: '$str'");
		return $str;
	}

	public static function parseOID($bytes,$cstart,$clength)
	{
    	$start = $cstart;
		$end = $cstart+$clength;

		$s='';$n=0;$bits=0;
		for($i=$start; $i< $end; $i++)
		{
			$v = ord($bytes[$i]);
			$n = ($n << 7) | ($v & 0x7f);
			$bits +=7;
			
			if (!($v & 0x80)) 
			{
				if (empty($s))
				{
					$s = (int)($n/40) . "." . ($n%40);
				}
				else
				{
					$s .= "." . (($bits >= 31) ? "bigint" : $n);//TODO bigint??
				}
				$n = $bits = 0;
			}
		}
		$oid = $s;
		return $oid;
	}

	public static function tagName($tag)
	{
		if (!empty($tag))
		{
			$tagClass = $tag >> 6;
			//$tagConstructed = ($tag >> 5) & 1;
			$tagNumber = $tag & 0x1F;

			if ($tagClass==0)//universal
			{
				switch ($tagNumber)
				{
					case self::U_EOC             : return "EOC";
					case self::U_BOOLEAN         : return "BOOLEAN";
					case self::U_INTEGER         : return "INTEGER";
					case self::U_BIT_STRING      : return "BIT_STRING";
					case self::U_OCTET_STRING    : return "OCTET_STRING";
					case self::U_NULL            : return "NULL";
					case self::U_OID             : return "OBJECT_IDENTIFIER";
					case self::U_ObjectDescriptor: return "ObjectDescriptor";
					case self::U_External        : return "EXTERNAL";
					case self::U_Real            : return "REAL";
					case self::U_Enumerated      : return "ENUMERATED";
					case self::U_EmbeddedPDV     : return "EMBEDDED_PDV";
					case self::U_UTF8String      : return "UTF8_STRING";
					case self::U_Sequence        : return "SEQUENCE";
					case self::U_Set             : return "SET";
					case self::U_NumericString   : return "NumericString";
					case self::U_PrintableString : return "PRINTABLE_STRING"; // ASCII subset
					case self::U_T61String       : return "TeletexString"; // aka T61String
					case self::U_VideoTexString  : return "VideotexString";
					case self::U_IA5String       : return "IA5_STRING"; // ASCII
					case self::U_UTCTime         : return "UTC_TIME";
					case self::U_GeneralizedTime : return "GeneralizedTime";
					case self::U_GraphicString   : return "GraphicString";
					case self::U_VisibleString   : return "VisibleString"; // ASCII subset
					case self::U_GeneralString   : return "GeneralString";
					case self::U_UniversalString : return "UniversalString";
					case self::U_BMPString       : return "BMPString";
					default: return "Universal_" . dechex($tagNumber);
				}
			}
			else if ($tagClass==1)
			{
				return "Application_" . dechex($tagNumber);
			}
			else if ($tagClass==2)
			{
				return "CONTEXT_SPECIFIC";
				//switch ($tagNumber) {
					//case 0x0: return "CONTEXT SPECIFIC (" . $tagNumber . ")";
					//case 0x3: return "CONTEXT SPECIFIC (" . $tagNumber . ")";
					//default: return "[" . $tagNumber . "]"; // Context
				//}
			}
			else if ($tagClass==3)
			{
				return "Private_" . dechex($tagNumber);
			}
		}
		return 'unknown';
	}
}//class

/*
 * additional testing:
 * exceptions thrown for csr 00242943
 */
