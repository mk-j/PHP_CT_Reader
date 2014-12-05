<?php

class ASN1Node
{
	private $tag = 0x00;
	private $cstart = 0;
	private $clength = 0;
	private $child_nodes=array();
	private $bytes = null;//holds a reference to the original file bytes

	public function __construct(&$bytes,$tag, $cstart, $clength, $header)
	{
		$this->bytes = &$bytes;//array of unsigned char, by reference to save memory
		$this->tag = $tag;
		$this->cstart = $cstart;
		$this->header = $header;
		$this->clength = $clength;
	}

	public function tag() { return $this->tag; }
	public function cstart() { return $this->cstart; }
	public function clength() { return $this->clength; }
	public function ulength($v) { $this->clength = $v; }//set undetermined length after you have determined it
	public function header() { return $this->header; }
	public function contentBytes() 
	{
		return substr($this->bytes,$this->cstart, $this->clength);
		//return array_slice($this->bytes,$this->cstart, $this->clength);
	}

	public function addChild($node)
	{
		$this->child_nodes[] = $node;
	}
	
	public function child($which_str)
	{
		$whichchild_arr = explode("-", (string)$which_str);
		$node = $this;
		foreach($whichchild_arr as $which)
		{
			$next = isset($node->child_nodes[$which]) ? $node->child_nodes[$which] : null;
			$node = $next;
		}
		return $node;
	}

	public function hasChildren()
	{
		return !empty($this->child_nodes) ? true : false;
	}

	public function children()
	{
		return $this->child_nodes;
	}
	
	public function tagInfo() //used by echoNode
	{
		$tag = $this->tag;
		$tagClass = $tag >> 6;
		$tagConstructed = ($tag >> 5) & 1;
		$tagNumber = $tag & 0x1F;
		$name = ASN1Parser::tagName($tag);

		$str='';
		$str.='tag'.(':0x'.dechex($tag) .':{');
		$str.='len'.(':'.$this->clength .',');
		$str.='class'.(':'.$tagClass .',');
		$str.='constructed'.(':'.$tagConstructed .',');
		$str.='number'.(':'.$tagNumber .',');
		$str.='name'.(':'.$name .'}');
		return $str;
	}
	
	public function toRawString() //if the caller knows he needs raw, this is faster
	{
		return ASN1Parser::parseStringISO($this->bytes, $this->cstart, $this->clength);
	}

	public function toHexString() //if the caller knows he needs hex, this is faster
	{
		return ASN1Parser::parseHexString($this->bytes, $this->cstart, $this->clength);
	}
	
	public function toString()
	{
		$bytes = $this->bytes;
		$cstart = $this->cstart;
		$clength = $this->clength;
		$tag = $this->tag;
		$has_children = $this->hasChildren();
		$string = ASN1Parser::parseContent($bytes,$cstart, $clength, $tag, $has_children);
		//return ASN1Utils::isValidUTF8($string) ? $string : ASN1Parser::parseHexString($bytes, $cstart, $clength);
		return preg_match('/^[\x9\xA\xD\x20-\x7E\x80-\x{D7FF}\x{E000}-\x{FFFD}]*$/u', $string) ? $string : ASN1Parser::parseHexString($bytes, $cstart, $clength);
		//return preg_match('/^[\x9\xA\xD\x20-\x7E\x80-\x{D7FF}\x{E000}-\x{FFFD}\x{10000}-\x{10FFFF}]*$/u', $string) ? $string : ASN1Parser::parseHexString($bytes, $cstart, $clength);
	}
}

