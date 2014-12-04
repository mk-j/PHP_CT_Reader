<?php
/**
 * Certificate Transparenct CTLog Reader, 
 * for parsing SSL X509 certificates from a ctlog:
 * http://www.certificate-transparency.org/
 *
 * @author     mk-j
 * @license    http://opensource.org/licenses/MIT
 * @link       https://github.com/mk-j/PHP_CT_Reader
*/
 
class CTReader
{
	private $ct_url='';//see: http://www.certificate-transparency.org/known-logs
	private $download_step=2000;

	public function __construct($ct_url)
	{
		$this->ct_url = rtrim($ct_url, "/");
	}

	public function getMax()
	{
		$url = $this->ct_url.'/ct/v1/get-sth';
		$contents = file_get_contents($url);
		if (($parsed = json_decode($contents,true))!==false)
		{
			file_put_contents("php://stderr", "log_size:{$parsed['tree_size']}\n");
			return $parsed['tree_size'];//$parsed = array('tree_size'=>, 'timestamp'=>, 'sha256_root_hash'=>, 'tree_head_signature'=>,);
		}
		return 0;
	}
	
	public function downloadNextRange($i)
	{
		$from=$i;
		$until=$i+$this->download_step-1;
		$filename = sprintf("%010d_to_%010d.json", $from, $until).".gz";
		$url = $this->ct_url.'/ct/v1/get-entries?start='.urlencode($from).'&end='.urlencode($until);
		if (!file_exists($filename))
		{
			file_put_contents("php://stderr", "$filename doesn't exist\n");
			$json = file_get_contents($url);
			$fd = fopen("compress.zlib://$filename","w");
			if ($fd)
			{
				fwrite($fd, $json);
				fclose($fd);
			}
		}
	}

	public function downloadAll()
	{
		$max = $this->getMax();
		$round_down = ($max - $max%$this->download_step);
		for($i=0, $ix=$round_down; $i<$ix; $i+=$this->download_step)
		{
			$this->downloadNextRange($i);
		}
	}

	public function parseFileList()
	{
		$files = glob("0*.json.gz");
		foreach($files as $filename)
		{
			file_put_contents("php://stderr", "reading file: $filename\n");
			if (($fd = fopen("compress.zlib://$filename","r"))!==false)
			{
				$f = "";
				while (!feof($fd)) { $f.=fread($fd, 1024); }
				if (($r = json_decode($f,true))!==false)
				{
					foreach($r['entries'] as $entry)
					{
						$this->parseEntry($entry);
					}
				}
			}
		}
	}

	public function parseEntry($entry)
	{
		$merkleTreeLeaf = base64_decode( substr($entry['leaf_input'],0,20) );
		$version = ord(substr($merkleTreeLeaf, 0, 1));//0=>version1
		$leafType = ord(substr($merkleTreeLeaf, 1, 1));//0=>timestamped entry
		$timestamp = substr($merkleTreeLeaf, 2, 8);//64 bit
		$entryType = ord(substr($merkleTreeLeaf, 10, 2));//x509_entry(0), precert_entry(1), 65536
		$pemLength = current(unpack("N", "\x00".substr($merkleTreeLeaf, 12, 3)));

		$bin = base64_decode( substr($entry['leaf_input'], 20) );
		$leaf_cert = base64_encode( substr($bin, 0, $pemLength) );
		$cert_pem = "-----BEGIN CERTIFICATE-----"."\r\n".chunk_split($leaf_cert)."-----END CERTIFICATE-----"."\r\n";
		$this->parseCert($cert_pem);
	}

	public function parseCert($cert_pem)
	{
		$parsed = openssl_x509_parse($cert_pem);
		print_r($parsed['subject']);//TODO - more parsing here...
	}
}

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
