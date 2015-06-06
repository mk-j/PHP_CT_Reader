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
	private $download_step=1000;

	public function __construct($ct_url)
	{
        	$this->download_step = 1000;
        	//different ct logs have different batch sizes
        	if (strpos($ct_url, 'digicert')!==false ) { $this->download_step=64;   }

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
	
	public function downloadNextRange($i=0)
	{
		$from=$i;
		$until=$i+$this->download_step-1;
		$filename = sprintf("%010d_to_%010d.json", $from, $until).".gz";
		$url = $this->ct_url.'/ct/v1/get-entries?start='.urlencode($from).'&end='.urlencode($until);
		if (!file_exists($filename))
		{
			file_put_contents("php://stderr", "$filename doesn't exist\n");
			$json = file_get_contents($url);
                	$entry_count = count($json['entries']);
                	file_put_contents("php://stderr", "REQ: ".$this->download_step.", got $entry_count\n");

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
            $merkleTreeLeaf = base64_decode( substr($entry['leaf_input'], 0, 16) );
            $entryType = ord(substr($merkleTreeLeaf, 10, 1)) *256 +ord(substr($merkleTreeLeaf, 11, 1));
            if ($entryType==0) //x509_entry
            {
                $length_bytes = base64_decode( substr($entry['leaf_input'], 16, 4) );
                $cert_length = current(unpack("N", "\x00".$length_bytes));
                $bin = base64_decode( substr($entry['leaf_input'], 20) );
                $leaf_cert = base64_encode( substr($bin, 0, $cert_length) );
                $cert_pem = "-----BEGIN CERTIFICATE-----"."\r\n".chunk_split($leaf_cert)."-----END CERTIFICATE-----"."\r\n";
                return $this->parseCert($cert_pem);
            }
            else if ($entryType==1) //precertEntry
            {
                $xtra = base64_decode($entry['extra_data']);//extract full leaf cert from extra_data
                $length_bytes = substr($xtra, 0, 3);
                $cert_length = current(unpack("N", "\x00".$length_bytes));
                $leaf_cert = base64_encode( substr($xtra, 3, $cert_length) );
                $cert_pem = "-----BEGIN CERTIFICATE-----"."\r\n".chunk_split($leaf_cert)."-----END CERTIFICATE-----"."\r\n";
                return $this->parseCert($cert_pem);
            }
            else
            {
                file_put_contents("php://stderr", "unable to parse ctlog entry\n");
            }
        }

	public function parseCert($cert_pem)
	{
		$parsed = openssl_x509_parse($cert_pem);
		print_r($parsed['subject']);//TODO - more parsing here...
	}
}

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
