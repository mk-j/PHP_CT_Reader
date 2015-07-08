<?php

class ASN1Utils
{
	private static $ev_oids = array(
		'1.3.6.1.4.1.8024.0.2.100.1.2' =>1,      //'EV_OID(Quo Vadis)',
		'1.2.40.0.17.1.22' => 1,                //'EV_OID(A-Trust)',
		'1.2.276.0.44.1.1.1.4' => 1,            //'EV_OID(Symantec / TC TrustCenter)',
		'1.2.392.200091.100.721.1' => 1,        //'EV_OID(SECOM Trust)',
		'1.2.616.1.113527.2.5.1.1' => 1,        //'EV_OID(Unizeto Certum)',
		'1.3.6.1.4.1.782.1.2.1.8.1' => 1,       //'EV_OID(Network Solutions)',
		'1.3.6.1.4.1.4146.1.1' => 1,            //'EV_OID(GlobalSign)',
		'1.3.6.1.4.1.6334.1.100.1' => 1,        //'EV_OID(Verizon / Cybertrust)',
		'1.3.6.1.4.1.6449.1.2.1.5.1' => 1,      //'EV_OID(Comodo)',
		'1.3.6.1.4.1.14370.1.6' => 1,           //'EV_OID(Symantec / GeoTrust)',
		'1.3.6.1.4.1.14777.6.1.1' => 1,         //'EV_OID(Izenpe)',
		'1.3.6.1.4.1.14777.6.1.2' => 1,         //'EV_OID(Izenpe)',
		'1.3.6.1.4.1.17326.10.8.12.1.2' => 1,   //'EV_OID(Camerfirma)',
		'1.3.6.1.4.1.17326.10.8.12.2.2' => 1,   //'EV_OID(Camerfirma)',
		'1.3.6.1.4.1.17326.10.14.2.1.2' => 1,   //'EV_OID(Camerfirma)',
		'1.3.6.1.4.1.17326.10.14.2.2.2' => 1,   //'EV_OID(Camerfirma)',
		'1.3.6.1.4.1.22234.2.5.2.3.1' => 1,     //'EV_OID(Keynectis / Certplus)',
		'1.3.6.1.4.1.23223.2' => 1,             //'EV_OID(StartCom)',
		'1.3.6.1.4.1.34697.2.1' => 1,           //'EV_OID(AffirmTrust)',
		'1.3.6.1.4.1.34697.2.2' => 1,           //'EV_OID(AffirmTrust)',
		'1.3.6.1.4.1.34697.2.3' => 1,           //'EV_OID(AffirmTrust)',
		'1.3.6.1.4.1.34697.2.4' => 1,           //'EV_OID(AffirmTrust)',
		//'2.16.528.1.1001.1.1.1.12.6.1.1.1' => 1,//'EV_OID(DigiNotar (DISABLED))',
		'2.16.578.1.26.1.3.3' => 1,             //'EV_OID(Buypass)',
		'2.16.756.1.89.1.2.1.1' => 1,           //'EV_OID(SwissSign)',
		'2.16.840.1.113733.1.7.23.6' => 1,      //'EV_OID(Symantec / VeriSign)',
		'2.16.840.1.113733.1.7.48.1' => 1,      //'EV_OID(Symantec / thawte)',
		'2.16.840.1.114028.10.1.2' => 1,        //'EV_OID(Entrust)',
		'2.16.840.1.114171.500.9' => 1,         //'EV_OID(Wells Fargo)',
		'2.16.840.1.114404.1.1.2.4.1' => 1,     //'EV_OID(Trustwave)',
		'2.16.840.1.114412.2.1' => 1,           //'EV_OID(DigiCert)',
		'2.16.840.1.114413.1.7.23.3' => 1,      //'EV_OID(Go Daddy)',
		'2.16.840.1.114414.1.7.23.3' => 1,      //'EV_OID(Go Daddy)', 
	);
//http://javadoc.iaik.tugraz.at/iaik_jce/current/iaik/asn1/structures/AlgorithmID.html
//http://nemid-php.googlecode.com/svn-history/r8/trunk/lib/Oids.php
//http://support.microsoft.com/kb/287547 (ms oids)
	private static $oids = array(
		'0.0'=>'null',//unofficial, i just added this to stop the syslogs
		'0.9.2342.19200300.100.1.25'=>'domainComponent',//uclDataNetworksDirectoryPilotDomainComponent
		'0.9.2342.19200300.100.1.1'=>'uclUserId',//uclDataNetworksDirectoryPilotUserId
		'1.2.840.10040.4.1'=>'dsaSignatureKey',
		'1.2.840.10040.4.3'=>'dsaEncryption',
		'1.2.840.10045.2.1'=>'ecPublicKey',//ECC
		'1.2.840.10045.3.1.1'=>'P-224/secp192r1',//Elliptic Curve
		'1.2.840.10045.3.1.7'=>'P-256/prime256v1/secp256r1',//Elliptic Curve
		'1.2.840.10045.4.1'=>'ecdsa-with-SHA1',//ECC sig
		'1.2.840.10045.4.3.1'=>'sha224ECDSA',
		'1.2.840.10045.4.3.2'=>'sha256ECDSA',
		'1.2.840.10045.4.3.3'=>'sha384ECDSA',//common sig
		'1.2.840.10045.4.3.4'=>'sha512ECDSA',
		'1.2.840.113533.7.65.0'=>'entrustVersionExtension',
		'1.2.840.113549.1.1.1'=>'rsaEncryption',
		'1.2.840.113549.1.1.2'=>'md2WithRSAEncryption',
		'1.2.840.113549.1.1.3'=>'md4WithRSAEncryption',
		'1.2.840.113549.1.1.4'=>'md5WithRSAEncryption',
		'1.2.840.113549.1.1.5'=>'sha1WithRSAEncryption',
		'1.2.840.113549.1.1.6'=>'rsaOAEPEncryptionSET',
		'1.2.840.113549.1.1.7'=>'id-RSAES-OAEP',
		'1.2.840.113549.1.1.10'=>'RSASSA-PSS',
		'1.2.840.113549.1.1.11'=>'sha256WithRSAEncryption',
		'1.2.840.113549.1.1.12'=>'sha384WithRSAEncryption',
		'1.2.840.113549.1.1.13'=>'sha512WithRSAEncryption',
		'1.2.840.113549.1.1.14'=>'sha224WithRSAEncryption',
		'1.2.840.113549.1.7.1'=>'pkcs7-data',
		'1.2.840.113549.1.7.2'=>'pkcs7-signedData',
		'1.2.840.113549.1.9.1'=>'email',//emailAddress
		'1.2.840.113549.1.9.2'=>'unstructuredName',//PKCS-9
		'1.2.840.113549.1.9.8'=>'unstructuredAddress',//PKCS-9
		'1.2.840.113549.1.9.14'=>'RequestedExtensions',
		'1.2.840.113549.1.9.15'=>'sMIMECapabilities',
		'1.2.840.113549.3.2'=>'rc2CBC',
		'1.2.840.113549.3.4'=>'rc4',
		'1.2.840.113549.3.7'=>'DES-EDE3-CBC',
		'1.2.840.113583.1.1.9.1'=>'adobeTimestamp',
		'1.2.840.113583.1.1.9.2'=>'adobeArchiveRevInfo',
		"1.3.6.1.4.1.3029.3.1.5"=>'microsoftKeyFeatures',
		"1.3.6.1.4.1.311.10.3.3"=>'microsoftSGC',//serverGatedCrypto
		'1.3.6.1.4.1.311.13.2.3'=>'szOID_OS_VERSION',
		'1.3.6.1.4.1.311.20.2'=>'szOID_ENROLL_CERTTYPE_EXTENSION',
		'1.3.6.1.4.1.311.20.2.2'=>'microsoftSmartCardLogon',
		'1.3.6.1.4.1.311.21.1'=>'szOID_CERTSRV_CA_VERSION',
		'1.3.6.1.4.1.311.21.2'=>'szOID_CERTSRV_PREVIOUS_CERT_HASH',
		'1.3.6.1.4.1.311.21.5'=>'szOID_KP_CA_EXCHANGE',
		'1.3.6.1.4.1.311.21.7'=>'szOID_CERTIFICATE_TEMPLATE',
		'1.3.6.1.4.1.311.21.10'=>'szOID_APPLICATION_CERT_POLICIES',
		'1.3.6.1.4.1.311.21.20'=>'szOID_REQUEST_CLIENT_INFO',
		'1.3.6.1.4.1.311.60.2.1'=>'statementId',
		'1.3.6.1.4.1.311.60.2.1.1'=>'jurisdictionOfIncorporationLocalityName',//X520LocalityName
		'1.3.6.1.4.1.311.60.2.1.2'=>'jurisdictionOfIncorporationStateOrProvinceName',//X520StateOrProvinceName
		'1.3.6.1.4.1.311.60.2.1.3'=>'jurisdictionOfIncorporationCountryName',//X520countryName
		'1.3.6.1.4.1.3401.8.1.1'=>'keyCreationDate',//openpgp
		'1.3.6.1.5.5.7.1.1'=>'authorityInfoAccess',
		'1.3.6.1.5.5.7.1.11'=>'subjectInfoAccess',//timestamping related?
		'1.3.6.1.5.5.7.1.12'=>'id-pe-logotype',
		'1.3.6.1.5.5.7.2.1'=>'cps',
		'1.3.6.1.5.5.7.2.2'=>'userNotice',
		'1.3.6.1.5.5.7.3.1'=>'serverAuth',
		'1.3.6.1.5.5.7.3.2'=>'clientAuth',
		'1.3.6.1.5.5.7.3.3'=>'codeSigning',
		'1.3.6.1.5.5.7.3.4'=>'emailProtection',
		'1.3.6.1.5.5.7.1.3'=>'id-pe-qcStatements',
		"1.3.6.1.5.5.7.3.5"=>'ipsecEndSystem',
		"1.3.6.1.5.5.7.3.6"=>'ipsecTunnel',
		"1.3.6.1.5.5.7.3.7"=>'ipsecUser',
		"1.3.6.1.5.5.7.3.8"=>'timeStamping',
		"1.3.6.1.5.5.7.3.9"=>'ocspSigning',
		"1.3.6.1.5.5.8.2.2"=>'ipsecProtection',
		'1.3.6.1.5.5.7.48.1'=>'ocsp',
		'1.3.6.1.5.5.7.48.2'=>'caIssuers',
        '1.3.6.1.7'=>'internetMail',//Internet: mail
		'1.3.14.3.2.7'=>'desCBC',
		'1.3.14.3.2.15'=>'shaWithRSASignature',
		'1.3.14.3.2.26'=>'sha1NoSign',
		'1.3.14.3.2.29'=>'sha1WithRSA',//deprecated?
		'1.3.14.3.2.15'=>'shaWithRSASignature',//old?
		'1.3.36.3.3.1.2'=>'ripemd160WithRSA',
		'1.3.132.0.33'=>'P-224/secp224r1',//Elliptic Curve
		'1.3.132.0.34'=>'P-384/secp384r1',//Elliptic Curve
		'1.3.132.0.35'=>'P-521/secp521r1',//Elliptic Curve
		'2.5.4.0'=>'id-at-objectClass',
		'2.5.4.1'=>'id-at-aliasedEntryName',
		'2.5.4.3'=>'commonName',
		'2.5.4.4'=>'id-at-surname',
		'2.5.4.5'=>'serialNumber',
		'2.5.4.6'=>'countryName',
		'2.5.4.7'=>'location',//localityName
		'2.5.4.8'=>'stateOrProvinceName',
		'2.5.4.9'=>'street1',//streetAddress
		'2.5.4.10'=>'organizationName',
		'2.5.4.11'=>'organizationalUnitName',
		'2.5.4.12'=>'id-at-title',
		'2.5.4.13'=>'id-at-description',
		'2.5.4.15'=>'businessCategory',
		'2.5.4.17'=>'postalCode',
		'2.5.4.18'=>'id-at-postOfficeBox',
		'2.5.4.20'=>'telephoneNumber',
		'2.5.4.41'=>'givenName',
		'2.5.4.42'=>'id-at-givenName',
		'2.5.4.43'=>'id-at-initials',
		'2.5.4.45'=>'id-at-uniqueIdentifier',
		'2.5.4.46'=>'id-at-dnQualifier',
		'2.5.29.1'=>'oldAuthorityKeyIdentifier',
		'2.5.29.3'=>'oldCertificatePoliciies',
		'2.5.29.9'=>'subjectDirectoryAttributes',
		'2.5.29.14'=>'subjectKeyIdentifier',
		'2.5.29.15'=>'keyUsage',
		'2.5.29.16'=>'privateKeyUsagePeriod',
		'2.5.29.17'=>'subjectAltName',
		'2.5.29.18'=>'issuerAltName',
		'2.5.29.19'=>'basicConstraints',
		'2.5.29.20'=>'crlNumber',//used in CRL (id-ce-crlNumber)
		'2.5.29.21'=>'reasonCode',//used in CRL (id-ce-reasonCode)
		'2.5.29.31'=>'crlDistributionPoints',
		'2.5.29.32'=>'certificatePolicies',
		'2.5.29.35'=>'authorityKeyIdentifier',
		'2.5.29.37'=>'extendedKeyUsage',
		"2.5.29.37.0"=>'anyExtendedKeyUsage',
		"2.5.29.46"=>'FreshestCRL',
		'2.16.840.1.113719.1.9.4.1'=>'novellSecurityAttributes',
		'2.16.840.1.113730.1.1'=>'nsCertType',//netscape-cert-type
		'2.16.840.1.113730.1.2'=>'nsBaseURL',
		'2.16.840.1.113730.1.3'=>'nsRevocationURL',
		'2.16.840.1.113730.1.4'=>'nsCaRevocationURL',
		'2.16.840.1.113730.1.7'=>'nsRenewalURL',
		'2.16.840.1.113730.1.8'=>'nsCaPolicyUrl',//netscape-ca-policy-url
		'2.16.840.1.113730.1.12'=>'nsSslServerName',
		'2.16.840.1.113730.1.13'=>'nsComment',//nsCertificateComment
		"2.16.840.1.113730.4.1"=>'netscapeSGC',//serverGatedCrypto
		'2.16.840.1.113733.1.6.7'=>'verisignSerialNumberRolloverId',
		'2.16.840.1.113733.1.8.1'=>'VeriSign SGC Identifier for CA Certificates',
		'2.16.840.1.113741.1.2.3'=>'intelAMTProvisioning',
	);

	private static $reason_codes = array(
		0 => 'Unspecified', 
		1 => 'Key Compromise', 
		2 => 'CA Compromise', 
		3 => 'Affiliation Changed',
		4 => 'Superseded', 
		5 => 'Cessation Of Operation', 
		6 => 'Certificate Hold',
		7 => 'Remove From CRL', 
		8 => 'Privilege Withdrawn', 
		9 => 'AA Compromise',
	);

	public static function oid($oid)
	{
		if (isset(self::$oids[$oid]))
		{
			return self::$oids[$oid];
		}
		//ignore custom oids http://support.microsoft.com/kb/287547
		if (substr($oid, 0,strlen('1.3.6.1.4.1.311.21.8.'))!='1.3.6.1.4.1.311.21.8.')
		{
			syslog(LOG_INFO, "[CERTTOOLS] Unknown OID in ASN1Utils: $oid");
		}
		return 'unknown_'.$oid;
	}

	public static function reasonCode($enum_index)
	{
		$enum_index = isset(self::$reason_codes[$enum_index]) ? $enum_index : 0;
		return self::$reason_codes[$enum_index];
	}

    public static function isValidUTF8($string)
    {
        if (is_string($string))
        {
			for ($i=0, $ix=strlen($string); $i < $ix; $i++)
			{
				$c = ord($string{$i});
				if ($c==0x09 || $c==0x0a || $c==0x0d || (0x20 <= $c && $c <= 0x7e) ) $n = 0; # 0bbbbbbb
				else if (($c & 0xE0) == 0xC0) $n=1; # 110bbbbb
				else if ($c==0xed && (ord($string{$i+1}) & 0xa0)==0xa0) return false; //code points, 0xd800 to 0xdfff
				else if (($c & 0xF0) == 0xE0) $n=2; # 1110bbbb
				else if (($c & 0xF8) == 0xF0) $n=3; # 11110bbb
				//else if (($c & 0xFC) == 0xF8) $n=4; # 111110bb //byte 5, unnecessary in 4 byte UTF-8
				//else if (($c & 0xFE) == 0xFC) $n=5; # 1111110b //byte 6, unnecessary in 4 byte UTF-8
				else return false;
				for ($j=0; $j<$n; $j++) { // n bytes matching 10bbbbbb follow ?
					if ((++$i == $ix) || ((ord($string{$i}) & 0xC0) != 0x80))
						return false;
				}
			}   
		}
		return true;
	}

	public static function encodeLength($length)
	{
		if (0<=$length && $length<=0x7f)
		{
			return chr($length);
		}
		else if (0x80<=$length && $length<=0xffffff)
		{
			$bytes = '';
			$int = $length;
			while($int>0)
			{
				$v = $int % 256;
				$int = $int >> 8;
				$bytes.= chr($v);
			}
			$byte1 = strlen($bytes)+0x80;
			return chr($byte1).strrev($bytes);
		}
		else
		{
			//ethrow();
			return '';
		}
	}
}
