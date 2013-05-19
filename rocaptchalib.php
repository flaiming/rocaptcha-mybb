<?php

/**
* A RoCaptchaResponse is returned from rocaptcha_check_answer()
*/
class RoCaptchaResponse {
	public $is_valid;
	public $error;
	public function RoCaptchaResponse($data = null) {
		if ($data !== null) {
			$this->is_valid = false;
			if (isset($data->status)) {
				if ($data->status == 'PASSED') {
					$this->is_valid = true;
				}
			}
			if (isset($data->content)) {
				$this->error = $data->content;
			}
		}
	}
}

class RoCaptcha {
	const ROCAPTCHA_API_SERVER = "http://rocaptcha.com/api";
	const ROCAPTCHA_VERIFY_SERVER = "rocaptcha.com";
	
	/**
	* Encodes the given data into a query string format
	* @param $data - array of string elements to be encoded
	* @return string - encoded request
	*/
	private static function qsencode ($data) {
		$req = "";
		foreach ( $data as $key => $value )
				$req .= $key . '=' . urlencode( stripslashes($value) ) . '&';
		// Cut the last '&'
		$req=substr($req,0,strlen($req)-1);
		return $req;
	}


	/**
	 * Submits an HTTP POST to a RoCAPTCHA server
	 * @param string $host
	 * @param string $path
	 * @param array $data
	 * @param int port
	 * @return json response
	 */
	private static function httpPost($host, $path, $data, $sessionid, $port = 80) {

		$req = self::qsencode($data);
		
		$sessionid = urlencode($sessionid);

		$opts = array(
			'http'=>array(
				'method'=>"POST",
				'header'  => "Host: $host\r\n".
				"Content-Type: application/x-www-form-urlencoded;\r\n".
				"Content-Length: " . strlen($req) . "\r\n".
				"User-Agent: RoCAPTCHA/PHP\r\n".
				"Cookie: sessionid=" . $sessionid . "\r\n",
				'content' => $req
			)
		);

		$context = stream_context_create($opts);
		$url = self::ROCAPTCHA_API_SERVER. $path;
		$result = file_get_contents($url, false, $context, -1, 200);

		$response = json_decode($result);

		return $response;
	}



	/**
	 * Gets the challenge HTML (javascript and non-javascript version).
	 * This is called from the browser, and the resulting RoCAPTCHA HTML widget
	 * is embedded within the HTML form it was called from.
	 * @param string $pubkey A public key for RoCAPTCHA
	 * @param string $error The error given by RoCAPTCHA (optional, default is null)
	 * @param string $lang Language code (example: en, cs)
	 * @return string - The HTML to be embedded in the user's form.
	 */
	public static function getHtml ($pubkey, $error = null, $lang = null)
	{
		if ($pubkey == null || $pubkey == '') {
			die ("To use RoCAPTCHA you must get an API key from <a href='http://rocaptcha.com/'>http://rocaptcha.com/</a>.");
		}
		$server = self::ROCAPTCHA_API_SERVER;
		$errorpart = "";
		if ($error) {
		   $errorpart = "&amp;error=" . $error;
		}
		$langpart = "";
		if ($lang) {
			$langpart = "&amp;lang=" . $lang;
		}
		return '<div id="rocaptcha_placeholder"></div>
		<script type="text/javascript" src="'. $server . '/js/?key=' . $pubkey . $langpart . $errorpart . '"></script>
		<script type="text/javascript">
			RoCaptcha.init("rocaptcha_placeholder");
		</script>';
	}

	/**
	 * Gets remote IP address.
	 * @return string - client IP address	 
	 */	 	
	private static function getIP() {
		if (getenv('HTTP_CLIENT_IP')) {
			$ip = getenv('HTTP_CLIENT_IP');
		}
		elseif (getenv('HTTP_X_FORWARDED_FOR')) {
			$ip = getenv('HTTP_X_FORWARDED_FOR');
		}
		elseif (getenv('HTTP_X_FORWARDED')) {
			$ip = getenv('HTTP_X_FORWARDED');
		}
		elseif (getenv('HTTP_FORWARDED_FOR')) {
			$ip = getenv('HTTP_FORWARDED_FOR');
		}
		elseif (getenv('HTTP_FORWARDED')) {
			$ip = getenv('HTTP_FORWARDED');
		}
		else {
			$ip = $_SERVER['REMOTE_ADDR'];
		}
		return $ip;
	}

	/**
	  * Calls an HTTP POST function to verify if the user's guess was correct
	  * @param string $privkey
	  * @param string $remoteip
	  * @param string $challenge
	  * @param string $response
	  * @param array $extra_params an array of extra variables to post to the server
	  * @return RoCaptchaResponse
	  */
	public static function checkAnswer ($privkey, $challenge, $response, $sessionid, $extra_params = array())
	{
		if ($privkey == null || $privkey == '') {
			die ("To use RoCAPTCHA you must get an API key from <a href='http://rocaptcha.com/'>http://rocaptcha.com/</a>.");
		}

		$remoteip = self::getIP();

		if ($remoteip == null || $remoteip == '') {
			die ("For security reasons, you must pass the remote ip to RoCAPTCHA");
		}

		//discard spam submissions
		if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0) {
				$rocaptcha_response = new RoCaptchaResponse();
				$rocaptcha_response->is_valid = false;
				$rocaptcha_response->error = 'FAILED';
				return $rocaptcha_response;
		}

		$response = self::httpPost(self::ROCAPTCHA_VERIFY_SERVER, "/verify/",
										  array (
												 'key' => $privkey,
												 'remoteip' => $remoteip,
												 'hash' => $challenge,
												 'response' => $response
												 ) + $extra_params,
											$sessionid
										  );

		$rocaptcha_response = new RoCaptchaResponse($response);
		return $rocaptcha_response;
	}

}

?>