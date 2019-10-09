<?php

error_reporting(0);

/**

 * AesCipher

 *

 * Encode/Decode text by password using AES-256-CBC algorithm

 */

class AesCipher 

{

    const CIPHER = 'AES-256-CBC';

    const INIT_VECTOR_LENGTH = 16;


    /**

     * Encoded/Decoded data

     *

     * @var null|string

     */

    protected $data;

    /**

     * Initialization vector value

     *

     * @var string

     */

    protected $initVector = null;

    /**

     * Error message if operation failed

     *

     * @var null|string

     */

    protected $errorMessage;



    /**

     * AesCipher constructor.

     *

     * @param string $initVector        Initialization vector value

     * @param string|null $data         Encoded/Decoded data

     * @param string|null $errorMessage Error message if operation failed

     */

    public function __construct($initVector, $data = null, $errorMessage = null)

    {

        $this->initVector = $initVector;

        $this->data = $data;

        $this->errorMessage = $errorMessage;

    }



    /**

     * Encrypt input text by AES-256-CBC algorithm

     *

     * @param string $secretKey 16/24/32 -characters secret password

     * @param string $plainText Text for encryption

     *

     * @return self Self object instance with data or error message

     */

    public static function encrypt($secretKey, $plainText)

    {

        try {

            // Check secret length

            if (!static::isKeyLengthValid($secretKey)) {

                throw new \InvalidArgumentException("Secret key's length must be 128, 192 or 256 bits");

            }



            // Get random initialization vector

            //$initVector = bin2hex(openssl_random_pseudo_bytes(static::INIT_VECTOR_LENGTH / 2));

            //set $initVector to NULL 
            $initVector = NULL;

            // Encrypt input text

            $raw = openssl_encrypt(

                $plainText,

                static::CIPHER,

                $secretKey,

                OPENSSL_RAW_DATA,

                $initVector
            );

           // OPENSSL_RAW_DATA


            // Return base64-encoded string: initVector + encrypted result

           // $result = base64_encode($initVector . $raw);
            $result = base64_encode($raw);

 
            if ($result === false) {

                // Operation failed
                

                return new static($initVector, null, openssl_error_string());

            }



            // Return successful encoded object

            return new static($initVector, $result);

        } catch (\Exception $e) {

            // Operation failed

            return new static(isset($initVector), null, $e->getMessage());

        }

    }



    /**

     * Decrypt encoded text by AES-256-CBC algorithm

     *

     * @param string $secretKey  16/24/32 -characters secret password

     * @param string $cipherText Encrypted text

     *

     * @return self Self object instance with data or error message

     */

    public static function decrypt($secretKey, $cipherText)

    {

        try {

            // Check secret length

            if (!static::isKeyLengthValid($secretKey)) {

                throw new \InvalidArgumentException("Secret key's length must be 128, 192 or 256 bits");

            }



            // Get raw encoded data

            $encoded = base64_decode($cipherText);

            // Slice initialization vector

            $initVector = substr($encoded, 0, static::INIT_VECTOR_LENGTH);

            // Slice encoded data

            $data = substr($encoded, static::INIT_VECTOR_LENGTH);



            // Trying to get decrypted text

            $decoded = openssl_decrypt(

                $data,

                static::CIPHER,

                $secretKey,

                OPENSSL_RAW_DATA,

                $initVector

            );

            //$initVector OPENSSL_RAW_DATA

            if ($decoded === false) {

                // Operation failed

                return new static(isset($initVector), null, openssl_error_string());

            }



            // Return successful decoded object

            return new static($initVector, $decoded);

        } catch (\Exception $e) {

            // Operation failed

            return new static(isset($initVector), null, $e->getMessage());

        }

    }



    /**

     * Check that secret password length is valid

     *

     * @param string $secretKey 16/24/32 -characters secret password

     *

     * @return bool

     */

    public static function isKeyLengthValid($secretKey)

    {

        $length = strlen($secretKey);



        return $length == 16 || $length == 24 || $length == 32;

    }



    /**

     * Get encoded/decoded data

     *

     * @return string|null

     */

    public function getData()

    {

        return $this->data;

    }



    /**

     * Get initialization vector value

     *

     * @return string|null

     */

    public function getInitVector()

    {

        return $this->initVector;

    }



    /**

     * Get error message

     *

     * @return string|null

     */

    public function getErrorMessage()

    {

        return $this->errorMessage;

    }



    /**

     * Check that operation failed

     *

     * @return bool

     */

    public function hasError()

    {

        return $this->errorMessage !== null;

    }



    /**

     * To string return resulting data

     *

     * @return null|string

     */

    public function __toString()

    {

        return $this->getData();

    }

}



// USAGE


// pass in your own secret key
$secretKey = 'B6280F633A862E98D95155A9C903F73A';


//  
$text = "0:username:password";



$encrypted = AesCipher::encrypt($secretKey, $text);

$enc = ($encrypted);
echo $enc.'</br>';

$cipherText = $encrypted;
$decrypted = AesCipher::decrypt($secretKey, $cipherText);
echo $decrypted.'</br>';


