<?php

/**
 * This class create and check csrf_token
 *
 * @author Pol
 * @version 13/2/2017
 */
class csrf_token {

    /**
     * This method create token key and save it in session
     * @private
     * @return string The token key
     */
    private static function createTokenData() {
        $token = [
            'ref'   => "http://{$_SERVER[ 'HTTP_HOST' ]}{$_SERVER[ 'REQUEST_URI' ]}",
            'time'  => time(),
            'token' => md5( uniqid( rand() ) ),
        ];

        $_SESSION[ 'csrf_token' ] = $token;

        return base64_encode( serialize( $token ) );
    }

    /**
     * This method return HTML input hidden for form
     * @param type $name The name of token input <defualt name: csrf_token>
     * @return string The input:hidden with value of token
     */
    public static function create( $name = 'csrf_token' ) {
        return '<input type="hidden" name="' . $name . '" value="' . self::createTokenData() . '">';
    }

    /**
     *
     * @param array|bool:false $time Its chack leagl time for action.
     * (array with 'min' or 'max' or both key with sec)
     * or false for not check time <defualt time: false>
     * @param string $method The method for check  (post / get / request) <defualt method: post>
     * @param string $name The name of token input <defualt name: csrf_token>
     * @return boolean If token is legal its return TURE or FALSE if token illgal
     */
    public static function is_token( $time = false, $method = 'post', $name = 'csrf_token' ) {
        if ( isset( $_SESSION[ 'csrf_token' ] ) ) {
            $method       = strtolower( $method );
            $sesson_token = $_SESSION[ 'csrf_token' ];
            unset( $_SESSION[ 'csrf_token' ] );

            if ( $method == 'post' && isset( $_POST[ $name ] ) ) {
                $token = $_POST[ $name ];
            } else if ( $method == 'get' && isset( $_GET[ $name ] ) ) {
                $token = $_POST[ $name ];
            } else if ( $method == 'request' && isset( $_REQUEST[ $name ] ) ) {
                $token = $_REQUEST[ $name ];
            }

            if ( !empty( $token ) ) {

                $token    = unserialize( base64_decode( $token ) );
                $is_token = $token[ 'ref' ] == $sesson_token[ 'ref' ] &&
                        $token[ 'ref' ] == $_SERVER[ 'HTTP_REFERER' ] &&
                        $token[ 'token' ] == $sesson_token[ 'token' ] &&
                        $token[ 'time' ] == $sesson_token[ 'time' ];


                if ( $is_token ) {
                    $timeLeft = time() - $token[ 'time' ];
                    if ( $time == FALSE ) {
                        return TRUE;
                    } elseif ( is_array( $time ) ) {
                        $leagal_time = ((isset( $time[ 'min' ] ) && $time[ 'min' ] <= $timeLeft) || !isset( $time[ 'min' ] )) &&
                                ((isset( $time[ 'max' ] ) && $time[ 'max' ] >= $timeLeft) || !isset( $time[ 'max' ] ));
                        if ( $leagal_time ) {
                            return TRUE;
                        }
                    }
                }
            }
        }
        return FALSE;
    }

}
