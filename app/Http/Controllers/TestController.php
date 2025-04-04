<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;

class TestController extends BaseController
{
    public function test(){
        $curl = curl_init();

        curl_setopt_array($curl, array(
          CURLOPT_URL => 'https://www.fast2sms.com/dev/bulkV2?authorization=wdWtBiYXZ3DboP9y1p0TVRzGOajeclMrSJnQk4xL7IEKfgmUs8BudVRcxOfMT8kmv4lQrjIAXh0bsD7C&route=dlt&sender_id=QNTOTP&message=167888&variables_values='.$otp.'&flash=0&numbers='.$request->phoneno,
          CURLOPT_RETURNTRANSFER => true,
          CURLOPT_ENCODING => '',
          CURLOPT_MAXREDIRS => 10,
          CURLOPT_TIMEOUT => 0,
          CURLOPT_FOLLOWLOCATION => true,
          CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
          CURLOPT_CUSTOMREQUEST => 'GET',
          CURLOPT_HTTPHEADER => array(
            'Cookie: XSRF-TOKEN=eyJpdiI6IkRrYlwvRG1wdlwvVWRacXlMY1JiRjdIdz09IiwidmFsdWUiOiIyYTVFYm4wR3IzS2d6b1p3VnJWXC9HSHV1N3g1d1pWMWdpMU9VWmVKVXVKMW5pXC9WZVpjbXpDbDhxWGc0WHpKaGp1N0dHVVF6UWM3NWZlTEp4XC9BUjBFdz09IiwibWFjIjoiMmJkZjlhMzU0MmNhMzQ3ZmU1NDFlM2U1N2MyMzAyYzczZTQ4MmQ2NzVjMzdmMTVlZDFhNmMxYjgwYzcxMzE4MSJ9; laravel_session=eyJpdiI6ImF5SU1QMUdWWkw2a3RvdXhQc3psWnc9PSIsInZhbHVlIjoiZm8ralZvZ3E3VzhqMmtJSlJBYlpjbjgyYVh3ZUhzUWRcL25JTWpmeXNJTGJrK2dHV1wvQmdSelFWUXc3T2hId3Z6R3JxdzJBazRZbERLbmhCY1NXZVptZz09IiwibWFjIjoiYzkxNmE0ODBkN2U1ZTZiZWYzMjEyMWFhNmJiYzEwYjFkZGM4YTZhYWUyZmQzYmJjYWIxZDdjYjU5MTVmZTE0YSJ9; oHx06S1gLorY9m72dkq2ujUIL6VULhiQm910LUir=eyJpdiI6IjBwOENYcnNBb2dpVjU0WGFjWUd3aFE9PSIsInZhbHVlIjoiUE41Q2p6SEV4VVwvOUpzd3J4WGVmSFpJWHZpMnpQb3NUQ0NPUDdyeUt2c0VHUDR6eFJRXC90Wk1cLzhsTlZVaVVBZ1dOaDNuQll5cEs1ZFRcL0VENWlCQ1YzXC8zVWZFTVQxSUxac2I5OElTZ3VFMDJUcExnU3Z4ZUdvdXpTdlZGNE0yU2NPM0pEVFROVDFYVmpCd0VLWDJlelpJS1RIeXpESE5ZRndHU3ZISUg3RWFcL3YrRFVDOGNKSTZZcHpXVXhcL2F0NFJqTmo2WldkcVdsM21vXC9ONmNpOXhSNkVHTHJLRVlIdTVpNlBtRTFRZTRsNjZsaFU0eTFSR25LbGJhSjNlcUREdytMQVJ0c0pCWUcrSGkyTWQ0ZDlHazNGelhwQ21yeVwvMlNPaDRyNDlnbVFvcDZneVwvdnBOUTdhT1hPU095dE5vSURod1FxTFZ1bTUzR1d6bFR1d1hIK2pYS3lVOWZxWEhzSmM5MVRtbWIxemI1SXNxOHl3d0dHY2FIanpDbnpVTFE3THF5YUhjV0xGVWZHK2ZNeFJzOHZqYnRiVlJ6bW54bk5QOG9TaFpKWlp2WXR2NVY0WVNvTUhKOXFEaGZsRUNtN01oVWJWTmRvSHlFOExTTllSRDcxcEFsUERsTTA4S0prSlV2OWg3U09RdnFJNGw5MkN0dW9xS3pFQjMzM01EVVwvSnpGQ3hCN0NRTys0ajBXbEUxRHhZbDhcL0lyejNVSm5MQzhLcVwvRFZ4ST0iLCJtYWMiOiJiYTBiZjZlNDY3ZmViYWE3OGYwNTU1NTExMmY4ZTg4ZGIyNjg3ZGY0NDQ0YTAzYjRiZmFlODdmMmFmNDRjYTNkIn0%3D'
          ),
        ));
        
        $response = curl_exec($curl);
        return $response;
    }
}
