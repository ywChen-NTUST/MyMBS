<?php
function preventXSS($str)
{
    $str = htmlentities($str, ENT_QUOTES | ENT_SUBSTITUTE, "UTF-8");
    $str = str_replace("%", "&percnt;", $str);
    $str = str_replace(".", "&period;", $str);
    $str = str_replace("/", "&sol;", $str);
    $str = str_replace("\\", "&bsol;", $str);
    $str = str_replace(":", "&ratio;", $str);
    $str = str_replace("=", "&equals;", $str);
    $str = str_replace("(", "&lpar;", $str);
    $str = str_replace(")", "&rpar;", $str);
    return $str;
}

function verifyProfile($dir, $image)
{
    $verified = true;
    if(is_null($image))
    {
        $verified = false;
    }
    elseif(strpos($image, '/') !== false || strpos($image, '\\') !== false)
    {
        $verified = false;
    }
    else
    {
        exec(escapeshellcmd("ls " . escapeshellarg("$dir/$image")), $output, $ret);
        unset($output);
        if($ret == 0)
        {
            $verified = true;
        }
        else
        {
            $verified = false;
        }
    }

    if($verified == true)
    {
        return "$dir/$image";
    }
    else
    {
        return "$dir/default.svg";
    }
}

function verifyAttachment($str)
{
    $str = str_replace("'", "%27", $str);
    $str = str_replace("\"", "%22;", $str);
    $str = str_replace("\\", "%5C;", $str);
    $str = str_replace("/", "%25", $str);
    return $str;
}

function checkIsIntStr($str)
{
    $is_int_str = true;
    $int_chars = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
    $str_chars = str_split($str);
    foreach($str_chars as $str_char)
    {
        if(!in_array($str_char, $int_chars))
        {
            $is_int_str = false;
        }
    }
    return $is_int_str;
}

function recoveryAttachment($str)
{
    // find front underline
    $i = 0;
    for($i=0; $i<strlen($str); $i++)
    {
        if($str[$i] == '_')
        {
            break;
        }
    }

    // 0ddd_'original-file-name'.txt
    return substr($str, $i+1, -4);
}

function prepareFile($filename, $next_id, $isimage=false, $maxlen=250)
{
    if($isimage == false)
    {
        $preserve_len = strlen("0") + strlen((string)$next_id) + strlen("_") + strlen(".txt");
    }
    else
    {
        $preserve_len = strlen("0") + strlen((string)$next_id) + strlen("_");
    }
    if(strlen($filename) > ($maxlen - $preserve_len))
    {
        $filename_pieces = explode(".", $filename);
        $tmp_fn = "";
        if(count($filename_pieces) == 1)
        {
            $tmp_fn_length = $maxlen - $preserve_len;
            $tmp_fn = substr($filename, 0, $tmp_fn_length);
        }
        else
        {
            for($i=0; $i<count($filename_pieces)-1; $i++)
            {
                $tmp_fn = $tmp_fn . $filename_pieces[$i] . '.';
            }
            $tmp_fn = substr($tmp_fn, 0, -1);
            $last_piece = $filename_pieces[count($filename_pieces)-1];
            $tmp_fn_length = $maxlen - $preserve_len - strlen('.') - strlen($last_piece);
            if($tmp_fn_length > 0)
            {
                $tmp_fn = substr($tmp_fn, 0, $tmp_fn_length);
                $tmp_fn = $tmp_fn . "." . $last_piece;
            }
            else
            {
                $tmp_fn = substr($tmp_fn, 0, 1);
                $last_piece_length = $maxlen - $preserve_len - strlen('.') - 1;
                $tmp_fn = $tmp_fn . "." . substr($last_piece, 0, $last_piece_length);
            }
        }
        $filename = $tmp_fn;
    }
    $filename = "0" . (string)$next_id . "_" . $filename;
    if($isimage == false)
    {
        $filename .= ".txt";
    }
    return $filename;
}

function checkisimgfile($filename, $tmp_filename="", $file_mime_type="")
{
    if($file_mime_type != "")
    {
        if(strlen($file_mime_type) <= 6)
        {
            return false;
        }
        elseif(strcmp(substr($file_mime_type, 0, 6), "image/") != 0)
        {
            return false;
        }
    }

    if($tmp_filename != "")
    {
        // $tmp_dir = ini_get('upload_tmp_dir');
        if(!is_array(getimagesize("$tmp_filename")))
        {
            return false;
        }
    }

    $img_type_list = array(
        "tiff", "pjp", "jfif", "bmp", "gif", "svg", 
        "png", "xbm", "dib", "jxl", "jpeg", "svgz", 
        "jpg", "webp", "ico", "tif", "pjpeg", "avif");

    $filename_pieces = explode(".", $filename);
    if(count($filename_pieces) < 2)
    {
        return false;
    }
    elseif(!in_array(strtolower($filename_pieces[count($filename_pieces)-1]), $img_type_list))
    {
        return false;
    }

    return true;
}

function BBCodeGen($str)
{
    // Use after preventXSS
    $str = preg_replace("/\[b\](.*?)\[&sol;b\]/",'<b>${1}</b>',$str);
    $str = preg_replace("/\[i\](.*?)\[&sol;i\]/",'<i>${1}</i>',$str);
    $str = preg_replace("/\[u\](.*?)\[&sol;u\]/",'<u>${1}</u>',$str);
    
    $uri_match_count = preg_match("/\[img\]\s*(?:https?)&ratio;&sol;&sol;(?:(?:[-a-zA-Z0-9@:%._\+~#=]{1,256}(?:&period;)?)*)((?:(?:&sol;)?(?:(?:[-a-zA-Z0-9@:%._\+~#=]|&period;){1,256}))*)\[&sol;img\]/",$str, $matches, PREG_OFFSET_CAPTURE);
    $tmp_uri = "";
    if($uri_match_count == 1)
    {
        $tmp_uri = $matches[1][0];
    }
    $tmp_uri = str_replace("&sol;", "/", $tmp_uri);
    $tmp_uri = str_replace("&period;", ".", $tmp_uri);
    $url_match_count = preg_match("/\[img\]\s*(?:https?)&ratio;&sol;&sol;((?:[-a-zA-Z0-9@:%._\+~#=]{1,256}(?:&period;)?)*)(?:(?:(?:&sol;)?(?:(?:[-a-zA-Z0-9@:%._\+~#=]|&period;){1,256}))*)\[&sol;img\]/",$str, $matches, PREG_OFFSET_CAPTURE);
    $tmp_url = "";
    if($url_match_count == 1)
    {
        $tmp_url = $matches[1][0];
    }
    $tmp_url = str_replace("&period;", ".", $tmp_url);
    $str = preg_replace("/\[img\]\s*(https?)&ratio;&sol;&sol;(?:(?:[-a-zA-Z0-9@:%._\+~#=]{1,256}(?:&period;)?)*)(?:(?:(?:&sol;)?(?:(?:[-a-zA-Z0-9@:%._\+~#=]|&period;){1,256}))*)\[&sol;img\]/",'<img src="${1}://'.$tmp_url.$tmp_uri.'">', $str);
    
    $str = preg_replace("/\[color&equals;([^\]]*)\](.*?)\[&sol;color\]/", '<span style="color:${1};">${2}</span>', $str);
    return $str;
}
?>