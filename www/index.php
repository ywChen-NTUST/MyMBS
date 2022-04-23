<?php // SPA (Single Page Application) stands for SPAghetti ?>
<?php
    function _fatalHandler()
    {
        $error = error_get_last();
        if ($error !== NULL && in_array($error['type'],
            array(E_ERROR, E_PARSE, E_CORE_ERROR, E_CORE_WARNING,
                E_COMPILE_ERROR, E_COMPILE_WARNING,E_RECOVERABLE_ERROR))) {

            print("<script> 
                alert(\"系統錯誤！\\n嘗試回到首頁\");
                window.location.href=\"index.php?page=home\";
                </script>");
            die();
        }
    }
    register_shutdown_function("_fatalHandler");
?>
<?php
    $max_filesize = ini_get('upload_max_filesize');
    $max_filesize = intval($max_filesize);
?>
<?php
    $session_expire = ini_get('session.gc_maxlifetime');
    $session_name = ini_get('session.name');
    if (empty($_COOKIE[$session_name])) {
        session_set_cookie_params(array(
            'lifetime' => $session_expire,
            'path' => '/',
            'domain' => null,
            'secure' => null,
            'httponly' => true,
            'samesite' => 'Lax'
        ));
        session_start();
    } else {
        session_start();
        setcookie($session_name, session_id(), array(
            'expires' => time() + $session_expire,
            'path' => '/',
            'domain' => null,
            'secure' => null,
            'httponly' => true,
            'samesite' => 'Lax'
        ));
    }

    $uid = $_SESSION['uid'];
?>
<?php require_once("securefunc.php"); ?>
<?php
    // connect db
    $dbhost = getenv('DB_SERVER_HOST');
    $dbport = getenv('DB_SERVER_PORT');
    $dbuser = getenv('DB_SERVER_USER');
    $dbpass = getenv('DB_SERVER_PASSWORD');
    $dbname = getenv('DB_SERVER_DB');

    error_reporting(E_ERROR | E_PARSE); // disable error and warning message
    $link = mysqli_connect($dbhost, $dbuser, $dbpass, $dbname, $dbport);
    if($link == FALSE)
    {
        // exit("ERROR: can't connect to mysql db. " . mysqli_connect_error());
        http_response_code(500);
        exit("ERROR: Can't connect to database");
    }
?>
<?php
    // handle request
    if(isset($uid))
    {
        $sql = "SELECT * FROM users WHERE uid=$uid;";
        $result = mysqli_query($link, $sql);
        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
        if(count($rows) != 1)
        {
            // invalid uid
            session_unset();
            header("Location: index.php?page=home");
            die();
        }
    }

    // GET
    $pages = array("home", "management", "login", "logout", "signup", "account", "singlemessage");
    $page = $_GET['page'];
    // POST
    $funcs = array("createmessage", "signup", "updatetitle", "updateaccount", "deletemessage", "login");
    $func = $_POST['func'];
    if(!isset($page) && !isset($func))
    {
        // no any param
        $page = "home";
    }
    elseif(isset($page))
    {
        // GET request
        if(!in_array($page, $pages))
        {
            // not in whitelist
            header("Location: index.php?page=home");
            die();
        }
        
        switch($page)
        {
            case "management":
                $pass = false;
                if(isset($uid))
                {
                    $sql = "SELECT isadmin FROM users WHERE uid=$uid;";
                    $result = mysqli_query($link, $sql);
                    $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                    if(count($rows) == 1)
                    {
                        if($rows[0]["isadmin"] == true)
                        {
                            $pass = true;
                        }
                    }
                }
                if($pass != true)
                {
                    print("<script> 
                        alert(\"權限不足！\\n使用者非管理員身分\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                break;
            case "login":
                if(isset($uid))
                {
                    print("<script> 
                        alert(\"登入失敗！\\n使用者已登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                break;
            case "logout":
                if(!isset($uid))
                {
                    print("<script> 
                        alert(\"登出失敗！\\n使用者未登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    session_unset();
                    print("<script> 
                        alert(\"登出成功！\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                break;
            case "signup":
                if(isset($uid))
                {
                    print("<script> 
                        alert(\"請登出後再使用註冊功能\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                break;
            case "account":
                if(!isset($uid))
                {
                    print("<script> 
                        alert(\"使用者未登入！\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                break;
            case "singlemessage":
                $mid = $_GET["mid"];
                $pass = false;
                if(isset($mid))
                {
                    if(is_string($mid) && !empty($mid))
                    {
                        $mid_is_int = checkIsIntStr($mid);
                        if($mid_is_int)
                        {
                            $sql = "SELECT isdelete FROM message WHERE mid=$mid;";
                            $result = mysqli_query($link, $sql);
                            $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                            if(count($rows) == 1)
                            {
                                if($rows[0]["isdelete"] == false)
                                {
                                    $pass = true;
                                }
                            }
                        }
                    }
                }
                if($pass != true)
                {
                    print("<script> 
                        alert(\"參數錯誤！\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                break;
        }
    }
    elseif(isset($func))
    {
        // POST request
        if(!in_array($func, $funcs))
        {
            // not in whitelist
            header("Location: index.php?page=home");
            die();
        }
        
        switch($func)
        {
            case "createmessage":
                if(!isset($uid))
                {
                    print("<script> 
                        alert(\"留言失敗！\\n使用者未登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                elseif(!isset($_POST['csrf']) || ($_POST['csrf'] != $_SESSION['csrf']))
                {
                    print("<script> 
                        alert(\"更新失敗！\\nCSRF錯誤\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    $message = $_POST['message'];
                    $attachment = $_FILES['attachment'];
                    if((!isset($message) || empty($message)) && (!isset($attachment) || $attachment['error'] == UPLOAD_ERR_NO_FILE))
                    {
                        print("<script> 
                            alert(\"留言失敗！\\n無留言內容\");
                            history.back();
                            </script>");
                        die();
                    }
                    elseif(isset($message) && strlen($message) > 900)
                    {
                        print("<script> 
                            alert(\"留言失敗！\\n留言過長\");
                            history.back();
                            </script>");
                        die();
                    }
                    else
                    {
                        $filename = "";
                        if(isset($attachment) && $attachment['error'] != UPLOAD_ERR_NO_FILE)
                        {
                            if($attachment['error'] == UPLOAD_ERR_INI_SIZE || 
                                $attachment['error'] == UPLOAD_ERR_FORM_SIZE || 
                                $attachment['error'] == UPLOAD_ERR_PARTIAL ||
                                ($attachment['error'] == UPLOAD_ERR_OK && ($attachment['size'] / 1024 / 1024) > $max_filesize))
                            {
                                print("<script> 
                                    alert(\"留言失敗！\\n檔案超過大小限制\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            elseif($attachment['error'] != UPLOAD_ERR_OK)
                            {
                                print("<script> 
                                    alert(\"留言失敗！\\n檔案發生未知錯誤\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                $sql = "SELECT MAX(mid)+1 AS next_mid FROM message;";
                                $result = mysqli_query($link, $sql);
                                $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                                if(count($rows) != 1)
                                {
                                    print("<script> 
                                        alert(\"留言失敗！\\n系統發生錯誤\");
                                        history.back();
                                        </script>");
                                    die();
                                }
                                else
                                {
                                    $next_mid = $rows[0]["next_mid"];
                                    if(is_null($next_mid))
                                    {
                                        $next_mid = 1;
                                    }
                                    $original_filename = prepareFile($attachment['name'], $next_mid);
                                    move_uploaded_file($attachment['tmp_name'], "attachments/" . $original_filename);
                                    $filename = $original_filename;
                                }
                            }
                        }
                        
                        if($filename == "")
                        {
                            $stmt = mysqli_prepare($link, "INSERT INTO message(uid, message) VALUES (?, ?)");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "is", $uid, $message);
                        }
                        else
                        {
                            $stmt = mysqli_prepare($link, "INSERT INTO message(uid, message, attachment) VALUES (?, ?, ?)");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "iss", $uid, $message, $original_filename);
                        }

                        $pass = false;
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $pass = true;
                            }
                        }
                        if($pass != true)
                        {
                            print("<script> 
                                alert(\"留言失敗！\\n可能含有非法參數或檔案\");
                                history.back();
                                </script>");
                            die();
                        }
                        else
                        {
                            print("<script> 
                                alert(\"留言成功！\");
                                window.location.href=\"index.php?page=home\";
                                </script>");
                            die();
                        }
                    }
                }
                break;
            case "signup":
                if(isset($uid))
                {
                    print("<script> 
                        alert(\"註冊失敗！\\n使用者已登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    $username = $_POST['username'];
                    $password = $_POST['password'];
                    $profile_url = $_POST['profile_url'];
                    $profile_file = $_FILES['profile_file'];
                    if(!isset($username) || empty($username) || !isset($password) || empty($password))
                    {
                        print("<script> 
                            alert(\"註冊失敗！\\n參數錯誤\");
                            history.back();
                            </script>");
                        die();
                    }
                    elseif(strlen($username) > 50 || strlen($password) > 50 || (isset($profile_url) && strlen($profile_url) > 300))
                    {
                        print("<script> 
                            alert(\"註冊失敗！\\n參數過長\");
                            history.back();
                            </script>");
                        die();
                    }
                    else
                    {
                        $userexist = false;
                        $stmt = mysqli_prepare($link, "SELECT uid FROM users WHERE username=?");
                        $bindsuccess = mysqli_stmt_bind_param($stmt, "s", $username);
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $result = mysqli_stmt_get_result($stmt);
                                if($result != false)
                                {
                                    $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                                    if(count($rows) == 1)
                                    {
                                        $userexist = true;
                                    }
                                }
                            }
                        }
                        if($userexist)
                        {
                            print("<script> 
                                alert(\"註冊失敗！\\n使用者已存在\");
                                history.back();
                                </script>");
                            die();
                        }

                        $filename = "";
                        if(isset($profile_file) && $profile_file['error'] != UPLOAD_ERR_NO_FILE)
                        {
                            if($profile_file['error'] == UPLOAD_ERR_INI_SIZE || 
                                    $profile_file['error'] == UPLOAD_ERR_FORM_SIZE || 
                                    $profile_file['error'] == UPLOAD_ERR_PARTIAL ||
                                    ($profile_file['error'] == UPLOAD_ERR_OK && ($profile_file['size'] / 1024 / 1024) > $max_filesize))
                            {
                                print("<script> 
                                    alert(\"註冊失敗！\\n檔案超過大小限制\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            elseif($profile_file['error'] != UPLOAD_ERR_OK)
                            {
                                print("<script> 
                                    alert(\"註冊失敗！\\n檔案發生未知錯誤\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            elseif(checkisimgfile($profile_file['name'], $profile_file['tmp_name'], $profile_file['type']) == false)
                            {
                                print("<script> 
                                    alert(\"註冊失敗！\\n檔案非圖片\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                $sql = "SELECT MAX(uid)+1 AS next_uid FROM users;";
                                $result = mysqli_query($link, $sql);
                                $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                                if(count($rows) != 1)
                                {
                                    print("<script> 
                                        alert(\"註冊失敗！\\n系統發生錯誤\");
                                        history.back();
                                        </script>");
                                    die();
                                }
                                else
                                {
                                    $next_uid = $rows[0]["next_uid"];
                                    if(is_null($next_uid))
                                    {
                                        $next_uid = 1;
                                    }
                                    $original_filename = prepareFile($profile_file['name'], $next_uid, true);
                                    move_uploaded_file($profile_file['tmp_name'], "profile_photo/" . $original_filename);
                                    $filename = $original_filename;
                                }
                            }
                        }
                        elseif(isset($profile_url) && !empty($profile_url))
                        {
                            $ch = curl_init();
                            curl_setopt($ch, CURLOPT_URL, $profile_url);
                            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                            curl_setopt($ch, CURLOPT_SSLVERSION, 1.1);
                            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                            $data = curl_exec($ch); // if file too large, will occur fatel error, handler is at line 17
                            $error = curl_error($ch);
                            curl_close($ch);

                            if($error == "")
                            {
                                $tmp_dir = ini_get('upload_tmp_dir');
                                $tmp_filename = md5(uniqid(mt_rand(), true)) . ".jpg";
                                $destination = $tmp_dir ."/" . $tmp_filename;
                                $file = fopen($destination, "w+");
                                fputs($file, $data);
                                fclose($file);
                            }
                            else
                            {
                                unset($data);
                            }
                            
                            exec(escapeshellcmd("ls " . escapeshellarg($destination)), $output, $ret);
                            unset($output);

                            if($ret != 0)
                            {
                                print("<script> 
                                    alert(\"註冊失敗！\\n檔案獲取失敗\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                $sql = "SELECT MAX(uid)+1 AS next_uid FROM users;";
                                $result = mysqli_query($link, $sql);
                                $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                                if(count($rows) != 1)
                                {
                                    print("<script> 
                                        alert(\"註冊失敗！\\n系統發生錯誤\");
                                        history.back();
                                        </script>");
                                    die();
                                }
                                else
                                {
                                    $next_uid = $rows[0]["next_uid"];
                                    if(is_null($next_uid))
                                    {
                                        $next_uid = 1;
                                    }
                                    $original_filename = prepareFile($tmp_filename, $next_uid, true);
                                    if(checkisimgfile($original_filename, "$tmp_dir/$tmp_filename") == false)
                                    {
                                        exec(escapeshellcmd("rm -f " . escapeshellarg($destination)), $output, $ret);
                                        unset($output);

                                        print("<script> 
                                            alert(\"註冊失敗！\\n檔案非圖片\");
                                            history.back();
                                            </script>");
                                        die();
                                    }
                                    else
                                    {
                                        exec(escapeshellcmd("mv " . escapeshellarg($destination) . " " . escapeshellarg("profile_photo/" . $original_filename)), $output, $ret);
                                        unset($output);

                                        if($ret != 0)
                                        {
                                            print("<script> 
                                                alert(\"註冊失敗！\\n系統發生錯誤\");
                                                history.back();
                                                </script>");
                                            die();
                                        }
                                        else
                                        {
                                            $filename = $original_filename;
                                        }
                                    }
                                }
                            }
                        }
                        
                        if($filename == "")
                        {
                            $stmt = mysqli_prepare($link, "INSERT INTO users (username, password) VALUES (?, sha2(?, 512));");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "ss", $username, $password);
                        }
                        else
                        {
                            $stmt = mysqli_prepare($link, "INSERT INTO users (username, password, profile) VALUES (?, sha2(?, 512), ?);");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "sss", $username, $password, $filename);
                        }
                        
                        $pass = false;
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $pass = true;
                            }
                        }
                        if($pass != true)
                        {
                            print("<script> 
                                alert(\"註冊失敗！\\n可能含有非法參數或檔案\");
                                history.back();
                                </script>");
                            die();
                        }
                        else
                        {
                            print("<script> 
                                alert(\"註冊成功！\\n請重新登入以使用系統\");
                                window.location.href=\"index.php?page=login\";
                                </script>");
                            die();
                        }
                    }
                }
                break;
            case "login":
                if(isset($uid))
                {
                    print("<script> 
                        alert(\"登入失敗！\\n使用者已登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    $username = $_POST['username'];
                    $password = $_POST['password'];
                    if(!isset($username) || empty($username) || !isset($password) || empty($password))
                    {
                        print("<script> 
                        alert(\"登入失敗！\\n參數錯誤\");
                        history.back();
                        </script>");
                        die();
                    }
                    elseif(strlen($username) > 50 || strlen($password) > 50)
                    {
                        print("<script> 
                        alert(\"登入失敗！\\n參數長度過長\");
                        history.back();
                        </script>");
                        die();
                    }
                    else
                    {
                        $pass = false;
                        $stmt = mysqli_prepare($link, "SELECT uid, password FROM users WHERE username=?");
                        $bindsuccess = mysqli_stmt_bind_param($stmt, "s", $username);
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $result = mysqli_stmt_get_result($stmt);
                                if($result != false)
                                {
                                    $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                                    if(count($rows) == 1)
                                    {
                                        $db_uid = $rows[0]["uid"];
                                        $db_password = $rows[0]["password"];
                                        $pass = true;
                                    }
                                }
                            }
                        }
                        if($pass != true)
                        {
                            print("<script> 
                                alert(\"登入失敗！\\n使用者帳號錯誤\");
                                history.back();
                                </script>");
                            die();
                        }
                        else
                        {
                            $hashed_password = hash("sha512", $password);
                            if($hashed_password != $db_password)
                            {
                                print("<script> 
                                    alert(\"登入失敗！\\n使用者密碼錯誤\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                $_SESSION['uid'] = $db_uid;
                                print("<script> 
                                    alert(\"登入成功！\");
                                    window.location.href=\"index.php?page=home\";
                                    </script>");
                                die();
                            }
                        }
                    }
                }
                break;
            case "updatetitle":
                $pass = false;
                if(isset($uid))
                {
                    $sql = "SELECT isadmin FROM users WHERE uid=$uid;";
                    $result = mysqli_query($link, $sql);
                    $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                    if(count($rows) == 1)
                    {
                        if($rows[0]["isadmin"] == true)
                        {
                            $pass = true;
                        }
                    }
                }

                if($pass != true)
                {
                    print("<script> 
                        alert(\"更新失敗！\\n權限不足\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                elseif(!isset($_POST['csrf']) || ($_POST['csrf'] != $_SESSION['csrf']))
                {
                    print("<script> 
                        alert(\"更新失敗！\\nCSRF錯誤\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    $updatetitle = $_POST['title'];
                    if(!isset($updatetitle) || empty($updatetitle))
                    {
                        print("<script> 
                            alert(\"更新失敗！\\n參數錯誤\");
                            history.back();
                            </script>");
                        die();
                    }
                    elseif(strlen($updatetitle) > 80)
                    {
                        print("<script> 
                            alert(\"更新失敗！\\n參數長度過長\");
                            history.back();
                            </script>");
                        die();
                    }
                    else
                    {
                        $pass = false;
                        $stmt = mysqli_prepare($link, "UPDATE title SET text=? WHERE id=1");
                        $bindsuccess = mysqli_stmt_bind_param($stmt, "s", $updatetitle);
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $pass = true;
                            }
                        }
                        if($pass != true)
                        {
                            print("<script> 
                                alert(\"更新失敗！\\n參數錯誤\");
                                history.back();
                                </script>");
                            die();
                        }
                        else
                        {
                            print("<script> 
                                alert(\"更新成功！\");
                                window.location.href=\"index.php?page=management\";
                                </script>");
                            die();
                        }
                    }
                }
                break;
            case "updateaccount":
                if(!isset($uid))
                {
                    print("<script> 
                        alert(\"更新失敗！\\n使用者未登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                elseif(!isset($_POST['csrf']) || ($_POST['csrf'] != $_SESSION['csrf']))
                {
                    print("<script> 
                        alert(\"更新失敗！\\nCSRF錯誤\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    $username = $_POST['username'];
                    $profile_url = $_POST['profile_url'];
                    $profile_file = $_FILES['profile_file'];
                    if((!isset($username) || empty($username)) && (!isset($profile_url) || empty($profile_url)) && (!isset($profile_url) || $profile_url['error'] == UPLOAD_ERR_NO_FILE))
                    {
                        print("<script> 
                        alert(\"更新失敗111！\\n無更新內容\");
                        history.back();
                        </script>");
                        die();
                    }
                    elseif((isset($username) && strlen($username) > 50) || (isset($profile_url) && strlen($profile_url) > 300))
                    {
                        print("<script> 
                        alert(\"更新失敗！\\n參數過長\");
                        history.back();
                        </script>");
                        die();
                    }
                    else
                    {
                        $userexist = false;
                        $stmt = mysqli_prepare($link, "SELECT uid FROM users WHERE username=?");
                        $bindsuccess = mysqli_stmt_bind_param($stmt, "s", $username);
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $result = mysqli_stmt_get_result($stmt);
                                if($result != false)
                                {
                                    $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                                    if(count($rows) == 1)
                                    {
                                        if($rows[0]["uid"] != $uid)
                                        {
                                            $userexist = true;
                                        }
                                    }
                                }
                            }
                        }
                        if($userexist)
                        {
                            print("<script> 
                                alert(\"更新失敗！\\n已有相同名稱使用者\");
                                history.back();
                                </script>");
                            die();
                        }

                        $filename = "";
                        if(isset($profile_file) && $profile_file['error'] != UPLOAD_ERR_NO_FILE)
                        {
                            if($profile_file['error'] == UPLOAD_ERR_INI_SIZE || 
                                    $profile_file['error'] == UPLOAD_ERR_FORM_SIZE || 
                                    $profile_file['error'] == UPLOAD_ERR_PARTIAL ||
                                    ($profile_file['error'] == UPLOAD_ERR_OK && ($profile_file['size'] / 1024 / 1024) > $max_filesize))
                            {
                                print("<script> 
                                    alert(\"更新失敗！\\n檔案超過大小限制\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            elseif($profile_file['error'] != UPLOAD_ERR_OK)
                            {
                                print("<script> 
                                    alert(\"更新失敗！\\n檔案發生未知錯誤\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            elseif(checkisimgfile($profile_file['name'], $profile_file['tmp_name'], $profile_file['type']) == false)
                            {
                                print("<script> 
                                    alert(\"更新失敗！\\n檔案非圖片\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                $original_filename = prepareFile($profile_file['name'], $uid, true);
                                move_uploaded_file($profile_file['tmp_name'], "profile_photo/" . $original_filename);
                                $filename = $original_filename;
                            }
                        }
                        elseif(isset($profile_url) && !empty($profile_url))
                        {
                            $ch = curl_init();
                            curl_setopt($ch, CURLOPT_URL, $profile_url);
                            curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
                            curl_setopt($ch, CURLOPT_SSLVERSION, 1.1);
                            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                            $data = curl_exec($ch); // if file too large, will occur fatel error, handler is at line 17
                            $error = curl_error($ch);
                            curl_close($ch);

                            if($error == "")
                            {
                                $tmp_dir = ini_get('upload_tmp_dir');
                                $tmp_filename = md5(uniqid(mt_rand(), true)) . ".jpg";
                                $destination = $tmp_dir ."/" . $tmp_filename;
                                $file = fopen($destination, "w+");
                                fputs($file, $data);
                                fclose($file);
                            }
                            else
                            {
                                unset($data);
                            }
                            
                            exec(escapeshellcmd("ls " . escapeshellarg($destination)), $output, $ret);
                            unset($output);

                            if($ret != 0)
                            {
                                print("<script> 
                                    alert(\"更新失敗！\\n檔案獲取失敗\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                $original_filename = prepareFile($tmp_filename, $uid, true);
                                if(checkisimgfile($original_filename, "$tmp_dir/$tmp_filename") == false)
                                {
                                    exec(escapeshellcmd("rm -f " . escapeshellarg($destination)), $output, $ret);
                                    unset($output);

                                    print("<script> 
                                        alert(\"更新失敗！\\n檔案非圖片\");
                                        history.back();
                                        </script>");
                                    die();
                                }
                                else
                                {
                                    exec(escapeshellcmd("mv " . escapeshellarg($destination) . " " . escapeshellarg("profile_photo/" . $original_filename)), $output, $ret);
                                    unset($output);

                                    if($ret != 0)
                                    {
                                        print("<script> 
                                            alert(\"更新失敗！\\n系統發生錯誤\");
                                            history.back();
                                            </script>");
                                        die();
                                    }
                                    else
                                    {
                                        $filename = $original_filename;
                                    }
                                }
                            }
                        }

                        if($filename != "")
                        {
                            $sql = "SELECT profile FROM users WHERE uid=$uid;";
                            $result = mysqli_query($link, $sql);
                            $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                            if(count($rows) != 1 || is_null($rows[0]["profile"]))
                            {
                                $old_filename = "";
                            }
                            else
                            {
                                $old_filename = $rows[0]["profile"];
                            }
                        }

                        if(isset($username) && !empty($username) && $filename == "")
                        {
                            $stmt = mysqli_prepare($link, "UPDATE users SET username=? WHERE uid=$uid;");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "s", $username);
                        }
                        elseif(isset($username) && !empty($username) && $filename != "")
                        {
                            $stmt = mysqli_prepare($link, "UPDATE users SET username=?, profile=? WHERE uid=$uid;");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "ss", $username, $filename);
                        }
                        elseif($filename != "")
                        {
                            $stmt = mysqli_prepare($link, "UPDATE users SET profile=? WHERE uid=$uid;");
                            $bindsuccess = mysqli_stmt_bind_param($stmt, "s", $filename);
                        }
                        else
                        {
                            print("<script> 
                                alert(\"更新失敗！\\n無更新內容\");
                                history.back();
                                </script>");
                            die();
                        }
                        
                        $pass = false;
                        if($bindsuccess)
                        {
                            $executesuccess = mysqli_stmt_execute($stmt);
                            if($executesuccess)
                            {
                                $pass = true;
                            }
                        }
                        if($pass != true)
                        {
                            print("<script> 
                                alert(\"更新失敗！\\n可能含有非法參數或檔案\");
                                history.back();
                                </script>");
                            die();
                        }
                        else
                        {
                            print("<script> 
                                alert(\"更新成功！\");
                                window.location.href=\"index.php?page=account\";
                                </script>");

                            if($filename != "")
                            {
                                exec(escapeshellcmd("rm -f " . escapeshellarg("profile_photo/".$old_filename)), $output, $ret);
                                unset($output);
                            }

                            die();
                        }
                    }
                }
                break;
            case "deletemessage":
                if(!isset($uid))
                {
                    print("<script> 
                        alert(\"刪除失敗！\\n使用者未登入\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                elseif(!isset($_POST['csrf']) || ($_POST['csrf'] != $_SESSION['csrf']))
                {
                    print("<script> 
                        alert(\"更新失敗！\\nCSRF錯誤\");
                        window.location.href=\"index.php?page=home\";
                        </script>");
                    die();
                }
                else
                {
                    $mid = $_POST['mid'];
                    if(!isset($mid) || !is_string($mid) || empty($mid))
                    {
                        print("<script> 
                            alert(\"刪除失敗！\\n參數錯誤\");
                            history.back();
                            </script>");
                        die();
                    }
                    elseif(checkIsIntStr($mid) == false)
                    {
                        print("<script> 
                            alert(\"刪除失敗！\\n參數錯誤\");
                            history.back();
                            </script>");
                        die();
                    }
                    else
                    {
                        $sql = "SELECT mid, isdelete FROM message WHERE uid=$uid and mid=$mid;";
                        $result = mysqli_query($link, $sql);
                        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);

                        if(count($rows) != 1)
                        {
                            print("<script> 
                                alert(\"刪除失敗！\\n權限錯誤\");
                                history.back();
                                </script>");
                            die();
                        }
                        elseif($rows[0]["isdelete"] == true)
                        {
                            print("<script> 
                                alert(\"刪除失敗！\\n無法刪除已刪除的留言\");
                                history.back();
                                </script>");
                            die();
                        }
                        else
                        {
                            $sql = "UPDATE message SET isdelete=true WHERE mid=$mid;";
                            $result = mysqli_query($link, $sql);
                            if($result == false)
                            {
                                print("<script> 
                                    alert(\"刪除失敗！\\n參數錯誤\");
                                    history.back();
                                    </script>");
                                die();
                            }
                            else
                            {
                                print("<script> 
                                    alert(\"刪除成功！\");
                                    window.location.href=\"index.php?page=home\";
                                    </script>");
                                die();
                            }
                        }
                    }
                }
                break;
        }
    }
    else
    {
        // GET + POST
        // WTF
        header("Location: index.php?page=home");
        die();
    }
?>
<?php
    // get title
    $sql = "SELECT text FROM title WHERE id=1;";
    $result = mysqli_query($link, $sql);
    $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
    if(count($rows) == 0)
    {
        $sql = "INSERT INTO title (id, text) VALUES (1, 'My Message Board System');";
        $result = mysqli_query($link, $sql);

        $sql = "SELECT text FROM title WHERE id=1;";
        $result = mysqli_query($link, $sql);
        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
    }
    $title = $rows[0][0];
    $title = preventXSS($title);
?>
<?php
    // generate csrf token
    if(isset($uid))
    {
        $csrf_token = md5(uniqid(mt_rand(), true));
        $_SESSION['csrf'] = $csrf_token;
    }
?>
<!DOCTYPE html>
<html lang="zh-tw">
    <head>
        <meta charset="utf-8">
        <title> <?php print($title); ?> </title>
        <link href="styles/style.css" rel="stylesheet">
        <?php
            switch($page)
            {
                case "home":
                    print("<link href=\"styles/messageBoard.css\" rel=\"stylesheet\">\r\n");
                    break;
                case 'management':
                    print("<link href=\"styles/management.css\" rel=\"stylesheet\">\r\n");
                    break;
                case 'login':
                    print("<link href=\"styles/login.css\" rel=\"stylesheet\">\r\n");
                    break;
                case 'signup':
                    print("<link href=\"styles/signup.css\" rel=\"stylesheet\">\r\n");
                    break;
                case 'account':
                    print("<link href=\"styles/account.css\" rel=\"stylesheet\">\r\n");
                    break;
                case 'singlemessage':
                    print("<link href=\"styles/singleMessage.css\" rel=\"stylesheet\">\r\n");
                    break;
                default:
                    print("\r\n");
                    break;
            }
        ?>
    </head>
    <body>
        <header>
            <a href="?page=home">
                <div>
                    <p> <?php print($title); ?> </p>
                </div>
            </a>
        </header>
        <nav>
            <div class="main">
                <div class="empty"> <!-- empty --> </div>
                <?php
                    if(isset($uid))
                    {
                        $sql = "SELECT isadmin FROM users WHERE uid=$uid;";
                        $result = mysqli_query($link, $sql);
                        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                        if(count($rows) == 1 && $rows[0]["isadmin"])
                        {
                            print("<a href=\"?page=management\">\r\n");
                            print("\t\t\t\t\t<div class=\"clickable\">\r\n");
                            print("\t\t\t\t\t\t<p> 管理 </p>\r\n");
                            print("\t\t\t\t\t</div>\r\n");
                            print("\t\t\t\t</a>\r\n");
                        }
                        else
                        {
                            print("\r\n");
                        }
                    }
                    else
                    {
                        print("\r\n");
                    }
                ?>
            </div>
            <div class="account">
                <div class="empty"> <!-- empty --> </div>
                <?php
                    if(!isset($uid))
                    {
                        print("<a href=\"?page=login\">\r\n");
                        print("\t\t\t\t\t<div class=\"clickable\">\r\n");
                        print("\t\t\t\t\t\t<p> 登入 </p>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t</a>\r\n");

                        print("\t\t\t\t<a href=\"?page=signup\">\r\n");
                        print("\t\t\t\t\t<div class=\"clickable\">\r\n");
                        print("\t\t\t\t\t\t<p> 註冊 </p>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t</a>\r\n");
                    }
                    else
                    {
                        $sql = "SELECT username, profile FROM users WHERE uid=$uid;";
                        $result = mysqli_query($link, $sql);
                        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                        $username = $rows[0]["username"];
                        $profile_image = $rows[0]["profile"];
                        if(strlen($username) > 30)
                        {
                            $username = substr($username, 0, 27) . '...';
                        }

                        print("<a href=\"?page=logout\">\r\n");
                        print("\t\t\t\t\t<div class=\"clickable\">\r\n");
                        print("\t\t\t\t\t\t<p> 登出 </p>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t</a>\r\n");

                        print("\t\t\t\t<a href=\"?page=account\">\r\n");
                        print("\t\t\t\t\t<div class=\"user clickable\">\r\n");
                        print("\t\t\t\t\t\t<img src=\"" . verifyProfile("profile_photo", $profile_image) . "\">\r\n");
                        print("\t\t\t\t\t\t<p> " . preventXSS($username) . " </p>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t</a>\r\n");
                    }
                ?>
            </div>
        </nav>
        <main>
            <?php
                switch($page)
                {
                    case "home":
                        $sql = "SELECT mid, m.uid, message, isdelete, attachment, profile, username
                            FROM message AS m INNER JOIN users AS u ON m.uid=u.uid ORDER BY mid;";
                        $result = mysqli_query($link, $sql);
                        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                        
                        print("<div class=\"messageContainer\">\r\n");
                        foreach($rows as $row)
                        {
                            $mid = $row['mid'];
                            if($row['isdelete'] == true)
                            {
                                print("\t\t\t\t<div id=\"$mid\" class=\"deleted\">\r\n");
                                print("\t\t\t\t\t<a href=\"#\">\r\n");
                                print("\t\t\t\t\t\t<div class=\"user\">\r\n");
                                print("\t\t\t\t\t\t\t<img src=\"profile_photo/default.svg\" />\r\n");
                                print("\t\t\t\t\t\t\t<p> 此訊息已刪除 </p>\r\n");
                                print("\t\t\t\t\t\t\t<p class=\"sequence\"> #$mid </p>\r\n");
                                print("\t\t\t\t\t\t</div>\r\n");
                                print("\t\t\t\t\t\t<div class=\"content\">\r\n");
                                print("\t\t\t\t\t\t\t<p> 此訊息已被使用者刪除 </p>\r\n");
                                print("\t\t\t\t\t\t</div>\r\n");
                                print("\t\t\t\t\t</a>\r\n");
                                print("\t\t\t\t</div>\r\n");
                            }
                            else
                            {
                                print("\t\t\t\t<div id=\"$mid\">\r\n");
                                print("\t\t\t\t\t<a href=\"?page=singlemessage&mid=$mid\">\r\n");
                                print("\t\t\t\t\t\t<div class=\"user\">\r\n");
                                print("\t\t\t\t\t\t\t<img src=\"" . verifyProfile("profile_photo", $row['profile']) . "\" />\r\n");
                                print("\t\t\t\t\t\t\t<p> " . preventXSS($row['username']) . " </p>\r\n");
                                print("\t\t\t\t\t\t\t<p class=\"sequence\"> #$mid </p>\r\n");
                                if(isset($uid) && $uid == $row['uid'])
                                {
                                    print("\t\t\t\t\t\t\t<form action=\"/index.php\" method=\"post\">\r\n");
                                    print("\t\t\t\t\t\t\t\t<input type=\"hidden\" name=\"csrf\" value=\"$csrf_token\">\r\n");
                                    print("\t\t\t\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"deletemessage\">\r\n");
                                    print("\t\t\t\t\t\t\t\t<input type=\"hidden\" name=\"mid\" value=\"$mid\">\r\n");
                                    print("\t\t\t\t\t\t\t\t<input type=\"image\" src=\"assets/trashcan.svg\" class=\"delete\">\r\n");
                                    print("\t\t\t\t\t\t\t</form>\r\n");
                                }
                                print("\t\t\t\t\t\t</div>\r\n");
                                print("\t\t\t\t\t\t<div class=\"content\">\r\n");
                                print("\t\t\t\t\t\t\t<p> " . BBCodeGen(preventXSS($row['message'])) . " </p>\r\n");
                                print("\t\t\t\t\t\t</div>\r\n");
                                print("\t\t\t\t\t</a>\r\n");
                                if(!is_null($row['attachment']))
                                {
                                    $attach = $row['attachment'];
                                    print("\t\t\t\t\t<div class=\"download\">\r\n");
                                    print("\t\t\t\t\t\t<a href=\"attachments/" . verifyAttachment($attach) . "\" download=\"" . recoveryAttachment($attach) . "\">\r\n");
                                    print("\t\t\t\t\t\t\t<img src=\"assets/paperclip.svg\">\r\n");
                                    print("\t\t\t\t\t\t\t<p> " . preventXSS(recoveryAttachment($attach)) . " </p>\r\n");
                                    print("\t\t\t\t\t\t</a>\r\n");
                                    print("\t\t\t\t\t</div>\r\n");
                                }
                                print("\t\t\t\t</div>\r\n");
                            }
                        }
                        print("\t\t\t</div>\r\n");
                        if(isset($uid))
                        {
                            print("\t\t\t<div class=\"sendMessage\">\r\n");
                            print("\t\t\t\t<form action=\"/index.php\" enctype=\"multipart/form-data\" method=\"post\">\r\n");
                            print("\t\t\t\t\t<input type=\"hidden\" name=\"csrf\" value=\"$csrf_token\">\r\n");
                            print("\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"createmessage\">\r\n");
                            print("\t\t\t\t\t<input type=\"text\" placeholder=\"請輸入留言（最長 900 字）\" class=\"message\" id=\"message\" name=\"message\" maxlength=\"900\">\r\n");
                            print("\t\t\t\t\t<input type=\"submit\" value=\"送出\" class=\"submit\">\r\n");
                            print("\t\t\t\t\t<label for=\"attachment\"> 上傳附件 (最大 $max_filesize MB)： </label>\r\n");
                            print("\t\t\t\t\t<input type=\"file\" class=\"file\" id=\"attachment\" name=\"attachment\">\r\n");
                            print("\t\t\t\t</form>\r\n");
                            print("\t\t\t</div>\r\n");
                        }
                        else
                        {
                            print("\t\t\t<div class=\"banner\">\r\n");
                            print("\t\t\t\t<div>\r\n");
                            print("\t\t\t\t\t<p> <a href=\"?page=login\"> 登入 </a> ／ <a href=\"?page=signup\"> 註冊 </a> 以啟用留言功能 </p>\r\n");
                            print("\t\t\t\t</div>\r\n");
                            print("\t\t\t</div>\r\n");
                        }
                        break;
                    case 'management':
                        print("<div class=\"management\">\r\n");
                        print("\t\t\t\t<p> Management </p>\r\n");
                        print("\t\t\t\t<form action=\"/index.php\" method=\"post\">\r\n");
                        if(isset($uid))
                        {
                            print("\t\t\t\t\t<input type=\"hidden\" name=\"csrf\" value=\"$csrf_token\">\r\n");
                        }
                        print("\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"updatetitle\">\r\n");
                        print("\t\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t\t<label for=\"title\"> 更改首頁標題： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"text\" id=\"title\" name=\"title\" placeholder=\"請輸入首頁標題（最長 80 字）\" value=\"$title\" maxlength=\"80\" required>\r\n");
                        print("\t\t\t\t\t\t<input type=\"submit\" value=\"送出\" class=\"submit\">\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t</form>\r\n");
                        print("\t\t\t</div>\r\n");
                        break;
                    case 'login':
                        print("<div class=\"login\">\r\n");
                        print("\t\t\t\t<p> Login </p>\r\n");
                        print("\t\t\t\t<form action=\"/index.php\" method=\"post\">\r\n");
                        print("\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"login\">\r\n");
                        print("\t\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t\t<label for=\"username\"> 帳號： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" maxlength=\"50\" required\r\n>");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t\t<label for=\"password\"> 密碼： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"current-password\" maxlength=\"50\" required>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<input type=\"submit\" value=\"送出\" class=\"submit\">\r\n");
                        print("\t\t\t\t</form>\r\n");
                        print("\t\t\t</div>\r\n");
                        break;
                    case 'signup':
                        print("<div class=\"signup\">\r\n");
                        print("\t\t\t\t<p> SignUp </p>\r\n");
                        print("\t\t\t\t<form action=\"/index.php\" enctype=\"multipart/form-data\" method=\"post\">\r\n");
                        print("\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"signup\">\r\n");
                        print("\t\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t\t<label for=\"username\"> 帳號： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"text\" id=\"username\" name=\"username\" autocomplete=\"username\" placeholder=\"請輸入帳號名稱（最長 50 字）\" maxlength=\"50\" required>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t\t<label for=\"password\"> 密碼： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"password\" id=\"password\" name=\"password\" autocomplete=\"new-password\" placeholder=\"請輸入密碼（最長 50 字）\" maxlength=\"50\" required>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<div class=\"fileUpload\">\r\n");
                        print("\t\t\t\t\t\t<label for=\"profile_file\"> 上傳大頭貼 (Optional，最大 $max_filesize MB) ： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"file\" id=\"profile_file\" name=\"profile_file\" accept=\"image/*\">\r\n");
                        print("\t\t\t\t\t\t<label for=\"profile_url\" class=\"or\"> Or </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"url\" placeholder=\"請輸入圖片網址（最長 300 字，請勿使用 reurl 等短網址服務）\" maxlength=\"300\" id=\"profile_url\" name=\"profile_url\">\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<input type=\"submit\" value=\"送出\" class=\"submit\">\r\n");
                        print("\t\t\t\t</form>\r\n");
                        print("\t\t\t</div>\r\n");
                        break;
                    case 'account':
                        $sql = "SELECT username, profile FROM users WHERE uid=$uid;";
                        $result = mysqli_query($link, $sql);
                        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                        $username = $rows[0]["username"];
                        $profile_image = $rows[0]["profile"];

                        print("<div class=\"account\">\r\n");
                        print("\t\t\t\t<p> Account </p>\r\n");
                        print("\t\t\t\t<div class=\"photo\">\r\n");
                        print("\t\t\t\t\t<img src=\"" . verifyProfile("profile_photo", $profile_image) . "\">\r\n");
                        print("\t\t\t\t</div>\r\n");
                        print("\t\t\t\t<form action=\"/index.php\" enctype=\"multipart/form-data\" method=\"post\">\r\n");
                        if(isset($uid))
                        {
                            print("\t\t\t\t\t<input type=\"hidden\" name=\"csrf\" value=\"$csrf_token\">\r\n");
                        }
                        print("\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"updateaccount\">\r\n");
                        print("\t\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t\t<label for=\"username\"> 變更帳號名稱： </label>\r\n");
                        print("\t\t\t\t\t\t<input type=\"text\" id=\"username\" name=\"username\" placeholder=\"請輸入新帳號名稱（最長 50 字）\" value=\"" . preventXSS($username) . "\" maxlength=\"50\">\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<div class=\"fileUpload\">\r\n");
                        print("\t\t\t\t\t\t<label for=\"profile_image\"> 更換大頭貼 (最大 $max_filesize MB)： </label>\r\n");
                        print("\t\t\t\t\t\t<div id=\"profile_image\">\r\n");
                        print("\t\t\t\t\t\t\t<input type=\"file\" id=\"profile_file\" name=\"profile_file\" accept=\"image/*\">\r\n");
                        print("\t\t\t\t\t\t\t<label for=\"profile_url\" class=\"or\"> Or </label>\r\n");
                        print("\t\t\t\t\t\t\t<input type=\"url\" placeholder=\"請輸入圖片網址（最長 300 字，請勿使用 reurl 等短網址服務）\" maxlength=\"100\" id=\"profile_url\" name=\"profile_url\">\r\n");
                        print("\t\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<input type=\"submit\" value=\"送出\" class=\"submit\">\r\n");
                        print("\t\t\t\t</form>\r\n");
                        print("\t\t\t</div>\r\n");
                        break;
                    case 'singlemessage':
                        $mid = $_GET["mid"];

                        $sql = "SELECT m.uid, message, attachment, profile, username
                            FROM message AS m INNER JOIN users AS u ON m.uid=u.uid WHERE mid=$mid;";
                        $result = mysqli_query($link, $sql);
                        $rows = mysqli_fetch_all($result, MYSQLI_BOTH);
                        $row = $rows[0];
                        
                        print("<div class=\"singleMessageContainer\">\r\n");
                        print("\t\t\t\t<div>\r\n");
                        print("\t\t\t\t\t<div class=\"user\">\r\n");
                        print("\t\t\t\t\t\t<img src=\"" . verifyProfile("profile_photo", $row['profile']) . "\" />\r\n");
                        print("\t\t\t\t\t\t<p> " . preventXSS($row['username']) . " </p>\r\n");
                        print("\t\t\t\t\t\t<p class=\"sequence\"> #$mid </p>\r\n");
                        if(isset($uid) && $uid == $row['uid'])
                        {
                            print("\t\t\t\t\t\t<form action=\"/index.php\" method=\"post\">\r\n");
                            print("\t\t\t\t\t\t\t<input type=\"hidden\" name=\"csrf\" value=\"$csrf_token\">\r\n");
                            print("\t\t\t\t\t\t\t<input type=\"hidden\" name=\"func\" value=\"deletemessage\">\r\n");
                            print("\t\t\t\t\t\t\t<input type=\"hidden\" name=\"mid\" value=\"$mid\">\r\n");
                            print("\t\t\t\t\t\t\t<input type=\"image\" src=\"assets/trashcan.svg\" class=\"delete\">\r\n");
                            print("\t\t\t\t\t\t</form>\r\n");
                        }
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t\t<div class=\"content\">\r\n");
                        print("\t\t\t\t\t\t<p> " . BBCodeGen(preventXSS($row['message'])) . " </p>\r\n");
                        if(!is_null($row['attachment']))
                        {
                            $attach = $row['attachment'];
                            print("\t\t\t\t\t\t<div class=\"download\">\r\n");
                            print("\t\t\t\t\t\t\t<a href=\"attachments/" . verifyAttachment($attach) . "\" download=\"" . recoveryAttachment($attach) . "\">\r\n");
                            print("\t\t\t\t\t\t\t\t<img src=\"assets/paperclip.svg\">\r\n");
                            print("\t\t\t\t\t\t\t\t<p> " . preventXSS(recoveryAttachment($attach)) . " </p>\r\n");
                            print("\t\t\t\t\t\t\t</a>\r\n");
                            print("\t\t\t\t\t\t</div>\r\n");
                        }
                        print("\t\t\t\t\t</div>\r\n");
                        print("\t\t\t\t</div>\r\n");
                        print("\t\t\t</div>\r\n");
                        break;
                    default:
                        print("\r\n");
                        break;
                }
            ?>
        </main>
        <footer>
            <div>
                <p> Author: ywChen-NTUST (ntust B10715029). MIT License </p>
            </div>
        </footer>
    </body>
</html>

<?php
    mysqli_close($link);
?>