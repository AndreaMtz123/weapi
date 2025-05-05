<?php 
// MEJORA: Validación robusta del archivo de configuración
function loadDatabaseSettings($pathjs){
    if(!file_exists($pathjs)) {
        throw new Exception('Config file not found');
    }
    $string = file_get_contents($pathjs);
    if($string === false) {
        throw new Exception('Failed to read config file');
    }
    $json_a = json_decode($string, true);
    if(json_last_error() !== JSON_ERROR_NONE) {
        throw new Exception('Invalid JSON config');
    }
    return $json_a;
}

// MEJORA: Generación segura de tokens con random_bytes() y hash sha256
function getToken(){
    $fecha = date_create();
    $tiempo = date_timestamp_get($fecha);
    $randomBytes = random_bytes(16);
    $token = bin2hex($randomBytes).$tiempo;
    return hash('sha256', $token);
}

require 'vendor/autoload.php';
$f3 = \Base::instance();

$f3->route('GET /',
    function() {
        echo 'Hello, world!';
    }
);

// MEJORA: Protección contra XSS con htmlspecialchars()
$f3->route('GET /saludo/@nombre',
    function($f3) {
        echo 'Hola '.htmlspecialchars($f3->get('PARAMS.nombre'), ENT_QUOTES, 'UTF-8');
    }
);

$f3->route('POST /Registro',
    function($f3) {
        try {
            $dbcnf = loadDatabaseSettings('db.json');
            $db=new DB\SQL(
                'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
                $dbcnf['user'],
                $dbcnf['password']
            );
            $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            
            $Cuerpo = $f3->get('BODY');
            $jsB = json_decode($Cuerpo,true);
            
            $R = array_key_exists('uname',$jsB) && array_key_exists('email',$jsB) && array_key_exists('password',$jsB);
            
            if (!$R){
                echo '{"R":-1}';
                return;
            }
            
            // MEJORA: Validación de formato de email
            if(!filter_var($jsB['email'], FILTER_VALIDATE_EMAIL)) {
                echo '{"R":-4}';
                return;
            }
            
            $stmt = $db->prepare('insert into Usuario values(null,?,?,?)');
            // MEJORA: Uso de password_hash() en lugar de md5()
            $hashedPassword = password_hash($jsB['password'], PASSWORD_BCRYPT);
            $R = $stmt->execute([$jsB['uname'], $jsB['email'], $hashedPassword]);
            
            echo '{"R":0,"D":'.json_encode(['id' => $db->lastInsertId()]).'}';
        } catch (Exception $e) {
            // MEJORA: Logging de errores sin exponer detalles al usuario
            error_log($e->getMessage());
            echo '{"R":-2}';
            return;
        }
    }
);

$f3->route('POST /Login',
    function($f3) {
        try {
            $dbcnf = loadDatabaseSettings('db.json');
            $db=new DB\SQL(
                'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
                $dbcnf['user'],
                $dbcnf['password']
            );
            $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            
            $Cuerpo = $f3->get('BODY');
            $jsB = json_decode($Cuerpo,true);
            
            $R = array_key_exists('uname',$jsB) && array_key_exists('password',$jsB);
            
            if (!$R){
                echo '{"R":-1}';
                return;
            }
            
            $stmt = $db->prepare('Select id, password from Usuario where uname = ?');
            $stmt->execute([$jsB['uname']]);
            $user = $stmt->fetch();
            
            // MEJORA: Verificación segura de contraseña con password_verify()
            if(!$user || !password_verify($jsB['password'], $user['password'])) {
                echo '{"R":-3}';
                return;
            }
            
            $T = getToken();
            // MEJORA: Consulta preparada para evitar SQL injection
            $db->exec('Delete from AccesoToken where id_Usuario = ?', $user['id']);
            $stmt = $db->prepare('insert into AccesoToken values(?,?,now())');
            $stmt->execute([$user['id'], $T]);
            
            echo '{"R":0,"D":"'.$T.'"}';
        } catch (Exception $e) {
            error_log($e->getMessage());
            echo '{"R":-2}';
            return;
        }
    }
);

$f3->route('POST /Imagen',
    function($f3) {
        try {
            // MEJORA: Permisos más restrictivos en directorios
            if (!file_exists('tmp')) {
                mkdir('tmp', 0755, true);
            }
            if (!file_exists('img')) {
                mkdir('img', 0755, true);
            }
            
            $Cuerpo = $f3->get('BODY');
            $jsB = json_decode($Cuerpo,true);
            
            $R = array_key_exists('name',$jsB) && array_key_exists('data',$jsB) && 
                 array_key_exists('ext',$jsB) && array_key_exists('token',$jsB);
            
            if (!$R){
                echo '{"R":-1}';
                return;
            }
            
            // MEJORA: Lista blanca de extensiones permitidas
            $allowedExtensions = ['jpg', 'jpeg', 'png', 'gif'];
            $ext = strtolower($jsB['ext']);
            if(!in_array($ext, $allowedExtensions)) {
                echo '{"R":-4}';
                return;
            }
            
            $dbcnf = loadDatabaseSettings('db.json');
            $db=new DB\SQL(
                'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
                $dbcnf['user'],
                $dbcnf['password']
            );
            $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            
            $TKN = $jsB['token'];
            
            $stmt = $db->prepare('select id_Usuario from AccesoToken where token = ?');
            $stmt->execute([$TKN]);
            $R = $stmt->fetchAll();
            
            if(empty($R)) {
                echo '{"R":-3}';
                return;
            }
            
            $id_Usuario = (int)$R[0]['id_Usuario'];
            $tmpPath = 'tmp/'.$id_Usuario.'.'.$ext;
            file_put_contents($tmpPath, base64_decode($jsB['data']));
            
            // MEJORA: Validación del tipo MIME real del archivo
            if(!getimagesize($tmpPath)) {
                unlink($tmpPath);
                echo '{"R":-5}';
                return;
            }
            
            $stmt = $db->prepare('insert into Imagen values(null,?,?,?)');
            $stmt->execute([$jsB['name'], 'img/', $id_Usuario]);
            
            // MEJORA: Consulta preparada para evitar SQL injection
            $R = $db->query('select max(id) as idImagen from Imagen where id_Usuario = ?', $id_Usuario);
            $idImagen = $R[0]['idImagen'];
            
            $newPath = 'img/'.$idImagen.'.'.$ext;
            $db->exec('update Imagen set ruta = ? where id = ?', [$newPath, $idImagen]);
            
            rename($tmpPath, $newPath);
            echo '{"R":0,"D":'.$idImagen.'}';
        } catch (Exception $e) {
            error_log($e->getMessage());
            echo '{"R":-2}';
            return;
        }
    }
);

$f3->route('POST /Descargar',
    function($f3) {
        try {
            $dbcnf = loadDatabaseSettings('db.json');
            $db=new DB\SQL(
                'mysql:host=localhost;port='.$dbcnf['port'].';dbname='.$dbcnf['dbname'],
                $dbcnf['user'],
                $dbcnf['password']
            );
            $db->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
            
            $Cuerpo = $f3->get('BODY');
            $jsB = json_decode($Cuerpo,true);
            
            $R = array_key_exists('token',$jsB) && array_key_exists('id',$jsB);
            
            if (!$R){
                echo '{"R":-1}';
                return;
            }
            
            $TKN = $jsB['token'];
            $idImagen = (int)$jsB['id'];
            
            // MEJORA: Verificación de permisos con JOIN en la consulta SQL
            $stmt = $db->prepare('Select I.name, I.ruta from Imagen I 
                                 JOIN AccesoToken A ON I.id_Usuario = A.id_Usuario 
                                 WHERE I.id = ? AND A.token = ?');
            $stmt->execute([$idImagen, $TKN]);
            $R = $stmt->fetchAll();
            
            if(empty($R)) {
                echo '{"R":-3}';
                return;
            }
            
            $web = \Web::instance();
            ob_start();
            $info = pathinfo($R[0]['ruta']);
            $web->send($R[0]['ruta'], NULL, 0, TRUE, $R[0]['name'].'.'.$info['extension']);
            ob_end_flush();
        } catch (Exception $e) {
            error_log($e->getMessage());
            echo '{"R":-2}';
            return;
        }
    }
);

$f3->run();
?>
