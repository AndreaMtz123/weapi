<?php 
function loadDatabaseSettings($pathjs){
    // VULNERABILIDAD: No verifica si el archivo existe o es legible
    $string = file_get_contents($pathjs);
    $json_a = json_decode($string, true);
    // VULNERABILIDAD: No valida si el JSON es válido
    return $json_a;
}

function getToken(){
    // VULNERABILIDAD: Uso de funciones criptográficas inseguras (sha1 y md5)
    // VULNERABILIDAD: mt_rand() no es criptográficamente seguro
    $fecha = date_create();
    $tiempo = date_timestamp_get($fecha);
    $numero = mt_rand();
    $cadena = ''.$numero.$tiempo;
    $numero2 = mt_rand();
    $cadena2 = ''.$numero.$tiempo.$numero2;
    $hash_sha1 = sha1($cadena);
    $hash_md5 = md5($cadena2);
    return substr($hash_sha1,0,20).$hash_md5.substr($hash_sha1,20);
}

require 'vendor/autoload.php';
$f3 = \Base::instance();

$f3->route('GET /',
    function() {
        echo 'Hello, world!';
    }
);

$f3->route('GET /saludo/@nombre',
    function($f3) {
        // VULNERABILIDAD: Falta sanitización de salida (XSS)
        echo 'Hola '.$f3->get('PARAMS.nombre');
    }
);

$f3->route('POST /Registro',
    function($f3) {
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
        
        try {
            // VULNERABILIDAD: Uso de md5 para contraseñas (debería ser password_hash)
            $stmt = $db->prepare('insert into Usuario values(null,?,?,md5(?))');
            $R = $stmt->execute([$jsB['uname'], $jsB['email'], $jsB['password']]);
        } catch (Exception $e) {
            // VULNERABILIDAD: Mensaje de error genérico pero no se registra el error real
            echo '{"R":-2}';
            return;
        }
        echo '{"R":0,"D":'.json_encode($R).'}';
    }
);

$f3->route('POST /Login',
    function($f3) {
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
        
        try {
            // VULNERABILIDAD: Uso de md5 para contraseñas
            $stmt = $db->prepare('Select id from Usuario where uname = ? and password = md5(?)');
            $stmt->execute([$jsB['uname'], $jsB['password']]);
            $R = $stmt->fetchAll();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }
        
        if (empty($R)){
            echo '{"R":-3}';
            return;
        }
        
        $T = getToken();
        // VULNERABILIDAD: Concatenación directa en consulta SQL (SQL Injection)
        $db->exec('Delete from AccesoToken where id_Usuario = '.$R[0]['id']);
        $stmt = $db->prepare('insert into AccesoToken values(?,?,now())');
        $stmt->execute([$R[0]['id'], $T]);
        echo '{"R":0,"D":"'.$T.'"}';
    }
);

$f3->route('POST /Imagen',
    function($f3) {
        // VULNERABILIDAD: Permisos de directorio demasiado abiertos (debería ser 0750)
        if (!file_exists('tmp')) {
            mkdir('tmp');
        }
        if (!file_exists('img')) {
            mkdir('img');
        }
        
        $Cuerpo = $f3->get('BODY');
        $jsB = json_decode($Cuerpo,true);
        
        $R = array_key_exists('name',$jsB) && array_key_exists('data',$jsB) && 
             array_key_exists('ext',$jsB) && array_key_exists('token',$jsB);
        
        if (!$R){
            echo '{"R":-1}';
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
        
        try {
            $stmt = $db->prepare('select id_Usuario from AccesoToken where token = ?');
            $stmt->execute([$TKN]);
            $R = $stmt->fetchAll();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }
        
        $id_Usuario = $R[0]['id_Usuario'];
        // VULNERABILIDAD: No se valida el tipo de archivo antes de guardar
        file_put_contents('tmp/'.$id_Usuario, base64_decode($jsB['data']));
        
        $stmt = $db->prepare('insert into Imagen values(null,?,?,?)');
        $stmt->execute([$jsB['name'], 'img/', $id_Usuario]);
        
        // VULNERABILIDAD: Concatenación directa en consulta SQL
        $R = $db->query('select max(id) as idImagen from Imagen where id_Usuario = '.$id_Usuario);
        $idImagen = $R[0]['idImagen'];
        
        $newPath = 'img/'.$idImagen.'.'.$jsB['ext'];
        //=========================================================================//
        // VULNERABILIDAD: Concatenación directa en consulta SQL
        //=========================================================================//
        $db->exec('update Imagen set ruta = "'.$newPath.'" where id = '.$idImagen);
        //=======================================================================//
        // VULNERABILIDAD: No se verifica que el archivo sea realmente una imagen
        //=======================================================================//
        rename('tmp/'.$id_Usuario, $newPath);
        echo '{"R":0,"D":'.$idImagen.'}';
    }
);

$f3->route('POST /Descargar',
    function($f3) {
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
        $idImagen = $jsB['id'];
        
        try {
            $stmt = $db->prepare('select id_Usuario from AccesoToken where token = ?');
            $stmt->execute([$TKN]);
            $R = $stmt->fetchAll();
        } catch (Exception $e) {
            echo '{"R":-2}';
            return;
        }
        
        try {
            //==========================================================================//
            // VULNERABILIDAD: Falta verificar que el usuario tiene permiso para esta imagen
            //==========================================================================//
            $stmt = $db->prepare('Select name,ruta from Imagen where id = ?');
            $stmt->execute([$idImagen]);
            $R = $stmt->fetchAll();
        } catch (Exception $e) {
            echo '{"R":-3}';
            return;
        }
        
        $web = \Web::instance();
        ob_start();
        $info = pathinfo($R[0]['ruta']);
        //==============================================================================//
        // VULNERABILIDAD: No se valida el tipo MIME real del archivo
        //==============================================================================//
        $web->send($R[0]['ruta'], NULL, 0, TRUE, $R[0]['name'].'.'.$info['extension']);
        ob_end_flush();
    }
);

$f3->run();
?>