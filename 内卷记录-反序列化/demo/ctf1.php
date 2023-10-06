<?php
class SoFun{
    protected $file='ctf1.php';
    function __destruct(){
        if(!empty($this->file)) {
            if(strchr($this-> file,"\\")===false &&  strchr($this->file, '/')===false)
                show_source(dirname (__FILE__).'/'.$this ->file);
            else      die('Wrong filename.');
        }
    }
    function __wakeup(){
        $this-> file='ctf1.php';
    }
    public function __toString(){
        return '' ;
    }
}
if (!isset($_GET['file'])){
    show_source('ctf1.php');
}
else{
    $file=base64_decode( $_GET['file']);
    echo unserialize($file );
}
?>   #<!--key in flag.php-->