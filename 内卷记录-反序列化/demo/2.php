<?php
class chybeta
{
    public $test = '123';
    function __wakeup()
    {
        $fp = fopen("shell.php","w") ;
        fwrite($fp,$this->test);
        fclose($fp);
    }
}
$class = @$_GET['test'];
print_r($class);
echo "</br>";
$class_unser = unserialize($class);

// 为显示效果，把这个shell.php包含进来
require "shell.php";
?>