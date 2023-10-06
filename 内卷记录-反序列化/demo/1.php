<?php
header("content-type:text/html;charset=utf-8");
//引用了logfile.php文件
include 'logfile.php';
//定义一个类
class Stu
{
    public $name = 'aa';
    public $age = 19;
    function StuData()
    {
        echo '姓名:'.$this->name.'<br>';
        echo '年龄:'.$this->age;
    }
}
//实例化对象
$stu = new Stu();
//重构用户输入的数据
$newstu = unserialize($_GET['stu']);
//O:3:"Stu":2:{s:4:"name";s:25:"<script>alert(1)</script>";s:3:"age";i:120;}
echo "<pre>";
var_dump($newstu) ;
?>