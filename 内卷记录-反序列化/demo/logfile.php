<?php
class LogFile
{
    //日志文件名
    public $filename = 'error.log';
    //存储日志文件
    function LogData($text)
    {
        //输出需要存储的内容
        echo 'log some data:'.$text.'<br>';
        file_put_contents($this->filename, $text,FILE_APPEND);
    }
    //删除日志文件
    function __destruct()
    {
        //输出删除的文件
        echo '析构函数__destruct 删除新建文件'.$this->filename;
        //绝对路径删除文件
        unlink(dirname(__FILE__).'/'.$this->filename);
    }
}
class test{
    public $test2 = 'test';
}
?>