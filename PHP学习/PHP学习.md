[TOC]

# PHP初级

### 变量传值

##### 值传递

把变量(a)保存的值赋值一份，然后将新的值给另一个变量(b)保存（两个变量没有关系）

<img src="image/Image.png" alt="Image"  />

##### 引用传递

将变量(a)保存的值所在的内存地址传递给另一个变量(b)，两个变量指向同一个内存空间（同一个值）

![Image](image/Image-1607170430812.png)

![Image](image/Image-1607170665680.png)

### PHP常量

##### 常量

程序运行中不可改变的数据，一旦定义通常不可改变（用户级别）

<img src="image/Image-1607170712836.png" alt="Image" style="zoom:80%;" />

![Image](image/Image-1607170731042.png)

![Image](image/Image-1607170758512.png)

![Image](image/Image-1607170767866.png)

##### 魔术常量

![Image](image/Image-1607170920997.png)

### PHP数据类型

> ### **var_dump()** 函数返回变量的数据类型和值

PHP数据类型包括String（字符串）, Integer（整型）, Float（浮点型）, Boolean（布尔型）, Array（数组）, Object（对象）, NULL（空值）。

<img src="image/Image-1607171124635.png" alt="Image" style="zoom:80%;" />

##### PHP整型

* 整数必须至少有一个数字 (0-9)

* 整数不能包含逗号或空格

* 整数是没有小数点的

* 整数可以是正数或负数

* 整型可以用三种格式来指定：十进制， 十六进制（ 以 0x 为前缀）或八进制（前缀为 0）。

##### PHP数组

<img src="image/Image-1607171629023.png" alt="Image" style="zoom: 50%;" />

##### PHP对象

对象数据类型也可以用于存储数据。
在 PHP 中，对象必须声明。
首先，你必须使用class关键字声明类对象。类是可以包含属性和方法的结构。
然后我们在类中定义数据类型，然后在实例化的类中使用数据类型

### 类型转换

![Image](image/Image-1607171864372.png)

##### 强制转换

<img src="image/Image-1607171898094.png" alt="Image" />

<img src="image/Image-1607171898094.png" alt="Image"  />

### 类型判断

<img src="image/Image-1607171964400.png" alt="Image" />

<img src="image/Image-1607171964400.png" alt="Image"  />

> ![Image](image/Image-1607171991258.png)

##### 整数类型进制简介

![Image](image/Image-1607172068032.png)

![Image](image/Image-1607172076529.png)

<img src="image/Image-1607172087782.png" alt="Image" style="zoom:80%;" />

> 默认php输出都会自动转换成10进制输出

### 整数类型进制转换

![Image](image/Image-1607172140461.png)

##### 手动转换

![Image](image/Image-1607172184801.png)

##### 自动转换

![Image](image/Image-1607172222164.png)

<img src="image/Image-1607172226647.png" alt="Image" style="zoom:80%;" />

### 浮点型和布尔型

##### 浮点型

<img src="image/Image-1607172346903.png" alt="Image" />

<img src="image/Image-1607172365059.png" alt="Image" style="zoom:80%;" />

> PHP_INT_MAX是int储存的最大值，整形超过自身储存的大小会转换成浮点型

![Image](image/Image-1607172394999.png)

> 尽量不用浮点型做精确判断

<img src="image/Image-1607172411821.png" alt="Image" style="zoom:80%;" />

##### 布尔型

<img src="image/Image-1607172461361.png" alt="Image" style="zoom:80%;" />

![Image](image/Image-1607172469954.png)

### PHP运算符

##### 算数运算符

![Image](image/Image-1607172523951.png)

##### 比较运算符

![Image](image/Image-1607172538618.png)

##### 逻辑运算符

![Image](image/Image-1607172553982.png)

##### 短路运算

![Image](image/Image-1607172575019.png)

##### 连接运算符

<img src="image/Image-1607172606895.png" alt="Image" />

<img src="image/Image-1607172623412.png" alt="Image" style="zoom:80%;" />

##### 错误抑制符

<img src="image/Image-1607172646488.png" alt="Image" style="zoom:80%;" />

##### 三目运算符

![Image](image/Image-1607172664515.png)

> 三目运算符也是运算符，有结果，可以赋值给其他变量

##### 自操作运算

<img src="image/Image-1607172689245.png" alt="Image" style="zoom:80%;" />

##### 计算机码

<img src="image/Image-1607172707733.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607172719751.png" alt="Image" style="zoom:80%;" />

##### 位运算

<img src="image/Image-1607172742496.png" alt="Image" style="zoom:80%;" />

> ![Image](image/Image-1607172760431.png)

##### 按位与

<img src="image/Image-1607172773735.png" alt="Image" style="zoom:80%;" />

##### 按位左移右移

![Image](image/Image-1607172792067.png)

![Image](image/Image-1607172796707.png)

### 运算符优先级

多种运算结合时的优先级

### 循环控制

##### continue

<img src="image/Image-1607172847115.png" alt="Image" style="zoom: 67%;" />

##### break

<img src="image/Image-1607172867578.png" alt="Image" style="zoom:67%;" />

<img src="C:/Users/Y5neKO/AppData/Local/Temp/Image.png" alt="Image" style="zoom:80%;" />

### 流程控制替代语法

<img src="image/Image-1607172907061.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607172919541.png" alt="Image" style="zoom:67%;" />

<img src="image/Image-1607172926777.png" alt="Image" style="zoom: 50%;" />

<img src="image/Image-1607172955896.png" alt="Image" style="zoom: 50%;" />

### 替代语法

![Image](image/Image-1607173000654.png)

<img src="image/Image-1607173003851.png" alt="Image" style="zoom: 55%;" />

> if；for；while；switch；foreach
>
> <img src="image/Image-1607173034745.png" alt="Image" style="zoom:80%;" />

### 常用系统函数

![Image](image/Image-1607173147885.png)

<img src="image/Image-1607173151431.png" alt="Image" style="zoom:67%;" />

### 文件包含

<img src="image/Image-1607173167289.png" alt="Image" style="zoom:67%;" />

<img src="image/Image-1607173178516.png" alt="Image" style="zoom:80%;" />

> require和include的区别：
> include的错误级别比较轻：不会阻止代码执行（warning）；
> require的错误级别比较高：会组织代码执行（error）。

### 文件加载路径

<img src="image/Image-1607173232847.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607173241138.png" alt="Image" style="zoom:80%;" />

# PHP中级

### 函数

##### 基本概念

![Image](image/Image-1607173429064.png)

##### 定义语法

<img src="image/Image-1607173465154.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607173472007.png" alt="Image" style="zoom:80%;" />

![Image](image/Image-1607173484372.png)

![Image](image/Image-1607173488374.png)

![Image](image/Image-1607173492579.png)

##### 命名规范

<img src="image/Image-1607173507272.png" alt="Image" style="zoom:80%;" />

##### 形参实参

<img src="image/Image-1607173526958.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607173534004.png" alt="Image" style="zoom: 67%;" />

> <img src="image/Image-1607173545281.png" alt="Image" style="zoom:80%;" />
>
> ![Image](image/Image-1607173557337.png)

##### 默认值

![Image](image/Image-1607173573548.png)

<img src="image/Image-1607173578116.png" alt="Image" style="zoom: 67%;" />

> ![Image](image/Image-1607173591798.png)

##### 引用传递

<img src="image/Image-1607173611290.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607173619640.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607173628141.png" alt="Image" style="zoom: 67%;" />

> 引用传值：在传入实参的时候，必须传入变量，否则会报错
>
> ![Image](image/Image-1607173678810.png)

### 函数体

<img src="image/Image-1607173699177.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607173708165.png" alt="Image" style="zoom: 67%;" />

###### 返回值作用

将计算结果返回给调用处，返回值可以是任何数据类型

<img src="image/Image-1607173752704.png" alt="Image" style="zoom:67%;" />

##### return关键字的作用

- return在函数内部存在的作用：返回当前函数的结果，也就意味着当前函数运行结束；

![Image](image/Image-1607173807884.png)

- return可以在文件中直接使用（不在函数中使用），也就是说在return后面的代码转交给包含（include）当前文件的位置（系统配置文件中使用较多），也代表着终止return后面的代码。

<img src="image/Image-1607173812092.png" alt="Image" style="zoom: 67%;" />

### php函数作用域

<img src="image/Image-1607173851083.png" alt="Image" style="zoom: 80%;" />

<img src="image/Image-1607173865997.png" alt="Image" style="zoom:80%;" />

##### 超全局变量

<img src="image/Image-1607173887421.png" alt="Image" style="zoom: 50%;" />

##### 局部访问全局变量

###### 方法一：$GLOBALS

![Image](image/Image-1607173936205.png)

<img src="image/Image-1607173940987.png" alt="Image" style="zoom:67%;" />

###### 方法二：参数传值/引用传值

![Image](image/Image-1607173962593.png)

###### 方法三：global关键字

![Image](image/Image-1607173980216.png)

<img src="image/Image-1607173987989.png" alt="Image" style="zoom: 50%;" />

<img src="image/Image-1607174000432.png" alt="Image" style="zoom:50%;" />

> ![Image](image/Image-1607174015658.png)

### 静态变量

![Image](image/Image-1607174034418.png)

![Image](image/Image-1607174037828.png)

<img src="image/Image-1607174041718.png" alt="Image" style="zoom:67%;" />

![Image](image/Image-1607174054215.png)

### 可变函数

<img src="image/Image-1607174085887.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607174097000.png" alt="Image" style="zoom: 60%;" />

##### 回调函数

![Image](image/Image-1607174138514.png)

### 匿名函数

<img src="image/Image-1607175381988.png" alt="Image" style="zoom:80%;" />

> 变量保存匿名函数，本质得到的是一个对象（closure）
>
> <img src="image/Image-1607175401398.png" alt="Image" style="zoom:67%;" />

##### 闭包（closure）

![Image](image/Image-1607175423730.png)

<img src="image/Image-1607175428970.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607175435394.png" alt="Image" style="zoom: 60%;" />

![Image](image/Image-1607175454508.png)

<img src="image/Image-1607175458852.png" alt="Image" style="zoom:67%;" />

![Image](image/Image-1607175467117.png)

### 伪类型

### 系统函数

##### 有关函数的函数

![Image](image/Image-1607175503290.png)

### 错误处理

##### 错误分类

<img src="image/Image-1607175524095.png" alt="Image" style="zoom:80%;" />

##### 错误代号

<img src="image/Image-1607175536424.png" alt="Image" style="zoom:80%;" />

<img src="image/Image-1607175547717.png" alt="Image" style="zoom:80%;" />

##### 错误触发

<img src="image/image-20201215194005880.png" alt="image-20201215194005880" style="zoom:80%;" />

<img src="image/image-20201215194022065.png" alt="image-20201215194022065" style="zoom:80%;" />

> trigger_error函数：人为触发错误

##### 自定义错误处理

<img src="image/image-20201216102528591.png" alt="image-20201216102528591" style="zoom:80%;" />

> set_error_handler函数：
>
> <img src="image/image-20201216102731089.png" alt="image-20201216102731089" style="zoom:80%;" />
>
> ![image-20201216102824322](image/image-20201216102824322.png)

### 字符串类型

##### 字符串定义语法

###### 单引号字符串

使用单引号包裹

###### 双引号字符串

使用双引号包裹

<img src="image/image-20201221181259485.png" alt="image-20201221181259485" style="zoom: 50%;" />

> 引号方式比较适合定义一些比较短（不超过一行）或者没有结构要求的字符串
>
> 如果有结构要求或者超过一行，可以是用以下两种结构定义

###### nowdoc字符串

没有单引号的单引号字符串

```php
$str1 = <<<'END'
		hello
			world
END;
```

###### heredoc字符串

没有双引号的双引号字符串

```php
$str2 = <<<END
		hello
			world
END;
```

> nowdoc和heredoc字符串可以将字符串原格式输出

##### 字符串转义

含义：

在计算机通用协议中，有一些特定的方式定义的字符，系统会特定处理；通常这种方式都是使用反斜杠“ \ ”+字母或单词的特性：

\r\n：回车，换行

PHP在识别转义字符的时候也是使用同样的模式，php常用的转义字符：

<img src="image/image-20201221192256619.png" alt="image-20201221192256619" style="zoom:80%;" />

###### 单引号与双引号转义区别

**①**单引号中**只能**识别单引号转义，双引号**不能**识别单引号转义

**②**双引号中因为能够识别$符号，所以双引号中可以解析变量，单引号不能

###### 双引号中变量识别的规则

**①**变量本身系统能够与后面的内容区分：应尽量保证变量的独立性，不要让系统难以区分

**②**使用变量专业表示符（区分），给变量加上一组大括号{}

<img src="image/image-20201221201040169.png" alt="image-20201221201040169" style="zoom:80%;" />

###### 结构化定义字符串变量的规则

边界符条件：

①上边界符后面不能跟任何内容，包括注释

②下边界符必须顶格写（最左边）

③下边界符后面只能跟分号，不能跟任何内容

> 结构化定义字符串的内部（边界符之间）的所有内容都是字符串本身，包括注释，js规则等

##### 字符串长度问题

基础函数strlen()：得到字符串的长度（字节为单位）

> 中文在utf-8字符集下占三个字节

多字节字符串拓展模块：mbstring扩展（mb：Multi Bytes）

> 可指定编码集对字符串长度进行统计
>
> <img src="image/image-20201221202644405.png" alt="image-20201221202644405" style="zoom:80%;" />

##### 字符串相关函数

<img src="image/image-20201221203008422.png" alt="image-20201221203008422" style="zoom:80%;" />

<img src="image/image-20201221203208007.png" alt="image-20201221203208007" style="zoom: 67%;" />

# PHP面向对象编程

<img src="image/image-20210323164358906.png" alt="image-20210323164358906" style="zoom:80%;" />

### 面向对象内容

- **类** − 定义了一件事物的抽象特点。类的定义包含了数据的形式以及对数据的操作。
- **对象** − 是类的实例。
- **成员变量** − 定义在类内部的变量。该变量的值对外是不可见的，但是可以通过成员函数访问，在类被实例化为对象后，该变量即可称为对象的属性。
- **成员函数** − 定义在类的内部，可用于访问对象的数据。
- **继承** − 继承性是子类自动共享父类数据结构和方法的机制，这是类之间的一种关系。在定义和实现一个类的时候，可以在一个已经存在的类的基础之上来进行，把这个已经存在的类所定义的内容作为自己的内容，并加入若干新的内容。
- **父类** − 一个类被其他类继承，可将该类称为父类，或基类，或超类。
- **子类** − 一个类继承其他类称为子类，也可称为派生类。
- **多态** − 多态性是指相同的函数或方法可作用于多种类型的对象上并获得不同的结果。不同的对象，收到同一消息可以产生不同的结果，这种现象称为多态性。
- **重载** − 简单说，就是函数或者方法有同样的名称，但是参数列表不相同的情形，这样的同名不同参数的函数或者方法之间，互相称之为重载函数或者方法。
- **抽象性** − 抽象性是指将具有一致的数据结构（属性）和行为（操作）的对象抽象成类。一个类就是这样一种抽象，它反映了与应用有关的重要性质，而忽略其他一些无关内容。任何类的划分都是主观的，但必须与具体的应用有关。
- **封装** − 封装是指将现实世界中存在的某个客体的属性与行为绑定在一起，并放置在一个逻辑单元内。
- **构造函数** − 主要用来在创建对象时初始化对象， 即为对象成员变量赋初始值，总与new运算符一起使用在创建对象的语句中。
- **析构函数** − 析构函数(destructor) 与构造函数相反，当对象结束其生命周期时（例如对象所在的函数已调用完毕），系统自动执行析构函数。析构函数往往用来做"清理善后" 的工作（例如在建立对象时用new开辟了一片内存空间，应在退出前在析构函数中用delete释放）。

### PHP类定义

定义类通常语法格式如下：

```php
<?php
    class phpClass {					//类使用class关键字后加上类名定义，类名后的{}内可以定义变量和方法
    var $var1;							//类的变量使用var来声明
    var $var2 = "字符串";				  //变量可以初始化值
    
    function myfunc($arg1,$arg2){
        [..]
    }
    [..]
}
?>									//PS：函数定义类似PHP函数的定义，但函数只能通过该类(class)及其实例化的对象访问
```

##### 实例

```php
<?php
class Site {
    /*成员变量*/
    var $url;
    var $title;

    /*成员函数*/
    function setUrl($par){
        $this -> url = $par;
    }

    function getUrl(){
        echo $this -> url . PHP_EOL;
    }

    function setTitle($par){
        $this -> title = $par;
    }

    function getTitle(){
        echo $this -> title . PHP_EOL;
    }
}
?>
```

> 变量 $this 代表自身的对象。
>
> PHP_EOL为php中换行符

### PHP中创建对象

类创建后可以通过**new**关键字来实例化该类的对象

```php
//创建了三个对象，三个对象各自独立
$runoob = new Site;
$taobao = new Site;
$google = new Site;
```

##### 调用成员方法

实例化对象后，我们可以使用该对象调用成员方法，**该对象**的成员方法只能操作**该对象的成员变量**

```php
//调用成员函数，设置标题和URL
$runoob -> setTitle("菜鸟教程");
$taobao -> setTitle("淘宝");
$google -> setTitle("谷歌搜索");

$runoob -> setUrl('www.runoob.com');
$taobao -> setUrl('www.taobao.com');
$google -> setUrl('www.google.com');

//调用成员函数，获取标题和URL
$runoob -> getTitle();
$runoob -> getUrl();
```

![image-20210323172033878](image/image-20210323172033878.png)

### PHP构造函数

构造函数是一种特殊的方法。主要用来在**创建对象**时**初始化对象**， 即为对象成员变量赋初始值，在创建对象的语句中与 **new** 运算符一起使用。

语法格式一般如下：

```php
void __construct ([ mixed $args [, $... ]] )
```

以刚才的实例举例，我们可以通过构造方法来初始化**$url**和$**title**变量

```php
function __construct($par1,$par2){
    $this -> url = $par1;
    $this -> title = $par2;
}
```

![image-20210323174107797](image/image-20210323174107797.png)

### PHP析构函数

析构函数(destructor) 与构造函数相反，当对象结束其生命周期时（例如对象所在的函数已调用完毕），系统自动执行析构函数。

其语法格式如下：

```php
void __destruct ( void )
```

##### 实例

```php
<?php
class  MyDestructableClass{
    function __construct(){								//首先构造函数
        print "构造函数\n";
        $this -> name = "MyDestructableClass";
    }

    function __destruct(){								//对象周期结束时自动执行构析函数
        // TODO: Implement __destruct() method.
        print "销毁" . $this->name . "\n";
    }
}

$obj = new MyDestructableClass();
?>
```

![image-20210323175152086](image/image-20210323175152086.png)

### 继承

PHP 使用关键字 **extends** 来继承一个类，PHP 不支持**多继承**，格式如下：

```php
class Child extends Parent {
   // 代码部分
}
```

##### 实例

实例中 **Child_Site** 类继承了 **Site** 类，并扩展了功能

```php
<?php
class Site{
    var $par1;

    function test(){
        $par1 = 1;
        echo "test " . $par1 . PHP_EOL;
    }
}

class Child_Site extends Site{
    var $category;

    function setCate($par){
        $this->category = $par;
    }

    function getCate(){
        echo $this->category . PHP_EOL;
    }
}

$Child = new Child_Site();

$Child->test();
$Child->setCate("category");
$Child->getCate();
?>
```

![image-20210323181335464](image/image-20210323181335464.png)

### 方法重写

如果从父类继承的方法不能满足子类的需求，可以对其进行改写，这个过程叫方法的覆盖（override），也称为方法的重写。

下面的实例重写了**test**方法：

##### 实例

```php
<?php
class Site{
    var $par1;

    function test(){
        $par1 = 1;
        echo "test " . $par1 . PHP_EOL;
    }
}

class Child_Site extends Site{
    var $category;
    var $par1;

    function setCate($par){
        $this->category = $par;
    }

    function getCate(){
        echo $this->category . PHP_EOL;
    }

    function test(){
        $this->par1 = 2;
        echo "override test\n";
        echo $this->par1 . PHP_EOL;
    }
}

$Child = new Child_Site();

$Child->test();
$Child->setCate("category");
$Child->getCate();
```

![image-20210323184723136](image/image-20210323184723136.png)

### 访问控制

PHP 对属性或方法的访问控制，是通过在前面添加关键字 public（公有），protected（受保护）或 private（私有）来实现的。

- **public（公有）：**公有的类成员可以在任何地方被访问。
- **protected（受保护）：**受保护的类成员则可以被其自身以及其子类和父类访问。
- **private（私有）：**私有的类成员则只能被其定义所在的类访问。

##### 属性的访问控制

类属性**必须定义为公有，受保护，私有之一**。如果用 **var** 定义，则被视为**公有**。                       

```php
<?php
//定义一个类
class MyClass{
    public $public = 'Public';
    protected $protected = 'Protected';
    private $private = "private";

    function printHello(){
        echo $this->public;
        echo $this->protected;
        echo $this->private;
    }
}

$obj = new MyClass();
echo $obj->public;			//这行正常输出
echo $obj->protected;		//这行会产生一个致命错误
echo $obj->private;			//这行也会产生一个致命错误
$obj->printHello();			//输出所有的属性
```

![image-20210323191846290](image/image-20210323191846290.png)

```php
//定义另一个类继承上一个
class MyClass2 extends MyClass{
    //可以对public和protected进行重定义，但private不行，见private描述
    protected $protected = "Protected2";

    function printHello(){
        echo $this->public;
        echo $this->protected;
        echo $this->private;
    }
}

$obj2 = new MyClass2();
echo $obj2->public;			//这行能正常输出
echo $obj2->private;		//private未定义
echo $obj2->protected;		//这行会产生一个致命错误
$obj2->printHello();		//输出public，Protected2和null/undefined
```

<img src="image/image-20210324150907610.png" alt="image-20210324150907610" style="zoom:80%;" />

##### 方法的访问控制

类中的方法可以被定义为公有，私有或受保护。如果没有设置这些关键字，则该方法默认为公有。

```php
<?php
//定义一个类
class MyClass{
    //声明一个共有构造函数
    public function __construct(){}

    //声明一个共有方法
    public function MyPublic(){}

    //声明一个受保护方法
    protected  function MyProtected(){}

    //声明一个私有方法
    private function MyPrivate(){}

    //此方法为共有
    function Foo(){
        $this->MyPublic();
        $this->MyProtected();
        $this->MyPrivate();
    }
}

$myclass = new MyClass;
$myclass->MyPublic();   //这行能正常执行
$myclass->MyProtected();	//产生致命错误
$myclass->MyPrivate();		//产生致命错误
$myclass->Foo();        //公用方法，私有、受保护都可以执行
```

继承父类，注意**受保护**和**私有**的区别

```php
//定义另一个类继承上一个类
class MyClass2 extends MyClass{
    //此方法为共有
    function Foo2(){
        $this->MyPublic();
        $this->MyProtected();
        $this->MyPrivate();     //产生一个致命错误
    }
}

$myclass2 = new MyClass2();
$myclass2->MyPublic();      //能正常执行
$myclass2->Foo2();          //共有和受保护可以执行，私有的不行
```

###### 实例

```php
class Bar{
    public function test(){
        $this->testPublic();
        $this->testPrivate();
    }

    public function testPublic(){
        echo "Bar::testPublic\n";
    }

    private function testPrivate(){
        echo "Bar::testPrivate\n";
    }
}

class Foo extends Bar{
    public function testPublic(){
        echo "Foo::testPublic\n";
    }

    private function testPrivate(){
        echo "Foo::testPrivate\n";      //私有不能被override
    }
}

$myFoo = new Foo();
$myFoo->test();
```

![image-20210324162441037](image/image-20210324162441037.png)

### 接口

使用接口（**interface**），可以指定某个类必须实现哪些方法，但不需要定义这些方法的具体内容。

接口是通过 **interface** 关键字来定义的，就像定义一个标准的类一样，但其中定义所有的方法都是空的。

接口中定义的所有方法都必须是公有，这是接口的特性。

要实现一个接口，使用 **implements** 操作符。类可以实现多个接口，用逗号来分隔多个接口的名称。

**理解**：接口其实就收一种规定，如果属于该类接口，必须遵循该规定

参考：https://blog.csdn.net/chengjianghao/article/details/92837947

> 注：**类中必须实现接口中定义的所有方法**，否则会报一个**致命错误**。
>
> ![image-20210324164115545](image/image-20210324164115545.png)

##### 实例

```php
<?php
//声明一个'iTemplate'接口
interface iTemplate{
    public function setVariable($name, $var);
    public function getHtml($template);
}

//实现接口
class Template implements iTemplate{
    private $vars = array();

    public function setVariable($name, $var)
    {
        $this->vars[$name] = $var;
    }

    public function getHtml($template)
    {
        foreach ($this->vars as $name =>$value){
            $template = str_replace('{' . $name . '}', $value, $template);
        }

        return $template;
    }
}
```

### 抽象类

关键字**abstract**，任何一个类，如果它里面**至少有一个方法**是被声明为抽象的，那么这个类就**必须被声明为抽象**的。

> 注1：定义为抽象的类不能被实例化。
>
> ![image-20210324170713043](image/image-20210324170713043.png)

被定义为抽象的方法只是声明了其调用方式（参数），不能定义其具体的功能实现。

> 注2：继承一个抽象类的时候，子类必须定义父类中的所有抽象方法；
>
> ![image-20210324170553535](image/image-20210324170553535.png)

> 注3：另外，这些方法的访问控制必须和父类中一样（或者更为宽松）。例如某个抽象方法被声明为受保护的，那么子类中实现的方法就应该声明为受保护的或者公有的，而不能定义为私有的。
>
> ![image-20210324171059019](image/image-20210324171059019.png)

##### 实例

```php
<?php
abstract class AbstractClass{
    //强制要求子类必须定义这些方法
    abstract protected function getValue();
    abstract protected function prefixValue($prefix);

    //普通方法（非抽象）
    public function printOut(){
        print $this->getValue() . PHP_EOL;
    }
}

class ConcreteClass1 extends AbstractClass{
    protected function getValue(){
        return "ConcreteClass1";
    }

    public function prefixValue($prefix){
        return "{$prefix}ConcreteClass1";
    }
}

class ConcreteClass2 extends AbstractClass{
    public function getValue(){
        return "ConcreteClass2";
    }

    public function prefixValue($prefix){
        return "{$prefix}ConcreteClass2";
    }
}

$class1 = new ConcreteClass1;
$class1->printOut();
echo $class1->prefixValue('FOO_') . PHP_EOL;

$class2 = new ConcreteClass2;
$class2->printOut();
echo $class2->prefixValue('FOO_') . PHP_EOL;
```

![image-20210324172716988](image/image-20210324172716988.png)

此外，子类方法可以包含父类抽象方法中不存在的可选参数。

例如，子类定义了一个可选参数，而父类抽象方法的声明里没有，则也是可以正常运行的。

![image-20210324174015951](image/image-20210324174015951.png)

### Static关键字

声明类属性或方法为 **static**(静态)，就可以不实例化类而直接访问。

静态属性不能通过一个类已实例化的对象来访问（但静态方法可以）。

由于静态方法不需要通过对象即可调用，所以伪变量 $this 在静态方法中不可用。

静态属性不可以由对象通过 -> 操作符来访问。

自 PHP 5.3.0 起，可以用一个变量来动态调用类。但该变量的值不能为关键字 **self**，**parent** 或 **static**。

> 双冒号操作符即作用域限定操作符Scope Resolution Operator可以访问静态、const和类中重写的属性与方法。

![image-20210324180208496](image/image-20210324180208496.png)

### Final关键字

PHP 5 新增了一个 final 关键字。如果父类中的方法被声明为 final，则子类无法覆盖该方法。如果一个类被声明为 final，则不能被继承。

以下代码执行会报错：

```php
<?php
class BaseClass{
    public function test(){
        echo "BaseClass::test() called" . PHP_EOL;
    }

    final public function moreTesting(){
        echo "BawseClass::moreTesting() called" . PHP_EOL;
    }
}

class ChildClass extends BaseClass{
    public function moreTesting(){
        echo "ChildClass::moreTesting() called" . PHP_EOL;
    }
}
```

![image-20210324181901048](image/image-20210324181901048.png)

### 调用父类构造方法

PHP 不会在子类的构造方法中自动的调用父类的构造方法。要执行父类的构造方法，需要在子类的构造方法中调用 **parent::__construct()** 。

```php
<?php
class BaseClass{
    function __construct(){
        print "BaseClass类中构造方法\n";
    }
}
class SubClass extends BaseClass{
    function __construct(){
        parent::__construct();
        print "SubClass类中构造方法\n";
    }
}
class OtherSubClass extends BaseClass{
    //继承BaseClass的构造方法
}

//调用BaseClass构造方法
$obj = new BaseClass();

//调用BaseClass、SubClass构造方法
$obj = new SubClass();

//调用BaseClass构造方法
$obj = new OtherSubClass();
```

