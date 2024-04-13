# Java快速入门
## 数组
### 遍历
通过for循环就可以遍历数组。因为数组的每个元素都可以通过索引来访问，因此，使用标准的for循环可以完成一个数组的遍历：
#### **标准for循环**
```java  
package com.y5neko.study.introduction.array;  
  
public class traversal {  
    public static void main(String[] args) {  
        int[] ns = {1, 2, 3, 4, 5};  
        for (int i = 0; i < ns.length; i++) {  
            System.out.println(ns[i]);  
        }  
    }  
}
```
![[Pasted image 20240407095801.png]]
#### **增强型for写法（for-each）**
增强for循环的语法结构如下：
```java
for (元素类型 变量名 : 需要遍历的数组或集合) { // 进行操作 }
```
其中，元素类型表示数组或集合中元素的类型，变量名表示每次迭代中获取到的当前元素的值。在循环体中，可以直接使用变量名访问当前的元素，并执行相应的操作。**增强for循环的优点是简洁、易读，并且能够避免索引操作，适用于不需要修改数组或集合元素的情况**。
```java
package com.y5neko.study.introduction.array;  
  
public class traversal {  
    public static void main(String[] args) {  
        int[] ns = {1, 2, 3, 4, 5};  
        for (int n : ns) {  
            System.out.println(n);  
        }  
    }  
}
```
**增强for循环不能对集合进行修改（添加、删除等）**。如果需要在循环过程中对集合进行操作，仍然需要使用迭代器或传统的for循环。
增强for循环适用于只需要访问数组或集合中的每个元素，并且不需要索引或迭代器的情况。它提供了一种简洁而直观的方式来遍历数组或集合中的元素。需要注意的是，**增强for循环是只读的，即不能通过它来修改数组或集合中的元素**。如果需要**修改元素，仍然需要使用传统的for循环或迭代器来完成。**
#### 打印数组内容
直接打印数组变量，得到的是数组在JVM中的引用地址：
![[Pasted image 20240407102328.png]]
Java标准库提供了`Arrays.toString()`，可以快速打印数组内容：
![[Pasted image 20240407102431.png]]
#### 倒序遍历数组
```java
package com.y5neko.study.introduction.array;  
  
public class traversal {  
    public static void main(String[] args) {  
        int[] ns = {1, 2, 3, 4, 5};  
        for (int i = ns.length - 1; i >= 0; i--) {  
            System.out.println(ns[i]);  
        }  
    }  
}
```
# 面向对象编程
面向对象编程，是一种通过对象的方式，把现实世界映射到计算机模型的一种编程方法。

现实世界中，我们定义了“人”这种抽象概念，而具体的人则是“小明”、“小红”、“小军”等一个个具体的人。所以，“人”可以定义为一个类（class），而具体的人则是实例（instance）

在OOP中，`class`和`instance`是“模版”和“实例”的关系；
定义`class`就是定义了一种数据类型，对应的`instance`是这种数据类型的实例；
`class`定义的`field`，在每个`instance`都会拥有各自的`field`，且互不干扰；
通过`new`操作符创建新的`instance`，然后用变量指向它，即可通过变量来引用这个`instance`；
访问实例字段的方法是`变量名.字段名`；
指向`instance`的变量都是引用变量。
## 方法
### 定义方法
```java
修饰符 方法返回类型 方法名(方法参数列表) {
    若干方法语句;
    return 方法返回值;
}
```
方法返回值通过`return`语句实现，如果没有返回值，返回类型设置为`void`，可以省略`return`。
### private方法
有`public`方法，自然就有`private`方法。和`private`字段一样，`private`方法不允许外部调用，那我们定义`private`方法有什么用？
定义`private`方法的理由是内部方法是可以调用`private`方法的。例如：
```java
public class Main {
    public static void main(String[] args) {
        Person ming = new Person();
        ming.setBirth(2008);
        System.out.println(ming.getAge());
    }
}

class Person {
    private String name;
    private int birth;

    public void setBirth(int birth) {
        this.birth = birth;
    }

    public int getAge() {
        return calcAge(2019); // 调用private方法
    }

    // private方法:
    private int calcAge(int currentYear) {
        return currentYear - this.birth;
    }
}
```
### this变量
在方法内部，可以使用一个隐含的变量`this`，它始终指向当前实例。因此，通过`this.field`就可以访问当前实例的字段。
如果没有命名冲突，可以省略`this`。例如：
```java
class Person {
    private String name;

    public String getName() {
        return name; // 相当于this.name
    }
}
```
但是，**如果有局部变量和字段重名，那么局部变量优先级更高**，就必须加上`this`：
```java
class Person {
    private String name;

    public void setName(String name) {
        this.name = name; // 前面的this不可少，少了就变成局部变量name了
        // 相当于name=name，无效语句
    }
}
```
### 方法参数
方法可以包含0个或任意个参数。方法参数用于接收传递给方法的变量值。调用方法时，必须严格按照参数的定义一一传递。例如：
```java
class Person {
    ...
    public void setNameAndAge(String name, int age) {
        ...
    }
}
```
调用这个`setNameAndAge()`方法时，必须有两个参数，且第一个参数必须为`String`，第二个参数必须为`int`：
```java
Person ming = new Person();
ming.setNameAndAge("Xiao Ming"); // 编译错误：参数个数不对
ming.setNameAndAge(12, "Xiao Ming"); // 编译错误：参数类型不对
```
### **可变参数**
可变参数用`类型...`定义，可变参数相当于数组类型：
```java
class Group {
    private String[] names;

    public void setNames(String... names) {
        this.names = names;
    }
}
```
上面的`setNames()`就定义了一个可变参数。调用时，可以这么写：
```java
Group g = new Group();
g.setNames("Xiao Ming", "Xiao Hong", "Xiao Jun"); // 传入3个String
g.setNames("Xiao Ming", "Xiao Hong"); // 传入2个String
g.setNames("Xiao Ming"); // 传入1个String
g.setNames(); // 传入0个String
```
**例**
![[Pasted image 20240407104618.png]]
### 参数绑定
调用方把参数传递给实例方法时，调用时传递的值会按参数位置一一绑定。
那什么是参数绑定？
我们先观察一个基本类型参数的传递： 
#### 基本类型参数传递
```java
public class Main {
    public static void main(String[] args) {
        Person p = new Person();
        int n = 15; // n的值为15
        p.setAge(n); // 传入n的值
        System.out.println(p.getAge()); // 15
        n = 20; // n的值改为20
        System.out.println(p.getAge()); // 15
    }
}

class Person {
    private int age;

    public int getAge() {
        return this.age;
    }

    public void setAge(int age) {
        this.age = age;
    }
}
```
运行代码，从结果可知，修改外部的局部变量`n`，不影响实例`p`的`age`字段，原因是`setAge()`方法获得的参数，复制了`n`的值，因此，`p.age`和局部变量`n`互不影响。
**结论：基本类型参数的传递，是调用方值的复制。双方各自的后续修改，互不影响。**
#### 引用类型参数传递
```java
public class Main {
    public static void main(String[] args) {
        Person p = new Person();
        String[] fullname = new String[] { "Homer", "Simpson" };
        p.setName(fullname); // 传入fullname数组
        System.out.println(p.getName()); // "Homer Simpson"
        fullname[0] = "Bart"; // fullname数组的第一个元素修改为"Bart"
        System.out.println(p.getName()); // "Homer Simpson"还是"Bart Simpson"?
    }
}

class Person {
    private String[] name;

    public String getName() {
        return this.name[0] + " " + this.name[1];
    }

    public void setName(String[] name) {
        this.name = name;
    }
}
```
注意到`setName()`的参数现在是一个数组。一开始，把`fullname`数组传进去，然后，修改`fullname`数组的内容，结果发现，实例`p`的字段`p.name`也被修改了！
**结论：引用类型参数的传递，调用方的变量，和接收方的参数变量，指向的是同一个对象。双方任意一方对这个对象的修改，都会影响对方（因为指向同一个对象）。**
#### 参数绑定机制
![[Pasted image 20240407105952.png]]
**在 Java 中，String 和 String[] 都是引用类型，存储的是对象的引用。但是，`String 类型的对象是不可变的`，也就是说，一旦创建了一个 String 对象，就无法再修改它的值，任何对 String 对象的修改都会创建一个新的对象。而 String[] 类型的对象是可变的，也就是说，可以修改数组中的元素值。**

**当我们将一个 String[] 类型的变量传递给一个方法时，实际上传递的是该变量所引用的数组对象在内存中的地址。因此，当我们在方法中修改数组中的元素值时，对数组进行的修改会影响到原始数组，在方法返回后也能保留。而 String 类型因为不可变，修改即创建新的对象也就有了新的地址，所以方法中引用的地址的值没有改变，输出的结果也就没有改变**
## 构造方法
创建实例的时候，我们经常需要同时初始化这个实例的字段，例如：
```java
Person ming = new Person();
ming.setName("小明");
ming.setAge(12);
```
初始化对象实例需要3行代码，而且，如果忘了调用`setName()`或者`setAge()`，这个实例内部的状态就是不正确的。
能否在创建对象实例时就把内部字段全部初始化为合适的值？
这时，我们就需要构造方法。
创建实例的时候，实际上是通过构造方法来初始化实例的。我们先来定义一个构造方法，能在创建`Person`实例的时候，一次性传入`name`和`age`，完成初始化：
```java
public class Main {
    public static void main(String[] args) {
        Person p = new Person("Xiao Ming", 15);
        System.out.println(p.getName());
        System.out.println(p.getAge());
    }
}

class Person {
    private String name;
    private int age;

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() {
        return this.name;
    }

    public int getAge() {
        return this.age;
    }
}
```
### 默认构造方法
任何`class`都有构造方法，如果一个类没有定义构造方法，编译器会自动为我们生成一个默认构造方法，它没有参数，也没有执行语句，类似这样：
```java
class Person {
    public Person() {
    }
}
```
要特别注意的是，如果我们自定义了一个构造方法，那么，编译器就_不再_自动创建默认构造方法
如果既要能使用带参数的构造方法，又想保留不带参数的构造方法，那么只能把两个构造方法都定义出来：
```java
public class Main {
    public static void main(String[] args) {
        Person p1 = new Person("Xiao Ming", 15); // 既可以调用带参数的构造方法
        Person p2 = new Person(); // 也可以调用无参数构造方法
    }
}

class Person {
    private String name;
    private int age;

    public Person() {
    }

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
    
    public String getName() {
        return this.name;
    }

    public int getAge() {
        return this.age;
    }
}
```
### 多构造方法
可以定义多个构造方法，在通过`new`操作符调用的时候，编译器通过构造方法的参数数量、位置和类型自动区分：
```java
class Person {
    private String name;
    private int age;

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }

    public Person(String name) {
        this.name = name;
        this.age = 12;
    }

    public Person() {
    }
}
```
## 方法重载
这种方法名相同，但各自的参数不同，称为方法重载（`Overload`）。
注意：方法重载的返回值类型通常都是相同的。
方法重载的目的是，功能类似的方法使用同一名字，更容易记住，因此，调用起来更简单。
举个例子，`String`类提供了多个重载方法`indexOf()`，可以查找子串：
- `int indexOf(int ch)`：根据字符的Unicode码查找；
- `int indexOf(String str)`：根据字符串查找；
- `int indexOf(int ch, int fromIndex)`：根据字符查找，但指定起始位置；
- `int indexOf(String str, int fromIndex)`根据字符串查找，但指定起始位置。
```java
package com.y5neko.study.oop;  
  
public class overloading_method {  
    public static void main(String[] args) {  
        String s = "Test string";  
        int n1 = s.indexOf('t');  
        int n2 = s.indexOf("st");  
        int n3 = s.indexOf("st", 4);  
        System.out.println(n1);  
        System.out.println(n2);  
        System.out.println(n3);  
    }  
}
```

![[Pasted image 20240407165619.png]]
## 继承
自定义一个Person1类
```java
package com.y5neko.study.oop;  
  
public class Person1 {  
    private String name;  
    private int age;  
  
    public void setAge(int age) {}  
  
    public void setName(String name) {}  
  
    public String getName() {  
        return name;  
    }  
    public int getAge() {  
        return age;  
    }  
}
```
假设我们需要定义一个Student类
```java
class Student {
    private String name;
    private int age;
    private int score;

    public String getName() {...}
    public void setName(String name) {...}
    public int getAge() {...}
    public void setAge(int age) {...}
    public int getScore() { … }
    public void setScore(int score) { … }
}
```
发现`Student`类包含了`Person`类已有的字段和方法，只是多出了一个`score`字段和相应的`getScore()`、`setScore()`方法。
这个时候，继承就派上用场了。
继承是面向对象编程中非常强大的一种机制，它首先可以复用代码。当我们让`Student`从`Person`继承时，`Student`就获得了`Person`的所有功能，我们只需要为`Student`编写新增的功能。
```java
package com.y5neko.study.oop;  
  
public class Student extends Person1 {  
    private int score;  
  
    public void setScore(int score) {  
        this.score = score;  
    }  
  
    public int getScore() {  
        return score;  
    }  
}
```
通过继承，`Student`只需要编写额外的功能，不再需要重复代码。
> 注意：子类自动获得了父类的所有字段，严禁定义与父类重名的字段！

在OOP的术语中，我们把`Person`称为超类（super class），父类（parent class），基类（base class），把`Student`称为子类（subclass），扩展类（extended class）。
### 继承树
注意到我们在定义`Person`的时候，没有写`extends`。在Java中，没有明确写`extends`的类，编译器会自动加上`extends Object`。所以，任何类，除了`Object`，都会继承自某个类。下图是`Person`、`Student`的继承树：
![[Pasted image 20240407170638.png]]
Java只允许一个class继承自一个类，因此，一个类有且仅有一个父类。只有`Object`特殊，它没有父类。
类似的，如果我们定义一个继承自`Person`的`Teacher`，它们的继承树关系如下：
![[Pasted image 20240407170714.png]]
### protected
继承有个特点，就是子类无法访问父类的`private`字段或者`private`方法。例如，`Student`类就无法访问`Person`类的`name`和`age`字段：
```java
class Person {
    private String name;
    private int age;
}

class Student extends Person {
    public String hello() {
        return "Hello, " + name; // 编译错误：无法访问name字段
    }
}
```
这使得继承的作用被削弱了。为了让子类可以访问父类的字段，我们需要把`private`改为`protected`。用`protected`修饰的字段可以被子类访问：
```java
class Person {
    protected String name;
    protected int age;
}

class Student extends Person {
    public String hello() {
        return "Hello, " + name; // OK!
    }
}
```
因此，`protected`关键字可以把字段和方法的访问权限控制在继承树内部，一个`protected`字段和方法可以被其子类，以及子类的子类所访问。
### super
`super`关键字表示父类（超类）。子类引用父类的字段时，可以用`super.fieldName`。例如：
```java
class Student extends Person {
    public String hello() {
        return "Hello, " + super.name;
    }
}
```
实际上，这里使用`super.name`，或者`this.name`，或者`name`，效果都是一样的。编译器会自动定位到父类的`name`字段。
但是，在某些时候，就必须使用`super`。我们来看一个例子：
```java
public class Main {
    public static void main(String[] args) {
        Student s = new Student("Xiao Ming", 12, 89);
    }
}

class Person {
    protected String name;
    protected int age;

    public Person(String name, int age) {
        this.name = name;
        this.age = age;
    }
}

class Student extends Person {
    protected int score;

    public Student(String name, int age, int score) {
        this.score = score;
    }
}
```
运行上面的代码，会得到一个编译错误，大意是在`Student`的构造方法中，无法调用`Person`的构造方法。
这是因为在Java中，任何`class`的构造方法，第一行语句必须是调用父类的构造方法。如果没有明确地调用父类的构造方法，编译器会帮我们自动加一句`super();`，所以，`Student`类的构造方法实际上是这样：
```java
class Student extends Person {
    protected int score;

    public Student(String name, int age, int score) {
        super(); // 自动调用父类的构造方法
        this.score = score;
    }
}
```
但是，`Person`类并没有无参数的构造方法，因此，编译失败。
解决方法是调用`Person`类存在的某个构造方法。例如：
```java
class Student extends Person {
    protected int score;

    public Student(String name, int age, int score) {
        super(name, age); // 调用父类的构造方法Person(String, int)
        this.score = score;
    }
}
```
**结论：如果父类没有默认的构造方法，子类就必须显式调用`super()`并给出参数以便让编译器定位到父类的一个合适的构造方法。**
**这里还顺带引出了另一个问题：即子类`不会继承`任何父类的构造方法。子类默认的构造方法是编译器自动生成的，不是继承的。**
### final
final表示最终的意思，也就表示不能被继承。
![[Pasted image 20240413140147.png]]
### 阻止继承
正常情况下，只要某个class没有`final`修饰符，那么任何类都可以从该class继承。
从Java 15开始，允许使用`sealed`修饰class，并通过`permits`明确写出能够从该class继承的子类名称。
例如，定义一个`Shape`类：
```java
public sealed class Shape permits Rect, Circle, Triangle {
    ...
}
```
上述`Shape`类就是一个`sealed`类，它只允许指定的3个类继承它。如果写：
```java
public final class Rect extends Shape {...}
```
是没问题的，因为`Rect`出现在`Shape`的`permits`列表中。但是，如果定义一个`Ellipse`就会报错：
```java
public final class Ellipse extends Shape {...}
// Compile error: class is not allowed to extend sealed class: Shape
```
原因是`Ellipse`并未出现在`Shape`的`permits`列表中。这种`sealed`类主要用于一些框架，防止继承被滥用。
`sealed`类在Java 15中目前是预览状态，要启用它，必须使用参数`--enable-preview`和`--source 15`。
### 向上转型
如果一个引用变量的类型是`Student`，那么它可以指向一个`Student`类型的实例：
```java
Student s = new Student();
```
如果一个引用类型的变量是`Person`，那么它可以指向一个`Person`类型的实例：
```java
Person p = new Person();
```
现在问题来了：如果`Student`是从`Person`继承下来的，那么，一个引用类型为`Person`的变量，能否指向`Student`类型的实例？
```java
Person p = new Student(); // ???
```
![[Pasted image 20240413140908.png]]
测试一下就可以发现，这种指向是允许的！
这是因为`Student`继承自`Person`，因此，它拥有`Person`的全部功能。`Person`类型的变量，如果指向`Student`类型的实例，对它进行操作，是没有问题的！
这种把一个子类类型安全地变为父类类型的赋值，被称为向上转型（upcasting）。
向上转型实际上是把一个子类型安全地变为**更加抽象的父类型**：
> 抽象：更概括，例如Person
> 具体：更准确，例如Student

```java
Student s = new Student();
Person p = s; // upcasting, ok
Object o1 = p; // upcasting, ok
Object o2 = s; // upcasting, ok
```
注意到继承树是`Student > Person > Object`，所以，可以把`Student`类型转型为`Person`，或者更高层次的`Object`。
### 向下转型
和向上转型相反，如果把一个父类类型强制转型为子类类型，就是向下转型（downcasting）。例如：
```java
Person p1 = new Student(); // upcasting, ok
Person p2 = new Person();
Student s1 = (Student) p1; // ok
Student s2 = (Student) p2; // runtime error! ClassCastException!
```
![[Pasted image 20240413141610.png]]
如果测试上面的代码，可以发现：
`Person`类型`p1`实际指向`Student`实例，`Person`类型变量`p2`实际指向`Person`实例。在向下转型的时候，把`p1`转型为`Student`会成功，因为`p1`确实指向`Student`实例，把`p2`转型为`Student`会失败，因为`p2`的实际类型是`Person`，不能把父类变为子类，因为子类功能比父类多，多的功能无法凭空变出来。
因此，向下转型很可能会失败。失败的时候，Java虚拟机会报`ClassCastException`。
#### instanceof 
为了避免向下转型出错，Java提供了`instanceof`操作符，可以先判断一个实例究竟是不是某种类型：
![[Pasted image 20240413143326.png]]
`instanceof`实际上判断一个变量所指向的实例是否是指定类型，或者这个类型的子类。如果一个引用变量为`null`，那么对任何`instanceof`的判断都为`false`。
利用`instanceof`，在向下转型前可以先判断：
```java
Object obj = "hello";
if (obj instanceof String) {
    String s = (String) obj;
    System.out.println(s.toUpperCase());
}
```
从Java 14开始，判断`instanceof`后，可以直接转型为指定变量，避免再次强制转型。例如：
```java
public class Main {
    public static void main(String[] args) {
        Object obj = "hello";
        if (obj instanceof String s) {
            // 可以直接使用变量s:
            System.out.println(s.toUpperCase());
        }
    }
}
```
### 区分继承和组合
在使用继承时，我们要注意逻辑一致性。
考察下面的`Book`类：
```java
class Book {
    protected String name;
    public String getName() {...}
    public void setName(String name) {...}
}
```
这个`Book`类也有`name`字段，那么，我们能不能让`Student`继承自`Book`呢？
```java
class Student extends Book {
    protected int score;
}
```
显然，从逻辑上讲，这是不合理的，`Student`不应该从`Book`继承，而应该从`Person`继承。
究其原因，是因为`Student`是`Person`的一种，它们是is关系，而`Student`并不是`Book`。实际上`Student`和`Book`的关系是has关系。
具有has关系不应该使用继承，而是使用组合，即`Student`可以持有一个`Book`实例：
```java
class Student extends Person {
    protected Book book;
    protected int score;
}
```
因此，继承是is关系，组合是has关系。
## 多态
在继承关系中，子类如果定义了一个与父类方法签名完全相同的方法，被称为覆写（Override）。
例如，在`Person`类中，我们定义了`run()`方法：
```java
class Person {
    public void run() {
        System.out.println("Person.run");
    }
}
```
在子类`Student`中，覆写这个`run()`方法：
```java
class Student extends Person {
    @Override
    public void run() {
        System.out.println("Student.run");
    }
}
```
![[Pasted image 20240413153239.png]]
Override和Overload不同的是，如果方法签名不同，就是Overload，Overload方法是一个新方法；如果方法签名相同，并且返回值也相同，就是`Override`。
>  注意：方法名相同，方法参数相同，但方法返回值不同，也是不同的方法。在Java程序中，出现这种情况，编译器会报错。

```java
class Person {
    public void run() { … }
}

class Student extends Person {
    // 不是Override，因为参数不同:
    public void run(String s) { … }
    // 不是Override，因为返回值不同:
    public int run() { … }
}
```
