## 跨平台原理

<img src="image/image-20220428141455132.png" alt="image-20220428141455132" style="zoom:80%;" />

**JVM虚拟机**

## 数据类型

**Java是强类型语言**

<img src="image/image-20220428143322795.png" alt="image-20220428143322795" style="zoom:67%;" />

<img src="image/image-20220428143545712.png" alt="image-20220428143545712" style="zoom:80%;" />

## 标识符定义规则

<img src="image/image-20220428145106203.png" alt="image-20220428145106203" style="zoom:80%;" />

## 类型转换

### 自动类型转换

<img src="image/image-20220428145411479.png" alt="image-20220428145411479" style="zoom:80%;" />

## 运算符

<img src="image/image-20220428161040204.png" alt="image-20220428161040204" style="zoom:80%;" />

<img src="image/image-20220428161118308.png" alt="image-20220428161118308" style="zoom:80%;" />

**自动提升后，需要用高优先级的数据类型来接收**

<img src="image/image-20220428161720534.png" alt="image-20220428161720534" style="zoom: 67%;" />

### 赋值运算

<img src="image/image-20220428162449307.png" alt="image-20220428162449307" style="zoom: 67%;" />

**+=会自动强制转换数据类型**

<img src="image/image-20220428162422141.png" alt="image-20220428162422141" style="zoom:80%;" />

### 关系运算

<img src="image/image-20220428163522455.png" alt="image-20220428163522455" style="zoom: 67%;" />

### 逻辑运算

<img src="image/image-20220428164413476.png" alt="image-20220428164413476" style="zoom:67%;" />

<img src="image/image-20220428164300995.png" alt="image-20220428164300995" style="zoom:80%;" />

### 短路逻辑运算

<img src="image/image-20220428164816114.png" alt="image-20220428164816114" style="zoom:67%;" />

### 三元运算

<img src="image/image-20220428164929876.png" alt="image-20220428164929876" style="zoom: 80%;" />

## 特殊符号

\t：制表符，补齐8个空格字符，用以对齐数据







## 数据输入

<img src="image/image-20220429115424628.png" alt="image-20220429115424628" style="zoom:80%;" />

## 流程控制

<img src="image/image-20220429115553084.png" alt="image-20220429115553084" style="zoom:80%;" />

### switch语句

![image-20220429122054874](image/image-20220429122054874.png)

## Random随机

<img src="image/image-20220430132624215.png" alt="image-20220430132624215" style="zoom:80%;" />

## 数组

### 数组定义格式

<img src="image/image-20220430135752065.png" alt="image-20220430135752065" style="zoom:80%;" />

### 动态初始化

<img src="image/image-20220430140101699.png" alt="image-20220430140101699" style="zoom:80%;" />

### 静态初始化

<img src="image/image-20220430141908957.png" alt="image-20220430141908957" style="zoom: 80%;" />

### 索引越界

访问了未分配的索引地址

<img src="image/image-20220430142244374.png" alt="image-20220430142244374" style="zoom:80%;" />

### 空指针异常

<img src="image/image-20220430142340138.png" alt="image-20220430142340138" style="zoom: 80%;" />

## 内存分配

<img src="image/image-20220430140741969.png" alt="image-20220430140741969" style="zoom:80%;" />

<img src="image/image-20220430140704352.png" alt="image-20220430140704352" style="zoom:80%;" />

<img src="image/image-20220430140929565.png" alt="image-20220430140929565" style="zoom:80%;" />

### 数组内存

<img src="image/image-20220430141439791.png" alt="image-20220430141439791" style="zoom:80%;" />

#### 数组指向地址相同的情况

<img src="image/image-20220430141722113.png" alt="image-20220430141722113" style="zoom:80%;" />

![image-20220430141737225](image/image-20220430141737225.png)

<img src="image/image-20220430141755996.png" alt="image-20220430141755996" style="zoom:80%;" />

## 遍历

```java
int[] arr = {1,2,3,4,5};
for(int x = 0; x < 5; x++){
    System.out.println(arr[x]);
}
```

### 获取数组元素的个数

<img src="image/image-20220430142828342.png" alt="image-20220430142828342" style="zoom:67%;" />

<img src="image/image-20220430142934382.png" alt="image-20220430142934382" style="zoom:67%;" />

## 最值

```java
int[] arr = {1,2,3,4,5};
int max = arr[0];
for(int x = 1; x < 5; x++){
    if (arr[x] > max){
        max = arr[x];
    }
}
System.out.println(max);
```

## 方法method

<img src="image/image-20220430144406824.png" alt="image-20220430144406824" style="zoom:80%;" />

### 带参数调用

<img src="image/image-20220430144921812.png" alt="image-20220430144921812" style="zoom:80%;" />

### 带返回值调用

<img src="image/image-20220430145934657.png" alt="image-20220430145934657" style="zoom:80%;" />

<img src="image/image-20220430150307980.png" alt="image-20220430150307980" style="zoom:80%;" />

### 方法重载

<img src="image/image-20220430150630940.png" alt="image-20220430150630940" style="zoom:80%;" />

**与返回值类型无关，必须在同一方法内**

### 方法参数传递

#### 基础类型

<img src="image/image-20220430151544753.png" alt="image-20220430151544753" style="zoom:80%;" />

#### 引用类型

<img src="image/image-20220430152148194.png" alt="image-20220430152148194" style="zoom:80%;" />

**引用类型参数是用的是内存中的地址，所以会影响**