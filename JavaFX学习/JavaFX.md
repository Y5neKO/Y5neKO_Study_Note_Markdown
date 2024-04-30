
# 环境准备
下载对应版本JavaFX，解压出来如下：
![[Pasted image 20240429164508.png]]
bin目录下所有dll放入jdk的bin目录，lib目录下的所有jar包添加进项目库，src为source源。
# Scene图
## 概述
Scene图是一种树形数据结构，它排列（和分组）图形对象以便于逻辑表示。 它还允许图形引擎以最有效的方式渲染对象， 完全或部分跳过在最终图像中看不到的对象。 下图显示了JavaFX场景图架构的一个示例。
![[Pasted image 20240429164815.png]]
在架构的最顶端有一个`Stage`。 `Stage`是原生操作系统窗口的JavaFX表示。 在任何给定的时间，阶段可以有一个单一的`Scene`连接到它。 场景是JavaFX场景图的容器。
JavaFX `Stage`图中的所有元素都表示为`Node`对象。 节点有三种类型：根、分支和叶。 根节点是唯一没有父节点的节点 直接包含在一个场景中，如上图所示。 分支和叶节点之间的区别在于叶节点没有子节点。
在scene图中，父节点的许多属性由子节点共享。 例如，应用于父节点的转换或事件也将递归地应用于其子节点。 因此，可以将复杂的节点层次结构视为单个节点，以简化编程模型。 我们将在后面的章节中探索转换和事件。
一个"Hello World" scene图的例子可以在下图中看到。
![[Pasted image 20240429224324.png]]
```java
package com.y5neko;  
  
import javafx.application.Application;  
import javafx.scene.Parent;  
import javafx.scene.Scene;  
import javafx.scene.layout.StackPane;  
import javafx.scene.text.Text;  
import javafx.stage.Stage;  
  
public class Main extends Application {  
    private Parent createContent() {  
        return new StackPane(new Text("Hello World"));  
    }  
  
    @Override  
    public void start(Stage stage) throws Exception {  
        stage.setScene(new Scene(createContent(), 300, 300));  
        stage.show();  
    }  
  
    public static void main(String[] args) {  
        launch(args);  
    }  
}
```
运行结果如下：
![[Pasted image 20240429224453.png]]
> 一个节点最多可以有1个父节点。
> "活动"（附加到当前可见场景）场景图中的节点只能从JavaFX应用程序线程修改。

## Transformations
下面将演示3种最常见的转换。
```java
package com.y5neko;  
  
import javafx.application.Application;  
import javafx.scene.Parent;  
import javafx.scene.Scene;  
import javafx.scene.layout.Pane;  
import javafx.scene.paint.Color;  
import javafx.scene.shape.Rectangle;  
import javafx.stage.Stage;  
  
public class TransformApp extends Application {  
  
    private Parent createContent() {  
        Rectangle box = new Rectangle(100, 50, Color.BLUE);  
  
        transform(box);  
  
        return new Pane(box);  
    }  
  
    private void transform(Rectangle box) {  
        // we will apply transformations here  
    }  
  
    @Override  
    public void start(Stage stage) throws Exception {  
        stage.setScene(new Scene(createContent(), 300, 300, Color.GRAY));  
        stage.show();  
    }  
  
    public static void main(String[] args) {  
        launch(args);  
    }  
}
```
运行结果如下： 
![[Pasted image 20240429224918.png]]
在JavaFX中，一个简单的转换可以发生在三个轴之一：X，Y或Z。 示例应用程序是2D的，因此我们将只考虑X和Y轴。
### Translate
在JavaFX和计算机图形学中，`translate`意味着移动。 我们可以在X轴上平移100像素，在Y轴上平移200像素。
```java
private void transform(Rectangle box) {
    box.setTranslateX(100);
    box.setTranslateY(200);
}
```
运行结果如下：
![[Pasted image 20240429225204.png]]
### Scale
可以应用缩放以使节点更大或更小。 缩放值是一个比率。 默认情况下，节点在每个轴上的缩放值为1（100%）。 我们可以通过在X和Y轴上应用1.5的缩放比例来放大我们的盒子。
```java
private void transform(Rectangle box) {
    // previous code

    box.setScaleX(1.5);
    box.setScaleY(1.5);
}
```
### Rotate
节点的旋转决定了渲染节点的角度。 在2D中，唯一合理的旋转轴是Z轴。 让我们把盒子旋转30度。
```java
private void transform(Rectangle box) {
    // previous code

    box.setRotate(30);
}
```
运行结果如下：
![[Pasted image 20240429225929.png]]
## Event Handling
事件通知发生了重要的事情。 事件通常是事件系统的"原语"（也称为事件总线）。 一般来说，事件系统有以下三个职责：
- `fire`（触发）事件
- 通知`listeners`（相关方）有关事件
- `handle`（处理）事件
事件通知机制由JavaFX平台自动完成。 因此只考虑如何触发事件，侦听事件以及如何处理。
首先创建一个自定义事件。
```java
package com.y5neko;  
  
import javafx.event.Event;  
import javafx.event.EventType;  
  
public class Handling extends Event {  
    public static final EventType<Handling> ANY = new EventType<>(Event.ANY, "ANY");  
  
    public static final EventType<Handling> LOGIN_SUCCEEDED = new EventType<>(ANY, "LOGIN_SUCCEEDED");  
  
    public static final EventType<Handling> LOGIN_FAILED = new EventType<>(ANY, "LOGIN_FAILED");  
  
    public Handling(EventType<? extends Event> eventType) {  
        super(eventType);  
    }  
}
```
由于事件类型是固定的，它们通常与事件在同一个源文件中创建。 我们可以看到有两种特定类型的事件：LOGIN_SUCCEEDED和LOGIN_FAILED。 我们可以监听这些特定类型的事件：
```java
Node node = ...
node.addEventHandler(UserEvent.LOGIN_SUCCEEDED, event -> {
    // handle event
});
```
或者，我们可以处理任何`UserEvent`：
```java
Node node = ...
node.addEventHandler(UserEvent.ANY, event -> {
    // handle event
});
```
最后，我们可以构建和触发自己的事件：
```java
UserEvent event = new UserEvent(UserEvent.LOGIN_SUCCEEDED);
Node node = ...
node.fireEvent(event);
```
例如，当用户尝试登录应用程序时，可能会触发`LOGIN_SUCCEEDED`或`LOGIN_FAILED`。 根据登录结果，我们可以允许用户访问应用程序或将其锁定在应用程序之外。 虽然同样的功能可以通过简单的`if`语句实现， 事件系统有一个显著的优点。 事件系统被设计成能够在各种模块（子系统）之间进行通信， 一个应用程序，而不紧密耦合它们。 因此，当用户登录时，音频系统可能会播放声音。 因此，在其自己的模块中维护所有音频相关代码。 但是，我们不会深入研究建筑风格。
### 输入事件
按键和鼠标事件是JavaFX中最常见的事件类型。 每个`Node`都提供了所谓的“便利方法”来处理这些事件。 例如，我们可以在按下按钮时运行一些代码：
```java
Button button = ...
button.setOnAction(event -> {
    // button was pressed
});
```
为了获得更大的灵活性，我们还可以使用以下方法：
```java
Button button = ...
button.setOnMouseEntered(e -> ...);
button.setOnMouseExited(e -> ...);
button.setOnMousePressed(e -> ...);
button.setOnMouseReleased(e -> ...);
```
上面的对象`e`属于类型`MouseEvent`，可以通过查询来获得有关事件的各种信息， 例如`x`和`y`位置、点击次数等。 最后，我们可以对keys做同样的事情：
```java
Button button = ...
button.setOnKeyPressed(e -> ...);
button.setOnKeyReleased(e -> ...);
```
这里的对象`e`属于类型`KeyEvent`，它携带有关键代码的信息，然后可以映射这些信息 键盘上的一个真实的物理键。
## Timing
理解JavaFX UI控件的创建和控件的显示之间的时间差异非常重要。 在创建UI控件时—通过直接API对象创建或通过FXML—您可能会丢失某些屏幕几何值，例如窗口的尺寸。这是以后可用的，在屏幕显示给用户的瞬间。 该显示事件称为OnShown，是指分配窗口和完成最终布局计算的时间。

为了演示这一点，考虑以下程序，该程序在创建UI控件时显示屏幕尺寸，在显示屏幕时显示屏幕尺寸。 下面的屏幕截图显示了程序的运行。 在创建UI控件（new VBox(), new Scene(), primaryStage.setScene()）时，没有可用的实际窗口高度和宽度值，这可以通过未定义的“NaN”值来证明。
![[Pasted image 20240430093300.png]]
但是，一旦显示窗口，宽度和高度的值就可用了。 程序为OnShown事件注册一个事件处理程序，并准备相同的输出。
```java
package com.y5neko;  
  
import javafx.application.Application;  
import javafx.beans.binding.Bindings;  
import javafx.beans.property.DoubleProperty;  
import javafx.beans.property.SimpleDoubleProperty;  
import javafx.scene.Scene;  
import javafx.scene.control.Label;  
import javafx.scene.control.TextField;  
import javafx.scene.layout.GridPane;  
import javafx.scene.layout.HBox;  
import javafx.scene.layout.VBox;  
import javafx.stage.Stage;  
  
import static javafx.geometry.Pos.CENTER;  
  
public class StartVsShownJavaFXApp extends Application {  
  
    private DoubleProperty startX = new SimpleDoubleProperty();  
    private DoubleProperty startY = new SimpleDoubleProperty();  
    private DoubleProperty shownX = new SimpleDoubleProperty();  
    private DoubleProperty shownY = new SimpleDoubleProperty();  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        Label startLabel = new Label("Start Dimensions");  
        TextField startTF = new TextField();  
        startTF.textProperty().bind(  
                Bindings.format("(%.1f, %.1f)", startX, startY)  
        );  
  
        System.out.println(startX);  
        System.out.println(startY);  
  
        Label shownLabel = new Label("Shown Dimensions");  
        TextField shownTF = new TextField();  
        shownTF.textProperty().bind(  
                Bindings.format("(%.1f, %.1f)", shownX, shownY)  
        );  
  
        GridPane gp = new GridPane();  
        gp.add( startLabel, 0, 0 );  
        gp.add( startTF, 1, 0 );  
        gp.add( shownLabel, 0, 1 );  
        gp.add( shownTF, 1, 1 );  
        gp.setHgap(10);  
        gp.setVgap(10);  
  
        HBox hbox = new HBox(gp);  
        hbox.setAlignment(CENTER);  
  
        VBox vbox = new VBox(hbox);  
        vbox.setAlignment(CENTER);  
  
        Scene scene = new Scene( vbox, 480, 320 );  
  
        primaryStage.setScene( scene );  
  
        // before show()...I just set this to 480x320, right?  
        startX.set( primaryStage.getWidth() );  
        startY.set( primaryStage.getHeight() );  
  
        primaryStage.setOnShown( (evt) -> {  
            shownX.set( primaryStage.getWidth() );  
            shownY.set( primaryStage.getHeight() );  // all available now  
        });  
  
        primaryStage.setTitle("Start Vs. Shown");  
        primaryStage.show();  
    }  
  
    public static void main(String[] args) {  
        launch(args);  
    }  
}
```
# UI控件
## ChoiceBox
这篇文章展示了`ChoiceBox`。 `ChoiceBox`控件是一个值列表，用户可以从中进行选择。 在这个特定的实现中，有一个空值，它使选择成为可选的。
下面为一个示例：
将`Label`、`ChoiceBox`和`Button`放入HBox。 在保存`Button`上设置一个操作，打印出该值。
`ChoiceBox`最简单的用法是用String填充它。 本文中的`ChoiceBox`构建在一个名为`Pair`的JavaFX类上。 `Pair`是任何键/值对的通用容器，可以用来代替域或其他特殊用途的对象。 字符串只有在不需要操作就可以使用或者可以一致地解码的情况下才应该使用。
`ChoiceBox`最简单的用法是用String填充它。 本文中的`ChoiceBox`构建在一个名为`Pair`的JavaFX类上。 `Pair`是任何键/值对的通用容器，可以用来代替域或其他特殊用途的对象。 字符串只有在不需要操作就可以使用或者可以一致地解码的情况下才应该使用。
```java
package com.y5neko;  
  
import javafx.application.Application;  
import javafx.geometry.Insets;  
import javafx.geometry.Pos;  
import javafx.scene.Scene;  
import javafx.scene.control.Button;  
import javafx.scene.control.ChoiceBox;  
import javafx.scene.control.Label;  
import javafx.scene.layout.HBox;  
import javafx.stage.Stage;  
import javafx.util.Pair;  
import javafx.util.StringConverter;  
  
import java.util.ArrayList;  
import java.util.List;  
  
public class ChoiceApp extends Application {  
    private final static Pair<String, String> EMPTY_PAIR = new Pair<>("", "");  
    private final ChoiceBox<Pair<String,String>> assetClass = new ChoiceBox<>();  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        Label label = new Label("Asset Class:");  
        assetClass.setPrefWidth(200);  
        assetClass.setValue(new Pair<>("Equipment", "20000"));  
        Button saveButton = new Button("Save");  
  
        HBox hbox = new HBox(  
                label,  
                assetClass,  
                saveButton);  
        hbox.setSpacing( 10.0d );  
        hbox.setAlignment(Pos.CENTER );  
        hbox.setPadding( new Insets(40) );  
  
        Scene scene = new Scene(hbox);  
  
        initChoice();  
  
        saveButton.setOnAction(  
                (evt) -> System.out.println("saving " + assetClass.getValue())  
        );  
  
        primaryStage.setTitle("ChoicesApp");  
        primaryStage.setScene( scene );  
        primaryStage.show();  
  
    }  
  
  
    private void initChoice() {  
  
        List<Pair<String,String>> assetClasses = new ArrayList<>();  
        assetClasses.add( new Pair<>("Equipment", "20000"));  
        assetClasses.add( new Pair<>("Furniture", "21000"));  
        assetClasses.add( new Pair<>("Investment", "22000"));  
  
        assetClass.setConverter( new StringConverter<Pair<String,String>>() {  
            @Override  
            public String toString(Pair<String, String> pair) {  
                return pair.getKey();  
            }  
  
            @Override  
            public Pair<String, String> fromString(String string) {  
                return null;  
            }  
        });  
  
        assetClass.getItems().add( EMPTY_PAIR );  
        assetClass.getItems().addAll( assetClasses );  
        assetClass.setValue(new Pair<>("Equipment", "20000"));  
  
    }  
}
```
运行结果如下： 
![[Pasted image 20240430110534.png]]
![[Pasted image 20240430110615.png]]
### StringConverter
当使用一个复杂的对象来支持一个`ChoiceBox`时，需要一个`StringConverter`。 这个对象将一个String序列化到`ChoiceBox`和从`Pair`序列化。 对于这个程序，只需要编写toString（）来替换undefined对象的默认toString（）。 (Both toString和fromString需要一个实现才能编译。）
空对象EMPTY_PAIR用于防止空指针插入。 从assetClass（）.getValue（）返回的值可以被一致地访问和比较，而不需要添加特殊的null处理逻辑。
```java
    private final static Pair<String, String> EMPTY_PAIR = new Pair<>("", "");

    private void initChoice() {

        List<Pair<String,String>> assetClasses = new ArrayList<>();
        assetClasses.add( new Pair("Equipment", "20000"));
        assetClasses.add( new Pair("Furniture", "21000"));
        assetClasses.add( new Pair("Investment", "22000"));

        assetClass.setConverter( new StringConverter<Pair<String,String>>() {
            @Override
            public String toString(Pair<String, String> pair) {
                return pair.getKey();
            }

            @Override
            public Pair<String, String> fromString(String string) {
                return null;
            }
        });

        assetClass.getItems().add( EMPTY_PAIR );
        assetClass.getItems().addAll( assetClasses );
        assetClass.setValue( EMPTY_PAIR );

    }
```
选择框用于从值列表中进行选择。 当值列表是复杂类型时，提供StringFormatter将列表对象序列化为可表示的对象。 如果可能，请使用空对象（而不是null）来支持可选值。
## ComboBox
`ComboBox`是一个混合控件，它提供一个值列表和一个编辑控件。 本文演示了`ComboBox`的基本形式，这是一个基于复杂数据结构的不可编辑的项目列表。
下面是一个示例：
向HBox添加了一个Label、一个ComboBox和一个Button。 ComboBox被实例化为一个字段，并在后面的initCombo（）方法中初始化。 处理程序放在保存按钮上，如果选择了某个项目，则输出一个值，如果未选择任何项目，则输出一条特殊消息。
```java
package com.y5neko;  
  
import javafx.application.Application;  
import javafx.geometry.Insets;  
import javafx.geometry.Pos;  
import javafx.scene.Scene;  
import javafx.scene.control.*;  
import javafx.scene.layout.HBox;  
import javafx.stage.Stage;  
import javafx.util.Callback;  
import javafx.util.Pair;  
  
import java.util.ArrayList;  
import java.util.List;  
  
public class CombosApp extends Application {  
    private final ComboBox<Pair<String, String>> account = new ComboBox<>();  
  
    private final static Pair<String, String> EMPTY_PAIR = new Pair<>("", "");  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        Label accountsLabel = new Label("Account:");  
        account.setPrefWidth(200);  
        Button saveButton = new Button("Save");  
  
        HBox hbox = new HBox(  
                accountsLabel,  
                account,  
                saveButton);  
        hbox.setSpacing( 10.0d );  
        hbox.setAlignment(Pos.CENTER );  
        hbox.setPadding( new Insets(40) );  
  
        Scene scene = new Scene(hbox);  
  
        initCombo();  
  
        saveButton.setOnAction( (evt) -> {  
            if( account.getValue().equals(EMPTY_PAIR) ) {  
                System.out.println("no save needed; no item selected");  
            } else {  
                System.out.println("saving " + account.getValue());  
            }  
        });  
  
        primaryStage.setTitle("CombosApp");  
        primaryStage.setScene( scene );  
        primaryStage.show();  
    }  
  
        private void initCombo() {  
  
        List<Pair<String,String>> accounts = new ArrayList<>();  
  
        accounts.add( new Pair<>("Auto Expense", "60000") );  
        accounts.add( new Pair<>("Interest Expense", "61000") );  
        accounts.add( new Pair<>("Office Expense", "62000") );  
        accounts.add( new Pair<>("Salaries Expense", "63000") );  
  
        account.getItems().add( EMPTY_PAIR );  
        account.getItems().addAll( accounts );  
        account.setValue( EMPTY_PAIR );  
  
        Callback<ListView<Pair<String,String>>, ListCell<Pair<String,String>>> factory =  
            (lv) ->  
                    new ListCell<Pair<String,String>>() {  
                        @Override  
                        protected void updateItem(Pair<String, String> item, boolean empty) {  
                            super.updateItem(item, empty);  
                            if( empty ) {  
                                setText("");  
                            } else {  
                                setText( item.getKey() );  
                            }  
                        }  
                    };  
  
        account.setCellFactory( factory );  
        account.setButtonCell( factory.call( null ) );  
    }  
}
```
### CellFactory
initCombo（）方法将几个费用帐户添加到`List`中。 在添加空的`List`对象之后，此`ComboBox`被添加到`Pair`项。 初始值设置为EMPTY_PAIR，它是一个常量。

如果没有指定，`ComboBox`将使用对象的toString（）方法（在本文中，是一个`Pair`）来呈现一个后台对象。 对于字符串，例如"是"或"否"选择，不需要额外的代码。 然而，`Pair`的toString（）将输出人类可读的键和机器首选的值。 此`ComboBox`的要求是在显示器中仅使用人类可读的键。

为此，提供了一个cellFactory，它将配置一个以`ListCell`键为内容的`Pair`对象。 `Callback`类型是冗长的，但工厂的要点是在匿名内部类的updateItem（）方法中设置`ListCell`的文本。 请注意，必须调用超类方法。

`Callback`在setButtonCell（）方法中用于为编辑控件提供单元格。 请注意，此程序不可编辑，这是默认设置。 但是，需要factory.call（null），否则只有弹出菜单的内容将被正确格式化，控件的视图将返回到toString（）。
本文介绍了`ComboBox`的一个简单用法。 由于此控件不可编辑，因此可以替换`ChoiceBox`。 对于不可编辑的图形渲染（例如状态值的颜色编码形状），仍然需要`ComboBox`来定义控件中使用的特定`Node`。
## ListView
### JavaFX中的ListView Filtering
本文演示了如何在JavaFX应用程序中过滤ListView。 应用程序管理两个列表。 一个列表包含数据模型中的所有项。 第二个列表包含当前正在查看的项目。 作为过滤器存储的比较逻辑碎片在两者之间进行调解。
大量使用绑定来保持数据结构与用户选择的内容同步。
这个屏幕截图显示了应用程序，它包含一个设置过滤器的ToggleView的顶行和一个包含对象的ListView。
#### 数据结构
该程序以一个域模型Player和一个Player对象数组开始。
```java
static class Player {

	private final String team;
	private final String playerName;
	public Player(String team, String playerName) {
		this.team = team;
		this.playerName = playerName;
	}
	public String getTeam() {
		return team;
	}
	public String getPlayerName() {
		return playerName;
	}
	@Override
	public String toString() { return playerName + " (" + team + ")"; }
}
```
Player类包含一对字段：team和playerName。 提供了toString（），以便在将对象添加到ListView（稍后介绍）时，不需要自定义ListCell类。
这个例子的测试数据是美国棒球运动员的列表。
```java
Player[] players = {new Player("BOS", "David Ortiz"),
                    new Player("BOS", "Jackie Bradley Jr."),
                    new Player("BOS", "Xander Bogarts"),
                    new Player("BOS", "Mookie Betts"),
                    new Player("HOU", "Jose Altuve"),
                    new Player("HOU", "Will Harris"),
                    new Player("WSH", "Max Scherzer"),
                    new Player("WSH", "Bryce Harper"),
                    new Player("WSH", "Daniel Murphy"),
                    new Player("WSH", "Wilson Ramos") };
```
#### Model
如本文开头所述，ListView过滤主要围绕两个列表的管理。 所有对象都存储在包装的ObservableList playersProperty中，当前可见的对象存储在包装的FilteredList，viewablePlayersProperty中。 viewablePlayersProperty是基于playersProperty构建的，因此对符合FilteredList条件的播放器进行的更新也会对viewablePlayers进行更新。
```java
ReadOnlyObjectProperty<ObservableList<Player>> playersProperty =
		new SimpleObjectProperty<>(FXCollections.observableArrayList());

ReadOnlyObjectProperty<FilteredList<Player>> viewablePlayersProperty =
		new SimpleObjectProperty<FilteredList<Player>>(
				new FilteredList<>(playersProperty.get()
						));
```
filterProperty（）是一种方便，允许调用者绑定到底层Predicate。
```java
ObjectProperty<Predicate<? super Player>> filterProperty =
	viewablePlayersProperty.get().predicateProperty();
```
UI根是一个VBox，其中包含一个ToggleView的HBox和一个ListView。
```java
VBox vbox = new VBox();
vbox.setPadding( new Insets(10));
vbox.setSpacing(4);

HBox hbox = new HBox();
hbox.setSpacing( 2 );

ToggleGroup filterTG = new ToggleGroup();
```
#### Filtering Action
一个处理程序被附加到ToggleList中，它将修改filterProperty。 每个ToggleButton都在userData字段中提供一个Predicate。 toggle设置filter属性时使用提供的Predicate。 这段代码设置了“全部显示”ToggleButton的特殊情况。
```java
@SuppressWarnings("unchecked")
EventHandler<ActionEvent> toggleHandler = (event) -> {
		ToggleButton tb = (ToggleButton)event.getSource();
	    Predicate<Player> filter = (Predicate<Player>)tb.getUserData();
	    filterProperty.set( filter );
	};

ToggleButton tbShowAll = new ToggleButton("Show All");
tbShowAll.setSelected(true);
tbShowAll.setToggleGroup( filterTG );
tbShowAll.setOnAction(toggleHandler);
tbShowAll.setUserData( (Predicate<Player>) (Player p) -> true);
```
筛选特定团队的切换表是在运行时基于Players数组创建的。 此Stream执行以下操作。
1. 将球员列表提取为团队字符串的不同列表
2. 为每个团队创建一个ToggleButton字符串
3. 为每个要用作过滤器的ToggleButton设置谓词
4. 收集Toggle标签以添加到HBox容器中
```java
List<ToggleButton> tbs = Arrays.asList( players)
		.stream()
		.map( (p) -> p.getTeam() )
		.distinct()
		.map( (team) -> {
			ToggleButton tb = new ToggleButton( team );
			tb.setToggleGroup( filterTG );
			tb.setOnAction( toggleHandler );
			tb.setUserData( (Predicate<Player>) (Player p) -> team.equals(p.getTeam()) );
			return tb;
		})
		.collect(Collectors.toList());

hbox.getChildren().add( tbShowAll );
hbox.getChildren().addAll( tbs );
```
#### ListView
下一步将创建ListView并将ListView绑定到viewablePlayersProperty。 这使ListView能够根据更改的筛选器接收更新。
```java
ListView<Player> lv = new ListView<>();
lv.itemsProperty().bind( viewablePlayersProperty );
```
程序的其余部分创建场景并显示舞台。 onShown将数据集加载到playersProperty和viewablePlayersProperty列表中。 尽管在这个程序的特殊版本中，两个列表是同步的，但是如果股票过滤器与"无过滤器"完全不同，则不需要修改此代码。
```java
vbox.getChildren().addAll( hbox, lv );

Scene scene = new Scene(vbox);

primaryStage.setScene( scene );
		primaryStage.setOnShown((evt) -> {
			playersProperty.get().addAll( players );
		});

primaryStage.show();
```
本文使用绑定将可查看的Player对象列表绑定到ListView。 当选择切换按钮时，可查看的播放器被更新。 这个选择应用了一个过滤器到一个完整的播放器集，它被单独维护为一个过滤列表。 绑定用于保持UI同步，并允许在设计中分离关注点。
#### 完整代码
```java
package com.y5neko;  
  
import javafx.application.Application;  
import javafx.beans.property.ObjectProperty;  
import javafx.beans.property.ReadOnlyObjectProperty;  
import javafx.beans.property.SimpleObjectProperty;  
import javafx.collections.FXCollections;  
import javafx.collections.ObservableList;  
import javafx.collections.transformation.FilteredList;  
import javafx.event.ActionEvent;  
import javafx.event.EventHandler;  
import javafx.geometry.Insets;  
import javafx.scene.Scene;  
import javafx.scene.control.ListView;  
import javafx.scene.control.ToggleButton;  
import javafx.scene.control.ToggleGroup;  
import javafx.scene.layout.HBox;  
import javafx.scene.layout.VBox;  
import javafx.stage.Stage;  
  
import java.util.Arrays;  
import java.util.List;  
import java.util.function.Predicate;  
import java.util.stream.Collectors;  
  
public class FilterListApp extends Application {  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
       //  
       // 创建测试数据  
       //  
       Player[] players = {new Player("BOS", "David Ortiz"),  
                           new Player("BOS", "Jackie Bradley Jr."),  
                           new Player("BOS", "Xander Bogarts"),  
                           new Player("BOS", "Mookie Betts"),  
                           new Player("HOU", "Jose Altuve"),  
                           new Player("HOU", "Will Harris"),  
                           new Player("WSH", "Max Scherzer"),  
                           new Player("WSH", "Bryce Harper"),  
                           new Player("WSH", "Daniel Murphy"),  
                           new Player("WSH", "Wilson Ramos") };  
  
       //  
       // 设置模型，该模型是两个玩家列表和一个筛选条件  
       //  
       ReadOnlyObjectProperty<ObservableList<Player>> playersProperty =  
             new SimpleObjectProperty<>(FXCollections.observableArrayList());  
  
       ReadOnlyObjectProperty<FilteredList<Player>> viewablePlayersProperty =  
             new SimpleObjectProperty<FilteredList<Player>>(  
                   new FilteredList<>(playersProperty.get()  
                         ));  
  
       ObjectProperty<Predicate<? super Player>> filterProperty =  
          viewablePlayersProperty.get().predicateProperty();  
  
  
       //  
       // 构建 UI       //       VBox vbox = new VBox();  
       vbox.setPadding( new Insets(10));  
       vbox.setSpacing(4);  
  
       HBox hbox = new HBox();  
       hbox.setSpacing( 2 );  
  
       ToggleGroup filterTG = new ToggleGroup();  
  
       //  
       // toggleHandler 操作将根据所选的 TB 设置筛选器  
       //  
       @SuppressWarnings("unchecked")  
       EventHandler<ActionEvent> toggleHandler = (event) -> {  
             ToggleButton tb = (ToggleButton)event.getSource();  
              Predicate<Player> filter = (Predicate<Player>)tb.getUserData();  
              filterProperty.set( filter );  
          };  
  
       ToggleButton tbShowAll = new ToggleButton("Show All");  
       tbShowAll.setSelected(true);  
       tbShowAll.setToggleGroup( filterTG );  
       tbShowAll.setOnAction(toggleHandler);  
       tbShowAll.setUserData( (Predicate<Player>) (Player p) -> true);  
  
       //  
       // 从 Player 对象创建不同的团队列表，然后创建  
       // ToggleButtons（切换按钮）  
       //  
       List<ToggleButton> tbs = Arrays.asList( players)  
             .stream()  
             .map( (p) -> p.getTeam() )  
             .distinct()  
             .map( (team) -> {  
                ToggleButton tb = new ToggleButton( team );  
                tb.setToggleGroup( filterTG );  
                tb.setOnAction( toggleHandler );  
                tb.setUserData( (Predicate<Player>) (Player p) -> team.equals(p.getTeam()) );  
                return tb;  
             })  
             .collect(Collectors.toList());  
  
       hbox.getChildren().add( tbShowAll );  
       hbox.getChildren().addAll( tbs );  
  
       //  
       // 创建绑定到 viewablePlayers 属性的 ListView       //       ListView<Player> lv = new ListView<>();  
       lv.itemsProperty().bind( viewablePlayersProperty );  
  
       vbox.getChildren().addAll( hbox, lv );  
  
       Scene scene = new Scene(vbox);  
  
       primaryStage.setScene( scene );  
       primaryStage.setOnShown((evt) -> {  
          playersProperty.get().addAll( players );  
       });  
  
       primaryStage.show();  
  
    }  
  
    public static void main(String[] args) {  
       launch(args);  
    }  
  
    static class Player {  
  
       private final String team;  
       private final String playerName;  
       public Player(String team, String playerName) {  
          this.team = team;  
          this.playerName = playerName;  
       }  
       public String getTeam() {  
          return team;  
       }  
       public String getPlayerName() {  
          return playerName;  
       }  
       @Override  
       public String toString() { return playerName + " (" + team + ")"; }  
    }  
}
```
运行结果如下：
![[Pasted image 20240430163242.png]]
## TableView
对于JavaFX业务应用程序，`TableView`是一个必不可少的控件。 当您需要在扁平的行/列结构中显示多个记录时，请使用`TableView`。 此示例显示了`TableView`的基本元素，并演示了应用JavaFX绑定时组件的强大功能。
演示应用程序是一个`TableView`和Buttons的pair。 `TableView`有四个表列：价格，项目，价格，税收。 `TableView`在三行中显示三个对象：机械键盘，产品键盘，O型环。 
禁用的逻辑取决于`TableView`中的选择。 最初，没有选择任何项目，因此两个选项都被禁用。 如果选择了任何项目（以下屏幕截图中的第一个项目），则会启用库存`Button`。     还启用了Tax `Button`，但这需要咨询Tax值。
如果所选项目的Tax值为false，则Tax `Button`将被禁用。 此屏幕截图显示了选定的第二个项目。 库存`Button`已启用，但税`Button`未启用。
### 模型及声明
`TableView`是基于一个称为Item的POJO模型。
```java
public class Item {

    private final String sku;
    private final String descr;
    private final Float price;
    private final Boolean taxable;

    public Item(String sku, String descr, Float price, Boolean taxable) {
        this.sku = sku;
        this.descr = descr;
        this.price = price;
        this.taxable = taxable;
    }

    public String getSku() {
        return sku;
    }

    public String getDescr() {
        return descr;
    }

    public Float getPrice() {
        return price;
    }

    public Boolean getTaxable() {
        return taxable;
    }
}
```
`TableView`和`TableColumn`在声明中使用泛型。 对于`TableView`，类型参数是Item。 对于TableColumns，类型参数是Item和字段类型。 `TableColumn`的构造函数接受一个列名。 在本例中，列名与实际字段名略有不同。
```java
        TableView<Item> tblItems = new TableView<>();

        TableColumn<Item, String> colSKU = new TableColumn<>("SKU");
        TableColumn<Item, String> colDescr = new TableColumn<>("Item");
        TableColumn<Item, Float> colPrice = new TableColumn<>("Price");
        TableColumn<Item, Boolean> colTaxable = new TableColumn<>("Tax");

        tblItems.getColumns().addAll(
            colSKU, colDescr, colPrice, colTaxable
        );
```
向`TableView`添加模型项是通过向基础集合添加项来完成的。
```java
        tblItems.getItems().addAll(
            new Item("KBD-0455892", "Mechanical Keyboard", 100.0f, true),
            new Item( "145256", "Product Docs", 0.0f, false ),
            new Item( "OR-198975", "O-Ring (100)", 10.0f, true)
        );
```
此时，已配置`TableView`并添加了测试数据。 但是，如果您要查看该程序，则会看到三个空行。 这是因为JavaFX缺少POJO和TableColumns之间的链接。 使用cellValueFactory将该链接添加到TableColumns。
```java
        colSKU.setCellValueFactory( new PropertyValueFactory<>("sku") );
        colDescr.setCellValueFactory( new PropertyValueFactory<>("descr") );
        colPrice.setCellValueFactory( new PropertyValueFactory<>("price") );
        colTaxable.setCellValueFactory( new PropertyValueFactory<>("taxable") );
```
此时查看程序将在相应的列中显示数据。
### Selection
要检索`TableView`中的选定项，请使用单独的selectionModel对象。 调用tblItems.getSelectionModel（）返回一个包含属性"selectedItem"的对象。 这可以在一个方法中检索和使用，比如调出一个编辑细节屏幕。 或者，getSelectionModel（）可以返回绑定表达式的JavaFX属性"selectedItemProperty"。
在演示应用中，两个参数绑定到`TableView`的selectionModel。 如果没有绑定，您可以添加侦听器来检查选择并在Button上进行类似setDisabled（）的调用。 在`TableView`选择之前，您还需要初始化逻辑来处理没有选择的情况。 绑定语法在声明性语句中表达此逻辑，该语句可以在一行中处理侦听器和初始化。
```java
        Button btnInventory = new Button("Inventory");
        Button btnCalcTax = new Button("Tax");

        btnInventory.disableProperty().bind(
            tblItems.getSelectionModel().selectedItemProperty().isNull()
        );
```
如果没有选择任何项目，btnInventory禁用属性将为true（islogy（））。 当屏幕首次显示时，不进行任何选择，`Button`被禁用。 一旦做出任何选择，btnInventory将被启用（disable=false）。

btnCalcTax逻辑稍微复杂一些。 btnCalcTax在没有选择时也被禁用。 但是，btnCalcTax也会考虑selectedItem的内容。 复合绑定或（）用于连接这两个条件。 和前面一样，有一个iscurry（）表达式表示没有选择。 Bindings.select（）检查Item.taxable的值。 一个真实的应税项目将启用btnCalcTax，而一个虚假的项目将禁用`Button`。
```java
        btnCalcTax.disableProperty().bind(
            tblItems.getSelectionModel().selectedItemProperty().isNull().or(
                    Bindings.select(
                        tblItems.getSelectionModel().selectedItemProperty(),
                        "taxable"
                    ).isEqualTo(false)
            )
        );
```
`Bindings.select（）`是从对象中提取字段的机制。 selectedItemProperty（）是更改的selectedItem，“taxable”是指向taxable字段的single-hop路径。
这个例子展示了如何基于POJO设置`TableView`。 它还提供了一对功能强大的绑定表达式，允许您链接相关控件，而无需编写额外的侦听器和初始化代码。 `TableView`是JavaFX业务应用程序开发人员不可或缺的控件。 它将是显示结构化项目列表的最佳和最熟悉的控件。
### 完整代码
```java
package com.y5neko.tableview;  
  
import javafx.application.Application;  
import javafx.beans.binding.Bindings;  
import javafx.geometry.Insets;  
import javafx.scene.Scene;  
import javafx.scene.control.Button;  
import javafx.scene.control.TableColumn;  
import javafx.scene.control.TableView;  
import javafx.scene.control.cell.PropertyValueFactory;  
import javafx.scene.layout.HBox;  
import javafx.scene.layout.Priority;  
import javafx.scene.layout.VBox;  
import javafx.stage.Stage;  
  
public class TableSelectApp extends Application {  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        TableView<Item> tblItems = new TableView<>();  
        tblItems.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);  
  
        VBox.setVgrow(tblItems, Priority.ALWAYS );  
  
        TableColumn<Item, String> colSKU = new TableColumn<>("SKU");  
        TableColumn<Item, String> colDescr = new TableColumn<>("Item");  
        TableColumn<Item, Float> colPrice = new TableColumn<>("Price");  
        TableColumn<Item, Boolean> colTaxable = new TableColumn<>("Tax");  
  
        colSKU.setCellValueFactory( new PropertyValueFactory<>("sku") );  
        colDescr.setCellValueFactory( new PropertyValueFactory<>("descr") );  
        colPrice.setCellValueFactory( new PropertyValueFactory<>("price") );  
        colTaxable.setCellValueFactory( new PropertyValueFactory<>("taxable") );  
  
        tblItems.getColumns().addAll(  
            colSKU, colDescr, colPrice, colTaxable  
        );  
  
        tblItems.getItems().addAll(  
            new Item("KBD-0455892", "Mechanical Keyboard", 100.0f, true),  
            new Item( "145256", "Product Docs", 0.0f, false ),  
            new Item( "OR-198975", "O-Ring (100)", 10.0f, true),  
            new Item( "S-123456", "Screwdriver", 5.0f, true)  
        );  
  
        Button btnInventory = new Button("Inventory");  
        Button btnCalcTax = new Button("Tax");  
  
        btnInventory.disableProperty().bind(  
            tblItems.getSelectionModel().selectedItemProperty().isNull()  
        );  
  
        btnCalcTax.disableProperty().bind(  
            tblItems.getSelectionModel().selectedItemProperty().isNull().or(  
                    Bindings.select(  
                        tblItems.getSelectionModel().selectedItemProperty(),  
                        "taxable"  
                    ).isEqualTo(false)  
            )  
        );  
  
        HBox buttonHBox = new HBox( btnInventory, btnCalcTax );  
        buttonHBox.setSpacing( 8 );  
  
        VBox vbox = new VBox( tblItems, buttonHBox );  
        vbox.setPadding( new Insets(10) );  
        vbox.setSpacing( 10 );  
  
        Scene scene = new Scene(vbox);  
  
        primaryStage.setTitle("TableSelectApp");  
        primaryStage.setScene( scene );  
        primaryStage.setHeight( 376 );  
        primaryStage.setWidth( 667 );  
        primaryStage.show();  
    }  
  
    public static void main(String[] args) {  
  
        launch(args);  
    }  
}
```
运行结果如下： 
![[Pasted image 20240430170905.png]]
## ImageView
JavaFX提供了`Image`和`ImageView`类来显示BMP、GIF、JPEG和PNG图形图像。 Image是一个保存图像字节和可选缩放信息的类。 Image对象由后台线程加载，Image类提供与加载操作交互的方法。 Image对象独立于ImageView用于创建光标和应用图标。
ImageView是一个JavaFX`Node`，它包含一个Image对象。 ImageView使图像在整个框架中可用。 ImageView可以单独添加到容器中，也可以与其他UI控件一起添加。 例如，可以通过设置标签的图形属性将图像添加到`Label`。
图像也可以使用JavaFX CSS显示和操作。
### Image
Image类提供了构造函数，用于从图像文件维度或转换后的对象构建Image对象。 这三个构造函数调用分别创建了用于右上、左下和右下图块的Image对象。
```java
public class ImageApp extends Application {

    private final static String IMAGE_LOC = "images/keyboard.jpg";

    @Override
    public void start(Stage primaryStage) throws Exception {

        Image image2 = new Image(IMAGE_LOC, 360.0d, 360.0d, true, true );
        Image image3 = new Image(IMAGE_LOC, 360.0d, 360.0d, false, true);
        Image image4 = new Image(IMAGE_LOC);
```
传入Image构造函数的所有形式的String URL都是相对于类路径的。 也可以使用绝对URL，例如“https://www.bekwam.com/images/bekwam_logo_hdr_rounded.png“。 请注意，绝对URL不会抛出一个错误，如果他们的资源没有找到。
图像2和图像3指定尺寸，形成比原始图像的矩形大的正方形。 image2将保留纵横比（“true”）。 image3的构造函数不保留纵横比，因此会显示为拉伸。
### ImageView
ImageView是一个Node容器，允许在JavaFX容器和UI控件中使用Image对象。 在左上角的图像中，使用了一个简短的ImageView格式，它只传递图像URL。 它将荣誉原始尺寸，并且不需要额外的Image对象。
```java
        ImageView iv1 = new ImageView(IMAGE_LOC);

        ImageView iv2 = new ImageView(image2);
        ImageView iv3 = new ImageView(image3);
        ImageView iv4 = new ImageView(image4);

        iv4.setPreserveRatio(true);
        iv4.setFitHeight(360);
        iv4.setFitWidth(360);
        Rectangle2D viewportRect = new Rectangle2D(20, 50, 100, 100);
        iv4.setViewport(viewportRect);
```
IV3和IV3基于图像2和图像3对象。 回想一下，这些对象产生了适合正方形容器的变换图像。
此外，调整了iv4的视口。 Viewport控制ImageView的可见部分。 在这种情况下，视口被定义为图像的100x100部分，左移20个像素，上移50个像素。
本节演示了Image和ImageView类，它们用于在容器或其他UI控件中显示图像。 这些类定义图像的缩放行为，并可与Rectangle2D Viewport一起使用，以给予额外的图像显示自定义。
### 完整代码
```java
package com.y5neko.imageview;  
  
import javafx.application.Application;  
import javafx.geometry.Rectangle2D;  
import javafx.scene.Scene;  
import javafx.scene.image.Image;  
import javafx.scene.image.ImageView;  
import javafx.scene.layout.TilePane;  
import javafx.stage.Stage;  
  
public class ImageApp extends Application {  
  
    private final static String IMAGE_LOC = "https://img1.baidu.com/it/u=466865769,2215436347&fm=253&fmt=auto&app=138&f=JPEG?w=660&h=440";  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        Image image2 = new Image(IMAGE_LOC, 360.0d, 360.0d, true, true );  
        Image image3 = new Image(IMAGE_LOC, 360.0d, 360.0d, false, true);  
        Image image4 = new Image(IMAGE_LOC);  
  
        ImageView iv1 = new ImageView(IMAGE_LOC);  
  
        ImageView iv2 = new ImageView(image2);  
        ImageView iv3 = new ImageView(image3);  
        ImageView iv4 = new ImageView(image4);  
  
        iv4.setPreserveRatio(true);  
        iv4.setFitHeight(360);  
        iv4.setFitWidth(360);  
        Rectangle2D viewportRect = new Rectangle2D(20, 50, 100, 100);  
        iv4.setViewport(viewportRect);  
          
        TilePane tiles = new TilePane(iv1, iv2, iv3, iv4);  
        tiles.setPrefColumns(2);  
  
        Scene scene = new Scene(tiles);  
  
        primaryStage.setTitle( "ImageApp" );  
        primaryStage.setScene( scene );  
        primaryStage.show();  
  
    }  
  
    public static void main(String[] args) {  
        launch(args);  
    }  
}
```
运行结果如下： 
![[Pasted image 20240430181851.png]]
## LineChart
虽然您可以在`Line`上使用`Canvas`绘制图形，但JavaFX的`LineChart`使图形更容易。 除了自定义轴图例等标准图表组件外，LineChart还封装了图形的源数据。 与所有JavaFX控件一样，LineChart允许您使用CSS来设置图形的样式。
### Data
LineChart包含一个用于管理数据的API。 数据点被分组为系列。 这个例子使用了一个系列。
```java
public class LineChartApp extends Application {

    @Override
    public void start(Stage primaryStage) throws Exception {

        XYChart.Series<Double, Double> series = new XYChart.Series<>();
        series.getData().add( new XYChart.Data<>(0.0,0.0));
        series.getData().add( new XYChart.Data<>(0.7,0.5));
        series.getData().add( new XYChart.Data<>(1.0,0.632));
        series.getData().add( new XYChart.Data<>(2.0,0.865));
        series.getData().add( new XYChart.Data<>(3.0,0.95));
        series.getData().add( new XYChart.Data<>( 4.0, 0.982 ));
        series.getData().add( new XYChart.Data<>( 5.0, 0.993 ));
```
每个数据点都是一个被添加到`XYChart.Data`容器中的`XYChart.Series`对象。 若要显示不同系列的比较，请创建其他XYChart.Series对象。 这些将由LineChart呈现为不同的颜色。
### 图表
LineChart对象是用Axis对象创建的。 第一个Axis参数用于X轴。每个轴对象都包含一个可选标签：时间常数、电压（Vs）。 接下来的两个数值参数给予下限和上限。 最后一个参数设置步长增量。 另一种形式的LineChart构造函数（本示例中未使用）接受数据。 本例对LineChart的数据字段进行了显式的add（）调用。
```java
        LineChart lc = new LineChart(
                new NumberAxis("Time Constant", 0.0, 5.0, 1),
                new NumberAxis("Voltage (Vs)", 0.0, 1.0, 0.1)
                );

        lc.getData().add( series );
```
LineChart可以使用setTitle（）自定义标题，使用setStyle（）自定义单个样式。 为了保持一致性，最好使用样式表，这样就可以在一组折线图中应用单个样式定义。
```java
        lc.setTitle("RC Charging");
        lc.setStyle("-fx-background-color: lightgray");
```
还有许多其他属性可以设置来配置折线图。 setLegendVisible（）删除系列标识符，因为此图中只有一个系列。 setRightSymbols（）删除每个数据点上的图形，这些数据点在图形的原点和端点处被裁剪。
```java
        lc.setCreateSymbols(false);
        lc.setLegendVisible(false);
```
对于适度的报告需求，JavaFX提供了像LineChart这样的类来将多个系列的数据点绘制成一个图。 LineChart对象是高度可定制的，可以控制图例、线条和数据点图标。 此外，CSS样式可用于使这些报告的集合保持一致。
### 完整代码
```java
package com.y5neko.linechart;  
  
import javafx.application.Application;  
import javafx.scene.Scene;  
import javafx.scene.chart.LineChart;  
import javafx.scene.chart.NumberAxis;  
import javafx.scene.chart.XYChart;  
import javafx.scene.layout.VBox;  
import javafx.stage.Stage;  
  
public class LineChartApp extends Application {  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        XYChart.Series<Double, Double> series = new XYChart.Series<>();  
        series.getData().add(new XYChart.Data<>(0.0,0.0));  
        series.getData().add(new XYChart.Data<>(0.7,0.5));  
        series.getData().add(new XYChart.Data<>(1.0,0.632));  
        series.getData().add(new XYChart.Data<>(2.0,0.865));  
        series.getData().add(new XYChart.Data<>(3.0,0.95));  
        series.getData().add(new XYChart.Data<>(4.0, 0.982));  
        series.getData().add(new XYChart.Data<>(5.0, 0.993));  
  
        LineChart lc = new LineChart(  
                new NumberAxis("Time Constant", 0.0, 5.0, 1),  
                new NumberAxis("Voltage (Vs)", 0.0, 1.0, 0.1)  
                );  
  
        lc.getData().add(series);  
  
        lc.setTitle("RC Charging");  
        lc.setStyle("-fx-background-color: lightgray");  
        lc.setCreateSymbols(false);  
        lc.setLegendVisible(false);  
  
        VBox vbox = new VBox(lc);  
  
        Scene scene = new Scene(vbox);  
  
        primaryStage.setScene(scene);  
        primaryStage.setTitle("LineChartApp");  
        primaryStage.show();  
    }  
  
    public static void main(String[] args) {  
        launch(args);  
    }  
}
```
运行结果如下： 
![[Pasted image 20240430182725.png]]
## 分页
分页是一个UI控件，允许您使用下一个、上一个和直接索引按钮逐步浏览结果块。 Pagination类可以在不需要滚动时拆分长列表。 本节介绍了一个特殊的情况下，单一项目的网页，以形成幻灯片。
### SlideShow应用程序
Pagination控件在屏幕底部呈现自定义节点（一个ImageView）和按钮。     对于三个图像中的每一个，都有一个直接访问按钮1、2和3。 还有一对箭头用于移动到下一个和上一个图像。 标签标记图像索引和图像数量，以补充按钮本身的视觉提示。
程序首先定义一个包含三个JavaFX图像的数组：imageURLs。 在start（）方法中，创建了一个引用数组大小的Pagination对象。 提供了一个PageFactory，它基于pageIndex参数创建一个Node。 对于本例，pageIndex是imageURLs数组的索引。
程序会形成一个Scene并将其添加到primaryStage。
### 完整代码
```java
package com.y5neko.pagination;  
  
import javafx.application.Application;  
import javafx.scene.Scene;  
import javafx.scene.control.Pagination;  
import javafx.scene.image.Image;  
import javafx.scene.image.ImageView;  
import javafx.scene.layout.VBox;  
import javafx.stage.Stage;  
  
public class SlideShowApp extends Application {  
  
    private Image[] imageURLs = {  
            new Image("https://img1.baidu.com/it/u=466865769,2215436347&fm=253&fmt=auto&app=138&f=JPEG?w=660&h=440"),  
            new Image("https://img1.baidu.com/it/u=466865769,2215436347&fm=253&fmt=auto&app=139&f=JPEG?w=660&h=440"),  
            new Image("https://img1.baidu.com/it/u=466865769,2215436347&fm=253&fmt=auto&app=1340&f=JPEG?w=660&h=440")  
    };  
  
    @Override  
    public void start(Stage primaryStage) throws Exception {  
  
        Pagination pagination = new Pagination(imageURLs.length, 0);  
        pagination.setPageFactory(  
            pageIndex -> new ImageView(imageURLs[pageIndex])  
        );  
  
        VBox vbox = new VBox( pagination );  
  
        Scene scene = new Scene(vbox);  
  
        primaryStage.setScene(scene);  
        primaryStage.show();  
    }  
  
    public static void main(String[] args) {  
        launch(args);  
    }  
}
```
Pagination类是一个简单的控件，用于遍历一长串项。 这个例子使用了每页一个项目来形成一个幻灯片。 在这两种情况下，这是滚动的替代方法，并且在您希望UI固定在位置时很有用。
# 布局
## VBox和HBox
JavaFX中的布局从选择正确的容器控件开始。 我最常用的两个布局控件是`VBox`和`HBox`。 `VBox`是一个容器，它将其子容器排列在垂直堆栈中。 `HBox`将其子元素排列在水平行中。 这两个控件的强大之处在于包装它们并设置几个关键属性：alignment、hgrow和vgrow。
本文将通过一个示例项目演示这些控件。 项目的模型显示了一个UI，其中包含以下内容： 
- 一行顶部控件，包含刷新Button和注销Hyperlink
- `TableView`将增长以占用额外的垂直空间
- 关闭按钮
UI还具有`Separator`，其将屏幕的顶部与可能成为应用程序的标准下部面板（保存`Button`、取消`Button`等）分开。
### Structure
`VBox`是最外面的容器“vbox”。 这将是提供给场景的`Parent`。 简单地将UI控件放在这个`VBox`中将允许控件-最值得注意的是`TableView`-拉伸以适应可用的水平空间。     最上面的控件，刷新`Button`和注销`Hyperlink`，被包装在`HBox`中。 类似地，我将底部Close `Button`包装在`HBox`中，以允许额外的重复。
```java
VBox vbox = new VBox();

Button btnRefresh = new Button("Refresh");

HBox topRightControls = new HBox();
topRightControls.getChildren().add( signOutLink );

topControls.getChildren().addAll( btnRefresh, topRightControls );

TableView<Customer> tblCustomers = new TableView<>();
Separator sep = new Separator();

HBox bottomControls = new HBox();

Button btnClose = new Button("Close");

bottomControls.getChildren().add( btnClose );

vbox.getChildren().addAll(
        topControls,
        tblCustomers,
        sep,
        bottomControls
);
```
### Alignment 和 Hgrow
刷新`Button`向左对齐，而注销`Hyperlink`向右对齐。 这是使用两个HBox完成的。 topControls是一个包含Refresh `HBox`的`Button`，还包含一个带有Sign Out `HBox`的`Hyperlink`。 随着屏幕变宽，退出`Hyperlink`将被拉到右侧，而刷新`Button`将保持其左对齐。
对齐是告知容器将控件定位在何处的属性。 topControls将对齐设置为BOTTOM_LEFT。 topRightControls将对齐设置为BOTTOM_RIGHT。 “BOTTOM”确保文本“Refresh”的基线与文本“Sign Out”的基线匹配。
为了使退出`Hyperlink`在屏幕变宽时向右移动，需要`Priority.ALWAYS`。 这是一个提示JavaFX扩大topRightControls。 否则，topControls将保留空间，topRightControls将显示在左侧。 注销`Hyperlink`仍然是右对齐的，但在一个更窄的容器中。
请注意，`setHgrow()`是一个静态方法，既不在topControls `HBox`上调用，也不在其自身topRightControls上调用。 这是JavaFX API的一个方面，可能会引起混淆，因为大多数API都是通过对象上的setter来设置属性的。