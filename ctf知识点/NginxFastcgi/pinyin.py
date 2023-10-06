from pypinyin import lazy_pinyin, Style
import linecache

output_file = open("training_pinyin.txt", "w")
readlist = list(range(0, 4))  # 人工校准的时候去掉了4条不是该角色的音频
for i in readlist:
    text = linecache.getline("training_1800_result.txt", i)
    text = " ".join(lazy_pinyin(text, style=Style.TONE3))
    output_file.write(text)
