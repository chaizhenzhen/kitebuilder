### Kitebuilder
#### Using Kitebuilder
```bash
用法: kitebuilder.py [-h] {parse,convert} ...

Assetnote OpenAPI/Swagger API schema parser

可选参数:
  -h, --help       展示帮助信息并退出

action:
  {parse,convert}
    parse          parse 将swagger JSON文件的目录解析为Kiterunner的单个JSON 文件输出
    convert        将文件转换为提供的输出目录中的多个swagger JSON 文件
```

Kitebuilder能够将大量swagger文件数据集解析为我们的iterim 格式，供Kiterunner使用。
它还提供了一个转换实用程序，可以将其他格式解析为许多规范文件。

```
用法: kitebuilder.py parse [-h] [--blacklist HOSTS] [--scrape-dir DIR] [--output-file FILE] [--output-file2 FILE] [--output-file3 FILE] [--output-top FILE]

optional arguments:
  -h, --help   显示帮助信息并退出
  --blacklist HOSTS   host黑名单设置（默认 googleapis、azure、petstore、amazon）
  --scrape-dir DIR   设置需要扫描的目录 (默认为 ./scrape)
  --output-file FILE   设置输出文件存储的路径及名称 (默认 output.json)
  --output-file2 FILE   设置输出文件存储的路径及名称，此项统计所有的swagger文件中的路径。
  --output-file3 FILE   设置输出文件存储的路径及名称，此项统计所有的swagger文件中的路径，统计之前，对swagger文件进行了去重操作。
  --output-top FILE   设置输出文件存储的路径及名称，此项输出top1000的解析文件。
```

```
用法: kitebuilder.py convert [-h] --file FILE [--format FORMAT] [--scrape-dir DIR]

optional arguments:
  -h, --help        显示帮助信息并退出
  --file FILE       设置要转换的swagger文件
  --format FORMAT   要转换的文件格式。仅支持CSV文件。格式必须为"id,name,content"
  --scrape-dir DIR  设置要扫描的目录 (默认为 ./scrape)
```
### 示例
#### 将./specs目录中的specs解析到output.json
```
python kitebuilder.py parse --scrape-dir ./specs --output-file output.json
```
请注意，此处的"--output-file"不是必需的，因为output.json 是默认值。


#### 将 BigQuery CSV导出转换为./specs中的多个规范文件
```
python kitebuilder.py convert --file swagger-github.csv --format CSV --scrape-dir ./specs
```
注意：这要求CSV文件的格式为"id,name,file_content"。

Looking for [Kiterunner](https://github.com/assetnote/kiterunner)?
