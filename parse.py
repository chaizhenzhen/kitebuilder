import json
from json import JSONDecodeError
from os import listdir
from os.path import isfile, join
import logging
import hashlib
import ksuid
import yaml
from collections import Counter
import sys

seen_hashes = {}


class ParserSpecPathDuplicateException(Exception):
    pass


def parse_security_definitions(spec):
    """
    Parses and pulls the security definitions from the spec, excluding oauth2 definitions.
    :param spec: the swagger spec being parsed
    :return: dictionary of the specs security definitions
    """
    defs = spec.get("securityDefinitions", {})

    if type(defs) != dict:
        return

    return {
        k: v for (k, v) in defs.items() if
        type(v) == dict and v.get("type") != "oauth2"
    }


def parse_security_schemes(spec):
    """
    Parses and pulls the security schemes from the v3 spec, excluding oauth2 definitions.
    :param spec: the openapi spec being parsed
    :return: dictionary of the specs security schemes
    """
    defs = spec.get("components", {}).get("securitySchemes", {})

    if type(defs) != dict:
        return

    return {
        k: v for (k, v) in defs.items() if
        type(v) == dict and v.get("type") != "oauth2"
    }


# resolve JSON Reference
def resolve_ref(spec, ref_name):
    """
    Resolve and replace a specs JSON schema $ref value
    :param spec: the swagger/openapi spec being parsed
    :param ref_name: the $ref value to be resolved
    :return: None if unable to parse the $ref value, otherwise will resolve to that ref definition
    """

    # don't parse any external definitions
    if ref_name[0:1] == "./" or ".json" in ref_name:
        return

    resolved_ref = None

    for part in ref_name.split('/'):
        if part == "#":
            resolved_ref = spec
            continue

        if resolved_ref is None:
            return

        resolved_ref = resolved_ref.get(part)

    return resolved_ref


# resolve Schema Object
def resolve_schema_object(spec, schema):
    if type(schema) != dict:
        return

    # handle Schema $ref (but don't return, we may need to resolve nested $refs)
    schema_ref = schema.get("$ref", None)
    if schema_ref:
        resolved_schema = resolve_ref(spec, schema_ref)

        if resolved_schema:
            schema = resolved_schema
        else:
            schema = dict(type="object")

    # handle Schema array items
    items = schema.get("items", {})
    if items and type(items) == dict:
        resolved_item = resolve_schema_object(spec, items)

        if resolved_item:
            schema.update({"items": resolved_item})

    # handle Schema object additionalProperties
    additional_properties = schema.get("additionalProperties", {})
    if additional_properties and type(additional_properties) == dict:
        resolved = resolve_schema_object(spec, additional_properties)

        if resolved:
            schema.update({"additionalProperties": resolved})

    # handle Schema object properties
    properties = schema.get("properties", {})
    if properties and type(properties) == dict:
        parsed_properties = {}

        for prop_name, prop_value in properties.items():
            # why is this even necessary ugh
            if prop_name == "$ref":
                continue

            resolved = resolve_schema_object(spec, prop_value)

            if resolved:
                parsed_properties[prop_name] = resolved

        if parsed_properties:
            schema.update({"properties": parsed_properties})

    # resolve and replace any $refs in allOf
    all_of = schema.get("allOf", [])
    if all_of and type(all_of) == list:
        for idx, item in enumerate(all_of):
            resolved_item = resolve_schema_object(spec, item)

            if resolved_item:
                all_of[idx] = resolved_item

        schema.update({"allOf": all_of})

    # resolve and replace any $refs in oneOf
    one_of = schema.get("oneOf", [])
    if one_of and type(one_of) == list:
        for idx, item in enumerate(one_of):
            resolved_item = resolve_schema_object(spec, item)

            if resolved_item:
                one_of[idx] = resolved_item

        schema.update({"oneOf": one_of})

    # resolve and replace any $refs in anyOf
    any_of = schema.get("anyOf", [])
    if any_of and type(any_of) == list:
        for idx, item in enumerate(any_of):
            resolved_item = resolve_schema_object(spec, item)

            if resolved_item:
                any_of[idx] = resolved_item

        schema.update({"oneOf": any_of})

    # handle examples (limit to only one, return str)
    example = schema.get("example", None)
    if example:
        if type(example) == dict:
            example = json.dumps(example)
        elif type(example) == list and len(example) >= 1:
            example = example[0]
        else:
            example = str(example)

        schema.update({"example": example})

    return schema


# if in == "body": Schema -> Schema Object (parse_schema_object)
# if in != "body" and type == "array": Parameter.items -> Items Object (parse_items_object?)
def resolve_parameter(spec, content_types, parameter):
    if type(parameter) != dict:
        return

    param_ref = parameter.get("$ref", None)
    if param_ref is not None:
        parameter = resolve_ref(spec, param_ref)
        if parameter is None:
            return

    # skip including any non dictionaries
    schema = parameter.get("schema", {})
    if schema and type(schema) == dict:
        resolved_schema = resolve_schema_object(spec, schema)

        if resolved_schema:
            parameter.update({"schema": resolved_schema})

    elif schema and type(schema) != dict:
        parameter.pop("schema")

    # handle Parameter array items
    items = parameter.get("items", {})
    if items and type(items) == dict:
        resolved_item = resolve_schema_object(spec, items)

        if resolved_item:
            parameter.update({"items": resolved_item})

    # basic check on name and description to determine if the string is a UUID
    param_desc = parameter.get("description", "")
    if param_desc and type(param_desc) == str and "uuid" in param_desc.lower():
        parameter["type"] = "uuid"

    param_name = parameter.get("name", "")
    if param_name and type(param_desc) == str and "uuid" in param_name.lower():
        parameter["type"] = "uuid"

    param_example = parameter.get("example", "")
    if param_example and type(param_example) == str and "uuid" in param_example.lower():
        parameter["type"] = "uuid"

    # check if a regex pattern exists, supplying it as the format if it does
    pattern = parameter.get("pattern", None)
    if pattern:
        parameter["format"] = pattern

    # x-examples
    x_examples = parameter.get("x-examples", None)
    _unknown_ct_idx = 0
    if x_examples is not None:
        if type(x_examples) == dict:
            new_examples = {}
            for content_type, example_data in x_examples.items():
                if content_type == "description":
                    continue

                if content_type not in content_types:
                    new_examples[f"unknown/{_unknown_ct_idx}"] = str(example_data)
                    _unknown_ct_idx += 1
                else:
                    new_examples[content_type] = example_data

            x_examples = new_examples

        if type(x_examples) == list:
            for idx, example in enumerate(x_examples):
                x_examples[f"unknown/{idx}"] = str(example)

        parameter["x-examples"] = x_examples

    return parameter


# check for extra parameters in path, such as :token and replace with {token} and a parameter in each route
def resolve_extra_path_params(path):
    extra_path_params = []
    for _idx, path_chunk in enumerate(path.split('/')):
        if len(path_chunk) > 0 and path_chunk[0] == ":":
            path_chunk = f"{{{path_chunk[1:]}}}"

            extra_path_params.append({
                "in": "path",
                "name": path_chunk,
                "required": True,
                "type": "number" if path_chunk.lower()[-2:] == "id" else "string"
            })

        if len(path_chunk) > 0 and path_chunk[0] == "[" and path_chunk[-1] == "]":
            path_chunk = f"{{{path_chunk[1:-1]}}}"

            extra_path_params.append({
                "in": "path",
                "name": path_chunk,
                "required": True,
                "type": "number" if path_chunk.lower()[-2:] == "id" else "string"
            })

    return extra_path_params


def parse_swagger_spec(file_name, blacklist):
    with open(file_name, encoding='utf-8-sig') as f:
        content = f.read()

        try:
            spec = None
            if "json" in file_name.lower():
                spec = json.loads(content)

            if "yaml" in file_name.lower():
                spec = yaml.safe_load(content)

        except JSONDecodeError as e:
            raise Exception(f"Failed to parse invalid spec (invalid JSON): {file_name}")

        except yaml.YAMLError:
            raise Exception(f"Failed to parse invalid spec (invalid YAML): {file_name}")

    if type(spec) != dict:
        raise Exception(f"Failed to parse invalid spec (invalid spec, invalid format): {file_name}")

    host = None
    security_definitions = None

    if spec.get("openapi") is not None:
        if spec.get("servers") is not None:
            host = spec.get("servers", [])[0]["url"]
            security_definitions = parse_security_definitions(spec)

    if spec.get("swagger") is not None:
        host = spec.get("host")
        if type(host) == list and len(host) > 0:
            host = host[0]
        # print(host)
        # print(type(host))
        security_definitions = parse_security_schemes(spec)

    # if host is not None and blacklist is not None and any(_host in host for _host in blacklist):
    #     raise Exception(f"Failed to parse invalid spec (blacklisted host): {file_name}")

    paths = spec.get("paths", {})
    if type(paths) != dict:
        raise Exception(f"Failed to parse invalid spec (invalid spec, missing paths): {file_name}")

    if paths is None:
        raise Exception(f"Failed to parse invalid spec (invalid spec, missing paths): {file_name}")

    base_path = spec.get('basePath', '/')
    if base_path is None:
        raise Exception(f"Failed to parse invalid spec (invalid spec, missing basePath)")

    # don't allow go templated base path, default to /
    if "{{." in base_path:
        base_path = '/'

    custom_schema = {
        "ksuid": str(ksuid.ksuid()),
        "url": host,
        "securityDefinitions": security_definitions,
        "paths": {}
    }

    for path in paths:
        if type(paths[path]) == str:
            continue

        full_path = f"{base_path}{path}".replace('//', '/')

        extra_path_params = resolve_extra_path_params(full_path)
        # print(extra_path_params)

        try:
            for method, endpoint_data in paths[path].items():
                if type(endpoint_data) != dict:
                    continue

                path_params = endpoint_data.get("parameters", [])
                if type(path_params) != list:
                    continue

                description = endpoint_data.get("description", None)
                if type(description) == dict:
                    description=json.dumps(description)
                    # if "$ref" in description.keys():
                    #     description = description["$ref"]
                if description is None:
                    description = endpoint_data.get("summary", "")

                operation_id = spec["paths"][path][method].get("operationId", None)
                consumes = endpoint_data.get("consumes", None)

                if consumes is None:
                    consumes = []

                parameters = [
                    parameter for parameter in
                    list(map(lambda param_fields: resolve_parameter(spec, consumes, param_fields), path_params))
                    if parameter is not None
                ]
                parameters.extend(extra_path_params)

                seen_route_hashes = seen_hashes.get(path, {}).get(method, [])

                # skip this spec if circular references are detected
                try:
                    json_params = json.dumps(parameters, sort_keys=True).encode('utf-8')
                    param_hash = hashlib.md5(json_params).hexdigest()
                except ValueError:
                    logging.warning(f"Failed to parse invalid spec (circular references): {file_name}")
                    return

                if param_hash in seen_route_hashes:
                    raise ParserSpecPathDuplicateException

                seen_route_hashes.append(param_hash)
                if seen_hashes.get(path, None) is None:
                    seen_hashes[path] = {}

                seen_hashes[path][method] = seen_route_hashes

                custom_schema["paths"][full_path] = {
                    method: {
                        "description": description,
                        "operationId": operation_id,
                        "parameters": parameters,
                        "consumes": consumes,
                        "produces": endpoint_data.get("produces", None),
                    }
                }

        except ParserSpecPathDuplicateException:
            continue

        except RecursionError:
            continue

    if len(custom_schema.get("paths", [])) == 0:
        return

    return custom_schema


# 这里用来统计文件中的路径出现的次数
def data_count(file_name):
    with open(file_name, encoding='utf-8-sig') as f:
        content = f.read()

        try:
            spec = None
            if "json" in file_name.lower():
                spec = json.loads(content)

            if "yaml" in file_name.lower():
                spec = yaml.safe_load(content)

        except JSONDecodeError as e:
            raise Exception(f"Failed to parse invalid spec (invalid JSON): {file_name}")

        except yaml.YAMLError:
            raise Exception(f"Failed to parse invalid spec (invalid YAML): {file_name}")

    if type(spec) != dict:
        raise Exception(f"Failed to parse invalid spec (invalid spec, invalid format): {file_name}")

    paths = spec.get("paths", {})
    if type(paths) != dict:
        raise Exception(f"Failed to parse invalid spec (invalid spec, missing paths): {file_name}")

    if paths is None:
        raise Exception(f"Failed to parse invalid spec (invalid spec, missing paths): {file_name}")

    base_path = spec.get('basePath', '/')
    if base_path is None:
        raise Exception(f"Failed to parse invalid spec (invalid spec, missing basePath)")

    # don't allow go templated base path, default to /
    if "{{." in base_path:
        base_path = '/'

    # 定义一个用来统计用的列表
    api_paths = []
    for path in paths:
        if type(paths[path]) == str:
            continue

        full_path = f"{base_path}{path}".replace('//', '/')
        # print(full_path)，把从swagger文件中读取到的路径，存储到api_paths中去
        api_paths.append(full_path)

    if len(api_paths) == 0:
        return

    return api_paths
    # print(api_paths)


# 用来获取文件MD5值，为了去重
def get_md5(file_name):
    # md5_dict = {}
    with open(file_name, 'rb') as f:
        content = f.read()
        m = hashlib.md5(content)
        md5_vaule = m.hexdigest()
        # md5_dict[file_name] = md5_vaule
    # return md5_vaule, file_name
    # print(md5_dict)
    return md5_vaule


# 根据kitebuilder转换后的output文件，获取top100
def get_top1000(top_file, kitebuilder_file, new_file):
    # 获取top1000的路径数据
    with open(top_file, 'r', encoding='utf-8') as dd:
        out_s = dd.read()
        api_top_dict = json.loads(out_s)
        # print(api_top_dict)
    k0 = list(api_top_dict.keys())
    k1 = k0[0:1000]
    # 获取kite解析数据包含top1000的数据
    with open(kitebuilder_file, 'r', encoding='utf-8') as ff:
        out = ff.read()
        list1 = json.loads(out)
        ids = []
        for idx, j in enumerate(list1):
            paths_dicts = j["paths"]
            k2 = list(paths_dicts.keys())
            for k in k2:
                if k in k1:
                    # 如果路径在top1000中，就把该路径所属swagger字典的索引返回出来。
                    ids.append(idx)
                    # print(idx)
                else:
                    continue
            logging.info(f"[{idx}] 进行中 ")
        # 将索引值去重
        test = set(ids)
    # 根据索引把swagger字典拿出来存到list2列表里
    list2 = []
    for i in test:
        list2.append(list1[i])
    # 把包含了top1000的kite解析数据保存为新的new文件
    sys.stdout = open(new_file, "w+", encoding='utf-8')
    print(json.dumps(list2, indent=4, ensure_ascii=False))
    sys.stdout.close()


def parse_specs(scrape_dir, output_file, top_paths, top_paths_md5, output_top,blacklist):
    try:
        files = [f"{scrape_dir}/{f}" for f in listdir(scrape_dir) if isfile(join(scrape_dir, f))]

    except FileNotFoundError:
        logging.error("Invalid spec directory supplied.")
        return

    output_contents = []

    for idx, file in enumerate(files):
        try:
            # custom_schema, api_paths = parse_swagger_spec(file, blacklist)
            custom_schema = parse_swagger_spec(file, blacklist)

        except KeyboardInterrupt:
            exit()

        except Exception as e:
            logging.error(f"[{idx}, {file}] {e}")
            continue

        if custom_schema is None:
            continue

        output_contents.append(custom_schema)

        logging.info(f"[{idx}] Successfully parsed spec: {file}")

    # 保存解析之后的文件
    with open(output_file, 'w+', encoding='utf-8') as f:
        f.write(json.dumps(output_contents, indent=4))
        logging.info(f"Wrote output to file: {output_file}")

    # 将每个文件获取的路径数据加到一个列表中，方便后续统计
    api_results_count = []
    for idx1, file1 in enumerate(files):
        try:
            api_paths = data_count(file1)

        except KeyboardInterrupt:
            exit()

        except Exception as e:
            logging.error(f"[{idx1}, {file1}] {e}")
            continue

        if api_results_count is None:
            continue

        # results_count.append(api_paths)
        if api_paths:
            api_results_count.extend(api_paths)
            logging.info(f"[{idx1}] Successfully data count: {file1}")
    # 调用Counter来统计，速度快
    # print(results_count[0])
    result = Counter(api_results_count)

    # print(result)
    # 按次数排个序
    result_sorted = dict(sorted(result.items(), key=lambda x: x[1], reverse=True))
    # 保存api路径的统计数据
    sys.stdout = open(top_paths, "w+", encoding='utf-8')
    print(json.dumps(result_sorted, indent=4, ensure_ascii=False))
    logging.info(f"Wrote output to file: {top_paths}")
    sys.stdout.close()

    # 对文件进行去重，然后再统计路径出现的次数
    md5_list = []
    api_results_count_2 = []
    for idx2, file2 in enumerate(files):
        md5_vaule = get_md5(file2)
        if md5_vaule not in md5_list:
            try:
                md5_list.append(md5_vaule)
                api_paths_2 = data_count(file2)

            except KeyboardInterrupt:
                exit()

            except Exception as e:
                logging.error(f"[{idx2}, {file2}] {e}")
                continue

            if api_results_count is None:
                continue

            # results_count.append(api_paths)
            if api_paths_2:
                api_results_count_2.extend(api_paths_2)
                logging.info(f"[{idx2}] Successfully data statistics deduplicated: {file2}")
        else:
            logging.info(f"[{idx2}] File MD5 duplicates: {file2},MD5 vaule is:{md5_vaule}")
    # 调用Counter来统计，速度快
    # print(results_count[0])
    result_2 = Counter(api_results_count_2)

    # print(result)
    # 按次数排个序
    result_sorted_2 = dict(sorted(result_2.items(), key=lambda x: x[1], reverse=True))
    # 保存去重后的api路径的统计数据
    sys.stdout = open(top_paths_md5, "w+", encoding='utf-8')
    print(json.dumps(result_sorted_2, indent=4, ensure_ascii=False))
    logging.info(f"Wrote output to file: {top_paths_md5}")
    sys.stdout.close()

    # 调用get_top1000()方法，获取top1000的kitebuilder数据
    get_top1000(top_paths_md5,output_file,output_top)

    return len(output_contents)


