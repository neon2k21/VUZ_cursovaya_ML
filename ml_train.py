import csv
import aiohttp
import asyncio
import esprima
from esprima import Node
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from joblib import dump

def convert_to_raw_url(github_url):
    raw_url = github_url.replace('https://github.com/', 'https://raw.githubusercontent.com/')
    raw_url = raw_url.replace('/blob/', '/')
    return raw_url

async def fetch_raw_file(session, github_url):
    raw_url = convert_to_raw_url(github_url)

    try:
        async with session.get(raw_url) as response:
            response.raise_for_status()
            content = await response.text()
            return content

    except aiohttp.ClientError as e:
        print(f"Error fetching GitHub file from {raw_url}: {e}")
        return None

def code_to_ast(code):
    print(code)
    try:
        parsed_code = esprima.parseScript(code)
        print(parsed_code)
        return parsed_code
    except esprima.Error as e:
        print(e)
        return f"Esprima Error: {e}"
    except Exception as e:
        print(e)
        return f"Error: {e}"

def node_to_dict(node):
    if isinstance(node, Node):
        node_dict = {
            'type': node.type,
            'range': node.range,
            'loc': node.loc
        }
        for key, value in node.__dict__.items():
            if key not in node_dict:
                node_dict[key] = node_to_dict(value)
        return node_dict
    elif isinstance(node, list):
        return [node_to_dict(child) for child in node]
    else:
        return node

def count_nodes_of_type(node, node_type):
    count = 0
    if isinstance(node, Node):
        if node.type == node_type:
            count += 1
        for child in node.__dict__.values():
            count += count_nodes_of_type(child, node_type)
    elif isinstance(node, list):
        for child in node:
            count += count_nodes_of_type(child, node_type)
    return count

async def process_csv_and_fetch_files(csv_file_path):
    results_list = []

    async with aiohttp.ClientSession() as session:
        tasks = []

        with open(csv_file_path, mode='r', encoding='utf-8-sig') as csv_file:
            csv_reader = csv.DictReader(csv_file)
            rows = list(csv_reader)
            for row in rows:
                github_url = row['full_repo_path']
                tasks.append(asyncio.create_task(fetch_raw_file(session, github_url)))

            results = await asyncio.gather(*tasks)

        for result in results:
            if result:
                ast = code_to_ast(result)
                print(ast)
                if isinstance(ast, str):
                    results_list.append({'error': ast})
                else:
                    ast_dict = node_to_dict(ast)
                    results_list.append({'ast': ast_dict})
    return results_list, rows

def preprocess_ast_data(ast_data):
    # Пример простейшей обработки AST: считаем количество узлов типа FunctionExpression
    return count_nodes_of_type(ast_data, 'FunctionExpression')

async def main():
    csv_file_path = 'JSVulnerabilityDataSet-1.0.csv'
    results, rows = await process_csv_and_fetch_files(csv_file_path)
    print(len(results))
    required_columns = ['name', 'longname', 'path', 'full_repo_path', 'CC', 'CCL', 'CCO', 'CI', 'CLC',
                        'CLLC', 'McCC', 'NL', 'NLE', 'CD', 'CLOC', 'DLOC', 'TCD', 'TCLOC', 'LLOC',
                        'LOC', 'NOS', 'NUMPAR', 'TLLOC', 'TLOC', 'TNOS', 'HOR_D', 'HOR_T', 'HON_D',
                        'HON_T', 'HLEN', 'HVOC', 'HDIFF', 'HVOL', 'HEFF', 'HBUGS', 'HTIME', 'CYCL',
                        'PARAMS', 'CYCL_DENS', 'Vuln']

    data = []
    for idx, row in enumerate(rows):
        if 'ast' in results[idx]:
            ast_feature = preprocess_ast_data(results[idx]['ast'])
        else:
            ast_feature = 0

        row_data = {col: row[col] for col in required_columns}
        row_data['ast_feature'] = ast_feature
        print(row_data)
        data.append(row_data)

    df = pd.DataFrame(data)
    print(df.info())

    X = df.drop(columns=['name', 'longname', 'path', 'full_repo_path'])
    y = df['Vuln'].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Сохранение модели
    dump(model, 'model.joblib')

    y_pred = model.predict(X_test)

    print(classification_report(y_test, y_pred))

# Запуск основного асинхронного цикла
asyncio.run(main())
