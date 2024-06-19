import os
import argparse
import esprima
from joblib import load
import pandas as pd

def code_to_ast_and_features(code):
    try:
        parsed_code = esprima.parseScript(code)
        return count_nodes_of_type(parsed_code, 'FunctionExpression')
    except esprima.Error as e:
        return 0  # В случае ошибки возвращаем 0 признаков
    except Exception as e:
        return 0  # В случае ошибки возвращаем 0 признаков

def count_nodes_of_type(node, node_type):
    count = 0
    if isinstance(node, esprima.nodes.Node):
        if node.type == node_type:
            count += 1
        for child in node.__dict__.values():
            count += count_nodes_of_type(child, node_type)
    elif isinstance(node, list):
        for child in node:
            count += count_nodes_of_type(child, node_type)
    return count

def load_model(model_file):
    try:
        model = load(model_file)
        return model
    except Exception as e:
        print(f"Error loading model from {model_file}: {e}")
        return None

def predict_vulnerabilities(directory_path, model):
    results = []
    for root, _, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name.endswith('.js'):
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        code = file.read()
                    ast_features = code_to_ast_and_features(code)

                    if isinstance(ast_features, (int, float)):
                        ast_features = [[ast_features]]
                    elif isinstance(ast_features, list):
                        ast_features = [ast_features]

                    while len(ast_features[0]) < 36:
                        ast_features[0].append(0)

                    prediction = model.predict(ast_features)[0]
                    results.append({'file': file_path, 'prediction': prediction})
                except Exception as e:
                    print(f"Error processing file {file_path}: {e}")
    return results

def main():
    parser = argparse.ArgumentParser(description='Analyze JavaScript files in a directory for vulnerabilities using a RandomForestClassifier model.')
    parser.add_argument('directory', type=str, help='Path to the directory containing JavaScript files to analyze')
    parser.add_argument('model_file', type=str, help='Path to the RandomForestClassifier model file (.joblib)')
    args = parser.parse_args()

    directory_path = args.directory
    model_file = args.model_file

    model = load_model(model_file)
    if model:
        predictions = predict_vulnerabilities(directory_path, model)
        if predictions:
            df = pd.DataFrame(predictions)
            print(df)
        else:
            print("No JavaScript files found or unable to make predictions.")
    else:
        print("Failed to load model. Exiting...")

if __name__ == "__main__":
    main()
